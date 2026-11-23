using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>
    /// Loại RECORD trên dây (lớp ngoài cùng). Chỉ có 2 loại:
    /// - Hello  : gói bắt tay DUY NHẤT ở dạng rõ (public key, nonce...)
    /// - Sealed : mọi thứ còn lại — AES-256-GCM. Loại gói thật (Text, FileChunk...)
    ///            nằm BÊN TRONG ciphertext, nên kẻ nghe lén không phân biệt được
    ///            chat với file, ping với chữ ký (giống TLS 1.3 ẩn content-type).
    /// </summary>
    public enum RecordType : byte
    {
        Hello = 0x48,   // 'H'
        Sealed = 0x53,  // 'S'
    }

    /// <summary>
    /// Loại gói BÊN TRONG record Sealed. Thêm loại mới ở đây khi mở rộng
    /// mà KHÔNG phải đụng vào logic đóng khung / mã hóa.
    /// </summary>
    public enum PacketType : byte
    {
        Auth = 0x01,     // chữ ký ECDSA lên transcript bắt tay — luôn là gói Sealed đầu tiên
        Text = 0x02,
        Ping = 0x03,     // heartbeat + đo RTT
        Pong = 0x04,
        Bye = 0x05,      // đóng phiên êm (graceful) — bên kia biết ngay, không phải chờ timeout

        // Luồng file CONSENT-FIRST: không byte dữ liệu nào được gửi trước khi bên nhận Accept.
        FileOffer = 0x10,    // {id, tên, size, contentKey, resume}
        FileAccept = 0x11,   // {id, offset} — offset>0 = RESUME; gửi lại giữa chừng = yêu cầu tua (resync)
        FileReject = 0x12,   // [16B id][1B lý do]
        FileChunk = 0x13,    // [16B id][8B offset][dữ liệu]
        FileComplete = 0x14, // [16B id][32B SHA-256 toàn file]
        FileCancel = 0x15,   // hủy giữa chừng (giữ .part để resume)
        FileResult = 0x16,   // [16B id][1B status] — bên nhận xác nhận đã kiểm SHA-256
    }

    /// <summary>
    /// Giao thức khung nhị phân (length-prefixed framing) trên TCP:
    ///
    ///   [1B RecordType][4B LE: độ dài body][body]
    ///
    /// TCP là STREAM (không có ranh giới message) nên bên nhận phải biết mỗi
    /// record dài bao nhiêu. Với record Sealed, 5 byte header này còn được đưa vào
    /// AAD của AES-GCM → sửa độ dài hay loại record trên đường truyền đều bị phát hiện.
    /// </summary>
    public static class Protocol
    {
        public const string Magic = "HLC";
        public const int Version = 2;

        public const int HeaderSize = 5;
        public const int TagSize = 16;
        public const int MaxHelloSize = 4 * 1024;          // trước khi xác thực: không cho cấp phát lớn
        public const int MaxRecordSize = 4 * 1024 * 1024;  // chunk 128KB + overhead — 4MB là dư dả

        public static void WriteHeader(Span<byte> dst, RecordType type, int bodyLength)
        {
            dst[0] = (byte)type;
            BinaryPrimitives.WriteInt32LittleEndian(dst.Slice(1, 4), bodyLength);
        }

        /// <summary>
        /// Đọc đúng 5 byte header. ReadExactlyAsync xử lý "partial read" (TCP có thể
        /// trả dữ liệu vụn từng mẩu). Ném EndOfStreamException khi bên kia đóng kết nối.
        /// </summary>
        public static async ValueTask<(RecordType Type, int Length)> ReadHeaderAsync(
            Stream stream, Memory<byte> header, CancellationToken ct)
        {
            await stream.ReadExactlyAsync(header[..HeaderSize], ct).ConfigureAwait(false);
            var type = (RecordType)header.Span[0];
            int length = BinaryPrimitives.ReadInt32LittleEndian(header.Span.Slice(1, 4));
            if (length < 0 || length > MaxRecordSize)
                throw new HlcProtocolException($"Kích thước record bất thường: {length}");
            return (type, length);
        }
    }

    /// <summary>Bên kia vi phạm giao thức (gói lạ, sai thứ tự, sai kích thước...) → đóng kết nối.</summary>
    public sealed class HlcProtocolException : IOException
    {
        public HlcProtocolException(string message) : base(message) { }
    }
}
