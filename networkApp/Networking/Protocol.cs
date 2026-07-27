using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>
    /// Loại gói tin. Thêm loại mới ở đây khi mở rộng (FileMeta, FileChunk, Resume...)
    /// mà KHÔNG phải đụng vào logic đọc/ghi khung.
    /// </summary>
    public enum PacketType : byte
    {
        Text = 0x01,
        Handshake = 0x02, // trao public key + salt — gói DUY NHẤT không mã hóa

        // Luồng file CONSENT-FIRST: không byte dữ liệu nào được gửi
        // trước khi bên nhận chủ động Accept.
        FileOffer = 0x10, // "Tôi muốn gửi file X, size Y" (JSON)
        FileAccept = 0x11, // "Đồng ý, gửi từ offset Z"  ← Z>0 = RESUME
        FileReject = 0x12, // "Từ chối"
        FileChunk = 0x13, // [16B transferId][dữ liệu]
        FileComplete = 0x14, // "Hết file"
        FileCancel = 0x15, // Một trong hai bên chủ động hủy giữa chừng (giữ .part để resume)
    }

    /// <summary>
    /// Giao thức khung nhị phân (length-prefixed framing) trên TCP:
    ///
    ///   [4 byte LE: độ dài payload][1 byte: PacketType][payload]
    ///
    /// Vì TCP là STREAM (không có ranh giới message), bên nhận phải tự biết
    /// mỗi "gói" dài bao nhiêu — đó là vai trò của 4 byte đầu. Đây là dạng
    /// serialization nhị phân + buffer management cơ bản nhất và nhanh nhất.
    /// </summary>
    public static class Protocol
    {
        private const int HeaderSize = 5;
        private const int MaxPayload = 16 * 1024 * 1024; // 16MB — chặn gói rác/độc làm cạn RAM

        public static async Task WriteFrameAsync(
            Stream stream, PacketType type, ReadOnlyMemory<byte> payload, CancellationToken ct)
        {
            byte[] header = new byte[HeaderSize];
            BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
            header[4] = (byte)type;

            await stream.WriteAsync(header, ct);
            await stream.WriteAsync(payload, ct);
            await stream.FlushAsync(ct);
        }

        public static Task WriteTextAsync(Stream stream, string text, CancellationToken ct)
            => WriteFrameAsync(stream, PacketType.Text, Encoding.UTF8.GetBytes(text), ct);

        /// <summary>
        /// Đọc đúng MỘT khung. ReadExactlyAsync đảm bảo đọc đủ N byte
        /// (TCP có thể trả dữ liệu vụn từng mẩu — "partial read").
        /// Ném EndOfStreamException khi bên kia đóng kết nối.
        /// </summary>
        public static async Task<(PacketType Type, byte[] Payload)> ReadFrameAsync(
            Stream stream, CancellationToken ct)
        {
            byte[] header = new byte[HeaderSize];
            await stream.ReadExactlyAsync(header, ct);

            int length = BinaryPrimitives.ReadInt32LittleEndian(header);
            var type = (PacketType)header[4];

            if (length < 0 || length > MaxPayload)
                throw new InvalidDataException($"Kích thước gói bất thường: {length}");

            byte[] payload = new byte[length];
            await stream.ReadExactlyAsync(payload, ct);
            return (type, payload);
        }
    }
}