using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace networkApp
{
    /// <summary>
    /// Gói Hello (bắt tay) — gói DUY NHẤT đi dạng rõ. Không chứa bí mật nào:
    /// Id/Eph là public key, Nonce là số ngẫu nhiên công khai.
    /// </summary>
    internal sealed record HelloMsg(
        string P,          // "HLC"
        int V,             // version giao thức
        byte[] Id,         // public key DANH TÍNH (ECDSA P-256, SubjectPublicKeyInfo) — bền vững
        byte[] Eph,        // public key TẠM (ECDH P-256) — sinh mới cho MỖI kết nối → forward secrecy
        byte[] Nonce,      // 32B ngẫu nhiên — mỗi phiên một transcript khác nhau
        string Name,
        int Port,          // cổng TCP đang lắng nghe (kết nối đến dùng cổng nguồn tạm)
        Guid Instance);

    /// <summary>
    /// Bắt tay HLC2 — mô hình SIGMA / TLS 1.3 thu gọn, chạy song song 2 chiều (1-RTT):
    ///
    ///   A ── Hello{IdA, EphA, NonceA} ──▶ B      (hai bên gửi ĐỒNG THỜI, không chờ nhau)
    ///   A ◀── Hello{IdB, EphB, NonceB} ── B
    ///        th  = SHA-256(transcript: helloInitiator ‖ helloResponder)
    ///        Z   = ECDH(EphA, EphB)                      ← chỉ 2 bên tính được
    ///        PRK = HKDF-Extract(salt = th, Z)
    ///        k_i2r, k_r2i = HKDF-Expand(PRK, "HLC2 key i2r" / "HLC2 key r2i")
    ///   A ── Sealed{Auth: SigA(th ‖ 'I')} ──▶ B   B kiểm bằng IdA → chắc chắn là A
    ///   A ◀── Sealed{Auth: SigB(th ‖ 'R')} ── B   A kiểm bằng IdB → chắc chắn là B
    ///
    /// Tính chất đạt được:
    /// • Perfect Forward Secrecy: khóa tạm bị hủy ngay sau ECDH; lộ khóa danh tính sau này
    ///   cũng KHÔNG giải mã được các phiên cũ đã bị ghi lại.
    /// • Xác thực 2 chiều: chữ ký phủ lên toàn bộ transcript → MITM thay Eph/Nonce là lộ.
    /// • Key confirmation: Auth đi trong Sealed → giải mã được nghĩa là cùng khóa.
    /// • Khóa riêng mỗi chiều + nonce dạng bộ đếm → chống replay / đảo thứ tự / xóa gói.
    /// </summary>
    internal static class Handshake
    {
        public const int NonceSize = 32;

        public sealed record Keys(byte[] InitiatorToResponder, byte[] ResponderToInitiator,
                                  byte[] Transcript, string SessionId);

        public static Keys Derive(ECDiffieHellman myEphemeral, byte[] theirEphemeralSpki,
                                  ReadOnlySpan<byte> initiatorHello, ReadOnlySpan<byte> responderHello)
        {
            using var other = ECDiffieHellman.Create();
            other.ImportSubjectPublicKeyInfo(theirEphemeralSpki, out _); // CNG kiểm điểm nằm trên đường cong
            if (other.KeySize != 256)
                throw new CryptographicException("Ephemeral key không phải P-256");

            byte[] z = myEphemeral.DeriveRawSecretAgreement(other.PublicKey);
            byte[] th = TranscriptHash(initiatorHello, responderHello);
            byte[] prk = HKDF.Extract(HashAlgorithmName.SHA256, z, th);
            try
            {
                byte[] i2r = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, "HLC2 key i2r"u8.ToArray());
                byte[] r2i = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, "HLC2 key r2i"u8.ToArray());
                byte[] sid = HKDF.Expand(HashAlgorithmName.SHA256, prk, 6, "HLC2 session id"u8.ToArray());
                return new Keys(i2r, r2i, th, Convert.ToHexString(sid));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(z);
                CryptographicOperations.ZeroMemory(prk);
            }
        }

        private static byte[] TranscriptHash(ReadOnlySpan<byte> initiatorHello, ReadOnlySpan<byte> responderHello)
        {
            using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            Span<byte> len = stackalloc byte[4];
            h.AppendData("HLC2-transcript"u8);
            BinaryPrimitives.WriteInt32BigEndian(len, initiatorHello.Length);
            h.AppendData(len);
            h.AppendData(initiatorHello);
            BinaryPrimitives.WriteInt32BigEndian(len, responderHello.Length);
            h.AppendData(len);
            h.AppendData(responderHello);
            return h.GetHashAndReset();
        }

        /// <summary>Dữ liệu được ký: nhãn ngữ cảnh + vai trò + transcript (chống "phản chiếu" chữ ký).</summary>
        public static byte[] AuthData(byte[] transcript, bool asInitiator)
        {
            byte[] label = Encoding.ASCII.GetBytes(asInitiator ? "HLC2-auth-I" : "HLC2-auth-R");
            byte[] data = new byte[label.Length + transcript.Length];
            label.CopyTo(data, 0);
            transcript.CopyTo(data, label.Length);
            return data;
        }
    }

    /// <summary>
    /// Trạng thái mã hóa MỘT chiều của phiên. AES-256-GCM với nonce = bộ đếm 64-bit
    /// (giống TLS 1.3): không gửi nonce trên dây, và bên nhận BẮT BUỘC đọc đúng thứ tự —
    /// gói bị phát lại, bị xóa hay bị đảo đều làm tag sai → đóng kết nối (fail-closed).
    /// Một instance AesGcm dùng cho cả phiên (không dựng lại key schedule mỗi gói).
    /// KHÔNG thread-safe: chiều gửi chỉ dùng trong writer loop, chiều nhận trong reader loop.
    /// </summary>
    internal sealed class CipherState : IDisposable
    {
        private readonly AesGcm _aes;
        private ulong _counter;

        /// <summary>Số thứ tự (= nonce) của record KẾ TIẾP — hiển thị trong Protocol Inspector.</summary>
        public ulong Counter => _counter;

        public CipherState(byte[] key)
        {
            _aes = new AesGcm(key, Protocol.TagSize);
            CryptographicOperations.ZeroMemory(key);
        }

        private void NextNonce(Span<byte> nonce)
        {
            nonce[..4].Clear();
            BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], _counter);
            _counter = checked(_counter + 1); // 2^64 gói — không bao giờ quay vòng
        }

        /// <summary>Mã hóa tại chỗ (in-place) — plaintext và ciphertext dùng chung vùng nhớ.</summary>
        public void SealInPlace(Span<byte> data, Span<byte> tag, ReadOnlySpan<byte> aad)
        {
            Span<byte> nonce = stackalloc byte[12];
            NextNonce(nonce);
            _aes.Encrypt(nonce, data, data, tag, aad);
        }

        /// <summary>Giải mã tại chỗ. Ném AuthenticationTagMismatchException nếu gói bị sửa/phát lại.</summary>
        public void OpenInPlace(Span<byte> data, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> aad)
        {
            Span<byte> nonce = stackalloc byte[12];
            NextNonce(nonce);
            _aes.Decrypt(nonce, data, tag, data, aad);
        }

        public void Dispose() => _aes.Dispose();
    }
}
