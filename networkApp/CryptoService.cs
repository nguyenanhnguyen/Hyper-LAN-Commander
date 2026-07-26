using System;
using System.IO;
using System.Security.Cryptography;

namespace networkApp
{
    /// <summary>
    /// Danh tính mật mã + mã hóa đầu-cuối.
    ///
    /// TRIẾT LÝ: danh tính ≠ địa chỉ.
    /// - IP chỉ là "đường đi" — đổi thoải mái, không mang ý nghĩa tin cậy.
    /// - Danh tính thật = cặp khóa ECDH P-256 sinh MỘT LẦN khi chạy app lần đầu,
    ///   lưu tại %AppData%\HyperLAN\identity.key.
    /// - Fingerprint = 8 byte đầu SHA-256(public key), dạng "A7F3-9B21-...":
    ///   không thể trùng (xác suất ~2^-64), không thể giả (giả thì không có
    ///   private key tương ứng để hoàn tất ECDH).
    ///
    /// PHIÊN LÀM VIỆC: hai máy trao public key + salt ngẫu nhiên khi bắt tay TCP.
    /// Khóa AES-256 = HKDF(ECDH-shared-secret, saltA ⊕ saltB) — khóa phiên
    /// KHÔNG BAO GIỜ chạy trên mạng; kẻ nghe lén Wi-Fi có đủ 2 public key
    /// và 2 salt vẫn không tính ra được (bài toán logarit rời rạc trên đường cong).
    ///
    /// AES-256-GCM cho từng gói: [12B nonce][ciphertext][16B auth tag].
    /// GCM = mã hóa (confidentiality) + chống sửa đổi (integrity): gói bị
    /// đụng vào 1 bit trên đường truyền → tag sai → bị loại ngay.
    /// </summary>
    public class CryptoService
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;

        private readonly ECDiffieHellman _identity;

        /// <summary>Public key (SubjectPublicKeyInfo) — an toàn để gửi công khai.</summary>
        public byte[] PublicKey { get; }
        /// <summary>"Chứng minh thư" hiển thị cho người dùng.</summary>
        public string Fingerprint { get; }

        public CryptoService()
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HyperLAN");
            Directory.CreateDirectory(dir);
            string keyPath = Path.Combine(dir, "identity.key");

            _identity = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            if (File.Exists(keyPath))
            {
                try
                {
                    _identity.ImportPkcs8PrivateKey(File.ReadAllBytes(keyPath), out _);
                }
                catch
                {
                    // File hỏng → sinh danh tính mới (fingerprint sẽ đổi, các máy
                    // quen sẽ thấy cảnh báo "khóa đã thay đổi" — đúng như mong muốn)
                    File.WriteAllBytes(keyPath, _identity.ExportPkcs8PrivateKey());
                }
            }
            else
            {
                File.WriteAllBytes(keyPath, _identity.ExportPkcs8PrivateKey());
            }

            PublicKey = _identity.ExportSubjectPublicKeyInfo();
            Fingerprint = ComputeFingerprint(PublicKey);
        }

        public static string ComputeFingerprint(byte[] publicKeyInfo)
        {
            byte[] h = SHA256.HashData(publicKeyInfo);
            return $"{h[0]:X2}{h[1]:X2}-{h[2]:X2}{h[3]:X2}-{h[4]:X2}{h[5]:X2}-{h[6]:X2}{h[7]:X2}";
        }

        /// <summary>
        /// ECDH + HKDF → khóa phiên AES-256. Salt XOR để cả hai bên đều đóng góp
        /// ngẫu nhiên (phiên mới = khóa mới dù danh tính không đổi) và phép XOR
        /// giao hoán nên hai bên tính ra cùng một khóa.
        /// </summary>
        public byte[] DeriveSessionKey(byte[] otherPublicKeyInfo, byte[] mySalt, byte[] theirSalt)
        {
            using var other = ECDiffieHellman.Create();
            other.ImportSubjectPublicKeyInfo(otherPublicKeyInfo, out _);

            byte[] sharedSecret = _identity.DeriveKeyMaterial(other.PublicKey);

            byte[] salt = new byte[Math.Min(mySalt.Length, theirSalt.Length)];
            for (int i = 0; i < salt.Length; i++)
                salt[i] = (byte)(mySalt[i] ^ theirSalt[i]);

            return HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret,
                outputLength: 32, salt: salt, info: "HLC1-AES256GCM"u8.ToArray());
        }

        /// <summary>Mã hóa 1 payload → [nonce][ciphertext][tag]. Nonce ngẫu nhiên mỗi gói.</summary>
        public static byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext)
        {
            byte[] result = new byte[NonceSize + plaintext.Length + TagSize];
            Span<byte> nonce = result.AsSpan(0, NonceSize);
            RandomNumberGenerator.Fill(nonce);

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce,
                plaintext,
                result.AsSpan(NonceSize, plaintext.Length),
                result.AsSpan(NonceSize + plaintext.Length, TagSize));
            return result;
        }

        /// <summary>Giải mã. Ném CryptographicException nếu gói bị sửa đổi (tag sai).</summary>
        public static byte[] Decrypt(byte[] key, ReadOnlySpan<byte> blob)
        {
            if (blob.Length < NonceSize + TagSize)
                throw new CryptographicException("Gói quá ngắn");

            ReadOnlySpan<byte> nonce = blob[..NonceSize];
            ReadOnlySpan<byte> tag = blob[^TagSize..];
            ReadOnlySpan<byte> ciphertext = blob[NonceSize..^TagSize];

            byte[] plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }
    }
}
