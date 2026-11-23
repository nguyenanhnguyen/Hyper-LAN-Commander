using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace networkApp
{
    /// <summary>
    /// Danh tính mật mã của máy.
    ///
    /// TRIẾT LÝ: danh tính ≠ địa chỉ.
    /// - IP chỉ là "đường đi" — đổi thoải mái (DHCP, Wi-Fi → Ethernet), không mang ý nghĩa tin cậy.
    /// - Danh tính thật = cặp khóa P-256 sinh MỘT LẦN khi chạy app lần đầu.
    /// - Fingerprint = 8 byte đầu SHA-256(public key), dạng "A7F3-9B21-...".
    ///   Giả fingerprint thì không có private key tương ứng để ký Auth trong bắt tay.
    ///
    /// Khóa danh tính chỉ dùng để KÝ (ECDSA). Khóa mã hóa phiên đến từ ECDH tạm thời
    /// (xem Handshake) → lộ khóa danh tính cũng không giải mã được phiên cũ (PFS).
    ///
    /// LƯU TRỮ: %AppData%\HyperLAN\identity.key, được bọc bằng Windows DPAPI
    /// (gắn với tài khoản Windows) → copy file sang máy/tài khoản khác là vô dụng.
    /// File định dạng cũ (PKCS#8 trần, bản v1) được tự động nâng cấp, GIỮ NGUYÊN fingerprint.
    /// </summary>
    public sealed class CryptoService : IDisposable
    {
        private static readonly byte[] FileMagic = "HLCK2"u8.ToArray();
        private static readonly byte[] DpapiEntropy = "Hyper-LAN Commander identity v2"u8.ToArray();

        private readonly ECDsa _identity;
        private readonly object _signLock = new();

        /// <summary>Public key (SubjectPublicKeyInfo) — an toàn để gửi công khai.</summary>
        public byte[] PublicKey { get; }
        /// <summary>"Chứng minh thư" hiển thị cho người dùng.</summary>
        public string Fingerprint { get; }
        /// <summary>true nếu danh tính vừa được tạo mới ở lần chạy này.</summary>
        public bool IsNewIdentity { get; }

        public CryptoService(string dataDir)
        {
            Directory.CreateDirectory(dataDir);
            string keyPath = Path.Combine(dataDir, "identity.key");

            _identity = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            if (!TryLoad(keyPath, _identity))
            {
                IsNewIdentity = true;
                Save(keyPath, _identity);
            }

            PublicKey = _identity.ExportSubjectPublicKeyInfo();
            Fingerprint = ComputeFingerprint(PublicKey);
        }

        private static bool TryLoad(string path, ECDsa key)
        {
            if (!File.Exists(path)) return false;
            try
            {
                byte[] raw = File.ReadAllBytes(path);
                if (raw.AsSpan().StartsWith(FileMagic))
                {
                    byte[] pkcs8 = ProtectedData.Unprotect(raw[FileMagic.Length..], DpapiEntropy,
                        DataProtectionScope.CurrentUser);
                    try { key.ImportPkcs8PrivateKey(pkcs8, out _); }
                    finally { CryptographicOperations.ZeroMemory(pkcs8); }
                    return true;
                }

                // Định dạng v1: PKCS#8 trần của khóa ECDH P-256. Cùng đường cong → import
                // sang ECDSA được, public key (và fingerprint) giữ nguyên → bạn bè không thấy cảnh báo.
                ImportLegacy(raw, key);
                Save(path, key); // nâng cấp lên dạng bọc DPAPI
                return true;
            }
            catch (Exception ex)
            {
                // File hỏng / thuộc tài khoản khác → sinh danh tính mới. Fingerprint sẽ đổi và
                // các máy quen sẽ thấy cảnh báo "danh tính đã thay đổi" — đúng như mong muốn.
                System.Diagnostics.Debug.WriteLine($"[Identity] cannot load: {ex.Message}");
                try { File.Copy(path, path + ".bak", overwrite: true); } catch { }
                return false;
            }
        }

        private static void ImportLegacy(byte[] pkcs8, ECDsa key)
        {
            try
            {
                key.ImportPkcs8PrivateKey(pkcs8, out _);
            }
            catch (CryptographicException)
            {
                // Một số bản CNG gắn "key usage = ECDH" → đi đường vòng qua ECParameters
                using var ecdh = ECDiffieHellman.Create();
                ecdh.ImportPkcs8PrivateKey(pkcs8, out _);
                ECParameters p = ecdh.ExportParameters(includePrivateParameters: true);
                try { key.ImportParameters(p); }
                finally { if (p.D is not null) CryptographicOperations.ZeroMemory(p.D); }
            }
        }

        private static void Save(string path, ECDsa key)
        {
            byte[] pkcs8 = key.ExportPkcs8PrivateKey();
            try
            {
                byte[] blob = ProtectedData.Protect(pkcs8, DpapiEntropy, DataProtectionScope.CurrentUser);
                byte[] file = new byte[FileMagic.Length + blob.Length];
                FileMagic.CopyTo(file, 0);
                blob.CopyTo(file, FileMagic.Length);
                AtomicFile.WriteAllBytes(path, file);
            }
            finally { CryptographicOperations.ZeroMemory(pkcs8); }
        }

        /// <summary>Ký (ECDSA P-256 / SHA-256, định dạng IEEE P1363 64 byte).</summary>
        public byte[] Sign(byte[] data)
        {
            lock (_signLock)
                return _identity.SignData(data, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        public static bool Verify(byte[] publicKeySpki, byte[] data, ReadOnlySpan<byte> signature)
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeySpki, out _);
            if (key.KeySize != 256) return false;
            return key.VerifyData(data, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        /// <summary>Kiểm public key danh tính hợp lệ (đúng P-256, điểm nằm trên đường cong).</summary>
        public static bool IsValidIdentityKey(byte[] spki)
        {
            try
            {
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(spki, out int read);
                return read == spki.Length && key.KeySize == 256;
            }
            catch { return false; }
        }

        public static string ComputeFingerprint(byte[] publicKeyInfo)
        {
            byte[] h = SHA256.HashData(publicKeyInfo);
            return $"{h[0]:X2}{h[1]:X2}-{h[2]:X2}{h[3]:X2}-{h[4]:X2}{h[5]:X2}-{h[6]:X2}{h[7]:X2}";
        }

        /// <summary>
        /// "Safety number" kiểu Signal: 30 chữ số dẫn xuất từ public key CỦA CẢ HAI bên
        /// (sắp xếp → hai máy ra cùng một dãy). Đọc to cho nhau qua điện thoại / gặp mặt:
        /// khớp = chắc chắn không có kẻ đứng giữa. Băm lặp 5200 vòng để chống dò ngược.
        /// </summary>
        public static string SafetyNumber(byte[] keyA, byte[] keyB)
        {
            byte[] first = keyA, second = keyB;
            if (keyA.AsSpan().SequenceCompareTo(keyB) > 0) (first, second) = (keyB, keyA);

            byte[] hash = Encoding.ASCII.GetBytes("HLC-safety-number-v1");
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
            for (int i = 0; i < 5200; i++)
            {
                sha.AppendData(hash);
                sha.AppendData(first);
                sha.AppendData(second);
                hash = sha.GetHashAndReset();
            }

            var sb = new StringBuilder();
            for (int g = 0; g < 6; g++)
            {
                ulong v = 0;
                for (int b = 0; b < 5; b++) v = (v << 8) | hash[g * 5 + b];
                if (g > 0) sb.Append(g == 3 ? "\n" : " ");
                sb.Append((v % 100000).ToString("D5"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// CHỈ cho Attack Lab (danh tính TẠM sinh trong phòng lab): mô phỏng kẻ tấn công đã đánh cắp
        /// khóa dài hạn, để chứng minh traffic đã ghi lại vẫn không giải mã được (forward secrecy).
        /// </summary>
        internal ECParameters ExportPrivateForLab() => _identity.ExportParameters(includePrivateParameters: true);

        public void Dispose() => _identity.Dispose();
    }

    /// <summary>Ghi file nguyên tử: ghi ra .tmp rồi đổi tên — mất điện giữa chừng không làm hỏng file cũ.</summary>
    internal static class AtomicFile
    {
        public static void WriteAllBytes(string path, byte[] data)
        {
            string tmp = path + ".tmp";
            File.WriteAllBytes(tmp, data);
            File.Move(tmp, path, overwrite: true);
        }

        public static void WriteAllText(string path, string text)
            => WriteAllBytes(path, Encoding.UTF8.GetBytes(text));
    }
}
