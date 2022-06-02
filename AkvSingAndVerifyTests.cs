
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AKV.SignAndVerify
{
    [TestClass]
    public class AkvSingAndVerifyTests
    {
        static string TenantId => MyConfig.AppSetting("TenantId");
        static string ClientId => MyConfig.AppSetting("ClientId");
        static string ClientSecret => MyConfig.AppSetting("ClientSecret");
        static string VaultUrl => MyConfig.AppSetting("VaultUrl");
        static string CertThumprint => MyConfig.AppSetting("CertThumprint");

        const string INPUT = "HelloWorld";
        const string SignatureFileName = "./test-signature.txt";

        [TestMethod]
        public void X509AndAkvCreateSameSignature()
        {
            var tokenCredentials = new ClientSecretCredential(TenantId, ClientId, ClientSecret);

            var certificateClient = new CertificateClient(new Uri(VaultUrl), tokenCredentials);
            var keyId = Utils.FindKeyIdForThumbprint(certificateClient, CertThumprint) ?? throw new Exception($"Certificate not found in [{VaultUrl}]");
            var x509 = Utils.FindX509CertificateByThumbprint(CertThumprint) ?? throw new Exception($"Certificate not found in [{StoreLocation.CurrentUser}/{StoreName.My}]");

            var digest = Utils.ComputeSha256(INPUT);

            // Sign using AKV
            var crypto = new CryptographyClient(keyId, tokenCredentials);
            var signingResult = crypto.Sign(SignatureAlgorithm.RS256, digest);
            var akvSignatureBytes = signingResult.Signature;
            var akvSignatureHex = Convert.ToHexString(akvSignatureBytes);

            // Sign using local X509 certificate
            using var rsa = x509.GetRSAPrivateKey() ?? throw new Exception("Certificate missing RSA private key?");
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var x509SignatureBytes = rsaFormatter.CreateSignature(digest);
            var x509SignatureHex = Convert.ToHexString(x509SignatureBytes);

            Console.WriteLine($"AKV and X509 made same signature? {string.Equals(x509SignatureHex, akvSignatureHex, StringComparison.OrdinalIgnoreCase)}");
            Assert.AreEqual(x509SignatureHex, akvSignatureHex);
        }

        [TestMethod]
        public void SignUsingAKV()
        {
            var tokenCredentials = new ClientSecretCredential(TenantId, ClientId, ClientSecret);

            var certificateClient = new CertificateClient(new Uri(VaultUrl), tokenCredentials);
            var keyId = Utils.FindKeyIdForThumbprint(certificateClient, CertThumprint) ?? throw new Exception($"Certificate not found in [{VaultUrl}]");

            var digest = Utils.ComputeSha256(INPUT);

            var crypto = new CryptographyClient(keyId, tokenCredentials);
            var signResult = crypto.Sign(SignatureAlgorithm.RS256, digest);
            var signatureBytes = signResult.Signature;
            var signatureHex = Convert.ToHexString(signatureBytes);

            Console.WriteLine(signResult.KeyId);
            Console.WriteLine(signatureHex);

            File.WriteAllText(SignatureFileName, signatureHex);
        }

        [TestMethod]
        public void VerifyUsingAKV()
        {
            var tokenCredentials = new ClientSecretCredential(TenantId, ClientId, ClientSecret);

            var certificateClient = new CertificateClient(new Uri(VaultUrl), tokenCredentials);
            var keyId = Utils.FindKeyIdForThumbprint(certificateClient, CertThumprint) ?? throw new Exception($"Certificate not found in [{VaultUrl}]");

            var digest = Utils.ComputeSha256(INPUT);

            var signatureHex = File.ReadAllText(SignatureFileName);
            var signatureBytes = Convert.FromHexString(signatureHex);

            var crypto = new CryptographyClient(keyId, tokenCredentials);
            var verifyResult = crypto.Verify(SignatureAlgorithm.RS256, digest, signatureBytes);

            Console.WriteLine($"Is valid: {verifyResult.IsValid}");
        }

        [TestMethod]
        public void SignUsingX509()
        {
            var x509 = Utils.FindX509CertificateByThumbprint(CertThumprint) ?? throw new Exception($"Certificate not found in [{StoreLocation.CurrentUser}/{StoreName.My}]");

            var digest = Utils.ComputeSha256(INPUT);

            using var rsa = x509.GetRSAPrivateKey() ?? throw new Exception("Certificate missing RSA private key?");
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var signatureBytes = rsaFormatter.CreateSignature(digest);

            var signatureHex = Convert.ToHexString(signatureBytes);

            Console.WriteLine(signatureHex);
            File.WriteAllText(SignatureFileName, signatureHex);
        }

        [TestMethod]
        public void VerifyUsingX509()
        {
            var x509 = Utils.FindX509CertificateByThumbprint(CertThumprint) ?? throw new Exception($"Certificate not found in [{StoreLocation.CurrentUser}/{StoreName.My}]");

            var digest = Utils.ComputeSha256(INPUT);

            var signatureHex = File.ReadAllText(SignatureFileName);
            var signatureBytes = Convert.FromHexString(signatureHex);

            using var rsa = x509.GetRSAPublicKey() ?? throw new Exception("Certificate missing RSA public key?");
            var rsaFormatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var good = rsaFormatter.VerifySignature(digest, signatureBytes);

            Console.WriteLine($"Is valid: {good}");
        }

        [TestMethod]
        public void EncryptPerformanceAkvVsX509()
        {
            var tokenCredentials = new ClientSecretCredential(TenantId, ClientId, ClientSecret);
            var certificateClient = new CertificateClient(new Uri(VaultUrl), tokenCredentials);
            var keyId = Utils.FindKeyIdForThumbprint(certificateClient, CertThumprint) ?? throw new Exception($"Certificate not found in [{VaultUrl}]");
            var x509 = Utils.FindX509CertificateByThumbprint(CertThumprint) ?? throw new Exception($"Certificate not found in [{StoreLocation.CurrentUser}/{StoreName.My}]");

            var digest = Utils.ComputeSha256(INPUT);

            // Sign using AKV
            var crypto = new CryptographyClient(keyId, tokenCredentials);

            void AKVEncrypt()
            {
                var signingResult = crypto.Sign(SignatureAlgorithm.RS256, digest);
                var akvSignatureBytes = signingResult.Signature;
            }

            void X509Encrypt()
            {
                using var rsa = x509.GetRSAPrivateKey() ?? throw new Exception("Certificate missing RSA private key?");
                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");
                var x509SignatureBytes = rsaFormatter.CreateSignature(digest);
            }

            // Warmup
            AKVEncrypt();
            X509Encrypt();

            const int LoopCount = 100;

            // Test
            var timer = Stopwatch.StartNew();
            for (int i = 0; i < LoopCount; i++) AKVEncrypt();
            timer.Stop();
            var ms = timer.Elapsed.TotalMilliseconds;
            Console.WriteLine($"AKV Encrypt - LoopCount: {LoopCount:#,0} Elapsed: {ms:#,0} milliSec. Average: {ms/LoopCount:#,0} milliSec");

            // Test
            timer = Stopwatch.StartNew();
            for (int i = 0; i < LoopCount; i++) X509Encrypt();
            timer.Stop();
            ms = timer.Elapsed.TotalMilliseconds;
            Console.WriteLine($"X509 Encrypt - LoopCount: {LoopCount:#,0} Elapsed: {ms:#,0} milliSec. Average: {ms/LoopCount:#,0} milliSec");
        }

    }

    static class Utils
    {
        internal static X509Certificate2? FindX509CertificateByThumbprint(string thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            _ = thumbprint ?? throw new ArgumentNullException(nameof(thumbprint));

            using X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            return store
                .Certificates
                .OfType<X509Certificate2>()
                .Where(x => x.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                .SingleOrDefault();
        }

        internal static Uri FindKeyIdForThumbprint(CertificateClient akvCertificateClient, string thumbprint)
        {
            _ = akvCertificateClient ?? throw new ArgumentNullException(nameof(akvCertificateClient));
            _ = thumbprint ?? throw new ArgumentNullException(nameof(thumbprint));

            Pageable<CertificateProperties> allCertificates = akvCertificateClient.GetPropertiesOfCertificates();

            foreach (CertificateProperties certInfo in allCertificates)
            {
                var x5t = Convert.ToHexString(certInfo.X509Thumbprint);

                if (x5t.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    var keyUrl = $"{certInfo.VaultUri}/keys/{certInfo.Name}";
                    return new Uri(keyUrl);
                }
            }

            // Can't find.
            return null;
        }

        internal static byte[] ComputeSha256(string input)
        {
            using (var sha256 = SHA256.Create()) return sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        }
    }
}
