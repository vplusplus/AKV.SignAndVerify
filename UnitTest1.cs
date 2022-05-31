
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AKV.SignAndVerify
{
    [TestClass]
    public class UnitTest1
    {
        const string TenantId = "AAD Tenant Id";
        const string ClientId = "AAD Clinet Id";
        const string ClientSecret = "Fill-Me-In";
        const string VaultUrl = "https://hello-akv-2205.vault.azure.net/";
        const string CertThumprint = "197e7cb9b16d49fe79d7bb639e057877bd76b0e9";

        const string INPUT = "HelloWorld";
        const string SignatureFileName = "./test-signature.txt";

        [TestMethod]
        public void X509AndAkvCreateSameSignature()
        {
            var tokenCredentials = new ClientSecretCredential(TenantId, ClientId, ClientSecret);
            var certificateClient = new CertificateClient(new Uri(VaultUrl), tokenCredentials);

            var x509 = X509Utils.FindX509CertificateByThumbprint(CertThumprint) ?? throw new Exception("Certificate not found in [currentuser/my]");
            var keyId = X509Utils.FindKeyIdForThumbprint(certificateClient, CertThumprint) ?? throw new Exception("Certificate or private key not found in AKV.");

            var digest = ComputeSha256(INPUT);

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
            // var keyId = new Uri($"{VaultUrl}/keys/{KeyName}");

            var tokenCredentials = new ClientSecretCredential(TenantId, ClientId, ClientSecret);

            var certificateClient = new CertificateClient(new Uri(VaultUrl), tokenCredentials);
            var keyId = X509Utils.FindKeyIdForThumbprint(certificateClient, CertThumprint) ?? throw new Exception("Certificate or private key not found in AKV.");

            var digest = ComputeSha256(INPUT);

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
            var keyId = X509Utils.FindKeyIdForThumbprint(certificateClient, CertThumprint) ?? throw new Exception("Certificate or private key not found in AKV.");

            var digest = ComputeSha256(INPUT);
            var signatureHex = File.ReadAllText(SignatureFileName);
            var signatureBytes = Convert.FromHexString(signatureHex);

            var crypto = new CryptographyClient(keyId, tokenCredentials);
            var verifyResult = crypto.Verify(SignatureAlgorithm.RS256, digest, signatureBytes);

            Console.WriteLine($"Is valid: {verifyResult.IsValid}");
        }

        [TestMethod]
        public void SignUsingX509()
        {
            var digest = ComputeSha256(INPUT);

            var x509 = X509Utils.FindX509CertificateByThumbprint(CertThumprint);
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
            var digest = ComputeSha256(INPUT);
            var signatureHex = File.ReadAllText(SignatureFileName);
            var signatureBytes = Convert.FromHexString(signatureHex);

            var x509 = X509Utils.FindX509CertificateByThumbprint(CertThumprint);
            using var rsa = x509.GetRSAPublicKey() ?? throw new Exception("Certificate missing RSA public key?");
            var rsaFormatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var good = rsaFormatter.VerifySignature(digest, signatureBytes);

            Console.WriteLine($"Is valid: {good}");
        }

        static byte[] ComputeSha256(string input)
        {
            using (var sha256 = SHA256.Create()) return sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        }
    }

    static class X509Utils
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

    }
}
