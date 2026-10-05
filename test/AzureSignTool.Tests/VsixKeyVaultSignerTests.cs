using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using AzureSign.Core;
using OpenVsixSignTool.Core;
using Xunit;

namespace AzureSignTool.Tests
{
    public class VsixKeyVaultSignerTests
    {
        [Fact]
        public void SignsVsixAsOpcPackage()
        {
            string path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.vsix");
            using (RSA key = RSA.Create(2048))
            using (X509Certificate2 certificate = CreateCertificate(key))
            {
                try
                {
                    CreatePackage(path);
                    var signer = new VsixKeyVaultSigner(key, certificate, HashAlgorithmName.SHA256, TimeStampConfiguration.None);

                    Assert.False(VsixKeyVaultSigner.IsSigned(path));
                    Assert.Equal(HRESULT.S_OK, signer.SignFile(path));
                    Assert.True(VsixKeyVaultSigner.IsSigned(path));

                    using (var package = OpcPackage.Open(path))
                    using (var signatureStream = package.GetSignatures().Single().Part.Open())
                    {
                        var document = new XmlDocument { PreserveWhitespace = true };
                        document.Load(signatureStream);
                        var signedXml = new SignedXml(document);
                        signedXml.LoadXml(document.DocumentElement!);
                        Assert.True(signedXml.CheckSignature(certificate, true));
                    }
                }
                finally
                {
                    File.Delete(path);
                }
            }
        }

        private static X509Certificate2 CreateCertificate(RSA key)
        {
            var request = new CertificateRequest(
                "CN=VSIX test",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

        private static void CreatePackage(string path)
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                AddEntry(archive, "[Content_Types].xml", """
                    <?xml version="1.0" encoding="utf-8"?>
                    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                      <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
                      <Default Extension="xml" ContentType="application/xml" />
                    </Types>
                    """);
                AddEntry(archive, "_rels/.rels", """
                    <?xml version="1.0" encoding="utf-8"?>
                    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships" />
                    """);
                AddEntry(archive, "extension.vsixmanifest", """
                    <?xml version="1.0" encoding="utf-8"?>
                    <PackageManifest xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" Version="2.0" />
                    """);
            }
        }

        private static void AddEntry(ZipArchive archive, string name, string content)
        {
            using (var writer = new StreamWriter(archive.CreateEntry(name).Open(), Encoding.UTF8))
            {
                writer.Write(content);
            }
        }
    }
}
