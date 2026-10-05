#nullable enable
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AzureSign.Core;
using Microsoft.Extensions.Logging;
using OpenVsixSignTool.Core;
using OpenVsixSignTool.Core.Timestamp;

namespace AzureSignTool
{
    internal sealed class VsixKeyVaultSigner
    {
        private readonly RSA _signingKey;
        private readonly X509Certificate2 _signingCertificate;
        private readonly HashAlgorithmName _fileDigestAlgorithm;
        private readonly TimeStampConfiguration _timeStampConfiguration;

        public VsixKeyVaultSigner(
            RSA signingKey,
            X509Certificate2 signingCertificate,
            HashAlgorithmName fileDigestAlgorithm,
            TimeStampConfiguration timeStampConfiguration)
        {
            _signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
            _signingCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
            _fileDigestAlgorithm = fileDigestAlgorithm;
            _timeStampConfiguration = timeStampConfiguration ?? throw new ArgumentNullException(nameof(timeStampConfiguration));
        }

        public int SignFile(string path, ILogger? logger = null)
        {
            if (_signingCertificate.GetRSAPublicKey() is null)
            {
                logger?.LogError("VSIX signing requires an RSA certificate.");
                return HRESULT.E_INVALIDARG;
            }

            if (_timeStampConfiguration.Type == TimeStampType.Authenticode)
            {
                logger?.LogError("Authenticode timestamps are not supported for VSIX files. Use an RFC3161 timestamp instead.");
                return HRESULT.E_INVALIDARG;
            }

            using (var package = OpcPackage.Open(path, OpcPackageFileMode.ReadWrite))
            {
                var builder = package.CreateSignatureBuilder();
                builder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();

                var signature = builder.Sign(new SignConfigurationSet(
                    _fileDigestAlgorithm,
                    _fileDigestAlgorithm,
                    _signingKey,
                    _signingCertificate));

                if (_timeStampConfiguration.Type == TimeStampType.RFC3161)
                {
                    var result = signature.CreateTimestampBuilder()
                        .SignAsync(new Uri(_timeStampConfiguration.Url!), _timeStampConfiguration.DigestAlgorithm)
                        .GetAwaiter()
                        .GetResult();

                    if (result != TimestampResult.Success)
                    {
                        logger?.LogError("Failed to timestamp the VSIX signature.");
                        return HRESULT.E_FAIL;
                    }
                }
            }

            return HRESULT.S_OK;
        }

        public static bool IsSigned(string path)
        {
            using (var package = OpcPackage.Open(path, OpcPackageFileMode.Read))
            {
                return package.GetSignatures().Any();
            }
        }
    }
}
