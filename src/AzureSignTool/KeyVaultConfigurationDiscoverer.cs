using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;

using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureSignTool
{
    internal class KeyVaultConfigurationDiscoverer
    {
        private readonly ILogger _logger;

        public KeyVaultConfigurationDiscoverer(ILogger logger)
        {
            _logger = logger;
        }

        public async Task<ErrorOr<AzureKeyVaultMaterializedConfiguration>> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            TokenCredential credential;
            if (configuration.ManagedIdentity)
            {
                credential = new DefaultAzureCredential();
            }
            else if(!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
            {
                credential = new AccessTokenCredential(configuration.AzureAccessToken);
            }
            else if (!string.IsNullOrWhiteSpace(configuration.AzureCertificateThumbprint))
            {
                string certificateThumbPrint = configuration.AzureCertificateThumbprint;
                X509Certificate2 clientCertificate = LoadCertificateByThumbprint(certificateThumbPrint, StoreLocation.CurrentUser);
                credential = new ClientCertificateCredential(configuration.AzureTenantId, configuration.AzureClientId, clientCertificate);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(configuration.AzureAuthority))
                {
                    credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret);
                }
                else
                {
                    ClientSecretCredentialOptions options = new()
                    {
                        AuthorityHost = AuthorityHostNames.GetUriForAzureAuthorityIdentifier(configuration.AzureAuthority)
                    };
                    credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret, options);
                }
            }


            X509Certificate2 certificate;
            KeyVaultCertificate azureCertificate;
            try
            {
                var certClient = new CertificateClient(configuration.AzureKeyVaultUrl, credential);

                if (!string.IsNullOrWhiteSpace(configuration.AzureKeyVaultCertificateVersion))
                {
                    _logger.LogTrace($"Retrieving version [{configuration.AzureKeyVaultCertificateVersion}] of certificate {configuration.AzureKeyVaultCertificateName}.");
                    azureCertificate = (await certClient.GetCertificateVersionAsync(configuration.AzureKeyVaultCertificateName, configuration.AzureKeyVaultCertificateVersion).ConfigureAwait(false)).Value;
                }
                else
                {
                    _logger.LogTrace($"Retrieving current version of certificate {configuration.AzureKeyVaultCertificateName}.");
                    azureCertificate = (await certClient.GetCertificateAsync(configuration.AzureKeyVaultCertificateName).ConfigureAwait(false)).Value;
                }
                _logger.LogTrace($"Retrieved certificate with Id {azureCertificate.Id}.");

                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (Exception e)
            {
                _logger.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate. Error message: {e.Message}.");
                _logger.LogTrace(e.ToString());

                return e;
            }
            var keyId = azureCertificate.KeyId;

            if (keyId is null)
            {
                return new InvalidOperationException("The Azure certificate does not have an associated private key.");
            }

            return new AzureKeyVaultMaterializedConfiguration(credential, certificate, keyId);
        }

        private X509Certificate2 LoadCertificateByThumbprint(string thumbprint, System.Security.Cryptography.X509Certificates.StoreLocation storeLocation)
        {
            X509Store certStore = new X509Store(StoreName.My, storeLocation);
            certStore.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (certCollection.Count > 0)
                {
                    X509Certificate2 cert = certCollection[0];
                    return cert;
                }
                else
                {
                    _logger.LogTrace($"Could not find certificate with thumbprint {thumbprint} in store {storeLocation}");
                    return null;
                }
            }
            finally
            {
                certStore.Close();
            }
        }

    }

}
