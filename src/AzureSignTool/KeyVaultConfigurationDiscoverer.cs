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
            try
            {
                if (configuration.ManagedIdentity)
                {
                    credential = new DefaultAzureCredential();
                }
                else if (!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
                {
                    credential = new AccessTokenCredential(configuration.AzureAccessToken);
                }
                else if (!string.IsNullOrWhiteSpace(configuration.AzureClientCertificateThumbprint))
                {
                    string certificateThumbPrint = configuration.AzureClientCertificateThumbprint;
                    X509Certificate2 clientCertificate = LoadCertificateByThumbprint(certificateThumbPrint, StoreLocation.CurrentUser);
                    credential = new ClientCertificateCredential(configuration.AzureTenantId, configuration.AzureClientId, clientCertificate);

                }
                else if (!string.IsNullOrWhiteSpace(configuration.AzureClientCertificateThumbprintMachine))
                {
                    string certificateThumbPrint = configuration.AzureClientCertificateThumbprintMachine;
                    X509Certificate2 clientCertificate = LoadCertificateByThumbprint(certificateThumbPrint, StoreLocation.LocalMachine);
                    credential = new ClientCertificateCredential(configuration.AzureTenantId, configuration.AzureClientId, clientCertificate);
                }
                else
                {
                    credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret);
                }
            }
            catch (Exception e)
            {
                _logger.LogError($"Could not create credentials for authentication to the Azure Key Vault.");
                _logger.LogTrace(e.ToString());
                
                return e;
            }


            X509Certificate2 certificate;
            KeyVaultCertificateWithPolicy azureCertificate;
            try
            {
                var certClient = new CertificateClient(configuration.AzureKeyVaultUrl, credential);

                _logger.LogTrace($"Retrieving certificate {configuration.AzureKeyVaultCertificateName}.");
                azureCertificate = (await certClient.GetCertificateAsync(configuration.AzureKeyVaultCertificateName).ConfigureAwait(false)).Value;
                _logger.LogTrace($"Retrieved certificate {configuration.AzureKeyVaultCertificateName}.");
                
                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (Exception e)
            {
                _logger.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate. Error message: {e.Message}.");
                _logger.LogTrace(e.ToString());
                
                return e;
            }
            var keyId = azureCertificate.KeyId;
            return new AzureKeyVaultMaterializedConfiguration(credential, certificate, keyId);
        }

        private X509Certificate2 LoadCertificateByThumbprint(string thumbprint, System.Security.Cryptography.X509Certificates.StoreLocation storeLocation)
        {
            X509Store certStore = new X509Store(StoreName.My, storeLocation);
            X509Store certStore2 = new X509Store();
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
                    _logger.LogError($"Could not find certificate with thumbprint {thumbprint} in store {storeLocation}");
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
