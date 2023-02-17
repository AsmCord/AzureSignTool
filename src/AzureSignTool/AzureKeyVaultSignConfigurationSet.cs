
using System;

namespace AzureSignTool
{
    public sealed class AzureKeyVaultSignConfigurationSet
    {
        public bool ManagedIdentity { get; set; }
        public string AzureClientId { get; set; }
        public string AzureClientSecret { get; set; }
        public string AzureTenantId { get; set; }
        public Uri AzureKeyVaultUrl { get; set; }
        public string AzureKeyVaultCertificateName { get; set; }
        public string AzureAccessToken { get; set; }
        public string AzureClientCertificateThumbprint { get; set; }
        public string AzureClientCertificateThumbprintMachine { get; set; }
    }
}
