using AuthenticationSdk.core;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticationSdk.util
{
    /// <summary>
    /// Backward-compatible static facade over the certificate/key cache.
    /// <para>
    /// All members delegate to the singleton <see cref="CertificateCache.Default"/>. This preserves the
    /// existing public API (and the process-wide, single-cache behaviour) while the real implementation now
    /// lives in <see cref="CertificateCache"/>, which is also registered as a singleton for dependency
    /// injection (see <c>ServiceCollectionExtensions.AddCertificateCache</c>).
    /// </para>
    /// </summary>
    public static class Cache
    {
        /// <summary>
        /// Gets or sets the logger instance used for logging cache, certificate, and MLE key operations.
        /// Delegates to <see cref="CertificateCache.Default"/> so existing callers keep working unchanged.
        /// </summary>
        public static ILogger Logger
        {
            get => CertificateCache.Default.Logger;
            set => CertificateCache.Default.Logger = value;
        }

        public static X509Certificate2Collection FetchCachedCertificate(string p12FilePath, string keyPassword)
            => CertificateCache.Default.FetchCachedCertificate(p12FilePath, keyPassword);

        [Obsolete("This method has been marked as Deprecated and will be removed in coming releases.", false)]
        public static RSAParameters FetchCachedRSAParameters(MerchantConfig merchantConfig)
            => CertificateCache.Default.FetchCachedRSAParameters(merchantConfig);

        public static X509Certificate2 GetCertBasedOnKeyAlias(X509Certificate2Collection certs, String keyAlias)
            => CertificateCache.Default.GetCertBasedOnKeyAlias(certs, keyAlias);

        public static X509Certificate2 GetRequestMLECertFromCache(MerchantConfig merchantConfig)
            => CertificateCache.Default.GetRequestMLECertFromCache(merchantConfig);

        public static AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(MerchantConfig merchantConfig)
            => CertificateCache.Default.GetMleResponsePrivateKeyFromFilePath(merchantConfig);

        public static CachedMLEKId GetMLEKIdDataFromCache(MerchantConfig merchantConfig)
            => CertificateCache.Default.GetMLEKIdDataFromCache(merchantConfig);

        public static void AddPublicKeyToCache(string publickey, string runEnvironment, string kid)
            => CertificateCache.Default.AddPublicKeyToCache(publickey, runEnvironment, kid);

        public static string GetPublicKeyFromCache(string runEnvironment, string keyId)
            => CertificateCache.Default.GetPublicKeyFromCache(runEnvironment, keyId);

        public static AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
            => CertificateCache.Default.GetMleResponsePrivateKeyFromFilePath(merchantCredentialSettings, merchantMLESettings, loggerFactory);

        public static CachedMLEKId GetMLEKIdDataFromCache(string keyIssuer, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
            => CertificateCache.Default.GetMLEKIdDataFromCache(keyIssuer, merchantMLESettings, loggerFactory);

        public static X509Certificate2 GetRequestMLECertFromCache(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
            => CertificateCache.Default.GetRequestMLECertFromCache(merchantCredentialSettings, merchantMLESettings, loggerFactory);
    }
}
