using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticationSdk.util;
using Microsoft.Extensions.Logging;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Abstraction over the certificate / key / MLE cache used by the Authentication SDK.
    /// <para>
    /// The canonical implementation is <see cref="CertificateCache"/>, which is registered as a
    /// singleton (see <c>ServiceCollectionExtensions.AddCertificateCache</c>). The static
    /// <c>Cache</c> class remains as a backward-compatible facade that delegates to
    /// <see cref="CertificateCache.Default"/>.
    /// </para>
    /// </summary>
    public interface ICache
    {
        /// <summary>
        /// Gets or sets the logger used by the legacy (non <c>ILoggerFactory</c>) code paths.
        /// Defaults to a no-op logger.
        /// </summary>
        ILogger Logger { get; set; }

        /// <summary>
        /// Loads and caches the X.509 certificate collection from the given P12/PFX file.
        /// </summary>
        X509Certificate2Collection FetchCachedCertificate(string p12FilePath, string keyPassword);

        /// <summary>
        /// Deprecated. Loads and caches RSA parameters from the PEM file referenced by the merchant configuration.
        /// </summary>
        [Obsolete("This method has been marked as Deprecated and will be removed in coming releases.", false)]
        RSAParameters FetchCachedRSAParameters(MerchantConfig merchantConfig);

        /// <summary>
        /// Returns the certificate whose simple name matches the supplied key alias.
        /// </summary>
        X509Certificate2 GetCertBasedOnKeyAlias(X509Certificate2Collection certs, string keyAlias);

        /// <summary>
        /// Retrieves the cached MLE request certificate for the supplied merchant configuration (legacy path).
        /// </summary>
        X509Certificate2 GetRequestMLECertFromCache(MerchantConfig merchantConfig);

        /// <summary>
        /// Retrieves the cached MLE response private key for the supplied merchant configuration (legacy path).
        /// </summary>
        AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(MerchantConfig merchantConfig);

        /// <summary>
        /// Retrieves cached MLE KID data for the supplied merchant configuration (legacy path).
        /// </summary>
        CachedMLEKId GetMLEKIdDataFromCache(MerchantConfig merchantConfig);

        /// <summary>
        /// Stores a public key in the cache keyed by run environment and KID.
        /// </summary>
        void AddPublicKeyToCache(string publickey, string runEnvironment, string kid);

        /// <summary>
        /// Retrieves a cached public key for the supplied run environment and key id.
        /// </summary>
        string GetPublicKeyFromCache(string runEnvironment, string keyId);

        /// <summary>
        /// Retrieves the cached MLE response private key (interface-based path).
        /// </summary>
        AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null);

        /// <summary>
        /// Retrieves cached MLE KID data (interface-based path).
        /// </summary>
        CachedMLEKId GetMLEKIdDataFromCache(string keyIssuer, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null);

        /// <summary>
        /// Retrieves the cached MLE request certificate (interface-based path).
        /// </summary>
        X509Certificate2 GetRequestMLECertFromCache(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null);
    }
}
