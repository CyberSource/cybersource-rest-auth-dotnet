using AuthenticationSdk.core;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace AuthenticationSdk.util
{
    public static class Cache
    {
        /// <summary>
        /// mutex to ensure that the operation is thread safe
        /// </summary>
        private static readonly object mutex = new object();

        private static readonly object mutexForPrivateKeyFromPEM = new object();

        private static readonly string regexForFileNameFromDirectory = "(^([a-z]|[A-Z]):(?=\\\\(?![\\0-\\37<>:\"/\\\\|?*])|\\/(?![\\0-\\37<>:\"/\\\\|?*])|$)|^\\\\(?=[\\\\\\/][^\\0-\\37<>:\"/\\\\|?*]+)|^(?=(\\\\|\\/)$)|^\\.(?=(\\\\|\\/)$)|^\\.\\.(?=(\\\\|\\/)$)|^(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+)|^\\.(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+)|^\\.\\.(?=(\\\\|\\/)[^\\0-\\37<>:\"/\\\\|?*]+))((\\\\|\\/)([^\\0-\\37<>:\"/\\\\|?*]+|(\\\\|\\/)$))*()$";

        private class CertInfo
        {
            public X509Certificate2Collection Certificates { get; set; }
            public DateTime Timestamp { get; set; }
            public X509Certificate2 MLECertificate { get; set; }
        }

        public static X509Certificate2Collection FetchCachedCertificate(string p12FilePath, string keyPassword)
        {
            try
            {
                lock(mutex)
                {
                    ObjectCache cache = MemoryCache.Default;

                    var matches = Regex.Match(p12FilePath, regexForFileNameFromDirectory);
                    var certFile = matches.Groups[11].ToString();
                    if (!cache.Contains(certFile) || ((CertInfo)cache[certFile]).Timestamp != File.GetLastWriteTime(p12FilePath))
                    {
                        var policy = new CacheItemPolicy();
                        var filePaths = new List<string>();
                        var cachedFilePath = Path.GetFullPath(p12FilePath);
                        filePaths.Add(cachedFilePath);
                        policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                        var certificates = new X509Certificate2Collection();
                        certificates.Import(p12FilePath, keyPassword, X509KeyStorageFlags.PersistKeySet);

                        CertInfo certInfo = new CertInfo();
                        certInfo.Certificates = certificates;
                        certInfo.Timestamp = File.GetLastWriteTime(p12FilePath);

                        cache.Set(certFile, certInfo, policy);
                    }
                    //return all certs in p12
                    return ((CertInfo)cache[certFile]).Certificates;
                }
            }
            catch (Exception e)
            {
                if (e.Message.Equals("The specified network password is not correct.\r\n"))
                {
                    throw new Exception($"{Constants.ErrorPrefix} KeyPassword provided:{keyPassword} is incorrect");
                }

                throw e;
            }
        }

        [Obsolete("This method has been marked as Deprecated and will be removed in coming releases.", false)]
        public static RSAParameters FetchCachedRSAParameters(MerchantConfig merchantConfig)
        {
            lock (mutexForPrivateKeyFromPEM) 
            {
                var pemFilePath = merchantConfig.PemFileDirectory;
                ObjectCache cache = MemoryCache.Default;

                var matches = Regex.Match(merchantConfig.PemFileDirectory, regexForFileNameFromDirectory);
                var certFile = matches.Groups[11].ToString();

                if (!cache.Contains(certFile))
                {
                    var policy = new CacheItemPolicy();
                    var filePaths = new List<string>();
                    var privateKey = File.ReadAllText(merchantConfig.PemFileDirectory);
                    var cachedFilePath = Path.GetFullPath(pemFilePath);
                    filePaths.Add(cachedFilePath);
                    policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

                    PemReader pemReader = new PemReader(new StringReader(privateKey));
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

                    cache.Set(certFile, rsaParams, policy);
                }
                return (RSAParameters)cache[certFile];
            }
        }

        public static X509Certificate2 GetCertBasedOnKeyAlias(X509Certificate2Collection certs, String keyAlias)
        {
            foreach (var cert in certs)
            {
                if (cert.GetNameInfo(X509NameType.SimpleName, false).Equals(keyAlias, StringComparison.OrdinalIgnoreCase))
                {
                    return cert;
                }
            }
            throw new Exception($"{Constants.ErrorPrefix} Certificate with alias {keyAlias} not found.");
            
        }

        public static X509Certificate2 GetRequestMLECertFromCache(MerchantConfig merchantConfig)
        {
            string merchantId = merchantConfig.MerchantId;
            string certificateIdentifier;
            string certificateFilePath;

            // Priority #1: Get cert from merchantConfig.mleForRequestPublicCertPath if certPath is provided
            if (!string.IsNullOrEmpty(merchantConfig.MleForRequestPublicCertPath))
            {
                certificateIdentifier = "mleCertFromMerchantConfig";
                certificateFilePath = merchantConfig.MleForRequestPublicCertPath;
            }
            // Priority #2: If merchantConfig.mleForRequestPublicCertPath not provided by merchant then get mlecert from merchant p12 if provided and jwt auth type
            else if (Constants.AuthMechanismJwt.Equals(merchantConfig.AuthenticationType, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(merchantConfig.P12Keyfilepath))
            {
                certificateIdentifier = "mleCertFromP12";
                certificateFilePath = merchantConfig.P12Keyfilepath;
            }
            // Priority #3: Get mlecert from default mle cert in SDK as per CAS or PROD env.
            else
            {
                certificateIdentifier = "mleCertFromDefaultInSDK";
                certificateFilePath = MLEUtility.GetDefaultMLECertPath(merchantConfig.RunEnvironment);
            }

            string cacheKey = $"{merchantId}_{certificateIdentifier}";
            return GetMLECertBasedOnCacheKey(merchantConfig, cacheKey, certificateFilePath);
        }

        private static X509Certificate2 GetMLECertBasedOnCacheKey(MerchantConfig merchantConfig, string cacheKey, string certificateFilePath)
        {
            lock(mutex)
            {
                ObjectCache cache = MemoryCache.Default;

                if (!cache.Contains(cacheKey))
                {
                    SetupCache(merchantConfig, cacheKey, certificateFilePath);
                }
                else
                {
                    CertInfo certInfo = (CertInfo) cache.Get(cacheKey);
                    if (certInfo != null || certInfo.Timestamp != File.GetLastWriteTime(certificateFilePath))
                    {
                        SetupCache(merchantConfig, cacheKey, certificateFilePath);
                    }
                }

                return ((CertInfo)cache.Get(cacheKey)).Certificates[0];
            }
        }

        private static void SetupCache(MerchantConfig merchantConfig, string cacheKey, string certificateFilePath)
        {
            X509Certificate2 mleCertificate = null;

            if (cacheKey.EndsWith("mleCertFromMerchantConfig"))
            {
                X509Certificate2Collection certificates = CertificateUtility.LoadCertificatesFromPemFile(certificateFilePath);

                mleCertificate = CertificateUtility.SearchCertificateByAlias(certificates, merchantConfig.MleKeyAlias);

                if (mleCertificate == null)
                {
                    // If no certificate found for the specified alias, fall back to first certificate
                    mleCertificate = certificates[0];
                }
            }

            if (cacheKey.EndsWith("mleCertFromP12"))
            {
                mleCertificate = InitializeMLECertificate(merchantConfig);
            }

            if (cacheKey.EndsWith("mleCertFromDefaultInSDK"))
            {
                X509Certificate2Collection certificates = CertificateUtility.LoadCertificatesFromPemFile(certificateFilePath);

                mleCertificate = CertificateUtility.SearchCertificateByAlias(certificates, Constants.DefaultMleAliasForCert);

                if (mleCertificate == null)
                {
                    // If no certificate found for the specified alias, fall back to first certificate
                    mleCertificate = certificates[0];
                }
            }

            CertInfo certInfo = new CertInfo();
            certInfo.MLECertificate = mleCertificate;
            certInfo.Timestamp = File.GetLastWriteTime(certificateFilePath);

            var policy = new CacheItemPolicy();
            var filePaths = new List<string>();
            var cachedFilePath = Path.GetFullPath(certificateFilePath);
            filePaths.Add(cachedFilePath);
            policy.ChangeMonitors.Add(new HostFileChangeMonitor(filePaths));

            ObjectCache cache = MemoryCache.Default;
            lock(mutex)
            {
                cache.Set(cacheKey, certInfo, policy);
            }
        }

        private static X509Certificate2 InitializeMLECertificate(MerchantConfig merchantConfig)
        {
            if (merchantConfig == null || string.IsNullOrEmpty(merchantConfig.MleKeyAlias) || string.IsNullOrEmpty(merchantConfig.P12Keyfilepath))
            {
                return null;
            }

            // Load all certificates from the PKCS#12 file
            var certCollection = new X509Certificate2Collection();
            certCollection.Import(merchantConfig.P12Keyfilepath, merchantConfig.KeyPass, X509KeyStorageFlags.Exportable);

            // Collect all 'aliases' (use FriendlyName if set, else Subject)
            var aliasList = new List<string>();
            foreach (var cert in certCollection)
            {
                aliasList.Add(!string.IsNullOrEmpty(cert.FriendlyName) ? cert.FriendlyName : cert.Subject);
            }

            // Validate/select the key alias
            string selectedAlias = ValidateKeyAlias(aliasList, merchantConfig.MleKeyAlias);

            // Find the matching certificate
            foreach (var cert in certCollection)
            {
                string certAlias = !string.IsNullOrEmpty(cert.FriendlyName) ? cert.FriendlyName : cert.Subject;
                if (string.Equals(certAlias, selectedAlias, StringComparison.OrdinalIgnoreCase))
                {
                    return cert;
                }
            }

            throw new KeyNotFoundException($"No certificate found for Request MLE for given mleKeyAlias {merchantConfig.MleKeyAlias} in p12 file {merchantConfig.KeyfileName}.p12");
        }

        private static string ValidateKeyAlias(List<string> aliasList, string mleKeyAlias)
        {
            foreach (var alias in aliasList)
            {
                if (string.Equals(alias, mleKeyAlias, StringComparison.OrdinalIgnoreCase))
                {
                    return alias;
                }
            }
            return null;
        }
    }
}
