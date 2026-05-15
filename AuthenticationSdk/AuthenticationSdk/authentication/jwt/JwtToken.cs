using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using AuthenticationSdk.core;
using AuthenticationSdk.util;

namespace AuthenticationSdk.authentication.jwt
{
    public class JwtToken : Token
    {
        /// <summary>
        /// Constructor for JWT with P12 certificate (asymmetric RS256 signing).
        /// </summary>
        public JwtToken(MerchantConfig merchantConfig)
        {
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;
            P12FilePath = merchantConfig.P12Keyfilepath;

            if (!File.Exists(P12FilePath))
            {
                throw new Exception($"{Constants.ErrorPrefix} File not found at the given path: {Path.GetFullPath(P12FilePath)}");
            }

            KeyAlias = merchantConfig.KeyAlias;
            KeyPass = merchantConfig.KeyPass;
            X509Certificate2Collection certs = Cache.FetchCachedCertificate(P12FilePath, KeyPass);
            Certificate = Cache.GetCertBasedOnKeyAlias(certs, merchantConfig.KeyAlias);
        }

        /// <summary>
        /// Constructor for JWT with Shared Secret (symmetric HS256 signing).
        /// Does not load P12 file or certificate.
        /// </summary>
        internal JwtToken(MerchantConfig merchantConfig, bool isSharedSecret)
        {
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;

            if (isSharedSecret)
            {
                MerchantKeyId = merchantConfig.MerchantKeyId;
                MerchantSecretKey = merchantConfig.MerchantSecretKey;
            }
        }

        public string BearerToken { get; set; }

        public string RequestJsonData { get; set; }

        public string HostName { get; set; }

        public string P12FilePath { get; set; }

        public string KeyAlias { get; set; }

        public string KeyPass { get; }

        public X509Certificate2 Certificate { get; }

        /// <summary>
        /// Key ID for JWT Shared Secret signing (used as 'kid' in JWT header).
        /// </summary>
        public string MerchantKeyId { get; set; }

        /// <summary>
        /// Base64-encoded shared secret key for HMAC-SHA256 signing.
        /// </summary>
        public string MerchantSecretKey { get; set; }
    }
}