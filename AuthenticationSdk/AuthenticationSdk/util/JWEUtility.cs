using Jose;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;
using AuthenticationSdk.core;

namespace AuthenticationSdk.util
{
    public static class JWEUtilty
    {
        public static string DecryptUsingPEM(MerchantConfig merchantConfig, string encodedData)
        {
            RSAParameters rsaParams = Cache.FetchCachedRSAParameters(merchantConfig);
            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);
            return JWT.Decode(encodedData, rsa, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM);
        }
    }
}
