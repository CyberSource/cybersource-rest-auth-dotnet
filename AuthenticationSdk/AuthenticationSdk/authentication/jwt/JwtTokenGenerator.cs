using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using Newtonsoft.Json.Linq;

namespace AuthenticationSdk.authentication.jwt
{
    public class JwtTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;
        private readonly JwtToken _jwtToken;
        private readonly bool _isResponseMLEForApi;

        public JwtTokenGenerator(MerchantConfig merchantConfig, bool isResponseMLEForApi)
        {
            _merchantConfig = merchantConfig;
            _jwtToken = new JwtToken(_merchantConfig);
            _isResponseMLEForApi = isResponseMLEForApi;
        }

        public Token GetToken()
        {
            _jwtToken.BearerToken = SetToken();
            return _jwtToken;
        }

        private static string GenerateDigest(string requestJsonData)
        {
            using (var sha256Hash = SHA256.Create())
            {
                var payloadBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(requestJsonData));
                var digest = Convert.ToBase64String(payloadBytes);
                return digest;
            }
        }

        private string SetToken()
        {
            var payloadClaimSet = GetPayloadClaimSet();
            var headerClaimSet = GetHeaderClaimSet();

            var x5Cert = _jwtToken.Certificate;
            var privateKey = x5Cert.GetRSAPrivateKey();

            var jwtBody = payloadClaimSet.ToString(Newtonsoft.Json.Formatting.None);
            var token = Jose.JWT.Encode(jwtBody, privateKey, Jose.JwsAlgorithm.RS256, headerClaimSet);
            return token;
        }

        private JObject GetPayloadClaimSet()
        {
            var jwtPayload = new JObject();

            // Setting the JWT digest and digest Algorithm when a POST, PUT, or PATCH request is made
            if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
            {
                var digest = GenerateDigest(_jwtToken.RequestJsonData);
                jwtPayload["digest"] = digest;
                jwtPayload["digestAlgorithm"] = "SHA-256";
            }

            // Set the iat and exp claims using Unix timestamps
            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            jwtPayload["iat"] = currentTime;
            jwtPayload["exp"] = currentTime + 120; // The exp claim is set to 2 mins more than the iat claim

            // Set the request method, host and resource path in the JWT body as per the specification for all request types
            jwtPayload["request-method"] = _merchantConfig.RequestType?.ToUpper();
            jwtPayload["request-host"] = _merchantConfig.RunEnvironment;
            jwtPayload["request-resource-path"] = ExtractResourcePath(_merchantConfig.RequestTarget);

            // Choose issuer claim in the JWT body as per the use_metakey flag in the config file
            string issuer;
            if (!string.IsNullOrEmpty(_merchantConfig.UseMetaKey) && 
                bool.TryParse(_merchantConfig.UseMetaKey, out bool useMetaKey) && useMetaKey)
            {
                issuer = _merchantConfig.PortfolioId;
            }
            else
            {
                issuer = _merchantConfig.MerchantId;
            }

            jwtPayload["iss"] = issuer;
            jwtPayload["jti"] = Guid.NewGuid().ToString();
            jwtPayload["v-c-jwt-version"] = "2";
            jwtPayload["v-c-merchant-id"] = _merchantConfig.MerchantId;

            if (_isResponseMLEForApi)
            {
                // Validate and auto-extract Response MLE KID if needed
                string validatedKid = util.MLEUtility.ValidateAndAutoExtractResponseMleKid(_merchantConfig);
                jwtPayload["v-c-response-mle-kid"] = validatedKid;
            }

            return jwtPayload;
        }

        private Dictionary<string, object> GetHeaderClaimSet()
        {
            var x5Cert = _jwtToken.Certificate;
            var serialNumber = CertificateUtility.ExtractSerialNumber(x5Cert);

            var jwtHeaders = new Dictionary<string, object>
            {
                { "kid", serialNumber },
                { "typ", "JWT" }
            };

            // Add any other future parameters to the header claim set here
            return jwtHeaders;
        }

        private string ExtractResourcePath(string requestTarget)
        {
            if (string.IsNullOrEmpty(requestTarget))
            {
                return string.Empty;
            }

            // Split the string to remove the query params
            var parts = requestTarget.Split('?');
            return parts[0];
        }
    }
}
