using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AuthenticationSdk.com.cybersource.authentication.core;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace AuthenticationSdk.com.cybersource.authentication.authentication.jwt
{
    public class JwtToken : Token
    {                                
        public string BearerToken { get; set; }
        public string RequestJsonData { get; set; }
        public string HostName { get; set; }
        public string P12FilePath { get; set; }
        public string KeyAlias { get; set; }        
        private string KeyPassword { get; }
        private X509Certificate2 Certificate { get; }

        public JwtToken(MerchantConfig merchantConfig)
        {            
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;
            P12FilePath = merchantConfig.P12Keyfilepath;

            if (!File.Exists(P12FilePath))
                throw new Exception($"{GlobalLabelParameters.ErrorPrefix} File not found at the given path: {Path.GetFullPath(P12FilePath)}");

            KeyAlias = merchantConfig.KeyAlias;
            KeyPassword = merchantConfig.KeyPassword;
            Certificate = Cache.FetchCachedCertificate(P12FilePath, KeyPassword);
            BearerToken = SetToken(merchantConfig.RequestType);            
        }        

        private string SetToken(string requestType)
        {
            var token = "";

            if (requestType == null)
                throw new Exception( $"{GlobalLabelParameters.ErrorPrefix} RequestType Property of Merchant Config Not Set");

            try
            {                
                if (requestType.ToUpper() == GlobalLabelParameters.GetUpperCase)
                    token = TokenForGet();
                else if (requestType.ToUpper() == GlobalLabelParameters.PostUpperCase || requestType.ToUpper() == GlobalLabelParameters.PutUpperCase)
                    token = TokenForPostOrPut();                
            }
            catch (CryptographicException e)
            {
                if (e.Message.Equals("The specified network password is not correct.\r\n"))
                    throw new Exception($"{GlobalLabelParameters.ErrorPrefix} KeyPassword provided:{KeyPassword} is incorrect");
            }
            return token;
        }
        
        private string TokenForGet()
        {                                                
            var jwtBody = "{ \"iat\":\"" + DateTime.Now.ToUniversalTime().ToString("r") + "\"}";            
            
            var x5Cert = Certificate;

            var publicKey = Convert.ToBase64String(x5Cert.RawData);

            var privateKey = x5Cert.GetRSAPrivateKey();

            var x5CList = new List<string>()
            {
                publicKey
            };

            var cybsHeaders = new Dictionary<string, object>()
            {
                { "v-c-merchant-id", KeyAlias },
                { "x5c", x5CList }
            };

            var token = Jose.JWT.Encode(jwtBody, privateKey, Jose.JwsAlgorithm.RS256, cybsHeaders);            
                        
            return token;
        }

        private string TokenForPostOrPut()
        {            
            var digest = GenerateDigest(RequestJsonData);            

            var jwtBody = "{\n            \"digest\":\"" + digest + "\", \"digestAlgorithm\":\"SHA-256\", \"iat\":\"" + DateTime.Now.ToUniversalTime().ToString("r") + "\"}";
            
            var x5Cert = Certificate;

            var publicKey = Convert.ToBase64String(x5Cert.RawData);

            var privateKey = x5Cert.GetRSAPrivateKey();
 
            var x5CList = new List<string>()
            {
                publicKey
            };
            var cybsHeaders = new Dictionary<string, object>()
            {
                { "v-c-merchant-id", KeyAlias },
                { "x5c", x5CList }
            };

            var token = Jose.JWT.Encode(jwtBody, privateKey, Jose.JwsAlgorithm.RS256, cybsHeaders);
                        
            return token;
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
    }
}