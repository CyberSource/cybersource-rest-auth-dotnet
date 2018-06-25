using System;
using System.Security.Cryptography;
using System.Text;
using AuthenticationSdk.com.cybersource.authentication.core;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace AuthenticationSdk.com.cybersource.authentication.authentication.http
{
    public class HttpToken : Token
    {                
        private static string _gmtDateTime;
        private static readonly string SignatureAlgorithm = GlobalLabelParameters.SignatureAlgorithm;

        public string MerchantId { get; set; }
        public string MerchantSecretKey { get; set; }
        public string RequestJsonData { get;}
        public string GmtDateTime => DateTime.Now.ToUniversalTime().ToString("r");
        public string HostName { get; }        
        public string Digest => GenerateDigest();
        public string SignatureParam { get; set; }
        public string GetRequestTarget { get; set; }
        public string PostOrPutRequestTarget { get; set; }        
        public string MerchantKeyId { get; set; }

        public HttpToken(MerchantConfig merchantConfig)
        {           
            _gmtDateTime = GmtDateTime;            
            RequestJsonData = merchantConfig.RequestJsonData;
            HostName = merchantConfig.HostName;
            MerchantId = merchantConfig.MerchantId;
            MerchantSecretKey = merchantConfig.MerchantSecretKey;
            MerchantKeyId = merchantConfig.MerchantKeyId;
            GetRequestTarget = merchantConfig.HttpSignGetRequestTarget;
            PostOrPutRequestTarget = merchantConfig.HttpSignPostOrPutRequestTarget;            
            SignatureParam = SetSignatureParam(merchantConfig.RequestType);            
        }                

        private string SetSignatureParam(string requestType)
        {            

            var signature = "";

            if (requestType == null)
                throw new Exception($"{GlobalLabelParameters.ErrorPrefix} RequestType Property of Merchant Config Not Set");
            
            if (requestType.ToUpper() == GlobalLabelParameters.GetUpperCase)
                signature = SignatureForGet();
            else if (requestType.ToUpper() == GlobalLabelParameters.PostUpperCase ||
                     requestType.ToUpper() == GlobalLabelParameters.PutUpperCase)
                signature = SignatureForPostOrPut();

            return signature;                        
        }

        private string SignatureForGet()
        {             
            var signatureString = new StringBuilder();
            var signatureHeaderValue = new StringBuilder();
            const string getHeaders = "host date (request-target) v-c-merchant-id";

            signatureString.Append('\n');
            signatureString.Append("host");
            signatureString.Append(": ");
            signatureString.Append(HostName);
            signatureString.Append('\n');
            signatureString.Append("date");
            signatureString.Append(": ");
            signatureString.Append(_gmtDateTime);
            signatureString.Append('\n');
            signatureString.Append("(request-target)");
            signatureString.Append(": ");
            signatureString.Append(GetRequestTarget);
            signatureString.Append('\n');
            signatureString.Append("v-c-merchant-id");
            signatureString.Append(": ");
            signatureString.Append(MerchantId);
            signatureString.Remove(0, 1);

            var signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());
            var decodedKey = Convert.FromBase64String(MerchantSecretKey);
            var aKeyId = new HMACSHA256(decodedKey);
            var hashmessage = aKeyId.ComputeHash(signatureByteString);
            var base64EncodedSignature = Convert.ToBase64String(hashmessage);

            signatureHeaderValue.Append("keyid=\"" + MerchantKeyId + "\"");
            signatureHeaderValue.Append(", algorithm=\"" + SignatureAlgorithm + "\"");
            signatureHeaderValue.Append(", headers=\"" + getHeaders + "\"");
            signatureHeaderValue.Append(", signature=\"" + base64EncodedSignature + "\"");

            return  signatureHeaderValue.ToString();
        }

        private string SignatureForPostOrPut()
        {            
            var signatureString = new StringBuilder();
            var signatureHeaderValue = new StringBuilder();
            var digest = GenerateDigest();
            const string postOrPutHeaders = "host date (request-target) digest v-c-merchant-id";
            
            signatureString.Append('\n');
            signatureString.Append("host");
            signatureString.Append(": ");
            signatureString.Append(HostName);
            signatureString.Append('\n');
            signatureString.Append("date");
            signatureString.Append(": ");
            signatureString.Append(_gmtDateTime);
            signatureString.Append('\n');
            signatureString.Append("(request-target)");
            signatureString.Append(": ");
            signatureString.Append(PostOrPutRequestTarget);
            signatureString.Append('\n');
            signatureString.Append("digest");
            signatureString.Append(": ");
            signatureString.Append(digest);
            signatureString.Append('\n');
            signatureString.Append("v-c-merchant-id");
            signatureString.Append(": ");
            signatureString.Append(MerchantId);
            signatureString.Remove(0, 1);

            var signatureByteString = Encoding.UTF8.GetBytes(signatureString.ToString());
            var decodedKey = Convert.FromBase64String(MerchantSecretKey);
            var aKeyId = new HMACSHA256(decodedKey);
            var hashmessage = aKeyId.ComputeHash(signatureByteString);
            var base64EncodedSignature = Convert.ToBase64String(hashmessage);

            signatureHeaderValue.Append("keyid=\"" + MerchantKeyId + "\"");
            signatureHeaderValue.Append(", algorithm=\"" + SignatureAlgorithm + "\"");
            signatureHeaderValue.Append(", headers=\"" + postOrPutHeaders + "\"");
            signatureHeaderValue.Append(", signature=\"" + base64EncodedSignature + "\"");

            return  signatureHeaderValue.ToString();
        }        


        private string GenerateDigest()
        {            

            string digest;            

            using (var sha256Hash = SHA256.Create())
            {
                var payloadBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(RequestJsonData));
                digest = Convert.ToBase64String(payloadBytes);
                digest = "SHA-256=" + digest;
            }

            return digest;
        }
    }

}