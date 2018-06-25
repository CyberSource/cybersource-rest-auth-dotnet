using System;
using System.Net.Http;
using System.Net.Http.Headers;
using ApiSdk.com.cybersource.api.util;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace ApiSdk.com.cybersource.api.connection
{
    public class HTTPConnection : IConnection
    {                        
        public HttpClient GetConnectionForGet(MerchantConfig merchantConfig)
        {
            if (!string.IsNullOrEmpty(merchantConfig.GetID))
                merchantConfig.HttpSignGetRequestTarget = GlobalLabelParametersAPI.GetLowerCase + " " +
                                                          merchantConfig.RequestTarget + "/" + merchantConfig.GetID;
            else
                merchantConfig.HttpSignGetRequestTarget = GlobalLabelParametersAPI.GetLowerCase + " " +
                                                          merchantConfig.RequestTarget;
                            
            var signature = AuthenticationHelper.GetSignature(merchantConfig);
            var client = HttpConnUtility.InitHttpclient(merchantConfig.ProxyAddress, merchantConfig.ProxyPort,
                merchantConfig.TimeOut);

            client.DefaultRequestHeaders
                        .Accept
                        .Add(new MediaTypeWithQualityHeaderValue(GlobalLabelParametersAPI.MediaTypeHalAndJson));            
            Console.WriteLine("\n {0} {1}", "Accept:", GlobalLabelParametersAPI.MediaTypeHalAndJson);

            client.DefaultRequestHeaders.Add("v-c-merchant-id", signature.MerchantId);            
            Console.WriteLine("{0} {1}", "v-c-merchant-id:", signature.MerchantId);

            client.DefaultRequestHeaders.Add("Date", signature.GmtDateTime);            
            Console.WriteLine("{0} {1}", "Date:", signature.GmtDateTime);

            client.DefaultRequestHeaders.Add("Host", signature.HostName);            
            Console.WriteLine("{0} {1}", "Host:", signature.HostName);

            client.DefaultRequestHeaders.Add("Signature", signature.SignatureParam);            
            Console.WriteLine("{0} {1}", "signature:", signature.SignatureParam);

            return client;
        }

        public HttpClient GetConnectionForPostOrPut(MerchantConfig merchantConfig)
        {
            if (merchantConfig.RequestType.ToUpper() == GlobalLabelParametersAPI.PutUpperCase)
            {
                if (!string.IsNullOrEmpty(merchantConfig.PutID))
                    merchantConfig.HttpSignPostOrPutRequestTarget = GlobalLabelParametersAPI.PutLowerCase + " " +
                                                               merchantConfig.RequestTarget + "/" + merchantConfig.PutID;
                else
                    merchantConfig.HttpSignPostOrPutRequestTarget = GlobalLabelParametersAPI.PutLowerCase + " " +
                                                                    merchantConfig.RequestTarget;
            }                        
            else if (merchantConfig.RequestType.ToUpper() == GlobalLabelParametersAPI.PostUpperCase)
                merchantConfig.HttpSignPostOrPutRequestTarget = GlobalLabelParametersAPI.PostLowerCase + " " +
                                                           merchantConfig.RequestTarget;
            
            var signature = AuthenticationHelper.GetSignature(merchantConfig);
            var client = HttpConnUtility.InitHttpclient(merchantConfig.ProxyAddress, merchantConfig.ProxyPort,
                merchantConfig.TimeOut);

            client.DefaultRequestHeaders.Add("v-c-merchant-id", signature.MerchantId);            
            Console.WriteLine("\n {0} {1}", "v-c-merchant-id:", signature.MerchantId);

            client.DefaultRequestHeaders.Add("Date", signature.GmtDateTime);            
            Console.WriteLine("{0} {1}", "Date:", signature.GmtDateTime);

            client.DefaultRequestHeaders.Add("Host", signature.HostName);            
            Console.WriteLine("{0} {1}", "Host:", signature.HostName);

            client.DefaultRequestHeaders.Add("Digest", signature.Digest);            
            Console.WriteLine("{0} {1}", "digest:", signature.Digest);

            client.DefaultRequestHeaders.Add("Signature", signature.SignatureParam);            
            Console.WriteLine("{0} {1}", "signature:", signature.SignatureParam);

            return client;            
        }
    }
}
