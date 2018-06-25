using System;
using System.Net.Http;
using System.Net.Http.Headers;
using ApiSdk.com.cybersource.api.util;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace ApiSdk.com.cybersource.api.connection
{
    public class JWTConnection : IConnection
    {        

        public HttpClient GetConnectionForGet(MerchantConfig merchantConfig)
        {                                                
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var client = HttpConnUtility.InitHttpclient(merchantConfig.ProxyAddress, merchantConfig.ProxyPort,
                merchantConfig.TimeOut);

            client.DefaultRequestHeaders
                .Accept
                .Add(new MediaTypeWithQualityHeaderValue(GlobalLabelParametersAPI.MediaTypeHalAndJson));            
            Console.WriteLine("\n {0} {1}", "Accept:", GlobalLabelParametersAPI.MediaTypeHalAndJson);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(GlobalLabelParametersAPI.Bearer, token.BearerToken);            
            Console.WriteLine("{0} {1}", GlobalLabelParametersAPI.Authorization + ":", token.BearerToken);

            return client;
        }

        public HttpClient GetConnectionForPostOrPut(MerchantConfig merchantConfig)
        {                        
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var client = HttpConnUtility.InitHttpclient(merchantConfig.ProxyAddress, merchantConfig.ProxyPort,
                merchantConfig.TimeOut);
            
            var content = new StringContent(merchantConfig.RequestJsonData);            
            content.Headers.ContentType = new MediaTypeHeaderValue(GlobalLabelParametersAPI.MediaTypeJson);            
            Console.WriteLine("\n {0} {1}", "Content-Type:", GlobalLabelParametersAPI.MediaTypeHalAndJson);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(GlobalLabelParametersAPI.Bearer, token.BearerToken);            
            Console.WriteLine("{0} {1}", GlobalLabelParametersAPI.Authorization + ":", token.BearerToken);

            return client;
        }
    }
}
