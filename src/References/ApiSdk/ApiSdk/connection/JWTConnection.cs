using System.Net.Http;
using System.Net.Http.Headers;
using ApiSdk.util;
using AuthenticationSdk.core;

namespace ApiSdk.connection
{
    public class JWTConnection : IConnection
    {
        public HttpClient GetConnectionForGet(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders
                .Accept
                .Add(new MediaTypeWithQualityHeaderValue(Constants.MediaTypeHalAndJson));

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }

        public HttpClient GetConnectionForPost(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            var content = new StringContent(merchantConfig.RequestJsonData);
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.MediaTypeJson);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }

        public HttpClient GetConnectionForPut(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            var content = new StringContent(merchantConfig.RequestJsonData);
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.MediaTypeJson);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }

        public HttpClient GetConnectionForPatch(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            var content = new StringContent(merchantConfig.RequestJsonData);
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.MediaTypeJson);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            client.DefaultRequestHeaders.Add("profile-id", "93B32398-AD51-4CC2-A682-EA3E93614EB1");

            return client;
        }

        public HttpClient GetConnectionForDelete(MerchantConfig merchantConfig)
        {
            var token = AuthenticationHelper.GetToken(merchantConfig);
            var httpConnUtility = new HttpConnUtility(merchantConfig.ProxyAddress, merchantConfig.ProxyPort, merchantConfig.TimeOut);
            var client = httpConnUtility.GetHttpClient();

            client.DefaultRequestHeaders
                .Accept
                .Add(new MediaTypeWithQualityHeaderValue(Constants.MediaTypeHalAndJson));

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constants.Bearer, token.BearerToken);

            return client;
        }
    }
}
