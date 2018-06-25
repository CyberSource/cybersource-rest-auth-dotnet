using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using ApiSdk.com.cybersource.api.connection;
using ApiSdk.com.cybersource.api.mask;
using ApiSdk.com.cybersource.api.util;
using AuthenticationSdk.com.cybersource.authentication.util;
using NLog;

namespace ApiSdk.com.cybersource.api.service
{
    public class PaymentRequestService
    {        
        private static int _statusCode;
        private static string _authenticaionType;
        private static string _hostName;            
        private static string _getUrlSuffix;        
        private static string _postUrlSuffix;
        private static string _putUrlSuffix;
        private static string _requestJsonData;
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly Masking Masking = new Masking();
        private static Response _response;        
        private static readonly HTTPConnection HttpConn = new HTTPConnection();
        private static readonly JWTConnection JwtConn = new JWTConnection();        

        //Generates the HttpClient Object and using it makes an async GET call to the API server
        public Response GetResponse(MerchantConfig merchantConfig)
        {
            _hostName = merchantConfig.HostName;

            if (!string.IsNullOrEmpty(merchantConfig.GetID))
                _getUrlSuffix = merchantConfig.RequestTarget + "/" + merchantConfig.GetID;
            else
                _getUrlSuffix = merchantConfig.RequestTarget;
                            
            _authenticaionType = merchantConfig.AuthenticationType;
            
            if (_authenticaionType.ToUpper() == GlobalLabelParametersAPI.AuthTypeHTTP)
            {
                var client = HttpConn.GetConnectionForGet(merchantConfig);
                RunAsyncGet(client, _getUrlSuffix, _hostName).Wait();
            }
            else if (_authenticaionType.ToUpper() == GlobalLabelParametersAPI.AuthTypeJWT)
            {
                var client = JwtConn.GetConnectionForGet(merchantConfig);
                RunAsyncGet(client, _getUrlSuffix, _hostName).Wait();
            }
                                   
            return _response;        
        }

        //Generates the HttpClient Object and using it makes an async POST call to the API server
        public Response PostResponse(MerchantConfig merchantConfig)
        {
            _hostName = merchantConfig.HostName;
            _requestJsonData = merchantConfig.RequestJsonData;

            if (string.IsNullOrEmpty(_requestJsonData))
                throw new Exception($"{GlobalLabelParametersAPI.ErrorPrefix} No Request JSON Data passed to the Service for the POST Call");
            
            _postUrlSuffix = merchantConfig.RequestTarget;                         
            _authenticaionType = merchantConfig.AuthenticationType;

            if (_authenticaionType.ToUpper() == GlobalLabelParametersAPI.AuthTypeHTTP)
            {                
                var client = HttpConn.GetConnectionForPostOrPut(merchantConfig);
                RunAsyncPost(client, _postUrlSuffix, _hostName, _requestJsonData).Wait();
            }
            else if (_authenticaionType.ToUpper() == GlobalLabelParametersAPI.AuthTypeJWT)
            {                
                var client = JwtConn.GetConnectionForPostOrPut(merchantConfig);
                RunAsyncPost(client, _postUrlSuffix, _hostName, _requestJsonData).Wait();
            }            

            return _response;
        }

        public Response PutResponse(MerchantConfig merchantConfig)
        {
            _hostName = merchantConfig.HostName;
            _requestJsonData = merchantConfig.RequestJsonData;

            if (string.IsNullOrEmpty(_requestJsonData))
                throw new Exception($"{GlobalLabelParametersAPI.ErrorPrefix} No Request JSON Data passed to the Service for the PUT Call");

            if (!string.IsNullOrEmpty(merchantConfig.PutID))
                _putUrlSuffix = merchantConfig.RequestTarget + "/" + merchantConfig.PutID;
            else
                _putUrlSuffix = merchantConfig.RequestTarget;

            _authenticaionType = merchantConfig.AuthenticationType;

            if (_authenticaionType.ToUpper() == GlobalLabelParametersAPI.AuthTypeHTTP)
            {
                var client = HttpConn.GetConnectionForPostOrPut(merchantConfig);
                RunAsyncPut(client, _putUrlSuffix, _hostName, _requestJsonData).Wait();
            }
            else if (_authenticaionType.ToUpper() == GlobalLabelParametersAPI.AuthTypeJWT)
            {
                var client = JwtConn.GetConnectionForPostOrPut(merchantConfig);
                RunAsyncPut(client, _putUrlSuffix, _hostName, _requestJsonData).Wait();
            }

            return _response;
        }


        //End point of the GET Call to the API server
        public async Task RunAsyncGet(HttpClient client, string getUrlSuffix, string hostName)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            using (client)
            {                
                var uriString = GlobalLabelParametersAPI.HttpsUriPrefix + hostName + getUrlSuffix;                                

                Logger.Trace("{0} {1}","URL ->",uriString);
                Console.WriteLine("\n {0} {1}","URL ->", uriString);

                try
                {
                    using (var response = await client.GetAsync(new Uri(uriString)))
                    {
                        _statusCode = (int)(TaskStatus)response.StatusCode;
                        var data = await response.Content.ReadAsStringAsync();
                        var dataMasked = Masking.MaskMessage(data);
                        var headers = response.Headers.ToString();

                        _response = new Response(_statusCode, headers, dataMasked);
                    }
                }
                catch (TaskCanceledException)
                {
                    throw new Exception($"{GlobalLabelParametersAPI.ErrorPrefix}Check and verify the connection timeout value.");
                }
            }
        }

        //End point of the POST Call to the API server
        public async Task RunAsyncPost(HttpClient client, string postUrlSuffix, string hostName, string requestJsonData)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            using (client)
            {                
                var request = requestJsonData;

                Logger.Trace("{0} {1}", "REQUEST BODY ->", Masking.MaskMessage(request));
                Console.WriteLine("\n {0} {1}", "REQUEST BODY ->", Masking.MaskMessage(request));

                var content = new StringContent(request);                    
                content.Headers.ContentType = new MediaTypeHeaderValue(GlobalLabelParametersAPI.MediaTypeJson);                    

                var uriString = GlobalLabelParametersAPI.HttpsUriPrefix + hostName + postUrlSuffix;

                Logger.Trace("{0} {1}", "URL ->", uriString);
                Console.WriteLine("\n {0} {1}", "URL ->", uriString);

                try
                {
                    using (var response = await client.PostAsync(uriString, content))
                    {
                        _statusCode = (int)(TaskStatus)response.StatusCode;
                        var data = await response.Content.ReadAsStringAsync();
                        var dataMasked = Masking.MaskMessage(data);
                        var headers = response.Headers.ToString();

                        _response = new Response(_statusCode, headers, dataMasked);
                    }
                }
                catch (TaskCanceledException)
                {
                    throw new Exception($"{GlobalLabelParametersAPI.ErrorPrefix}Check and verify the connection timeout value.");
                }
            }
        }

        //End point of the PUT Call to the API server
        public async Task RunAsyncPut(HttpClient client, string putUrlSuffix, string hostName, string requestJsonData)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            using (client)
            {
                var request = requestJsonData;

                Logger.Trace("{0} {1}", "REQUEST BODY ->", Masking.MaskMessage(request));
                Console.WriteLine("\n {0} {1}", "REQUEST BODY ->", Masking.MaskMessage(request));

                var content = new StringContent(request);
                content.Headers.ContentType = new MediaTypeHeaderValue(GlobalLabelParametersAPI.MediaTypeJson);

                var uriString = GlobalLabelParametersAPI.HttpsUriPrefix + hostName + putUrlSuffix;

                Logger.Trace("{0} {1}", "URL ->", uriString);
                Console.WriteLine("\n {0} {1}", "URL ->", uriString);

                try
                {
                    using (var response = await client.PutAsync(uriString, content))
                    {
                        _statusCode = (int)(TaskStatus)response.StatusCode;
                        var data = await response.Content.ReadAsStringAsync();
                        var dataMasked = Masking.MaskMessage(data);
                        var headers = response.Headers.ToString();

                        _response = new Response(_statusCode, headers, dataMasked);
                    }
                }
                catch (TaskCanceledException)
                {
                    throw new Exception($"{GlobalLabelParametersAPI.ErrorPrefix}Check and verify the connection timeout value.");
                }
            }
        }
    }
}