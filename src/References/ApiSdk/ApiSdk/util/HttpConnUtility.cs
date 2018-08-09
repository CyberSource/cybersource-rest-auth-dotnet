using System;
using System.Net;
using System.Net.Http;

namespace ApiSdk.util
{
    public  class HttpConnUtility
    {
        private HttpClient _client;
        private HttpClientHandler _handler;
        private readonly string _prefix = ConstantsApi.HttpUriPrefix;
        private readonly string _address;
        private readonly string _port;
        private readonly string _timeout;

        public HttpConnUtility(string address, string port, string timeout)
        {
            _address = address;
            _port = port;
            _timeout = timeout;            
        }


        public HttpClient GetHttpClient()
        {
            if (string.IsNullOrEmpty(_address) || string.IsNullOrEmpty(_port))
                _client = new HttpClient();
            else
            {
                _handler = new HttpClientHandler()
                {
                    Proxy = new WebProxy(string.Concat(_prefix, _address, ":", _port)),
                    UseProxy = true,
                };
                _client = new HttpClient(_handler);
            }
            if (!string.IsNullOrEmpty(_timeout))
                _client.Timeout = TimeSpan.FromMilliseconds(Convert.ToDouble(_timeout));

            return _client;
        }
    }
}
