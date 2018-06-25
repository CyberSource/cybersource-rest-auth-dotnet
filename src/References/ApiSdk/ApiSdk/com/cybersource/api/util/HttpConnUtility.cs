using System;
using System.Net;
using System.Net.Http;

namespace ApiSdk.com.cybersource.api.util
{
    public static class HttpConnUtility
    {
        public static HttpClient InitHttpclient(string address, string port, string timeout)
        {
            //Declare HttpClient Object
            HttpClient client;            

            //Set the Proxy parameters if the address and port are provided
            if (string.IsNullOrEmpty(address) || string.IsNullOrEmpty(port))
                client = new HttpClient();
            else
            {
                var prefix = GlobalLabelParametersAPI.HttpUriPrefix;

                var handler = new HttpClientHandler()
                {
                    Proxy = new WebProxy(string.Concat(prefix, address, ":", port)),
                    UseProxy = true,
                };

                client = new HttpClient(handler);
            }

            if (!string.IsNullOrEmpty(timeout))
                client.Timeout = TimeSpan.FromMilliseconds(Convert.ToDouble(timeout));
                
            return client;
        }
    }
}
