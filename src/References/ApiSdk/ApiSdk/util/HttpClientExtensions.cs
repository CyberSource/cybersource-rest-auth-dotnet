using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ApiSdk.util
{
    public static class HttpClientExtensions
    {
        public static async Task<HttpResponseMessage> PatchAsync(this HttpClient client, Uri requestUri, HttpContent iContent)
        {
            var method = new HttpMethod("PATCH");
            var request = new HttpRequestMessage(method, requestUri)
            { Content = iContent };

            HttpResponseMessage response = new HttpResponseMessage();

            response = await client.SendAsync(request);
            return response;
        }

        public static async Task<HttpResponseMessage> PatchAsync(this HttpClient client, string requestUri, HttpContent iContent)
        {
            var method = new HttpMethod("PATCH");
            var request = new HttpRequestMessage(method, requestUri)
            { Content = iContent };

            HttpResponseMessage response = new HttpResponseMessage();

            response = await client.SendAsync(request);
            return response;
        }

        public static async Task<HttpResponseMessage> PatchAsync(this HttpClient client, Uri requestUri, HttpContent iContent, CancellationToken cancellationToken)
        {
            var method = new HttpMethod("PATCH");
            var request = new HttpRequestMessage(method, requestUri)
            { Content = iContent };

            HttpResponseMessage response = new HttpResponseMessage();

            response = await client.SendAsync(request, cancellationToken);
            return response;
        }

        public static async Task<HttpResponseMessage> PatchAsync(this HttpClient client, string requestUri, HttpContent iContent, CancellationToken cancellationToken)
        {
            var method = new HttpMethod("PATCH");
            var request = new HttpRequestMessage(method, requestUri)
            { Content = iContent };

            HttpResponseMessage response = new HttpResponseMessage();

            response = await client.SendAsync(request, cancellationToken);
            return response;
        }
    }
}