using System;

namespace ApiSdk.com.cybersource.api.util
{
    public class Response
    {
        public Response(int statusCode, string headers, string data)
        {
            StatusCode = statusCode;
            Data = data;
            Headers = headers;
        }

        public int StatusCode { get; }
        public string Data { get; }
        public string Headers { get; }

        public string GetResponseHeaderValue(string responseHeadersString, string headerToFind)
        {
            var responseHeaderarray = responseHeadersString.Split(new[] { GlobalLabelParametersAPI.ResponseHeadersSeparator }, StringSplitOptions.None);

            foreach (var header in responseHeaderarray)
            {
                var headerKeyValue = header.Split(':');
                var headerKey = headerKeyValue[0];
                var headerValue = headerKeyValue[1];

                if (headerKey == headerToFind)
                    return headerValue.Trim();                
            }
            return "";
        }
    }
}