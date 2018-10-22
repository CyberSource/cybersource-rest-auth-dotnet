using System;
using AuthenticationSdk.core;
using AuthenticationSdk.util;

namespace SampleCode.samplecode.GenerateHTTPRequestHeaders
{
    public class GetGenerateHeaders
    {
        // GET request to retrieve the payment details of the provided Payment ID
        // Below Request fetches the payment details of payment ID: 5289697403596987704107
        private const string RequestTarget = "/pts/v2/payments/5289697403596987704107";

        public static void Main(string[] args)
        {
            try
            {
                // Setting up Merchant Config
                var merchantConfig = new MerchantConfig
                {
                    RequestTarget = RequestTarget,
                    RequestType = Enumerations.RequestType.GET.ToString(),
                };

                // Call to the Authorize class of AuthSDK to get the signature and token objects
                var authorizeObj = new Authorize(merchantConfig);

                if (string.Equals(merchantConfig.AuthenticationType, Enumerations.AuthenticationType.HTTP_SIGNATURE.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    var requestHeaders = authorizeObj.GetSignature();

                    Console.WriteLine("{0} {1}", "Accept:", "application/hal+json");
                    Console.WriteLine("{0} {1}", "v-c-merchant-id:", requestHeaders.MerchantId);
                    Console.WriteLine("{0} {1}", "Date:", requestHeaders.GmtDateTime);
                    Console.WriteLine("{0} {1}", "Host:", requestHeaders.HostName);
                    Console.WriteLine("{0} {1}", "signature:", requestHeaders.SignatureParam);
                }
                else if (string.Equals(merchantConfig.AuthenticationType, Enumerations.AuthenticationType.JWT.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    var requestHeaders = authorizeObj.GetToken();

                    Console.WriteLine("{0} {1}", "Accept:", "application/hal+json");
                    Console.WriteLine("{0} {1}", "Authorization:", requestHeaders.BearerToken);
                }
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
            }

            Console.WriteLine("\n Press any key to exit the Application...");
            Console.ReadLine();
        }
    }
}