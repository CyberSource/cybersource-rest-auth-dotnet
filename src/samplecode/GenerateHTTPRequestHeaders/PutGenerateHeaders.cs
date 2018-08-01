using System;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using CyberSource_Authentication_SDK_dotNet.data;

namespace CyberSource_Authentication_SDK_dotNet.samplecode.GenerateHTTPRequestHeaders
{
    public class PutGenerateHeaders
    {                                     
        //Request Target of the CYBS REST API that needs to be hit
        private const string RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";
        private const string RequestJsonFilePath = "..\\..\\Resource\\TRRReport.json";

        public static void Main(string[] args)
        {            
            try
            {
                //Setting up Merchant Config
                var requestData = new RequestData();

                var merchantConfig = new MerchantConfig
                {
                    RequestTarget = RequestTarget,
                    RequestType = Enumerations.RequestType.PUT.ToString(),                    
                    RequestJsonData = requestData.JsonFileData(RequestJsonFilePath)
                };

                //Call to the Authorize class of AuthSDK to get the signature and token objects                
                var authorizeObj = new Authorize(merchantConfig);

                if (string.Equals(merchantConfig.AuthenticationType,
                    Enumerations.AuthenticationType.HTTP_SIGNATURE.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    var requestHeaders = authorizeObj.GetSignature();

                    Console.WriteLine("{0} {1}", "Content-Type:", "application/json");
                    Console.WriteLine("{0} {1}", "v-c-merchant-id:", requestHeaders.MerchantId);
                    Console.WriteLine("{0} {1}", "Date:", requestHeaders.GmtDateTime);
                    Console.WriteLine("{0} {1}", "Host:", requestHeaders.HostName);
                    Console.WriteLine("{0} {1}", "digest:", requestHeaders.Digest);
                    Console.WriteLine("{0} {1}", "signature:", requestHeaders.SignatureParam);
                }
                else if (string.Equals(merchantConfig.AuthenticationType, Enumerations.AuthenticationType.JWT.ToString(),
                    StringComparison.OrdinalIgnoreCase))
                {
                    var requestHeaders = authorizeObj.GetToken();

                    Console.WriteLine("{0} {1}", "Content-Type:", "application/json");
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