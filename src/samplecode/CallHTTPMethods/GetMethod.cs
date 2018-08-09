using System;
using ApiSdk.controller;
using AuthenticationSdk.util;

namespace CyberSource_Authentication_SDK_dotNet.samplecode.CallHTTPMethods
{
    public class GetMethod
    {
        //Request Target of the CYBS REST API that needs to be hit
        //private const string RequestTarget = "/reporting/v2/reportSubscriptions?organizationId=testrest";
        private const string RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";
        //private const string RequestTarget = "/pts/v2/payments/5319754772076048103525";
        //private const string RequestTarget = "/pts/v2/captures/5289697403596987704107";

        public static void Main(string[] args)
        {
            try
            {
                //Setting up Merchant Config
                var merchantConfig = new MerchantConfig
                {
                    RequestTarget = RequestTarget,
                    RequestType = Enumerations.RequestType.GET.ToString()                    
                };

                //Call to the Controller of API_SDK   
                var apiController = new APIController(merchantConfig);
                var response = apiController.GetPayment();

                //printing the response details
                if (response != null)
                {
                    Console.WriteLine("\n v-c-correlation-id:{0}", response.GetResponseHeaderValue(response.Headers, "v-c-correlation-id"));
                    Console.WriteLine("\n Response Code:{0}", response.StatusCode);
                    Console.WriteLine("\n Response Message:{0}", response.Data);
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