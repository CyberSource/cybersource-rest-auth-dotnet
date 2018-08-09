using System;
using ApiSdk.controller;
using AuthenticationSdk.util;
using CyberSource_Authentication_SDK_dotNet.data;

namespace CyberSource_Authentication_SDK_dotNet.samplecode.CallHTTPMethods
{
    public class PostObjectMethod
    {        
        //Request Target of the CYBS REST API that needs to be hit
        private const string RequestTarget = "/pts/v2/payments/";

        public static void Main(string[] args)
        {
            try
            {
                //Setting up Merchant Config 
                var config = new Configuration();
                var requestData = new RequestData();

                var merchantConfig = new MerchantConfig(config.GetConfiguration())
                {
                    RequestTarget = RequestTarget,
                    RequestType = Enumerations.RequestType.POST.ToString(),
                    RequestJsonData = requestData.SamplePaymentsData() //Set RequestJson Data using the sample payments data
                };

                //Call to the Controller of API_SDK   
                var apiController = new APIController(merchantConfig);
                var response = apiController.PostPayment();

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