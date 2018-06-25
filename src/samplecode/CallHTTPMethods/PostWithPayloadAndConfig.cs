using System;
using ApiSdk.com.cybersource.api.controller;
using ApiSdk.com.cybersource.api.util;
using AuthenticationSdk.com.cybersource.authentication.util;
using NLog;
using samplecode.data;

namespace samplecode.samplecode.CallHTTPMethods
{
    public class PostWithPayloadAndConfig
    {
        private static Response _response;
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly APIController APIController = new APIController();
        private static readonly RequestData RequestData = new RequestData();
        private const string RequestType = "POST";
        //Request Target of the CYBS REST API that needs to be hit
        private const string RequestTarget = "/pts/v2/payments/";         
        
        public static void Main(string[] args)
        {
            try
            {
                var merchantConfig = new MerchantConfig(Configuration.GetConfiguration());
                LogUtility.InitLogConfig(merchantConfig);
                Enumerations.ValidateAuthenticationType(merchantConfig, Logger);

                //Setting up Merchant Config                
                merchantConfig.RequestTarget = RequestTarget;
                merchantConfig.RequestType = RequestType;

                //Set RequestJson Data
                merchantConfig.RequestJsonData = RequestData.SamplePaymentsData();

                //Call to the Controller of API_SDK                
                _response = APIController.Payments(merchantConfig);

                //printing the response details
                Console.WriteLine("\n v-c-correlation-id:{0}", _response.GetResponseHeaderValue(_response.Headers, "v-c-correlation-id"));
                Console.WriteLine("\n Response Code:{0}", _response.StatusCode);
                Console.WriteLine("\n Response Message:{0}", _response.Data);
            }
            catch (Exception e)
            {
                Console.WriteLine("\n Error: Check Log file for more details.");
                if (e.Message != null)
                {
                    Logger.Error(e.Message);

                    if (!(e.Message.Contains("Error:") || e.Message.Contains("Warning:")) && e.StackTrace != null)
                        Logger.Trace(e.StackTrace);
                }

                if (e.InnerException?.Message != null)
                    Logger.Error(e.InnerException.Message);
            }

            Console.WriteLine("\n Press any key to exit the Application...");
            Console.ReadLine();
        }
    }
}
