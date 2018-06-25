using System;
using ApiSdk.com.cybersource.api.controller;
using ApiSdk.com.cybersource.api.util;
using AuthenticationSdk.com.cybersource.authentication.util;
using NLog;
using samplecode.data;

namespace samplecode.samplecode.CallHTTPMethods
{
    public class GET_Method
    {
        private static Response _response;                               
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly APIController APIController = new APIController();
        private static string _getID = "5289697403596987704107";
        private const string RequestType = "GET";
        //Request Target of the CYBS REST API that needs to be hit
        //private const string RequestTarget = "/reporting/v2/reportSubscriptions/TRRReport?organizationId=testrest";
        //private const string RequestTarget = "/pts/v2/payments";
        private const string RequestTarget = "/pts/v2/captures";

        public static void Main(string[] args)
        {            
            try
            {
                var merchantConfig = new MerchantConfig();
                LogUtility.InitLogConfig(merchantConfig);
                Enumerations.ValidateAuthenticationType(merchantConfig, Logger);

                //Setting up Merchant Config
                merchantConfig.RequestTarget = RequestTarget;
                merchantConfig.RequestType = RequestType;

                //Taking Get ID from the user
                Console.WriteLine("\n Please provide the Get ID: (Press enter to use the default GET ID)");                
                var tempGetID = Console.ReadLine();
                if (tempGetID != string.Empty) _getID = tempGetID;               
                merchantConfig.GetID = _getID;              

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