using System;
using ApiSdk.com.cybersource.api.util;
using AuthenticationSdk.com.cybersource.authentication.core;
using AuthenticationSdk.com.cybersource.authentication.util;
using NLog;
using samplecode.data;

namespace samplecode.samplecode.GenerateHTTPRequestHeaders
{
    public class PUT_Generate_Headers
    {      
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly RequestData RequestData = new RequestData();
        private const string RequestType = "PUT";
        private const string RequestTarget = "/pts/v2/payments"; //Request Target of the CYBS REST API that needs to be hit
        private const string RequestJsonFilePath = "..\\..\\Resource\\TRRReport.json";
        private static readonly Authorize AuthorizeObj = new Authorize();

        public static void Main(string[] args)
        {            
            try
            {
                var merchantConfig = new MerchantConfig();
                LogUtility.InitLogConfig(merchantConfig);

                Logger.Trace("\n");
                Logger.Trace("START> =======================================");

                Enumerations.ValidateAuthenticationType(merchantConfig, Logger);

                //Setting up Merchant Config
                merchantConfig.RequestTarget = RequestTarget;
                merchantConfig.RequestType = RequestType;
                Logger.Trace("Using Request Target:'{0}'", RequestTarget);
                Console.WriteLine("\n Using Request Target:'{0}'", RequestTarget);

                //logging Authentication type                                              
                Logger.Trace("Authentication Type -> {0}", merchantConfig.AuthenticationType);
                Console.WriteLine("\n Authentication Type -> {0}", merchantConfig.AuthenticationType);

                //Logging all the Properties of MerchantConfig and their respective Values                                 
                Logger.Trace("MERCHCFG > {0}", (MerchantConfig.LogAllproperties(merchantConfig)));
                Console.WriteLine("\n MERCHCFG > {0}", (MerchantConfig.LogAllproperties(merchantConfig)));
                Console.WriteLine("\n");

                //Set RequestJson Data
                merchantConfig.RequestJsonData = RequestData.JsonFileData(RequestJsonFilePath);

                //Call to the Authorize class of AuthSDK to get the signature and token objects
                if (merchantConfig.AuthenticationType.ToUpper() == "HTTP_SIGNATURE")
                {
                    var requestHeaders = AuthorizeObj.GetSignature(merchantConfig);

                    Console.WriteLine("{0} {1}", "Content-Type:", "application/json");
                    Console.WriteLine("{0} {1}", "v-c-merchant-id:", requestHeaders.MerchantId);
                    Console.WriteLine("{0} {1}", "Date:", requestHeaders.GmtDateTime);
                    Console.WriteLine("{0} {1}", "Host:", requestHeaders.HostName);
                    Console.WriteLine("{0} {1}", "digest:", requestHeaders.Digest);
                    Console.WriteLine("{0} {1}", "signature:", requestHeaders.SignatureParam);
                }
                else if (merchantConfig.AuthenticationType.ToUpper() == "JWT")
                {
                    var requestHeaders = AuthorizeObj.GetToken(merchantConfig);

                    Console.WriteLine("{0} {1}", "Content-Type:", "application/json");
                    Console.WriteLine("{0} {1}", "Authorization:", requestHeaders.BearerToken);
                }
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
            Logger.Trace("END> =======================================");
            Console.ReadLine();
        }       
    }
}