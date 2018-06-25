using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using NLog;

namespace AuthenticationSdk.com.cybersource.authentication.util
{
    public class MerchantConfig
    {
        public string MerchantId { get; set; } 
        public string MerchantSecretKey { get; set; }
        public string MerchantKeyId { get; set; }
        public string AuthenticationType { get; set; }
        public string KeysDirectory { get; set; }
        public string KeyfileName { get; set; }
        public string RunEnvironment { get; set; }
        public string KeyAlias { get; set; }
        public string KeyPassword { get; set; }        
        public string EnableLog { get; set; }
        public string LogDirectory { get; set; }
        public string LogfileMaxSize { get; set; }
        public string TimeOut { get; set; }
        public string ProxyAddress { get; set; }
        public string ProxyPort { get; set; }        
        public Logger Logger { get; set; }
        public string HostName { get; set; }      
        public string P12Keyfilepath { get; set; }
        public string RequestTarget { get; set; }
        public string HttpSignGetRequestTarget { get; set; }
        public string HttpSignPostOrPutRequestTarget { get; set; }        
        public string GetID { get; set; }
        public string PutID { get; set; }    
        public string RequestJsonData { get; set; }   
        public string RequestType { get; set; } 

        public MerchantConfig(IReadOnlyDictionary<string, string> merchantConfigDictionary = null)
        {            
            Logger = LogManager.GetCurrentClassLogger();

            //MerchantConfig section inside App.Config File
            var merchantConfigSection = (NameValueCollection)ConfigurationManager.GetSection("MerchantConfig");
            
            //Set the properties of Merchant Config
            //If a dictionary object has been passed use that object
            //If no dictionary object is passed, that means use app.config
            //Howevere if App.Config does not contain Merchan Config, throw an exception
            if (merchantConfigDictionary != null)
                SetValuesUsingDictObj(merchantConfigDictionary);
            else
            {
                if(merchantConfigSection != null)
                    SetValuesFromAppConfig(merchantConfigSection);
                else
                    throw new Exception($"{GlobalLabelParameters.ErrorPrefix} Merchant Config Missing in App.Config File!");
            }

            //Fallback Logic
            DefaultPropValues();
        }

        public void SetValuesFromAppConfig(NameValueCollection merchantConfigSection)
        {                        
            Console.WriteLine($"\n Reading Merchant Config from App.Config File");
            Logger.Trace($"Reading Merchant Config from App.Config File");

            MerchantId = merchantConfigSection["merchantID"];

            MerchantSecretKey = merchantConfigSection["merchantsecretKey"];

            MerchantKeyId = merchantConfigSection["merchantKeyId"];

            AuthenticationType = merchantConfigSection["authenticationType"];

            KeysDirectory = merchantConfigSection["keysDirectory"];

            KeyfileName = merchantConfigSection["keyFilename"];

            RunEnvironment = merchantConfigSection["runEnvironment"];

            KeyAlias = merchantConfigSection["keyAlias"];

            KeyPassword = merchantConfigSection["keyPassword"];                    

            EnableLog = merchantConfigSection["enableLog"];

            LogDirectory = merchantConfigSection["logDirectory"];

            LogfileMaxSize = merchantConfigSection["logFileMaxSize"];

            TimeOut = merchantConfigSection["timeout"];

            ProxyAddress = merchantConfigSection["proxyAddress"];

            ProxyPort = merchantConfigSection["proxyPort"];            
        }

        private void SetValuesUsingDictObj(IReadOnlyDictionary<string, string> merchantConfigDictionary)
        {
            try
            {
                if (merchantConfigDictionary != null)
                {
                    Console.WriteLine($"\n Reading Merchant Config from Dictionary Object");
                    Logger.Trace($"Reading Merchant Config from Dictionary Object");

                    MerchantId = merchantConfigDictionary["merchantID"];

                    MerchantSecretKey = merchantConfigDictionary["merchantsecretKey"];

                    MerchantKeyId = merchantConfigDictionary["merchantKeyId"];

                    AuthenticationType = merchantConfigDictionary["authenticationType"];

                    KeysDirectory = merchantConfigDictionary["keysDirectory"];

                    KeyfileName = merchantConfigDictionary["keyFilename"];

                    RunEnvironment = merchantConfigDictionary["runEnvironment"];

                    KeyAlias = merchantConfigDictionary["keyAlias"];

                    KeyPassword = merchantConfigDictionary["keyPassword"];

                    EnableLog = merchantConfigDictionary["enableLog"];

                    LogDirectory = merchantConfigDictionary["logDirectory"];

                    LogfileMaxSize = merchantConfigDictionary["logFileMaxSize"];

                    TimeOut = merchantConfigDictionary["timeout"];

                    ProxyAddress = merchantConfigDictionary["proxyAddress"];

                    ProxyPort = merchantConfigDictionary["proxyPort"];
                }
            }
            catch (KeyNotFoundException)
            {
                throw new Exception(
                    $"{GlobalLabelParameters.ErrorPrefix} A Required Key Missing in the Configuration Dictionary Object Passed to the instance of MerchantConfig Object");
            }       
        }

        private void DefaultPropValues()
        {
            //verify mandatory properties
            if (string.IsNullOrEmpty(MerchantId))
                throw new Exception( $"{GlobalLabelParameters.ErrorPrefix} Merchant Config field - MerchantID is Mandatory");
            if (string.IsNullOrEmpty(AuthenticationType))
                throw new Exception( $"{GlobalLabelParameters.ErrorPrefix} Merchant Config field - AuthenticationType is Mandatory");

            //fallback for missing values            
            if (string.IsNullOrEmpty(EnableLog))
                EnableLog = "TRUE";

            if (string.IsNullOrEmpty(LogfileMaxSize))
                LogfileMaxSize = "10485760";    //10 MB = 10485760 bytes

            if (string.IsNullOrEmpty(TimeOut))
                TimeOut = "";   //In Milllisec

            if (string.IsNullOrEmpty(LogDirectory))
                LogDirectory = "../../logs";                        

            //setting up hostname based on the tun rnvironment value
            if (RunEnvironment.ToUpper().Equals(GlobalLabelParameters.CybsSandboxRunEnv.ToUpper()))
                HostName = GlobalLabelParameters.CybsSandboxHostName;
            else if (RunEnvironment.ToUpper().Equals(GlobalLabelParameters.CybsProdRunEnv.ToUpper()))
                HostName = GlobalLabelParameters.CybsProdHostName;
            else if (string.IsNullOrEmpty(RunEnvironment))
            {
                HostName = GlobalLabelParameters.CybsSandboxHostName;
                Console.WriteLine($"\n {GlobalLabelParameters.WarningPrefix} RunEnvironment not provided. Using Default Value: CYBERSOURCE.ENVIRONMENT.SANDBOX");
                Logger.Warn($"{GlobalLabelParameters.WarningPrefix} RunEnvironment not provided. Using Default Value: CYBERSOURCE.ENVIRONMENT.SANDBOX");
            }
            else
                HostName = RunEnvironment.ToLower();

            //authentication mechanism specific checks
            if (string.Equals(AuthenticationType, GlobalLabelParameters.AuthMechanismHttp, StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(MerchantKeyId))
                    throw new Exception( $"{GlobalLabelParameters.ErrorPrefix} Merchant Config field - MerchantKeyId is Mandatory");

                if (string.IsNullOrEmpty(MerchantSecretKey))
                    throw new Exception( $"{GlobalLabelParameters.ErrorPrefix} Merchant Config field - MerchantSecretKey is Mandatory");
            }
            else if (string.Equals(AuthenticationType, GlobalLabelParameters.AuthMechanismJwt, StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(KeyAlias))
                {
                    KeyAlias = MerchantId;
                    Console.WriteLine($"\n {GlobalLabelParameters.WarningPrefix} KeyAlias not provided. Assigning the value of [MerchantID]");
                    Logger.Warn($"{GlobalLabelParameters.WarningPrefix} KeyAlias not provided. Assigning the value of: [MerchantID]");
                }

                if (string.IsNullOrEmpty(KeyPassword))
                {
                    KeyPassword = MerchantId;
                    Console.WriteLine($"\n {GlobalLabelParameters.WarningPrefix} KeyPassword not provided. Assigning the value of: [MerchantID]");
                    Logger.Warn($"{GlobalLabelParameters.WarningPrefix} KeyPassword not provided. Assigning the value of: [MerchantID]");
                }

                if (string.IsNullOrEmpty(KeysDirectory))
                {
                    KeysDirectory = "..\\..\\Resource";
                    Console.WriteLine($"\n {GlobalLabelParameters.WarningPrefix} KeysDirectory not provided. Using Default Path: [..\\..\\Resource]");
                    Logger.Warn($"{GlobalLabelParameters.WarningPrefix} KeysDirectory not provided. Using Default Path: [..\\..\\Resource]");
                }

                if (string.IsNullOrEmpty(KeyfileName))
                {
                    KeyfileName = MerchantId;
                    Console.WriteLine($"\n {GlobalLabelParameters.WarningPrefix} KeyfileName not provided. Assigning the value of: [MerchantId]");
                    Logger.Warn($"{GlobalLabelParameters.WarningPrefix} KeyfileName not provided. Assigning the value of: [MerchantId]");
                }

                //property using other properties
                P12Keyfilepath = KeysDirectory + "\\" + KeyfileName + ".p12";
            }
        }

        public static string LogAllproperties(MerchantConfig obj)
        {
            var hiddenProperties = GlobalLabelParameters.HideMerchantConfigProps.Split(',');
            var merchCfgLogString = " ";
            var merchantConfigProperties = typeof(MerchantConfig).GetProperties();
            foreach (var property in merchantConfigProperties)
            {
                //If HiddenProperties Array does not contain any value of the current property being iterated
                //It simply means if the current property is not a hidden property, only then log it
                if (!hiddenProperties.Any(property.Name.Contains))
                {
                    merchCfgLogString += property.Name;
                    merchCfgLogString += " ";
                    merchCfgLogString += property.GetValue(obj);
                    merchCfgLogString += ", ";
                }                
            }
            return(merchCfgLogString);
        }              
    }
}