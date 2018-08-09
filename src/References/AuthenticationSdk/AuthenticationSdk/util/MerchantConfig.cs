using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using NLog;
using static AuthenticationSdk.util.Enumerations;

namespace AuthenticationSdk.util
{
    public class MerchantConfig
    {
        public string MerchantId { get; set; }
        public string MerchantSecretKey { get; set; }
        public string MerchantKeyId { get; set; }
        public string AuthenticationType { get; set; }
        public string KeyDirectory { get; set; }
        public string KeyfileName { get; set; }
        public string RunEnvironment { get; set; }
        public string KeyAlias { get; set; }
        public string KeyPass { get; set; }
        public string EnableLog { get; set; }
        public string LogDirectory { get; set; }
        public string LogfileMaxSize { get; set; }
        public string LogFileName { get; set; }
        public string TimeOut { get; set; }
        public string ProxyAddress { get; set; }
        public string ProxyPort { get; set; }
        public Logger Logger { get; set; }
        public string HostName { get; set; }
        public string P12Keyfilepath { get; set; }
        public string RequestTarget { get; set; }
        public string HttpSignRequestTarget { get; set; }        
        public string RequestJsonData { get; set; }
        public string RequestType { get; set; }
        public bool IsGetRequest { get; set; }
        public bool IsPostRequest { get; set; }
        public bool IsPutRequest { get; set; }
        public bool IsDeleteRequest { get; set; }         
        public bool IsHttpSignAuthType { get; set; }
        public bool IsJwtTokenAuthType { get; set; }

        private string _propertiesSetUsing = "";

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
                if (merchantConfigSection != null)
                    SetValuesFromAppConfig(merchantConfigSection);
                else
                    throw new Exception($"{ConstantsAuth.ErrorPrefix} Merchant Config Missing in App.Config File!");
            }

            //Log initialization, Fallback logic, Validations... and so much more....
            ValidateProperties();
        }

        public void SetValuesFromAppConfig(NameValueCollection merchantConfigSection)
        {
            _propertiesSetUsing = "App.Config File";

            MerchantId = merchantConfigSection["merchantID"];
            MerchantSecretKey = merchantConfigSection["merchantsecretKey"];
            MerchantKeyId = merchantConfigSection["merchantKeyId"];
            AuthenticationType = merchantConfigSection["authenticationType"];
            KeyDirectory = merchantConfigSection["keysDirectory"];
            KeyfileName = merchantConfigSection["keyFilename"];
            RunEnvironment = merchantConfigSection["runEnvironment"];
            KeyAlias = merchantConfigSection["keyAlias"];
            KeyPass = merchantConfigSection["keyPass"];
            EnableLog = merchantConfigSection["enableLog"];
            LogDirectory = merchantConfigSection["logDirectory"];
            LogfileMaxSize = merchantConfigSection["logFileMaxSize"];
            LogFileName = merchantConfigSection["logFileName"];
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
                    _propertiesSetUsing = "Dictionary Object";

                    MerchantId = merchantConfigDictionary["merchantID"];
                    MerchantSecretKey = merchantConfigDictionary["merchantsecretKey"];
                    MerchantKeyId = merchantConfigDictionary["merchantKeyId"];
                    AuthenticationType = merchantConfigDictionary["authenticationType"];                                        
                    KeyDirectory = merchantConfigDictionary["keysDirectory"];
                    KeyfileName = merchantConfigDictionary["keyFilename"];
                    RunEnvironment = merchantConfigDictionary["runEnvironment"];
                    KeyAlias = merchantConfigDictionary["keyAlias"];
                    KeyPass = merchantConfigDictionary["keyPass"];
                    EnableLog = merchantConfigDictionary["enableLog"];
                    LogDirectory = merchantConfigDictionary["logDirectory"];
                    LogfileMaxSize = merchantConfigDictionary["logFileMaxSize"];
                    LogFileName = merchantConfigDictionary["logFileName"];
                    TimeOut = merchantConfigDictionary["timeout"];
                    ProxyAddress = merchantConfigDictionary["proxyAddress"];
                    ProxyPort = merchantConfigDictionary["proxyPort"];
                }
            }
            catch (KeyNotFoundException)
            {
                throw new Exception(
                    $"{ConstantsAuth.ErrorPrefix} A Required Key Missing in the Configuration Dictionary Object Passed to the instance of MerchantConfig Object");
            }
        }

        private void ValidateProperties()
        {
            //Setting up the Log Properties first and Initializing the logger object,
            //before moving to other Validations.
            //Because Initialization of logger object is dependent on these properties' values
            if (string.IsNullOrEmpty(EnableLog))
                EnableLog = "TRUE";

            if (!string.Equals(EnableLog, "true", StringComparison.OrdinalIgnoreCase))
                EnableLog = "FALSE";

            if (string.IsNullOrEmpty(LogDirectory))
                LogDirectory = "../../logs";

            if (string.IsNullOrEmpty(LogFileName))
                LogFileName = "cybs.log";

            if (string.IsNullOrEmpty(LogfileMaxSize))
                LogfileMaxSize = "10485760";    //10 MB = 10485760 bytes

            LogUtility.InitLogConfig(EnableLog, LogDirectory, LogFileName, LogfileMaxSize);

            //Logger object is ready to Log
            Logger.Trace("\n");
            Logger.Trace("START> =======================================");

            //Logging the source of properties' values
            Logger.Trace("Reading Merchant Configuration from " + _propertiesSetUsing);

            //VALIDATIONS COMMON FOR BOTH AUTH MECH.
            if (string.IsNullOrEmpty(MerchantId))
                throw new Exception($"{ConstantsAuth.ErrorPrefix} Merchant Config field - MerchantID is Mandatory");

            //Validating and setting up Authentication type
            ValidateAuthenticationType(AuthenticationType);

            if (string.Equals(AuthenticationType, Enumerations.AuthenticationType.HTTP_SIGNATURE.ToString(),
                StringComparison.OrdinalIgnoreCase))
                IsHttpSignAuthType = true;
            
            else if (string.Equals(AuthenticationType, Enumerations.AuthenticationType.JWT.ToString(),
                StringComparison.OrdinalIgnoreCase))
                IsJwtTokenAuthType = true;
            
            
            if (string.IsNullOrEmpty(TimeOut))
            TimeOut = "";   //In Milllisec                                    

            //setting up hostname based on the run environment value
            if (string.IsNullOrEmpty(RunEnvironment))
                throw new Exception($"{ConstantsAuth.ErrorPrefix} Merchant Config field - RunEnvironment is Mandatory");

            if (RunEnvironment.ToUpper().Equals(ConstantsAuth.CybsSandboxRunEnv.ToUpper()))
                HostName = ConstantsAuth.CybsSandboxHostName;
            else if (RunEnvironment.ToUpper().Equals(ConstantsAuth.CybsProdRunEnv.ToUpper()))
                HostName = ConstantsAuth.CybsProdHostName;            
            else
                HostName = RunEnvironment.ToLower();

            //AUTHENTICATION MECHANISM SPECIFIC CHECKS
            //1. FOR HTTP SIGNATURE            
            if (IsHttpSignAuthType)
            {
                if (string.IsNullOrEmpty(MerchantKeyId))
                    throw new Exception($"{ConstantsAuth.ErrorPrefix} Merchant Config field - MerchantKeyId is Mandatory");

                if (string.IsNullOrEmpty(MerchantSecretKey))
                    throw new Exception($"{ConstantsAuth.ErrorPrefix} Merchant Config field - MerchantSecretKey is Mandatory");
            }
            //2. FOR JWT TOKEN
            //sharath
            else if (IsJwtTokenAuthType)
            {
                if (string.IsNullOrEmpty(KeyAlias))
                {
                    KeyAlias = MerchantId;
                    Logger.Warn($"{ConstantsAuth.WarningPrefix} KeyAlias not provided. Assigning the value of: [MerchantID]");
                }

                if (!string.Equals( KeyAlias, MerchantId))
                {
                    KeyAlias = MerchantId;
                    Logger.Warn($"{ConstantsAuth.WarningPrefix} Incorrect value of KeyAlias provided. Assigning the value of: [MerchantID]");
                }

                if (string.IsNullOrEmpty(KeyPass))
                {
                    KeyPass = MerchantId;
                    Logger.Warn($"{ConstantsAuth.WarningPrefix} KeyPassword not provided. Assigning the value of: [MerchantID]");
                }

                if (string.IsNullOrEmpty(KeyDirectory))
                {
                    KeyDirectory = ConstantsAuth.P12FileDirectory;
                    Logger.Warn($"{ConstantsAuth.WarningPrefix} KeysDirectory not provided. Using Default Path: {KeyDirectory}");
                }

                if (string.IsNullOrEmpty(KeyfileName))
                {
                    KeyfileName = MerchantId;
                    Logger.Warn($"{ConstantsAuth.WarningPrefix} KeyfileName not provided. Assigning the value of: [MerchantId]");
                }

                P12Keyfilepath = KeyDirectory + "\\" + KeyfileName + ".p12";
            }
        }

        public static string LogAllproperties(MerchantConfig obj)
        {
            var hiddenProperties = ConstantsAuth.HideMerchantConfigProps.Split(',');
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
            return (merchCfgLogString);
        }
    }
}