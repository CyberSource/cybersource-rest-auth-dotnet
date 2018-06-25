using System.Collections.Generic;

namespace samplecode.data
{
    public static class Configuration
    {
        //initialize dictionary object

        private static readonly Dictionary<string, string> ConfigurationDictionary = new Dictionary<string, string>();

        //set the values of dictionary keys

        private const string MerchantId = "testrest";

        private const string MerchantSecretKey = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

        private const string MerchantKeyId = "08c94330-f618-42a3-b09d-e1e43be5efda";

        private const string AuthenticationType = "jwt";

        private const string KeysDirectory = "..\\..\\Resource";

        private const string KeyfileName = "testrest";

        private const string RunEnvironment = "cybersource.environment.sandbox";

        private const string KeyAlias = "testrest";

        private const string KeyPassword = "testrest";

        private const string EnableLog = "TRUE";

        private const string LogDirectory = "C:/CYBS/Infy Solution/PR3334_Ver3_Combined/CyberSource_Authentication_SDK_dotNet/src/logs/";        

        private const string LogfileMaxSize = "5242880"; //In Bytes

        private const string TimeOut = "1000";   //In millisec

        private const string ProxyAddress = "";  //userproxy.visa.com

        private const string ProxyPort = "";    //443

        public static Dictionary<string, string> GetConfiguration()
        {
            ConfigurationDictionary.Add("merchantID", MerchantId);
            ConfigurationDictionary.Add("merchantsecretKey", MerchantSecretKey);
            ConfigurationDictionary.Add("merchantKeyId", MerchantKeyId);
            ConfigurationDictionary.Add("authenticationType", AuthenticationType);
            ConfigurationDictionary.Add("keysDirectory", KeysDirectory);
            ConfigurationDictionary.Add("keyFilename", KeyfileName);
            ConfigurationDictionary.Add("runEnvironment", RunEnvironment);
            ConfigurationDictionary.Add("keyAlias", KeyAlias);
            ConfigurationDictionary.Add("keyPassword", KeyPassword);            
            ConfigurationDictionary.Add("enableLog", EnableLog);
            ConfigurationDictionary.Add("logDirectory", LogDirectory);
            ConfigurationDictionary.Add("logFileMaxSize", LogfileMaxSize);
            ConfigurationDictionary.Add("timeout", TimeOut);
            ConfigurationDictionary.Add("proxyAddress", ProxyAddress);
            ConfigurationDictionary.Add("proxyPort", ProxyPort);

            return ConfigurationDictionary;
        }                              
    }
}
