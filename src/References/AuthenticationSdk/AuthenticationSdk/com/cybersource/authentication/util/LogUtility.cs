using NLog;
using NLog.Targets;

namespace AuthenticationSdk.com.cybersource.authentication.util
{
    public static class LogUtility
    {
        public static void InitLogConfig(MerchantConfig objMerchantConfig)
        {
            //If user does not want logging the EnableLog property can be set to FALSE
            if(objMerchantConfig.EnableLog.ToUpper()=="FALSE")
                LogManager.DisableLogging();

            var target = LogManager.Configuration.FindTargetByName("file") as FileTarget;
            
            if (target != null)
            {                
                //using the log path set by the merchant, if not set, using default value set in NLog.config
                if (objMerchantConfig.LogDirectory != null)
                    target.FileName = objMerchantConfig.LogDirectory + "/cybs.log";                               

                //set the maximum allowed size of the log file
                if (objMerchantConfig.LogfileMaxSize != null)                
                    target.ArchiveAboveSize = long.Parse(objMerchantConfig.LogfileMaxSize);                
            }
        }
    }
}
