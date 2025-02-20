using AuthenticationSdk.core;   

namespace AuthenticationSdk.util
{
    public static class MLEUtility
    {
        public static bool checkIsMLEForAPI(MerchantConfig merchantConfig, bool isMLESupportedByCybsForApi, string operationIds)
        {
            //isMLE for an api is false by default
            bool isMLEForAPI = false;

            return isMLEForAPI;

        }

        public static object encryptRequestPayload(MerchantConfig merchantConfig, object requestBody)
        {
            return requestBody;
        }
    }
}
