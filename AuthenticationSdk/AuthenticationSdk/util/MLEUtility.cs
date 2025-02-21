using AuthenticationSdk.core;   

namespace AuthenticationSdk.util
{
    public static class MLEUtility
    {
        public static bool checkIsMLEForAPI(MerchantConfig merchantConfig, bool isMLESupportedByCybsForApi, string operationIds)
        {
            bool isMLEForAPI = false;

            // Check here useMLEGlobally True or False
            // if API is part of MLE then check for useMLEGlobally global parameter
            if (isMLESupportedByCybsForApi && merchantConfig.UseMLEGlobally)
            {
                isMLEForAPI = true;
            }

            // OperationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the MLE only from map
            if (merchantConfig.MapToControlMLEonAPI != null && merchantConfig.MapToControlMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantConfig.MapToControlMLEonAPI.ContainsKey(operationId))
                    {
                        isMLEForAPI = merchantConfig.MapToControlMLEonAPI[operationId];
                        break;
                    }
                }
            }

            return isMLEForAPI;
        }

        public static object encryptRequestPayload(MerchantConfig merchantConfig, object requestBody)
        {
            return requestBody;
        }
    }
}
