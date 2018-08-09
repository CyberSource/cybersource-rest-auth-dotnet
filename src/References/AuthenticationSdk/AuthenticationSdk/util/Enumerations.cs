using System;

namespace AuthenticationSdk.util
{
    public class Enumerations
    {        
        public enum AuthenticationType
        {
            HTTP_SIGNATURE,
            JWT
        }

        public enum RequestType
        {
            GET,
            POST,
            PUT,
            DELETE              
        }
      
        public static bool ValidateAuthenticationType(string authType)
        {
            //Validating the Authentication type by comparing with the values in Enum
            if (string.IsNullOrEmpty(authType))
                throw new Exception(
                    $"{ConstantsAuth.ErrorPrefix} No Authentication type provided in config file");
            if (Enum.IsDefined(typeof(AuthenticationType), authType.ToUpper()))
                return true;
                
            throw new Exception(
                $"{ConstantsAuth.ErrorPrefix}Invalid Auth type {authType} provided in config file");
        }

        public static bool ValidateRequestType(string requestType)
        {
            if (requestType == null)
            {
                throw new Exception(
                    $"{ConstantsAuth.ErrorPrefix} RequestType has not been set. Set it to any one of the Valid Values: GET/POST/PUT/DELETE");
            }

            if (requestType.Trim() == string.Empty)
            {
                throw new Exception(
                    $"{ConstantsAuth.ErrorPrefix} RequestType has been set as blank. Set it to any one of the Valid Values: GET/POST/PUT/DELETE");
            }

            if (!Enum.IsDefined(typeof (RequestType), requestType.ToUpper()))
            {
                throw new Exception(
                    $"{ConstantsAuth.ErrorPrefix} Invalid Request Type:{requestType} . Valid Values: GET/POST/PUT/DELETE");
            }

            return true;
        }

        public static void SetRequestType(MerchantConfig merchantConfig)
        {
            if (string.Equals(merchantConfig.RequestType, RequestType.GET.ToString(),
                StringComparison.OrdinalIgnoreCase))
                merchantConfig.IsGetRequest = true;
            else if (string.Equals(merchantConfig.RequestType, RequestType.POST.ToString(),
                StringComparison.OrdinalIgnoreCase))
                merchantConfig.IsPostRequest = true;
            else if (string.Equals(merchantConfig.RequestType, RequestType.PUT.ToString(),
                StringComparison.OrdinalIgnoreCase))
                merchantConfig.IsPutRequest = true;
            else if (string.Equals(merchantConfig.RequestType, RequestType.DELETE.ToString(),
                StringComparison.OrdinalIgnoreCase))
                merchantConfig.IsDeleteRequest = true;
        }
    }
}
