using System;
using AuthenticationSdk.com.cybersource.authentication.util;
using NLog;

namespace ApiSdk.com.cybersource.api.util
{
    public class Enumerations
    {
        public enum AuthenticationType
        {
            HTTP_SIGNATURE,
            JWT
        }

        public static bool ValidateAuthenticationType(MerchantConfig merchantConfig, Logger logger)
        {
            //Validating the Authentication type by comparing with the values in Enum
            if (Enum.IsDefined(typeof (AuthenticationType), merchantConfig.AuthenticationType.ToUpper()))
                return true;
                       
            throw new Exception($"{GlobalLabelParametersAPI.ErrorPrefix}Invalid Auth type {merchantConfig.AuthenticationType} provided in config file");            
        }
    }
}
