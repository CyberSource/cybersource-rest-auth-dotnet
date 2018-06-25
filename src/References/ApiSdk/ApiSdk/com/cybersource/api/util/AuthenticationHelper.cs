using AuthenticationSdk.com.cybersource.authentication.authentication.http;
using AuthenticationSdk.com.cybersource.authentication.authentication.jwt;
using AuthenticationSdk.com.cybersource.authentication.core;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace ApiSdk.com.cybersource.api.util
{
    public class AuthenticationHelper
    {
        private static readonly Authorize AuthorizeObj = new Authorize();

        public static HttpToken GetSignature(MerchantConfig merchantConfig)
        {
            return AuthorizeObj.GetSignature(merchantConfig);
        }

        public static JwtToken GetToken(MerchantConfig merchantConfig)
        {
            return AuthorizeObj.GetToken(merchantConfig);
        }
    }
}
