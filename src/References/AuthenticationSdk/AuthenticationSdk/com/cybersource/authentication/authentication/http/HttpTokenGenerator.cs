using AuthenticationSdk.com.cybersource.authentication.core;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace AuthenticationSdk.com.cybersource.authentication.authentication.http
{
    public class HttpTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;

        public HttpTokenGenerator(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
        }

        public Token GetToken()
        {
            return new HttpToken(_merchantConfig);
        }
    }
}
