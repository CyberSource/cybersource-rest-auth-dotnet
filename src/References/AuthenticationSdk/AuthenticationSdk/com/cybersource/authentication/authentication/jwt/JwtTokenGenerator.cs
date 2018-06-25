using AuthenticationSdk.com.cybersource.authentication.core;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace AuthenticationSdk.com.cybersource.authentication.authentication.jwt
{
    public class JwtTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;

        public JwtTokenGenerator(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
        }

        public Token GetToken()
        {
            return new JwtToken(_merchantConfig);
        }
    }
}
