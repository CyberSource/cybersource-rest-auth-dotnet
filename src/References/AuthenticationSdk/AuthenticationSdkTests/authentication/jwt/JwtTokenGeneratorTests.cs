using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using NUnit.Framework;

namespace AuthenticationSdkTests.authentication.jwt
{
    [TestFixture]
    public class JwtTokenGeneratorTests
    {
        [Test]
        public void GetTokenTest_RequestTypeGet()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "GET"
            };

            var token = new JwtTokenGenerator(merchConfigObj).GetToken();

            Assert.IsInstanceOf(typeof(Token), token);
        }

        [Test]
        public void GetTokenTest_VerifyBearerTokenNotEmpty()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "GET"
            };

            var token = (JwtToken)new JwtTokenGenerator(merchConfigObj).GetToken();

            Assert.IsNotEmpty(token.BearerToken);
        }
    }
}
