using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using NUnit.Framework;

namespace AuthenticationSdkTests.authentication.jwt
{
    [TestFixture]
    public class JwtTokenTests
    {
        [Test]
        public void JwtTokenTest_Get()
        {
            var merchantConfig = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "GET"
            };

            var jwtToken = new JwtToken(merchantConfig);

            Assert.IsInstanceOf(typeof(JwtToken), jwtToken);
        }
    }
}
