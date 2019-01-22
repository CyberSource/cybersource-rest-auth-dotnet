using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using NUnit.Framework;
using System;

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
        [Ignore("Ignoring this test for Travis CI as private key extraction failing in Linux OS")]
        public void GetTokenTest_VerifyBearerTokenNotEmpty()
        {
            Console.WriteLine("Starting Test: Verify whether the Bearer token is empty or not");

            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "GET",
                IsGetRequest = true // need to set it because we are not calling Authorize class which handles setting up the value of this property
            };

            Console.WriteLine("Merchant Config object created");

            var token = (JwtToken)new JwtTokenGenerator(merchConfigObj).GetToken();

            Assert.IsNotEmpty(token.BearerToken);
        }
    }
}
