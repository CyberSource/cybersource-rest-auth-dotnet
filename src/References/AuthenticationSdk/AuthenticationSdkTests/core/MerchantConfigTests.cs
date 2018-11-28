using AuthenticationSdk.core;
using NUnit.Framework;

namespace AuthenticationSdkTests.core
{
    [TestFixture]
    public class MerchantConfigTests
    {
        [Test]
        public void MerchantConfigTest_JwtGet()
        {
            var merchantConfig = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "GET"
            };

            Assert.IsInstanceOf(typeof(MerchantConfig), merchantConfig);
        }
    }
}
