using System.Collections.Specialized;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using AuthenticationSdk.util;
using NUnit.Framework;

namespace AuthenticationSdkTests.util
{
    [TestFixture]
    public class CacheTests
    {
        [Test]
        public void FetchCachedCertificateTest()
        {
            var merchantConfigSection = (NameValueCollection)ConfigurationManager.GetSection("MerchantConfig");
            var keyPass = merchantConfigSection["keyPass"];
            var certificate = Cache.FetchCachedCertificate(Constants.ResourceFolderPath, keyPass);

            Assert.IsInstanceOf(typeof(X509Certificate2), certificate);
        }
    }
}
