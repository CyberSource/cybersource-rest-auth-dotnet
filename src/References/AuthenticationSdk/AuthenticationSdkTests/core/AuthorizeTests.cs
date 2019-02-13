using System.Collections.Generic;
using System.IO;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using NUnit.Framework;

namespace AuthenticationSdkTests.core
{
    [TestFixture]
    public class AuthorizeTests
    {
        private string resourceFolderPath = $"..{Path.DirectorySeparatorChar}..{Path.DirectorySeparatorChar}Resource";

        // READING MERCHANT CONFIG FROM DICTIONARY OBJECT
        // GET
        [Test]
        public void GetTokenTest_Get_DictObj()
        {            
            var authType = "jwt";
            var requestType = "GET";

            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", ""},
                {"keyPass", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileName",""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = requestType };            

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof (JwtToken), testObj);
        }

        [Test]
        public void GetSignatureTest_Get_DictObj()
        {
            var authType = "http_signature";
            var requestType = "GET";

            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", "..\\..\\Resource"},
                {"keyFilename", ""},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", ""},
                {"keyPass", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"logFileName",""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = requestType };

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        // POST
        [Test]
        public void GetTokenTest_Post_DictObj()
        {
            var authType = "jwt";
            var requestType = "POST";

            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", ""},
                {"keyPass", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileName",""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = requestType };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
        }

        [Test]
        public void GetSignatureTest_Post_DictObj()
        {
            var authType = "http_signature";
            var requestType = "POST";

            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", ""},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", ""},
                {"keyPass", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileName",""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = requestType };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        // READING MERCHANT CONFIG FROM APP.CONFIG FILE
        // GET
        [Test]
        public void GetTokenTest_Get_MerchCfgObj()
        {           
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "GET"
            };
            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof (JwtToken), testObj);
        }

        [Test]
        public void GetSignatureTest_Get_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "http_signature",
                RequestType = "GET"
            };
            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        // POST
        [Test]
        public void GetTokenTest_Post_MerchCfgObj()
        {            
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "POST"
            };

            using (var r = new StreamReader(resourceFolderPath +"\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
        }

        [Test]
        public void GetSignatureTest_Post_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "http_signature",
                RequestType = "POST"
            };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        // PUT
        [Test]
        public void GetTokenTest_Put_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "PUT"
            };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
        }

        [Test]
        public void GetSignatureTest_Put_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "http_signature",
                RequestType = "PUT"
            };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        // DELETE
        [Test]
        public void GetTokenTest_Delete_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "DELETE"
            };

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
        }

        [Test]
        public void GetSignatureTest_Delete_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "http_signature",
                RequestType = "DELETE"
            };

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        // PATCH
        [Test]
        public void GetTokenTest_Patch_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "PATCH"
            };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
        }

        [Test]
        public void GetsignatureTest_Patch_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "http_signature",
                RequestType = "PATCH"
            };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        [Test]        
        public void PathNotFound()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", "http_signature"},
                {"keysDirectory", ""},
                {"keyFilename", ""},
                {"runEnvironment", "cybersource.environment.sandbox"},
                {"keyAlias", ""},
                {"keyPass", ""},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileMaxSize", ""},
                {"logFileName",""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var obj = new MerchantConfig(configurationDictionary);
            obj.RequestType = "GET";
            var authObj = new Authorize(obj);            

            Assert.AreEqual(null, authObj.GetToken());
        }
    }
}

