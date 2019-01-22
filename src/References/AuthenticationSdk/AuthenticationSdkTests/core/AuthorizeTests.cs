using System.Collections.Generic;
using System.IO;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using NUnit.Framework;
using Constants = AuthenticationSdkTests.util.Constants;
using System;

namespace AuthenticationSdkTests.core
{
    [TestFixture]
    public class AuthorizeTests
    {
        private readonly string _resourceFolderPath = Constants.ResourceFolderPath;

        [Test]
        public void CheckAccessibilityOfP12File()
        {
            var p12FileName = "testrest.p12";
            var p12FileExists = File.Exists(_resourceFolderPath + Path.DirectorySeparatorChar + p12FileName);

            Assert.AreEqual(true, p12FileExists);
        }

        [Test]
        public void AuthorizeTest_Jwt_Get_MerchCfgObj()
        {
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "GET"
            };

            var authorizeObj = new Authorize(merchConfigObj);

            Assert.IsInstanceOf(typeof(Authorize), authorizeObj);
        }

        [Test]
        [Ignore("Ignoring this test for Travis CI as private key extraction failing in Linux OS")]
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
                {"keysDirectory", _resourceFolderPath},
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
        [Ignore("Ignoring this test for Travis CI as private key extraction failing in Linux OS")]
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
        [Ignore("Ignoring this test for Travis CI as private key extraction failing in Linux OS")]
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
                {"keysDirectory", _resourceFolderPath},
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

            using (var r = new StreamReader(_resourceFolderPath + $"{Path.DirectorySeparatorChar}request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof (JwtToken), testObj);
        }


        [Test]
        [Ignore("Ignoring this test for Travis CI as private key extraction failing in Linux OS")]
        public void GetTokenTest_Post_MerchCfgObj()
        {            
            var merchConfigObj = new MerchantConfig
            {
                AuthenticationType = "jwt",
                RequestType = "POST"
            };

            using (var r = new StreamReader(_resourceFolderPath + $"{Path.DirectorySeparatorChar}request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
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

            Assert.Throws<ArgumentNullException>(() => new Authorize(obj).GetToken());
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
                {"keysDirectory", ""},
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
                {"keysDirectory", ""},
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

            using (var r = new StreamReader($"{_resourceFolderPath}{Path.DirectorySeparatorChar}request_payments.json"))
            {
                merchConfigObj.RequestJsonData = r.ReadToEnd();
            }

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }
        
    }
}

