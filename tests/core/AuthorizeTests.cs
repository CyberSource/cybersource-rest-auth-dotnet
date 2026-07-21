using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using NUnit.Framework;
using System.Collections.Generic;
using System.IO;
using static AuthenticationSdk.util.Enumerations;

namespace AuthenticationSdkTests.NetCore.core
{
    [TestFixture]
    public class AuthorizeTests
    {
        private string resourceFolderPath =
            "..\\..\\..\\Resource";

        [Test]
        public void GetTokenTest_Get_DictObj()
        {            
            var authType = "jwt";
            var requestType = "GET";
            var requestTarget = "/pts/v2/payments";
            var requestJsonData = "";

            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", "testrest"},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", "testrest"},
                {"keyPass", "testrest"},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileName",""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchantCredentialSettingsObj = new MerchantCredentialSettings(configurationDictionary);
            var merchantMLESettingsObj = new MerchantMLESettings(configurationDictionary);
            var merchantRequestSettingsObj = new MerchantRequestSettings(requestType, requestTarget, requestJsonData);

            var authObj = new Authorize(merchantCredentialSettingsObj, merchantRequestSettingsObj, merchantMLESettingsObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof (JwtToken), testObj);
        }


        [Test]
        public void GetTokenTest_Post_DictObj()
        {            
            var authType = "jwt";
            var requestType = "POST";
            var requestTarget = "/pts/v2/payments";
            var requestJsonData = "";

            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", authType},
                {"keysDirectory", resourceFolderPath},
                {"keyFilename", "testrest"},
                {"runEnvironment", "apitest.cybersource.com"},
                {"keyAlias", "testrest"},
                {"keyPass", "testrest"},
                {"enableLog", ""},
                {"logDirectory", ""},
                {"logFileName",""},
                {"logFileMaxSize", ""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            using (var r = new StreamReader(resourceFolderPath + "\\request_payments.json"))
            {
                requestJsonData = r.ReadToEnd();
            }

            var merchantCredentialSettingsObj = new MerchantCredentialSettings(configurationDictionary);
            var merchantMLESettingsObj = new MerchantMLESettings(configurationDictionary);
            var merchantRequestSettingsObj = new MerchantRequestSettings(requestType, requestTarget, requestJsonData);

            var authObj = new Authorize(merchantCredentialSettingsObj, merchantRequestSettingsObj, merchantMLESettingsObj);

            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof (JwtToken), testObj);
        }
        
        [Test]
        public void GetSignatureTest_Get_DictObj()
        {
            var authType = "http_signature";
            var requestType = "GET";
            var requestTarget = "/pts/v2/payments";
            var requestJsonData = "";

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
                {"logFileMaxSize", ""},
                {"logFileName",""},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchantCredentialSettingsObj = new MerchantCredentialSettings(configurationDictionary);
            var merchantMLESettingsObj = new MerchantMLESettings(configurationDictionary);
            var merchantRequestSettingsObj = new MerchantRequestSettings(requestType, requestTarget, requestJsonData);

            var authObj = new Authorize(merchantCredentialSettingsObj, merchantRequestSettingsObj, merchantMLESettingsObj);

            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);            
        }

        [Test]
        public void GetSignatureTest_Post_DictObj()
        {
            var authType = "http_signature";
            var requestType = "POST";
            var requestTarget = "/pts/v2/payments";
            var requestJsonData = "";

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
                requestJsonData = r.ReadToEnd();
            }

            var merchantCredentialSettingsObj = new MerchantCredentialSettings(configurationDictionary);
            var merchantMLESettingsObj = new MerchantMLESettings(configurationDictionary);
            var merchantRequestSettingsObj = new MerchantRequestSettings(requestType, requestTarget, requestJsonData);

            var authObj = new Authorize(merchantCredentialSettingsObj, merchantRequestSettingsObj, merchantMLESettingsObj);

            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }
        
    }
}

