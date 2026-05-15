using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace AuthenticationSdkTests.core
{
    [TestFixture]
    public class AuthorizeTests
    {
        private string resourceFolderPath = Path.GetFullPath(
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "Resource"));

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

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = requestType };

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof (JwtToken), testObj);
        }

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

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = requestType };
            merchConfigObj.RequestJsonData = "{\"clientReferenceInformation\":{\"code\":\"TC50171_3\"},\"paymentInformation\":{\"card\":{\"number\":\"4111111111111111\",\"expirationMonth\":\"12\",\"expirationYear\":\"2031\"}},\"orderInformation\":{\"amountDetails\":{\"totalAmount\":\"102.21\",\"currency\":\"USD\"}}}";

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
            merchConfigObj.RequestJsonData = "{\"clientReferenceInformation\":{\"code\":\"TC50171_3\"},\"paymentInformation\":{\"card\":{\"number\":\"4111111111111111\",\"expirationMonth\":\"12\",\"expirationYear\":\"2031\"}},\"orderInformation\":{\"amountDetails\":{\"totalAmount\":\"102.21\",\"currency\":\"USD\"}}}";

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetSignature();

            Assert.IsInstanceOf(typeof(HttpToken), testObj);
        }

        // ===== JWT SHARED_SECRET (Symmetric / HS256) Tests =====

        [Test]
        public void GetTokenTest_JwtSharedSecret_Get()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", "jwt"},
                {"jwtKeyType", "SHARED_SECRET"},
                {"runEnvironment", "apitest.cybersource.com"},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = "GET", RequestTarget = "/pts/v2/payments" };

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
            Assert.IsNotNull(testObj.BearerToken);
            Assert.IsNotEmpty(testObj.BearerToken);

            // Validate JWT structure: header.payload.signature
            var parts = testObj.BearerToken.Split('.');
            Assert.AreEqual(3, parts.Length, "JWT should have 3 parts separated by dots");

            // Decode and validate header
            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            var header = JObject.Parse(headerJson);
            Assert.AreEqual("HS256", header["alg"]?.ToString(), "Algorithm should be HS256 for shared secret");
            Assert.AreEqual("08c94330-f618-42a3-b09d-e1e43be5efda", header["kid"]?.ToString(), "kid should be merchantKeyId");
            Assert.AreEqual("JWT", header["typ"]?.ToString());

            // Decode and validate payload
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            var payload = JObject.Parse(payloadJson);
            Assert.IsNotNull(payload["iat"]);
            Assert.IsNotNull(payload["exp"]);
            Assert.AreEqual("testrest", payload["iss"]?.ToString());
            Assert.IsNotNull(payload["jti"]);
            Assert.AreEqual("apitest.cybersource.com", payload["request-host"]?.ToString());
            Assert.AreEqual("GET", payload["request-method"]?.ToString());
            Assert.AreEqual("2", payload["v-c-jwt-version"]?.ToString());
            Assert.AreEqual("testrest", payload["v-c-merchant-id"]?.ToString());

            // GET should NOT have digest
            Assert.IsNull(payload["digest"]);
            Assert.IsNull(payload["digestAlgorithm"]);
        }

        [Test]
        public void GetTokenTest_JwtSharedSecret_Post()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", "jwt"},
                {"jwtKeyType", "SHARED_SECRET"},
                {"runEnvironment", "apitest.cybersource.com"},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = "POST", RequestTarget = "/pts/v2/payments" };

            // Use inline JSON body for test independence from file system
            merchConfigObj.RequestJsonData = "{\"clientReferenceInformation\":{\"code\":\"TC50171_3\"},\"paymentInformation\":{\"card\":{\"number\":\"4111111111111111\",\"expirationMonth\":\"12\",\"expirationYear\":\"2031\"}},\"orderInformation\":{\"amountDetails\":{\"totalAmount\":\"102.21\",\"currency\":\"USD\"}}}";

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
            Assert.IsNotNull(testObj.BearerToken);

            // Validate JWT structure
            var parts = testObj.BearerToken.Split('.');
            Assert.AreEqual(3, parts.Length);

            // Decode and validate header uses HS256
            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            var header = JObject.Parse(headerJson);
            Assert.AreEqual("HS256", header["alg"]?.ToString());
            Assert.AreEqual("08c94330-f618-42a3-b09d-e1e43be5efda", header["kid"]?.ToString());

            // POST should have digest
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            var payload = JObject.Parse(payloadJson);
            Assert.IsNotNull(payload["digest"], "POST request should include digest");
            Assert.AreEqual("SHA-256", payload["digestAlgorithm"]?.ToString());
            Assert.AreEqual("POST", payload["request-method"]?.ToString());
        }

        [Test]
        public void GetTokenTest_JwtSharedSecret_CaseInsensitive()
        {
            var configurationDictionary = new Dictionary<string, string>
            {
                {"merchantID", "testrest"},
                {"merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="},
                {"merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda"},
                {"authenticationType", "jwt"},
                {"jwtKeyType", "shared_secret"},
                {"runEnvironment", "apitest.cybersource.com"},
                {"timeout", ""},
                {"proxyAddress", ""},
                {"proxyPort", ""}
            };

            var merchConfigObj = new MerchantConfig(configurationDictionary) { RequestType = "GET", RequestTarget = "/pts/v2/payments" };

            var authObj = new Authorize(merchConfigObj);
            var testObj = authObj.GetToken();

            Assert.IsInstanceOf(typeof(JwtToken), testObj);
            Assert.IsNotNull(testObj.BearerToken);
        }

        /// <summary>
        /// Helper to decode Base64Url-encoded strings (JWT uses Base64Url, not standard Base64).
        /// </summary>
        private static byte[] Base64UrlDecode(string base64Url)
        {
            string padded = base64Url.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "="; break;
            }
            return System.Convert.FromBase64String(padded);
        }
        
    }
}

