using System;
using System.Collections.Generic;
using System.IO;
using AuthenticationSdk.core;
using NUnit.Framework;
using Assert = Microsoft.VisualStudio.TestTools.UnitTesting.Assert;

namespace AuthenticationSdkTests.NetCore.util
{
    /// <summary>
    /// Tests for MLE (Message Level Encryption) configuration with different JWT key types.
    /// Covers JWT+P12 and JWT+SharedSecret scenarios for both old (MerchantConfig) and new (interface-based) patterns.
    /// </summary>
    [TestFixture]
    public class MLEConfigTests
    {
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        /// <summary>
        /// Gets the absolute path to a file inside the test resource folder.
        /// </summary>
        private static string AbsResourceFile(string fileName)
        {
            return Path.Combine(ResourceDir, fileName);
        }

        #region Helper Methods

        /// <summary>
        /// Creates a base configuration dictionary for JWT+P12 authentication.
        /// </summary>
        private Dictionary<string, string> GetJwtP12ConfigDictionary()
        {
            return new Dictionary<string, string>
            {
                { "authenticationType", "jwt" },
                { "merchantID", "testrest" },
                { "merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=" },
                { "merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda" },
                { "keysDirectory", ResourceDir },
                { "keyFilename", "testrest" },
                { "runEnvironment", "apitest.cybersource.com" },
                { "keyAlias", "testrest" },
                { "keyPass", "testrest" },
                { "timeout", "300000" },
                // Configs related to meta key
                { "portfolioID", "" },
                { "useMetaKey", "false" },
                // Configs related to OAuth
                { "enableClientCert", "false" },
                { "clientCertDirectory", "Resource" },
                { "clientCertFile", "" },
                { "clientCertPassword", "" },
                { "clientId", "" },
                { "clientSecret", "" },
                // PEM Key file path (optional, for JWE decryption)
                { "pemFileDirectory", AbsResourceFile("NetworkTokenCert.pem") },
                // Logging
                { "enableLog", "" },
                { "logDirectory", "" },
                { "logFileName", "" },
                { "logFileMaxSize", "" },
                // Proxy
                { "proxyAddress", "" },
                { "proxyPort", "" }
            };
        }

        /// <summary>
        /// Creates a base configuration dictionary for JWT+SharedSecret authentication.
        /// </summary>
        private Dictionary<string, string> GetJwtSharedSecretConfigDictionary()
        {
            return new Dictionary<string, string>
            {
                { "authenticationType", "jwt" },
                { "jwtKeyType", "SHARED_SECRET" },
                { "merchantID", "testrest" },
                { "merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=" },
                { "merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda" },
                { "runEnvironment", "apitest.cybersource.com" },
                { "timeout", "300000" },
                // Configs related to meta key
                { "portfolioID", "" },
                { "useMetaKey", "false" },
                // Configs related to OAuth
                { "enableClientCert", "false" },
                { "clientCertDirectory", "Resource" },
                { "clientCertFile", "" },
                { "clientCertPassword", "" },
                { "clientId", "" },
                { "clientSecret", "" },
                // PEM Key file path (optional, for JWE decryption)
                { "pemFileDirectory", AbsResourceFile("NetworkTokenCert.pem") },
                // Logging
                { "enableLog", "" },
                { "logDirectory", "" },
                { "logFileName", "" },
                { "logFileMaxSize", "" },
                // Proxy
                { "proxyAddress", "" },
                { "proxyPort", "" }
            };
        }

        #endregion

        #region MerchantConfig - JWT+P12 MLE Tests

        [Test]
        public void JwtP12_MerchantConfig_DefaultJwtKeyType_IsP12()
        {
            var config = GetJwtP12ConfigDictionary();

            // jwtKeyType not set — should default to P12
            var merchantCredentialSettings = new MerchantCredentialSettings(config);

            Assert.AreEqual("P12", merchantCredentialSettings.JwtKeyType);
            Assert.IsFalse(merchantCredentialSettings.IsSharedSecretKeyType());
        }

        [Test]
        public void JwtP12_MerchantConfig_ExplicitJwtKeyTypeP12()
        {
            var config = GetJwtP12ConfigDictionary();
            config["jwtKeyType"] = "P12";
            var merchantCredentialSettings = new MerchantCredentialSettings(config);

            Assert.AreEqual("P12", merchantCredentialSettings.JwtKeyType);
            Assert.IsFalse(merchantCredentialSettings.IsSharedSecretKeyType());
        }

        [Test]
        public void JwtP12_MerchantConfig_WithRequestMLE_ConfigIsValid()
        {
            var config = GetJwtP12ConfigDictionary();
            config["enableRequestMLEForOptionalApisGlobally"] = "true";
            config["requestMleKeyAlias"] = "CyberSource_SJC_US";

            var merchantMLESettings = new MerchantMLESettings(config);

            Assert.IsTrue(merchantMLESettings.EnableRequestMLEForOptionalApisGlobally);
            Assert.AreEqual("CyberSource_SJC_US", merchantMLESettings.RequestMleKeyAlias);
        }

        [Test]
        public void JwtP12_MerchantConfig_WithResponseMLE_ConfigIsValid()
        {
            var config = GetJwtP12ConfigDictionary();
            config["enableResponseMleGlobally"] = "true";
            config["responseMlePrivateKeyFilePath"] = AbsResourceFile("testrest.p12");
            config["responseMlePrivateKeyFilePassword"] = "testrest";

            var merchantMLESettings = new MerchantMLESettings(config);

            Assert.IsTrue(merchantMLESettings.EnableResponseMleGlobally);
            Assert.IsNotNull(merchantMLESettings.ResponseMlePrivateKeyFilePath);
            Assert.IsNotNull(merchantMLESettings.ResponseMlePrivateKeyFilePassword);
        }

        #endregion

        #region MerchantConfig - JWT+SharedSecret MLE Tests

        [Test]
        public void JwtSS_MerchantConfig_JwtKeyTypeIsSharedSecret()
        {
            var config = GetJwtSharedSecretConfigDictionary();
            var merchantCredentialSettings = new MerchantCredentialSettings(config);

            Assert.AreEqual("SHARED_SECRET", merchantCredentialSettings.JwtKeyType);
            Assert.IsTrue(merchantCredentialSettings.IsSharedSecretKeyType());
        }

        [Test]
        public void JwtSS_MerchantConfig_SharedSecretKeysArePopulated()
        {
            var config = GetJwtSharedSecretConfigDictionary();
            var merchantCredentialSettings = new MerchantCredentialSettings(config);

            Assert.IsNotNull(merchantCredentialSettings.MerchantSecretKey, "MerchantSecretKey should be populated for JWT+SharedSecret");
            Assert.IsNotNull(merchantCredentialSettings.MerchantKeyId, "MerchantKeyId should be populated for JWT+SharedSecret");
            Assert.AreEqual("yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=", merchantCredentialSettings.MerchantSecretKey);
            Assert.AreEqual("08c94330-f618-42a3-b09d-e1e43be5efda", merchantCredentialSettings.MerchantKeyId);
        }

        [Test]
        public void JwtSS_MerchantConfig_WithRequestMLE_ExternalCertPath()
        {
            var config = GetJwtSharedSecretConfigDictionary();
            config["enableRequestMLEForOptionalApisGlobally"] = "true";
            config["mleForRequestPublicCertPath"] = AbsResourceFile("testrest.p12");

            var merchantCredentialSettings = new MerchantCredentialSettings(config);
            var merchantMLESettings = new MerchantMLESettings(config);

            Assert.IsTrue(merchantMLESettings.EnableRequestMLEForOptionalApisGlobally);
            Assert.IsTrue(merchantCredentialSettings.IsSharedSecretKeyType());
            Assert.IsNotNull(merchantMLESettings.MleForRequestPublicCertPath, "For JWT+SharedSecret, mleForRequestPublicCertPath must be provided for request MLE");
        }

        [Test]
        public void JwtSS_MerchantConfig_WithRequestMLE_NoCertPath_ReturnsNull()
        {
            // JWT+SharedSecret without external cert path — P12 fallback is skipped because IsSharedSecretKeyType = true
            var config = GetJwtSharedSecretConfigDictionary();
            config["enableRequestMLEForOptionalApisGlobally"] = "true";

            var merchantCredentialSettings = new MerchantCredentialSettings(config);
            var merchantMLESettings = new MerchantMLESettings(config);

            Assert.IsTrue(merchantMLESettings.EnableRequestMLEForOptionalApisGlobally);
            Assert.IsTrue(merchantCredentialSettings.IsSharedSecretKeyType());
            Assert.IsNull(merchantMLESettings.MleForRequestPublicCertPath,
                "No cert path should be set — JWT+SharedSecret has no P12 to fall back to");
        }

        [Test]
        public void JwtSS_MerchantConfig_WithResponseMLE_ConfigIsValid()
        {
            var config = GetJwtSharedSecretConfigDictionary();
            config["enableResponseMleGlobally"] = "true";
            config["responseMlePrivateKeyFilePath"] = AbsResourceFile("testrest.p12");
            config["responseMlePrivateKeyFilePassword"] = "testrest";

            var merchantCredentialSettings = new MerchantCredentialSettings(config);
            var merchantMLESettings = new MerchantMLESettings(config);

            Assert.IsTrue(merchantMLESettings.EnableResponseMleGlobally);
            Assert.IsTrue(merchantCredentialSettings.IsSharedSecretKeyType());
            Assert.IsNotNull(merchantMLESettings.ResponseMlePrivateKeyFilePath);
            Assert.IsNotNull(merchantMLESettings.ResponseMlePrivateKeyFilePassword);
        }

        [Test]
        public void JwtSS_MerchantConfig_EmptyResponseMleKID_IsNull()
        {
            // Verifies that empty string responseMleKID is treated as null (allows auto-extraction)
            var config = GetJwtSharedSecretConfigDictionary();
            config["enableResponseMleGlobally"] = "true";
            config["responseMleKID"] = "";
            config["responseMlePrivateKeyFilePath"] = AbsResourceFile("testrest.p12");
            config["responseMlePrivateKeyFilePassword"] = "testrest";

            Assert.ThrowsException<Exception>(() => new MerchantMLESettings(config));
        }

        [Test]
        public void JwtSS_MerchantConfig_WithBothRequestAndResponseMLE()
        {
            var config = GetJwtSharedSecretConfigDictionary();
            config["enableRequestMLEForOptionalApisGlobally"] = "true";
            config["mleForRequestPublicCertPath"] = AbsResourceFile("testrest.p12");
            config["enableResponseMleGlobally"] = "true";
            config["responseMlePrivateKeyFilePath"] = AbsResourceFile("testrest.p12");
            config["responseMlePrivateKeyFilePassword"] = "testrest";

            var merchantCredentialSettings = new MerchantCredentialSettings(config);
            var merchantMLESettings = new MerchantMLESettings(config);

            Assert.IsTrue(merchantMLESettings.EnableRequestMLEForOptionalApisGlobally);
            Assert.IsTrue(merchantMLESettings.EnableResponseMleGlobally);
            Assert.IsTrue(merchantCredentialSettings.IsSharedSecretKeyType());
        }

        #endregion

        #region MerchantMLESettings - Interface-based Tests

        [Test]
        public void MerchantMLESettings_RequestMLEEnabled_DefaultAlias()
        {
            var mleDict = new Dictionary<string, string>
            {
                { "enableRequestMLEForOptionalApisGlobally", "true" }
            };

            var mleSettings = new MerchantMLESettings(mleDict);

            Assert.IsTrue(mleSettings.EnableRequestMLEForOptionalApisGlobally);
            Assert.AreEqual("CyberSource_SJC_US", mleSettings.RequestMleKeyAlias,
                "Default requestMleKeyAlias should be CyberSource_SJC_US");
        }

        [Test]
        public void MerchantMLESettings_ResponseMLEEnabled_WithP12Path()
        {
            var mleDict = new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMlePrivateKeyFilePath", AbsResourceFile("testrest.p12") },
                { "responseMlePrivateKeyFilePassword", "testrest" }
            };

            var mleSettings = new MerchantMLESettings(mleDict);

            Assert.IsTrue(mleSettings.EnableResponseMleGlobally);
            Assert.IsNotNull(mleSettings.ResponseMlePrivateKeyFilePath);
        }

        [Test]
        public void MerchantMLESettings_EmptyResponseMleKID_IsNull()
        {
            // Empty responseMleKID is invalid when key is explicitly present.
            var mleDict = new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMleKID", "" },
                { "responseMlePrivateKeyFilePath", AbsResourceFile("testrest.p12") },
                { "responseMlePrivateKeyFilePassword", "testrest" }
            };

            Assert.ThrowsException<Exception>(() => new MerchantMLESettings(mleDict));
        }

        [Test]
        public void MerchantMLESettings_WhitespaceResponseMleKID_IsNull()
        {
            // Whitespace responseMleKID is invalid when key is explicitly present.
            var mleDict = new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMleKID", "   " },
                { "responseMlePrivateKeyFilePath", AbsResourceFile("testrest.p12") },
                { "responseMlePrivateKeyFilePassword", "testrest" }
            };

            Assert.ThrowsException<Exception>(() => new MerchantMLESettings(mleDict));
        }

        [Test]
        public void MerchantMLESettings_ExplicitResponseMleKID_IsPreserved()
        {
            var mleDict = new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMleKID", "my-custom-kid-123" },
                { "responseMlePrivateKeyFilePath", AbsResourceFile("testrest.p12") },
                { "responseMlePrivateKeyFilePassword", "testrest" }
            };

            var mleSettings = new MerchantMLESettings(mleDict);

            Assert.AreEqual("my-custom-kid-123", mleSettings.ResponseMleKID,
                "Explicit responseMleKID value should be preserved");
        }

        [Test]
        public void MerchantMLESettings_EmptyPrivateKeyFilePath_IsNull()
        {
            // Private key path is preserved as provided when response MLE is disabled.
            var mleDict = new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "false" },
                { "responseMlePrivateKeyFilePath", "" }
            };

            var mleSettings = new MerchantMLESettings(mleDict);

            Assert.AreEqual(string.Empty, mleSettings.ResponseMlePrivateKeyFilePath,
                "Empty responseMlePrivateKeyFilePath should be preserved when response MLE is disabled");
        }

        [Test]
        public void MerchantMLESettings_MleForRequestPublicCertPath_IsSet()
        {
            // Verifies that mleForRequestPublicCertPath is correctly read from dictionary
            var mleDict = new Dictionary<string, string>
            {
                { "enableRequestMLEForOptionalApisGlobally", "true" },
                { "mleForRequestPublicCertPath", AbsResourceFile("testrest.p12") }
            };

            var mleSettings = new MerchantMLESettings(mleDict);

            Assert.IsNotNull(mleSettings.MleForRequestPublicCertPath,
                "MleForRequestPublicCertPath should be read from dictionary");
        }

        [Test]
        public void MerchantMLESettings_MapToControlMLEonAPI_RequestAndResponse()
        {
            var mleDict = new Dictionary<string, string>
            {
                { "enableRequestMLEForOptionalApisGlobally", "false" },
                { "responseMlePrivateKeyFilePath", AbsResourceFile("testrest.p12") },
                { "responseMlePrivateKeyFilePassword", "testrest" }
            };

            var mleControlMap = new Dictionary<string, string>
            {
                { "getAccountInfo", "true::true" }  // requestMLE=true, responseMLE=true
            };

            var mleSettings = new MerchantMLESettings(mleDict, mleControlMap);

            Assert.IsNotNull(mleSettings.MapToControlMLEonAPI);
        }

        #endregion
    }
}
