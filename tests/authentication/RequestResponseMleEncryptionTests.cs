using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.authentication
{
    /// <summary>
    /// Functional tests for request <b>and</b> response Message Level Encryption (MLE) exercised through the
    /// public SDK surface for the three supported authentication mechanisms:
    /// <list type="bullet">
    /// <item><description>JWT signed with a P12 certificate — request MLE sources the certificate from the P12 keystore.</description></item>
    /// <item><description>JWT signed with a shared secret — request MLE supplies the certificate via <c>mleForRequestPublicCertPath</c>.</description></item>
    /// <item><description>HTTP Signature — request MLE supplies the certificate via <c>mleForRequestPublicCertPath</c>.</description></item>
    /// </list>
    /// Each mechanism test performs a full round trip:
    /// <list type="number">
    /// <item><description>Encrypts an outbound payload through <see cref="MLEUtility.EncryptRequestPayload(IMerchantCredentialSettings, IMerchantMLESettings, object)"/> and verifies the JWE envelope.</description></item>
    /// <item><description>Decrypts a server-style encrypted response through <see cref="MLEUtility.DecryptMleResponsePayload(IMerchantCredentialSettings, IMerchantMLESettings, string)"/> and verifies the cleartext is recovered.</description></item>
    /// </list>
    /// Response fixtures are produced with the same RSA-OAEP-256 + AES-256-GCM JWE format the server uses, bound to
    /// the <c>testrest.p12</c> public certificate, so the matching private key decrypts them and a regression in the
    /// crypto path is caught rather than just a structural change.
    /// </summary>
    [TestFixture]
    public class RequestResponseMleEncryptionTests
    {
        // Resolve the test 'Resource' folder relative to the test assembly output directory
        // (bin/<config>/<tfm>/ -> up three levels -> tests/ -> Resource).
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        private static readonly string P12Path = Path.Combine(ResourceDir, "testrest.p12");

        private const string MerchantId = "testrest";
        private const string RunEnvironment = "apitest.cybersource.com";

        // testrest.p12 -> password/alias are both "testrest"; subject carries SERIALNUMBER=<ExpectedKid>.
        private const string KeyFilename = "testrest";
        private const string KeyAlias = "testrest";
        private const string KeyPass = "testrest";
        private const string ExpectedKid = "5112228966230177031579";

        private const string MerchantKeyId = "08c94330-f618-42a3-b09d-e1e43be5efda";
        private const string MerchantSecretKey = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

        // Distinct request / response payloads so the round-trip assertions are meaningful.
        private const string RequestPayload =
            "{\"clientReferenceInformation\":{\"code\":\"TC-12345\"}," +
            "\"orderInformation\":{\"amountDetails\":{\"totalAmount\":\"100.00\",\"currency\":\"USD\"}}}";

        private const string ResponsePayload =
            "{\"id\":\"7000000000000000000001\",\"status\":\"AUTHORIZED\"," +
            "\"orderInformation\":{\"amountDetails\":{\"authorizedAmount\":\"100.00\",\"currency\":\"USD\"}}}";

        // A DER public certificate exported from testrest.p12, written to a temp file so the password-less
        // LoadCertificatesFromPemFile import path (used for mleForRequestPublicCertPath) can consume it.
        // Shared by the shared-secret and HTTP-signature request-MLE scenarios.
        private static string _publicCertPath;

        [OneTimeSetUp]
        public void ExportPublicCertificate()
        {
            X509Certificate2 cert = LoadTestCertificate();
            byte[] der = cert.Export(X509ContentType.Cert);
            _publicCertPath = Path.Combine(Path.GetTempPath(), "mle-response-test-" + Guid.NewGuid().ToString("N") + ".cer");
            File.WriteAllBytes(_publicCertPath, der);
        }

        [OneTimeTearDown]
        public void RemovePublicCertificate()
        {
            if (!string.IsNullOrEmpty(_publicCertPath) && File.Exists(_publicCertPath))
            {
                File.Delete(_publicCertPath);
            }
        }

        #region Full request + response round trips per auth mechanism

        [Test]
        public void JwtP12_RequestAndResponseMle_RoundTrips()
        {
            MerchantCredentialSettings credentials = JwtP12Credentials();

            // ----- Request MLE: encrypt the outbound payload (certificate sourced from the P12) -----
            object encryptedRequest = MLEUtility.EncryptRequestPayload(
                credentials, RequestMleEnabled(certPath: null, alias: KeyAlias), RequestPayload);

            Assert.That(encryptedRequest.ToString(), Does.Not.Contain(RequestPayload),
                "The cleartext request payload must not be present in the MLE envelope.");
            AssertJweHeader(ExtractToken(encryptedRequest, "encryptedRequest"));

            // ----- Response MLE: decrypt a server-style encrypted response (private key from the P12) -----
            string encryptedResponseBody = BuildEncryptedResponseBody(ResponsePayload);
            string decryptedResponse = MLEUtility.DecryptMleResponsePayload(
                credentials, ResponseMleWithP12Path(), encryptedResponseBody);

            Assert.That(decryptedResponse, Is.EqualTo(ResponsePayload),
                "Decrypting the response with the matching private key must reproduce the original payload.");
        }

        [Test]
        public void JwtSharedSecret_RequestAndResponseMle_RoundTrips()
        {
            MerchantCredentialSettings credentials = JwtSharedSecretCredentials();

            // ----- Request MLE: shared-secret auth has no P12, so the public cert path is mandatory -----
            object encryptedRequest = MLEUtility.EncryptRequestPayload(
                credentials, RequestMleEnabled(_publicCertPath, alias: null), RequestPayload);

            Assert.That(encryptedRequest.ToString(), Does.Not.Contain(RequestPayload),
                "The cleartext request payload must not be present in the MLE envelope.");
            AssertJweHeader(ExtractToken(encryptedRequest, "encryptedRequest"));

            // ----- Response MLE: decrypt a server-style encrypted response -----
            string encryptedResponseBody = BuildEncryptedResponseBody(ResponsePayload);
            string decryptedResponse = MLEUtility.DecryptMleResponsePayload(
                credentials, ResponseMleWithP12Path(), encryptedResponseBody);

            Assert.That(decryptedResponse, Is.EqualTo(ResponsePayload),
                "Decrypting the response with the matching private key must reproduce the original payload.");
        }

        [Test]
        public void HttpSignature_RequestAndResponseMle_RoundTrips()
        {
            MerchantCredentialSettings credentials = HttpSignatureCredentials();

            // ----- Request MLE: HTTP Signature requires the public cert path to encrypt the request -----
            object encryptedRequest = MLEUtility.EncryptRequestPayload(
                credentials, RequestMleEnabled(_publicCertPath, alias: null), RequestPayload);

            Assert.That(encryptedRequest.ToString(), Does.Not.Contain(RequestPayload),
                "The cleartext request payload must not be present in the MLE envelope.");
            AssertJweHeader(ExtractToken(encryptedRequest, "encryptedRequest"));

            // ----- Response MLE: decrypt a server-style encrypted response -----
            string encryptedResponseBody = BuildEncryptedResponseBody(ResponsePayload);
            string decryptedResponse = MLEUtility.DecryptMleResponsePayload(
                credentials, ResponseMleWithP12Path(), encryptedResponseBody);

            Assert.That(decryptedResponse, Is.EqualTo(ResponsePayload),
                "Decrypting the response with the matching private key must reproduce the original payload.");
        }

        #endregion

        #region Response MLE configuration variations and edge cases

        [Test]
        public void ResponseMle_WithDirectPrivateKeyObject_DecryptsToOriginal()
        {
            // The response private key can be supplied as an in-memory object instead of a file path.
            // For a directly supplied key the responseMleKID must be configured explicitly.
            using (RSA privateKey = LoadTestCertificate().GetRSAPrivateKey())
            {
                string encryptedResponseBody = BuildEncryptedResponseBody(ResponsePayload);

                string decryptedResponse = MLEUtility.DecryptMleResponsePayload(
                    JwtP12Credentials(), ResponseMleWithKeyObject(privateKey, ExpectedKid), encryptedResponseBody);

                Assert.That(decryptedResponse, Is.EqualTo(ResponsePayload));
            }
        }

        [Test]
        public void ResponseMle_WithEmptyEncryptedToken_ReturnsBodyUnchanged()
        {
            // When the encryptedResponse token is empty the SDK falls back to returning the body verbatim
            // rather than attempting (and failing) a decrypt.
            string body = new JsonObject { ["encryptedResponse"] = "" }.ToJsonString();

            string result = MLEUtility.DecryptMleResponsePayload(
                JwtP12Credentials(), ResponseMleWithP12Path(), body);

            Assert.That(result, Is.EqualTo(body));
        }

        [Test]
        public void ResponseMle_WithPlaintextBody_Throws()
        {
            // A normal (non-MLE) JSON response is not wrapped under a single encryptedResponse property,
            // so the SDK rejects it as not MLE encrypted.
            string plaintextResponse = "{\"id\":\"7000000000000000000001\",\"status\":\"AUTHORIZED\"}";

            Assert.That(
                () => MLEUtility.DecryptMleResponsePayload(
                    JwtP12Credentials(), ResponseMleWithP12Path(), plaintextResponse),
                Throws.Exception.With.Message.Contains("not MLE encrypted"));
        }

        [Test]
        public void ResponseMle_WithMismatchedPrivateKey_ThrowsMleException()
        {
            // A response encrypted to the testrest certificate cannot be decrypted with an unrelated key;
            // the failure is surfaced as an MLEException.
            using (RSA wrongKey = RSA.Create())
            {
                wrongKey.KeySize = 2048;
                string encryptedResponseBody = BuildEncryptedResponseBody(ResponsePayload);

                Assert.That(
                    () => MLEUtility.DecryptMleResponsePayload(
                        JwtP12Credentials(), ResponseMleWithKeyObject(wrongKey, "mismatched-kid"), encryptedResponseBody),
                    Throws.InstanceOf<MLEException>());
            }
        }

        #endregion

        #region Settings builders

        private static MerchantCredentialSettings JwtP12Credentials()
        {
            return new MerchantCredentialSettings(new Dictionary<string, string>
            {
                { "merchantID", MerchantId },
                { "authenticationType", "jwt" },
                { "jwtKeyType", "P12" },
                { "runEnvironment", RunEnvironment },
                { "keysDirectory", ResourceDir },
                { "keyFilename", KeyFilename },
                { "keyAlias", KeyAlias },
                { "keyPass", KeyPass }
            });
        }

        private static MerchantCredentialSettings JwtSharedSecretCredentials()
        {
            return new MerchantCredentialSettings(new Dictionary<string, string>
            {
                { "merchantID", MerchantId },
                { "authenticationType", "jwt" },
                { "jwtKeyType", "SHARED_SECRET" },
                { "runEnvironment", RunEnvironment },
                { "merchantKeyId", MerchantKeyId },
                { "merchantsecretKey", MerchantSecretKey }
            });
        }

        private static MerchantCredentialSettings HttpSignatureCredentials()
        {
            return new MerchantCredentialSettings(new Dictionary<string, string>
            {
                { "merchantID", MerchantId },
                { "authenticationType", "http_signature" },
                { "runEnvironment", RunEnvironment },
                { "merchantKeyId", MerchantKeyId },
                { "merchantsecretKey", MerchantSecretKey }
            });
        }

        private static MerchantMLESettings RequestMleEnabled(string certPath, string alias)
        {
            var dict = new Dictionary<string, string>
            {
                { "enableRequestMLEForOptionalApisGlobally", "true" }
            };

            if (!string.IsNullOrEmpty(alias))
            {
                dict["requestMleKeyAlias"] = alias;
            }

            if (!string.IsNullOrEmpty(certPath))
            {
                dict["mleForRequestPublicCertPath"] = certPath;
            }

            return new MerchantMLESettings(dict);
        }

        private static MerchantMLESettings ResponseMleWithP12Path()
        {
            // P12/PFX response keys allow the responseMleKID to be auto-extracted, so it can be omitted here.
            return new MerchantMLESettings(new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMlePrivateKeyFilePath", P12Path },
                { "responseMlePrivateKeyFilePassword", KeyPass }
            });
        }

        private static MerchantMLESettings ResponseMleWithKeyObject(RSA privateKey, string kid)
        {
            var dict = new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMleKID", kid }
            };

            return new MerchantMLESettings(dict, null, privateKey);
        }

        #endregion

        #region Crypto / decoding helpers

        /// <summary>
        /// Produces a server-style MLE response body by encrypting <paramref name="payload"/> into the same
        /// RSA-OAEP-256 + A256GCM JWE the server emits (bound to the testrest public certificate) and wrapping
        /// it under the <c>encryptedResponse</c> envelope key.
        /// </summary>
        private static string BuildEncryptedResponseBody(string payload)
        {
            object encrypted = MLEUtility.EncryptRequestPayload(
                JwtP12Credentials(), RequestMleEnabled(certPath: null, alias: KeyAlias), payload);

            string jwe = ExtractToken(encrypted, "encryptedRequest");
            return new JsonObject { ["encryptedResponse"] = jwe }.ToJsonString();
        }

        private static string ExtractToken(object envelopeResult, string propertyName)
        {
            Assert.That(envelopeResult, Is.Not.Null);

            JsonObject envelope = JsonNode.Parse(envelopeResult.ToString())!.AsObject();
            Assert.That(envelope.ContainsKey(propertyName), Is.True,
                $"The MLE envelope must wrap the JWE token under the '{propertyName}' key.");

            return envelope[propertyName]!.GetValue<string>();
        }

        private static void AssertJweHeader(string jwe)
        {
            string[] parts = jwe.Split('.');
            Assert.That(parts.Length, Is.EqualTo(5),
                "A JWE compact serialization must contain header, encrypted key, IV, ciphertext and tag.");

            string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            JsonObject header = JsonNode.Parse(headerJson)!.AsObject();
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("RSA-OAEP-256"));
            Assert.That(header["enc"]!.GetValue<string>(), Is.EqualTo("A256GCM"));
            Assert.That(header["kid"]!.GetValue<string>(), Is.EqualTo(ExpectedKid),
                "kid must be the MLE certificate serial number.");
        }

        private static X509Certificate2 LoadTestCertificate()
        {
            X509Certificate2Collection certs = Cache.FetchCachedCertificate(P12Path, KeyPass);
            return Cache.GetCertBasedOnKeyAlias(certs, KeyAlias);
        }

        private static byte[] Base64UrlDecode(string input)
        {
            string value = input.Replace('-', '+').Replace('_', '/');
            switch (value.Length % 4)
            {
                case 2: value += "=="; break;
                case 3: value += "="; break;
            }
            return Convert.FromBase64String(value);
        }

        #endregion
    }
}
