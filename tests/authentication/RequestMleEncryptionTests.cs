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
    /// Functional tests for request Message Level Encryption (MLE) exercised through
    /// <see cref="MLEUtility.EncryptRequestPayload(IMerchantCredentialSettings, IMerchantMLESettings, object)"/>
    /// for the three supported authentication mechanisms:
    /// <list type="bullet">
    /// <item><description>JWT signed with a P12 certificate — the MLE certificate is sourced from the P12 keystore.</description></item>
    /// <item><description>JWT signed with a shared secret — the MLE certificate must be supplied via <c>mleForRequestPublicCertPath</c>.</description></item>
    /// <item><description>HTTP Signature — request MLE is unsupported and falls back to plaintext unless a certificate is supplied.</description></item>
    /// </list>
    /// Each encrypting test verifies the produced JWE envelope (alg/enc/kid headers) and then performs a
    /// real RSA-OAEP-256 + AES-256-GCM round trip with the matching private key, so a regression in the
    /// encryption logic is caught rather than just a structural change.
    /// </summary>
    [TestFixture]
    public class RequestMleEncryptionTests
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

        private const string RequestTarget = "/pts/v2/payments";

        private const string SamplePayload =
            "{\"clientReferenceInformation\":{\"code\":\"TC-12345\"}," +
            "\"orderInformation\":{\"amountDetails\":{\"totalAmount\":\"100.00\",\"currency\":\"USD\"}}}";

        // A DER public certificate exported from testrest.p12, written to a temp file so the
        // password-less LoadCertificatesFromPemFile import path (used for mleForRequestPublicCertPath)
        // can consume it. Shared by the shared-secret and HTTP-with-cert scenarios.
        private static string _publicCertPath;

        [OneTimeSetUp]
        public void ExportPublicCertificate()
        {
            X509Certificate2 cert = LoadTestCertificate();
            byte[] der = cert.Export(X509ContentType.Cert);
            _publicCertPath = Path.Combine(Path.GetTempPath(), "mle-request-test-" + Guid.NewGuid().ToString("N") + ".cer");
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

        #region JWT with P12 certificate

        [Test]
        public void RequestMle_JwtP12_EncryptsPayloadAndRoundTripsToOriginal()
        {
            object result = MLEUtility.EncryptRequestPayload(
                JwtP12Credentials(), RequestMleEnabled(certPath: null, alias: KeyAlias), SamplePayload);

            Assert.That(result, Is.Not.Null);
            Assert.That(result.ToString(), Does.Not.Contain(SamplePayload),
                "The cleartext payload must not be present in the MLE envelope.");

            string jwe = ExtractEncryptedRequest(result);
            JsonObject header = DecodeJweHeader(jwe);
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("RSA-OAEP-256"));
            Assert.That(header["enc"]!.GetValue<string>(), Is.EqualTo("A256GCM"));
            Assert.That(header["kid"]!.GetValue<string>(), Is.EqualTo(ExpectedKid),
                "kid must be the MLE certificate serial number.");

            Assert.That(DecryptJwe(jwe), Is.EqualTo(SamplePayload),
                "Decrypting with the matching private key must reproduce the original payload.");
        }

        [Test]
        public void RequestMle_JwtP12_NullBody_ReturnsNull()
        {
            object result = MLEUtility.EncryptRequestPayload(
                JwtP12Credentials(), RequestMleEnabled(certPath: null, alias: KeyAlias), null);

            Assert.That(result, Is.Null, "A null request body must be returned unchanged (null).");
        }

        #endregion

        #region JWE "cty" (content type) header

        [TestCase("application/json")]
        [TestCase("application/hal+json")]
        [TestCase("application/json; charset=utf-8")]
        public void RequestMle_ContentTypeSupplied_SetsJweCtyToExactValue(string contentType)
        {
            object result = MLEUtility.EncryptRequestPayload(
                JwtP12Credentials(), RequestMleEnabled(certPath: null, alias: KeyAlias), SamplePayload,
                loggerFactory: null, contentType: contentType);

            string jwe = ExtractEncryptedRequest(result);
            JsonObject header = DecodeJweHeader(jwe);
            Assert.That(header["cty"]!.GetValue<string>(), Is.EqualTo(contentType),
                "The JWE 'cty' header must equal the exact Content-Type selected by the API operation, " +
                "including parameters such as charset, and must not be inferred from Accept.");
        }

        [Test]
        public void RequestMle_ContentTypeOmitted_JweHeaderHasNoCty()
        {
            // Preserves prior behavior for callers that do not supply a content type.
            object result = MLEUtility.EncryptRequestPayload(
                JwtP12Credentials(), RequestMleEnabled(certPath: null, alias: KeyAlias), SamplePayload);

            string jwe = ExtractEncryptedRequest(result);
            JsonObject header = DecodeJweHeader(jwe);
            Assert.That(header.ContainsKey("cty"), Is.False,
                "No 'cty' header should be present when the caller does not supply a content type.");
        }

        #endregion

        #region JWT with shared secret

        [Test]
        public void RequestMle_JwtSharedSecret_WithCertPath_EncryptsPayloadAndRoundTrips()
        {
            object result = MLEUtility.EncryptRequestPayload(
                JwtSharedSecretCredentials(), RequestMleEnabled(_publicCertPath, alias: null), SamplePayload);

            Assert.That(result.ToString(), Does.Not.Contain(SamplePayload),
                "The cleartext payload must not be present in the MLE envelope.");

            string jwe = ExtractEncryptedRequest(result);
            JsonObject header = DecodeJweHeader(jwe);
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("RSA-OAEP-256"));
            Assert.That(header["enc"]!.GetValue<string>(), Is.EqualTo("A256GCM"));
            Assert.That(header["kid"]!.GetValue<string>(), Is.EqualTo(ExpectedKid));

            Assert.That(DecryptJwe(jwe), Is.EqualTo(SamplePayload),
                "Decrypting with the matching private key must reproduce the original payload.");
        }

        [Test]
        public void RequestMle_JwtSharedSecret_WithoutCertPath_Throws()
        {
            // Shared-secret authentication has no P12 to fall back to, so an explicit public
            // certificate path is mandatory when request MLE is enabled.
            Assert.That(
                () => MLEUtility.EncryptRequestPayload(
                    JwtSharedSecretCredentials(), RequestMleEnabled(certPath: null, alias: null), SamplePayload),
                Throws.TypeOf<ArgumentException>(),
                "Shared-secret request MLE without mleForRequestPublicCertPath must throw.");
        }

        #endregion

        #region HTTP Signature

        [Test]
        public void RequestMle_HttpSignature_WithoutCert_FallsBackToPlaintext()
        {
            // Request MLE using HTTP Signature is not supported by CyberSource; with no certificate
            // configured the SDK falls back to the original, unencrypted payload.
            object result = MLEUtility.EncryptRequestPayload(
                HttpSignatureCredentials(), RequestMleEnabled(certPath: null, alias: null), SamplePayload);

            Assert.That(result, Is.EqualTo(SamplePayload),
                "HTTP Signature without an MLE certificate must return the unencrypted payload.");
        }

        [Test]
        public void RequestMle_HttpSignature_WithCertPath_EncryptsPayloadAndRoundTrips()
        {
            object result = MLEUtility.EncryptRequestPayload(
                HttpSignatureCredentials(), RequestMleEnabled(_publicCertPath, alias: null), SamplePayload);

            Assert.That(result.ToString(), Does.Not.Contain(SamplePayload),
                "The cleartext payload must not be present in the MLE envelope.");

            string jwe = ExtractEncryptedRequest(result);
            JsonObject header = DecodeJweHeader(jwe);
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("RSA-OAEP-256"));
            Assert.That(header["enc"]!.GetValue<string>(), Is.EqualTo("A256GCM"));
            Assert.That(header["kid"]!.GetValue<string>(), Is.EqualTo(ExpectedKid));

            Assert.That(DecryptJwe(jwe), Is.EqualTo(SamplePayload),
                "Decrypting with the matching private key must reproduce the original payload.");
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

        #endregion

        #region Crypto / decoding helpers

        private static string ExtractEncryptedRequest(object encryptResult)
        {
            Assert.That(encryptResult, Is.Not.Null);

            JsonObject envelope = JsonNode.Parse(encryptResult.ToString())!.AsObject();
            Assert.That(envelope.Count, Is.EqualTo(1), "The MLE envelope must contain exactly one property.");
            Assert.That(envelope.ContainsKey("encryptedRequest"), Is.True,
                "The MLE envelope must wrap the JWE token under the 'encryptedRequest' key.");

            return envelope["encryptedRequest"]!.GetValue<string>();
        }

        private static JsonObject DecodeJweHeader(string jwe)
        {
            string[] parts = jwe.Split('.');
            Assert.That(parts.Length, Is.EqualTo(5),
                "A JWE compact serialization must contain header, encrypted key, IV, ciphertext and tag.");

            string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            return JsonNode.Parse(headerJson)!.AsObject();
        }

        private static string DecryptJwe(string jwe)
        {
            // Decrypt with the certificate's RSA private key directly via the SDK's cross-framework
            // decryptor. We intentionally do NOT export the key (ExportParameters(true)) because the
            // testrest.p12 CNG key is non-exportable and would throw a CryptographicException; the
            // private-key unwrap of the content-encryption key works without exporting the key material.
            X509Certificate2 cert = LoadTestCertificate();
            using (RSA privateKey = cert.GetRSAPrivateKey()!)
            {
                return JWEUtilty.DecryptUsingRSA(privateKey, jwe);
            }
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
