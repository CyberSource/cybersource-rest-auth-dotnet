using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.authentication
{
    /// <summary>
    /// Functional tests for the three supported authentication mechanisms exposed through <see cref="Authorize"/>:
    /// <list type="bullet">
    /// <item><description>JWT signed with RS256 using a P12 certificate.</description></item>
    /// <item><description>JWT signed with HS256 using a shared secret key.</description></item>
    /// <item><description>HTTP Signature (HMAC-SHA256).</description></item>
    /// </list>
    /// Each test drives the real token generators and then independently re-validates the produced
    /// signature so that a regression in the signing logic is caught, not just a structural change.
    /// </summary>
    [TestFixture]
    public class AuthenticationTokenTests
    {
        // Resolve the test 'Resource' folder relative to the test assembly output directory
        // (bin/<config>/<tfm>/ -> up three levels -> tests/ -> Resource).
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        private const string MerchantId = "testrest";
        private const string RunEnvironment = "apitest.cybersource.com";

        // testrest.p12 -> password/alias are both "testrest"; subject carries SERIALNUMBER=<ExpectedP12Kid>.
        private const string KeyFilename = "testrest";
        private const string KeyAlias = "testrest";
        private const string KeyPass = "testrest";
        private const string ExpectedP12Kid = "5112228966230177031579";

        private const string MerchantKeyId = "08c94330-f618-42a3-b09d-e1e43be5efda";
        private const string MerchantSecretKey = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

        private const string RequestTarget = "/pts/v2/payments";
        private const string SampleJson = "{\"amount\":\"100\"}";

        #region JWT with P12 certificate (RS256)

        [Test]
        public void JwtToken_P12Certificate_Get_ProducesValidRs256Token()
        {
            var authorize = new Authorize(JwtP12Credentials(), Request("GET", null), MleSettings());

            var token = authorize.GetToken();

            Assert.That(token, Is.InstanceOf<JwtToken>());
            Assert.That(token.BearerToken, Is.Not.Null.And.Not.Empty);

            var parts = token.BearerToken.Split('.');
            Assert.That(parts.Length, Is.EqualTo(3), "A JWS compact token must contain header, payload and signature.");

            var header = DecodeSegment(parts[0]);
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("RS256"));
            Assert.That(header["typ"]!.GetValue<string>(), Is.EqualTo("JWT"));
            Assert.That(header["kid"]!.GetValue<string>(), Is.EqualTo(ExpectedP12Kid),
                "kid must be the certificate serial number.");

            var payload = DecodeSegment(parts[1]);
            Assert.That(payload["iss"]!.GetValue<string>(), Is.EqualTo(MerchantId));
            Assert.That(payload["v-c-merchant-id"]!.GetValue<string>(), Is.EqualTo(MerchantId));
            Assert.That(payload["request-method"]!.GetValue<string>(), Is.EqualTo("GET"));
            Assert.That(payload["request-host"]!.GetValue<string>(), Is.EqualTo(RunEnvironment));
            Assert.That(payload["request-resource-path"]!.GetValue<string>(), Is.EqualTo(RequestTarget));
            Assert.That(payload["digest"], Is.Null, "GET requests must not carry a body digest claim.");

            Assert.That(VerifyRs256(parts), Is.True,
                "RS256 signature must verify against the certificate public key.");
        }

        [Test]
        public void JwtToken_P12Certificate_Post_IncludesBodyDigestAndValidSignature()
        {
            var authorize = new Authorize(JwtP12Credentials(), Request("POST", SampleJson), MleSettings());

            var token = authorize.GetToken();
            var parts = token.BearerToken.Split('.');

            var payload = DecodeSegment(parts[1]);
            Assert.That(payload["request-method"]!.GetValue<string>(), Is.EqualTo("POST"));
            Assert.That(payload["digest"]!.GetValue<string>(), Is.EqualTo(Sha256Base64(SampleJson)),
                "digest claim must be the Base64 SHA-256 hash of the request body.");
            Assert.That(payload["digestAlgorithm"]!.GetValue<string>(), Is.EqualTo("SHA-256"));

            Assert.That(VerifyRs256(parts), Is.True,
                "RS256 signature must verify against the certificate public key.");
        }

        [Test]
        public void JwtToken_P12Certificate_SetsTwoMinuteExpiry()
        {
            var authorize = new Authorize(JwtP12Credentials(), Request("GET", null), MleSettings());

            var token = authorize.GetToken();
            var payload = DecodeSegment(token.BearerToken.Split('.')[1]);

            long iat = payload["iat"]!.GetValue<long>();
            long exp = payload["exp"]!.GetValue<long>();
            Assert.That(exp - iat, Is.EqualTo(120), "exp must be exactly 120 seconds after iat.");
        }

        #endregion

        #region JWT with shared secret (HS256)

        [Test]
        public void JwtToken_SharedSecret_Get_ProducesValidHs256Token()
        {
            var authorize = new Authorize(JwtSharedSecretCredentials(), Request("GET", null), MleSettings());

            var token = authorize.GetToken();

            Assert.That(token, Is.InstanceOf<JwtToken>());
            Assert.That(token.BearerToken, Is.Not.Null.And.Not.Empty);

            var parts = token.BearerToken.Split('.');
            Assert.That(parts.Length, Is.EqualTo(3));

            var header = DecodeSegment(parts[0]);
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("HS256"));
            Assert.That(header["typ"]!.GetValue<string>(), Is.EqualTo("JWT"));
            Assert.That(header["kid"]!.GetValue<string>(), Is.EqualTo(MerchantKeyId),
                "kid must be the merchant key id for shared secret signing.");

            var payload = DecodeSegment(parts[1]);
            Assert.That(payload["iss"]!.GetValue<string>(), Is.EqualTo(MerchantId));
            Assert.That(payload["digest"], Is.Null, "GET requests must not carry a body digest claim.");

            AssertHmacSignatureMatches(parts);
        }

        [Test]
        public void JwtToken_SharedSecret_Post_IncludesBodyDigestAndValidSignature()
        {
            var authorize = new Authorize(JwtSharedSecretCredentials(), Request("POST", SampleJson), MleSettings());

            var token = authorize.GetToken();
            var parts = token.BearerToken.Split('.');

            var payload = DecodeSegment(parts[1]);
            Assert.That(payload["digest"]!.GetValue<string>(), Is.EqualTo(Sha256Base64(SampleJson)));
            Assert.That(payload["digestAlgorithm"]!.GetValue<string>(), Is.EqualTo("SHA-256"));

            AssertHmacSignatureMatches(parts);
        }

        #endregion

        #region HTTP Signature (HMAC-SHA256)

        [Test]
        public void HttpSignature_Get_ProducesCategory1Signature()
        {
            var authorize = new Authorize(HttpSignatureCredentials(), Request("GET", null), MleSettings());

            var token = authorize.GetSignature();

            Assert.That(token, Is.InstanceOf<HttpToken>());
            Assert.That(token.SignatureParam, Does.Contain($"keyid=\"{MerchantKeyId}\""));
            Assert.That(token.SignatureParam, Does.Contain("algorithm=\"HmacSHA256\""));
            Assert.That(token.SignatureParam, Does.Contain("headers=\"host date request-target v-c-merchant-id\""));
            Assert.That(token.Digest, Is.Null, "GET requests do not generate a payload digest.");

            var signingString =
                $"host: {token.HostName}\n" +
                $"date: {token.GmtDateTime}\n" +
                $"request-target: {token.HttpSignRequestTarget}\n" +
                $"v-c-merchant-id: {MerchantId}";

            Assert.That(ExtractSignature(token.SignatureParam), Is.EqualTo(ComputeHttpHmac(signingString)),
                "Embedded signature must match a freshly computed HMAC-SHA256 over the signing string.");
        }

        [Test]
        public void HttpSignature_Post_ProducesCategory2SignatureWithDigest()
        {
            var authorize = new Authorize(HttpSignatureCredentials(), Request("POST", SampleJson), MleSettings());

            var token = authorize.GetSignature();

            Assert.That(token.SignatureParam, Does.Contain("headers=\"host date request-target digest v-c-merchant-id\""));
            Assert.That(token.Digest, Is.EqualTo("SHA-256=" + Sha256Base64(SampleJson)),
                "POST digest header must be 'SHA-256=' followed by the Base64 SHA-256 of the body.");

            var signingString =
                $"host: {token.HostName}\n" +
                $"date: {token.GmtDateTime}\n" +
                $"request-target: {token.HttpSignRequestTarget}\n" +
                $"digest: {token.Digest}\n" +
                $"v-c-merchant-id: {MerchantId}";

            Assert.That(ExtractSignature(token.SignatureParam), Is.EqualTo(ComputeHttpHmac(signingString)),
                "Embedded signature must match a freshly computed HMAC-SHA256 over the signing string.");
        }

        #endregion

        #region Response MLE header claims

        [Test]
        public void JwtToken_ResponseMleEnabled_IncludesResponseMleAlgAndKidClaims()
        {
            var authorize = new Authorize(JwtP12Credentials(), Request("GET", null), ResponseMleSettings());

            var token = authorize.GetToken(isResponseMLEForApi: true);
            var payload = DecodeSegment(token.BearerToken.Split('.')[1]);

            // testrest.p12 is a CyberSource-generated certificate, so its kid is auto-extracted.
            Assert.That(payload["v-c-response-mle-kid"]!.GetValue<string>(), Is.EqualTo(ExpectedP12Kid));
            Assert.That(payload["v-c-response-mle-algo"]!.GetValue<string>(), Is.EqualTo("RSA-OAEP-256"));
        }

        [Test]
        public void JwtToken_ResponseMleDisabled_OmitsResponseMleClaims()
        {
            var authorize = new Authorize(JwtP12Credentials(), Request("GET", null), MleSettings());

            var token = authorize.GetToken(isResponseMLEForApi: false);
            var payload = DecodeSegment(token.BearerToken.Split('.')[1]);

            Assert.That(payload["v-c-response-mle-kid"], Is.Null);
            Assert.That(payload["v-c-response-mle-algo"], Is.Null);
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

        private static MerchantRequestSettings Request(string requestType, string requestJsonData)
        {
            return new MerchantRequestSettings(requestType, RequestTarget, requestJsonData);
        }

        private static MerchantMLESettings MleSettings()
        {
            // MLE is not exercised by these tests; an empty configuration disables it.
            return new MerchantMLESettings(new Dictionary<string, string>());
        }

        private static MerchantMLESettings ResponseMleSettings()
        {
            return new MerchantMLESettings(new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMlePrivateKeyFilePath", Path.Combine(ResourceDir, KeyFilename + ".p12") },
                { "responseMlePrivateKeyFilePassword", KeyPass }
            });
        }

        #endregion

        #region Crypto / decoding helpers

        private static bool VerifyRs256(string[] parts)
        {
            var certs = Cache.FetchCachedCertificate(Path.Combine(ResourceDir, KeyFilename + ".p12"), KeyPass);
            var cert = Cache.GetCertBasedOnKeyAlias(certs, KeyAlias);

            using (RSA rsa = cert.GetRSAPublicKey()!)
            {
                byte[] signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
                byte[] signature = Base64UrlDecode(parts[2]);
                return rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        private static void AssertHmacSignatureMatches(string[] parts)
        {
            using (var hmac = new HMACSHA256(Convert.FromBase64String(MerchantSecretKey)))
            {
                byte[] expected = hmac.ComputeHash(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]));
                Assert.That(Base64UrlDecode(parts[2]), Is.EqualTo(expected),
                    "HS256 signature must match a freshly computed HMAC-SHA256 of the signing input.");
            }
        }

        private static string ComputeHttpHmac(string signingString)
        {
            using (var hmac = new HMACSHA256(Convert.FromBase64String(MerchantSecretKey)))
            {
                return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(signingString)));
            }
        }

        private static string Sha256Base64(string data)
        {
            using (var sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(data)));
            }
        }

        private static string? ExtractSignature(string signatureParam)
        {
            Match match = Regex.Match(signatureParam, "signature=\"([^\"]+)\"");
            return match.Success ? match.Groups[1].Value : null;
        }

        private static JsonObject DecodeSegment(string segment)
        {
            string json = Encoding.UTF8.GetString(Base64UrlDecode(segment));
            return JsonNode.Parse(json)!.AsObject();
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
