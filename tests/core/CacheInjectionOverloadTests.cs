using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.core
{
    /// <summary>
    /// Verifies the certificate-cache injection overloads added to <see cref="JwtTokenGenerator"/>,
    /// <see cref="Authorize"/> and <see cref="MLEUtility"/>:
    /// <list type="bullet">
    /// <item><description>The explicit-cache overloads route every cache access through the injected <see cref="ICache"/>.</description></item>
    /// <item><description>Passing <c>null</c> to an explicit-cache overload throws <see cref="ArgumentNullException"/> (fail-fast); use the parameterless overload for the default.</description></item>
    /// <item><description>The backward-compatible overloads (no cache parameter) keep working and resolve to the default cache.</description></item>
    /// </list>
    /// The spy cache delegates to <see cref="CertificateCache.Default"/> so the real crypto still runs; the
    /// tests assert the routing (call counts) as well as the functional result.
    /// </summary>
    [TestFixture]
    public class CacheInjectionOverloadTests
    {
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        private static readonly string P12Path = Path.Combine(ResourceDir, "testrest.p12");

        private const string MerchantId = "testrest";
        private const string RunEnvironment = "apitest.cybersource.com";
        private const string KeyFilename = "testrest";
        private const string KeyAlias = "testrest";
        private const string KeyPass = "testrest";
        private const string ExpectedKid = "5112228966230177031579";
        private const string MerchantKeyId = "08c94330-f618-42a3-b09d-e1e43be5efda";
        private const string MerchantSecretKey = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";
        private const string RequestTarget = "/pts/v2/payments";

        private const string SamplePayload =
            "{\"clientReferenceInformation\":{\"code\":\"TC-12345\"}}";

        private const string ResponsePayload =
            "{\"id\":\"7000000000000000000001\",\"status\":\"AUTHORIZED\"}";

        #region JwtTokenGenerator

        [Test]
        public void JwtTokenGenerator_ExplicitCacheOverload_RoutesCertLoadingThroughInjectedCache()
        {
            var spy = new DelegatingSpyCache();

            // Certificate loading happens during construction (the generator builds its JwtToken there).
            var generator = new JwtTokenGenerator(
                JwtP12Credentials(), Request("GET"), Mle(), isResponseMLEForApi: false, loggerFactory: null, cache: spy);

            Assert.That(spy.FetchCachedCertificateCalls, Is.EqualTo(1),
                "JwtTokenGenerator did not route certificate loading through the injected cache.");
            Assert.That(spy.GetCertBasedOnKeyAliasCalls, Is.EqualTo(1),
                "JwtTokenGenerator did not route alias resolution through the injected cache.");

            AssertIsRs256Jwt(((JwtToken)generator.GetToken()).BearerToken);
        }

        [Test]
        public void JwtTokenGenerator_ExplicitCacheOverload_NullCache_Throws()
        {
            // The explicit-cache overload requires a non-null cache; use the parameterless overload for the default.
            Assert.That(
                () => new JwtTokenGenerator(
                    JwtP12Credentials(), Request("GET"), Mle(), isResponseMLEForApi: false, loggerFactory: null, cache: null),
                Throws.TypeOf<ArgumentNullException>());
        }

        [Test]
        public void JwtTokenGenerator_BackwardCompatOverload_UsesDefaultCache()
        {
            // The no-cache overload must remain available and resolve to the default cache.
            var generator = new JwtTokenGenerator(
                JwtP12Credentials(), Request("GET"), Mle(), isResponseMLEForApi: false);

            AssertIsRs256Jwt(((JwtToken)generator.GetToken()).BearerToken);
        }

        [Test]
        public void JwtTokenGenerator_SharedSecret_ExplicitCacheOverload_BypassesCertificateCache()
        {
            // HS256 signs with the shared secret and loads no certificate, so the injected cache must
            // stay untouched even when supplied. This pins the overload's behaviour on the shared-secret path.
            var spy = new DelegatingSpyCache();

            var generator = new JwtTokenGenerator(
                JwtSharedSecretCredentials(), Request("GET"), Mle(), isResponseMLEForApi: false, loggerFactory: null, cache: spy);

            AssertIsHs256Jwt(((JwtToken)generator.GetToken()).BearerToken);
            Assert.That(spy.FetchCachedCertificateCalls, Is.EqualTo(0),
                "The HS256 shared-secret path must not load a certificate from the cache.");
            Assert.That(spy.GetCertBasedOnKeyAliasCalls, Is.EqualTo(0),
                "The HS256 shared-secret path must not resolve a certificate alias.");
        }

        #endregion

        #region Authorize

        [Test]
        public void Authorize_ExplicitCacheOverload_RoutesTokenGenerationThroughInjectedCache()
        {
            var spy = new DelegatingSpyCache();

            var authorize = new Authorize(
                JwtP12Credentials(), Request("GET"), Mle(), loggerFactory: null, cache: spy);

            var token = (JwtToken)authorize.GetToken();

            Assert.That(spy.FetchCachedCertificateCalls, Is.EqualTo(1),
                "Authorize did not forward the injected cache down to the JWT token pipeline.");
            AssertIsRs256Jwt(token.BearerToken);
        }

        [Test]
        public void Authorize_ExplicitCacheOverload_NullCache_Throws()
        {
            Assert.That(
                () => new Authorize(
                    JwtP12Credentials(), Request("GET"), Mle(), loggerFactory: null, cache: null),
                Throws.TypeOf<ArgumentNullException>());
        }

        [Test]
        public void Authorize_BackwardCompatOverload_UsesDefaultCache()
        {
            var authorize = new Authorize(JwtP12Credentials(), Request("GET"), Mle());

            AssertIsRs256Jwt(((JwtToken)authorize.GetToken()).BearerToken);
        }

        #endregion

        #region MLEUtility

        [Test]
        public void MleUtility_EncryptRequestPayload_ExplicitCacheOverload_RoutesThroughInjectedCache()
        {
            var spy = new DelegatingSpyCache();

            object result = MLEUtility.EncryptRequestPayload(
                JwtP12Credentials(), RequestMleEnabled(alias: KeyAlias), SamplePayload, loggerFactory: null, cache: spy);

            Assert.That(result, Is.Not.Null);
            Assert.That(spy.GetRequestMleCertCalls, Is.EqualTo(1),
                "EncryptRequestPayload did not source the request MLE certificate from the injected cache.");
            Assert.That(result.ToString(), Does.Not.Contain(SamplePayload),
                "The cleartext payload must not survive in the MLE envelope.");
        }

        [Test]
        public void MleUtility_EncryptRequestPayload_NullCache_Throws()
        {
            Assert.That(
                () => MLEUtility.EncryptRequestPayload(
                    JwtP12Credentials(), RequestMleEnabled(alias: KeyAlias), SamplePayload, loggerFactory: null, cache: null),
                Throws.TypeOf<ArgumentNullException>());
        }

        [Test]
        public void MleUtility_ValidateAndAutoExtractResponseMleKid_ExplicitCacheOverload_RoutesThroughInjectedCache()
        {
            var spy = new DelegatingSpyCache();

            string kid = MLEUtility.ValidateAndAutoExtractResponseMleKid(
                MerchantId, ResponseMleWithP12Path(), loggerFactory: null, cache: spy);

            Assert.That(spy.GetMleKidDataCalls, Is.EqualTo(1),
                "ValidateAndAutoExtractResponseMleKid did not read the KID data from the injected cache.");
            Assert.That(kid, Is.EqualTo(ExpectedKid),
                "The auto-extracted responseMleKID must match the testrest certificate serial number.");
        }

        [Test]
        public void MleUtility_DecryptMleResponsePayload_ExplicitCacheOverload_RoutesThroughInjectedCache()
        {
            var spy = new DelegatingSpyCache();
            string encryptedResponseBody = BuildEncryptedResponseBody(ResponsePayload);

            string decrypted = MLEUtility.DecryptMleResponsePayload(
                JwtP12Credentials(), ResponseMleWithP12Path(), encryptedResponseBody, loggerFactory: null, cache: spy);

            Assert.That(spy.GetMleResponsePrivateKeyCalls, Is.EqualTo(1),
                "DecryptMleResponsePayload did not obtain the response private key from the injected cache.");
            Assert.That(decrypted, Is.EqualTo(ResponsePayload),
                "Decrypting with the matching private key must reproduce the original payload.");
        }

        [Test]
        public void MleUtility_ValidateAndAutoExtractResponseMleKid_NullCache_Throws()
        {
            Assert.That(
                () => MLEUtility.ValidateAndAutoExtractResponseMleKid(
                    MerchantId, ResponseMleWithP12Path(), loggerFactory: null, cache: null),
                Throws.TypeOf<ArgumentNullException>());
        }

        [Test]
        public void MleUtility_DecryptMleResponsePayload_NullCache_Throws()
        {
            string encryptedResponseBody = BuildEncryptedResponseBody(ResponsePayload);

            Assert.That(
                () => MLEUtility.DecryptMleResponsePayload(
                    JwtP12Credentials(), ResponseMleWithP12Path(), encryptedResponseBody, loggerFactory: null, cache: null),
                Throws.TypeOf<ArgumentNullException>());
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

        private static MerchantRequestSettings Request(string requestType) =>
            new MerchantRequestSettings(requestType, RequestTarget, "");

        private static MerchantMLESettings Mle() =>
            new MerchantMLESettings(new Dictionary<string, string>());

        private static MerchantMLESettings RequestMleEnabled(string alias)
        {
            var dict = new Dictionary<string, string>
            {
                { "enableRequestMLEForOptionalApisGlobally", "true" }
            };
            if (!string.IsNullOrEmpty(alias))
            {
                dict["requestMleKeyAlias"] = alias;
            }
            return new MerchantMLESettings(dict);
        }

        private static MerchantMLESettings ResponseMleWithP12Path()
        {
            return new MerchantMLESettings(new Dictionary<string, string>
            {
                { "enableResponseMleGlobally", "true" },
                { "responseMlePrivateKeyFilePath", P12Path },
                { "responseMlePrivateKeyFilePassword", KeyPass }
            });
        }

        #endregion

        #region Helpers

        private static void AssertIsRs256Jwt(string jwt)
        {
            Assert.That(jwt, Is.Not.Null.And.Not.Empty, "Expected a signed JWT.");
            string[] parts = jwt.Split('.');
            Assert.That(parts.Length, Is.EqualTo(3), "A JWS compact serialization must have three segments.");

            string headerJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            JsonObject header = JsonNode.Parse(headerJson)!.AsObject();
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("RS256"),
                "P12-based JWT tokens must be signed with RS256.");
        }

        private static void AssertIsHs256Jwt(string jwt)
        {
            Assert.That(jwt, Is.Not.Null.And.Not.Empty, "Expected a signed JWT.");
            string[] parts = jwt.Split('.');
            Assert.That(parts.Length, Is.EqualTo(3), "A JWS compact serialization must have three segments.");

            string headerJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            JsonObject header = JsonNode.Parse(headerJson)!.AsObject();
            Assert.That(header["alg"]!.GetValue<string>(), Is.EqualTo("HS256"),
                "Shared-secret JWT tokens must be signed with HS256.");
        }

        private static string BuildEncryptedResponseBody(string payload)
        {
            object encrypted = MLEUtility.EncryptRequestPayload(
                JwtP12Credentials(), RequestMleEnabled(alias: KeyAlias), payload);

            JsonObject envelope = JsonNode.Parse(encrypted.ToString())!.AsObject();
            string jwe = envelope["encryptedRequest"]!.GetValue<string>();
            return new JsonObject { ["encryptedResponse"] = jwe }.ToJsonString();
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

        /// <summary>
        /// An <see cref="ICache"/> spy that forwards every pipeline call to <see cref="CertificateCache.Default"/>
        /// (so the real certificate/key material and crypto are used) while counting the calls, proving the
        /// injected cache is the one the code path actually uses.
        /// </summary>
        private sealed class DelegatingSpyCache : ICache
        {
            private readonly ICache _inner = CertificateCache.Default;

            public int FetchCachedCertificateCalls { get; private set; }
            public int GetCertBasedOnKeyAliasCalls { get; private set; }
            public int GetRequestMleCertCalls { get; private set; }
            public int GetMleResponsePrivateKeyCalls { get; private set; }
            public int GetMleKidDataCalls { get; private set; }

            public ILogger Logger { get; set; } = NullLogger.Instance;

            public X509Certificate2Collection FetchCachedCertificate(string p12FilePath, string keyPassword)
            {
                FetchCachedCertificateCalls++;
                return _inner.FetchCachedCertificate(p12FilePath, keyPassword);
            }

            public X509Certificate2 GetCertBasedOnKeyAlias(X509Certificate2Collection certs, string keyAlias)
            {
                GetCertBasedOnKeyAliasCalls++;
                return _inner.GetCertBasedOnKeyAlias(certs, keyAlias);
            }

            public X509Certificate2 GetRequestMLECertFromCache(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
            {
                GetRequestMleCertCalls++;
                return _inner.GetRequestMLECertFromCache(merchantCredentialSettings, merchantMLESettings, loggerFactory);
            }

            public AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
            {
                GetMleResponsePrivateKeyCalls++;
                return _inner.GetMleResponsePrivateKeyFromFilePath(merchantCredentialSettings, merchantMLESettings, loggerFactory);
            }

            public CachedMLEKId GetMLEKIdDataFromCache(string keyIssuer, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
            {
                GetMleKidDataCalls++;
                return _inner.GetMLEKIdDataFromCache(keyIssuer, merchantMLESettings, loggerFactory);
            }

            // Legacy MerchantConfig-based members are not exercised by these tests.
            public RSAParameters FetchCachedRSAParameters(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public X509Certificate2 GetRequestMLECertFromCache(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public CachedMLEKId GetMLEKIdDataFromCache(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public void AddPublicKeyToCache(string publickey, string runEnvironment, string kid) => throw new NotImplementedException();
            public string GetPublicKeyFromCache(string runEnvironment, string keyId) => throw new NotImplementedException();
        }
    }
}
