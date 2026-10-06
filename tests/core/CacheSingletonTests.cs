using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.core
{
    /// <summary>
    /// Verifies the certificate cache is exposed as a single shared instance both through the
    /// static <see cref="Cache"/> facade and through dependency injection, and that the injected
    /// <see cref="ICache"/> is actually used by the token pipeline (i.e. the cache is now mockable).
    /// </summary>
    [TestFixture]
    public class CacheSingletonTests
    {
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        [Test]
        public void AddCertificateCache_RegistersICache_AsSharedSingleton()
        {
            var services = new ServiceCollection();

            services.AddCertificateCache();

            using ServiceProvider provider = services.BuildServiceProvider();

            var first = provider.GetService<ICache>();
            var second = provider.GetService<ICache>();

            Assert.That(first, Is.Not.Null, "ICache was not registered by AddCertificateCache().");
            Assert.That(first, Is.SameAs(second), "ICache should resolve to the same singleton instance every time.");
            Assert.That(first, Is.SameAs(CertificateCache.Default),
                "The DI registration must resolve to the same shared instance used by the static Cache facade.");
        }

        [Test]
        public void StaticFacade_DelegatesToTheSameSingletonInstance()
        {
            ILogger original = CertificateCache.Default.Logger;
            try
            {
                var spyLogger = new RecordingLogger();

                // Setting via the static facade must mutate the shared singleton...
                Cache.Logger = spyLogger;
                Assert.That(CertificateCache.Default.Logger, Is.SameAs(spyLogger),
                    "Cache.Logger setter did not delegate to CertificateCache.Default.");

                // ...and reading back through the facade must observe the singleton's state.
                Assert.That(Cache.Logger, Is.SameAs(spyLogger),
                    "Cache.Logger getter did not delegate to CertificateCache.Default.");
            }
            finally
            {
                CertificateCache.Default.Logger = original;
            }
        }

        [Test]
        public void JwtToken_UsesInjectedCache_WhenProvided()
        {
            (IMerchantCredentialSettings cred, IMerchantRequestSettings req) = BuildJwtCredentials();
            var fakeCache = new RecordingCache();

            var token = new JwtToken(cred, req, isSharedSecret: false, cache: fakeCache);

            Assert.That(fakeCache.FetchCachedCertificateCalls, Is.EqualTo(1),
                "JwtToken did not route certificate loading through the injected ICache.");
            Assert.That(fakeCache.GetCertBasedOnKeyAliasCalls, Is.EqualTo(1),
                "JwtToken did not route alias resolution through the injected ICache.");
            Assert.That(token.Certificate, Is.SameAs(fakeCache.CertToReturn),
                "JwtToken did not use the certificate returned by the injected ICache.");
        }

        [Test]
        public void JwtToken_FallsBackToDefaultSingleton_WhenNoCacheInjected()
        {
            (IMerchantCredentialSettings cred, IMerchantRequestSettings req) = BuildJwtCredentials();

            // No cache injected: the fallback must be CertificateCache.Default, which loads the real
            // certificate from disk (proving the default singleton path executed without an injected cache).
            var token = new JwtToken(cred, req, isSharedSecret: false);

            Assert.That(token.Certificate, Is.Not.Null,
                "Expected the default singleton cache to load the certificate when no cache is injected.");
        }

        [Test]
        public void StaticFacade_FetchCachedCertificate_DelegatesToSingleton_AndLoadsUsableCertificate()
        {
            string p12Path = Path.Combine(ResourceDir, "testrest.p12");

            X509Certificate2Collection certs = Cache.FetchCachedCertificate(p12Path, "testrest");
            X509Certificate2 cert = Cache.GetCertBasedOnKeyAlias(certs, "testrest");

            Assert.That(cert, Is.Not.Null,
                "The static Cache facade did not load the certificate through CertificateCache.Default.");
            Assert.That(cert.HasPrivateKey, Is.True,
                "The certificate loaded via the facade must expose its private key for RS256 signing.");
        }

        [Test]
        public void StaticFacade_PublicKeyCache_RoundTripsThroughSharedSingleton()
        {
            const string runEnvironment = "apitest.cybersource.com";
            const string publicKey = "sample-public-key-material";
            string kid = "unit-test-" + Guid.NewGuid().ToString("N");

            Cache.AddPublicKeyToCache(publicKey, runEnvironment, kid);

            Assert.That(Cache.GetPublicKeyFromCache(runEnvironment, kid), Is.EqualTo(publicKey),
                "The static facade must store and retrieve the public key through the shared singleton cache.");
            Assert.That(() => Cache.GetPublicKeyFromCache(runEnvironment, "missing-" + Guid.NewGuid().ToString("N")),
                Throws.Exception, "A public-key cache miss must surface as an exception rather than returning null.");
        }

        [Test]
        public void AddCertificateCache_ResolvedCache_DrivesAuthorizeTokenPipeline()
        {
            var services = new ServiceCollection();
            services.AddCertificateCache();
            using ServiceProvider provider = services.BuildServiceProvider();

            var cache = provider.GetRequiredService<ICache>();
            (IMerchantCredentialSettings cred, IMerchantRequestSettings req) = BuildJwtCredentials();
            var mle = new MerchantMLESettings(new Dictionary<string, string>());

            var token = (JwtToken)new Authorize(cred, req, mle, loggerFactory: null, cache: cache).GetToken();

            Assert.That(token.BearerToken, Is.Not.Null.And.Not.Empty,
                "The DI-resolved ICache did not drive the Authorize JWT pipeline to a signed token.");
            Assert.That(token.BearerToken.Split('.').Length, Is.EqualTo(3),
                "Expected a three-segment JWS from the DI-resolved pipeline.");
        }

        private static (IMerchantCredentialSettings cred, IMerchantRequestSettings req) BuildJwtCredentials()
        {
            Dictionary<string, string> config = new Dictionary<string, string>
            {
                { "merchantID", "testrest" },
                { "merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=" },
                { "merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda" },
                { "authenticationType", "jwt" },
                { "keysDirectory", ResourceDir },
                { "keyFilename", "testrest" },
                { "runEnvironment", "apitest.cybersource.com" },
                { "keyAlias", "testrest" },
                { "keyPass", "testrest" }
            };

            var cred = new MerchantCredentialSettings(config);
            var req = new MerchantRequestSettings("GET", "/pts/v2/payments", "");
            return (cred, req);
        }

        /// <summary>
        /// A hand-rolled <see cref="ICache"/> that records the calls made by the token pipeline and
        /// returns canned values. Demonstrates the cache is now mockable/testable.
        /// </summary>
        private sealed class RecordingCache : ICache
        {
            public X509Certificate2 CertToReturn { get; } = null;
            public int FetchCachedCertificateCalls { get; private set; }
            public int GetCertBasedOnKeyAliasCalls { get; private set; }

            public ILogger Logger { get; set; } = NullLogger.Instance;

            public X509Certificate2Collection FetchCachedCertificate(string p12FilePath, string keyPassword)
            {
                FetchCachedCertificateCalls++;
                return new X509Certificate2Collection();
            }

            public X509Certificate2 GetCertBasedOnKeyAlias(X509Certificate2Collection certs, string keyAlias)
            {
                GetCertBasedOnKeyAliasCalls++;
                return CertToReturn;
            }

            public RSAParameters FetchCachedRSAParameters(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public X509Certificate2 GetRequestMLECertFromCache(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public CachedMLEKId GetMLEKIdDataFromCache(MerchantConfig merchantConfig) => throw new NotImplementedException();
            public void AddPublicKeyToCache(string publickey, string runEnvironment, string kid) => throw new NotImplementedException();
            public string GetPublicKeyFromCache(string runEnvironment, string keyId) => throw new NotImplementedException();
            public AsymmetricAlgorithm GetMleResponsePrivateKeyFromFilePath(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null) => throw new NotImplementedException();
            public CachedMLEKId GetMLEKIdDataFromCache(string keyIssuer, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null) => throw new NotImplementedException();
            public X509Certificate2 GetRequestMLECertFromCache(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null) => throw new NotImplementedException();
        }

        private sealed class RecordingLogger : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
            public bool IsEnabled(LogLevel logLevel) => false;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new NullScope();
                public void Dispose() { }
            }
        }
    }
}
