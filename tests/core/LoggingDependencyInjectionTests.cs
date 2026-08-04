using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.core
{
    /// <summary>
    /// Verifies that logging is wired through dependency injection: components accept an
    /// optional <see cref="ILoggerFactory"/>, use it to create their logger, route log records
    /// through the injected logger, and gracefully fall back to a no-op logger when none is supplied.
    /// </summary>
    [TestFixture]
    public class LoggingDependencyInjectionTests
    {
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        [Test]
        public void Authorize_InterfaceConstructor_WithoutLoggerFactory_FallsBackToNullLogger_AndGeneratesToken()
        {
            (IMerchantCredentialSettings cred, IMerchantRequestSettings req, IMerchantMLESettings mle) = BuildJwtGetSettings();

            Authorize authorize = null;
            Assert.DoesNotThrow(() => authorize = new Authorize(cred, req, mle),
                "Authorize should construct without an injected ILoggerFactory (NullLogger fallback).");

            JwtToken token = null;
            Assert.DoesNotThrow(() => token = authorize.GetToken(),
                "Authorize should operate with the NullLogger fallback when no factory is injected.");
            Assert.That(token, Is.Not.Null);
        }

        [Test]
        public void Authorize_InterfaceConstructor_InjectedLoggerFactory_IsUsedToCreateAuthorizeLogger()
        {
            (IMerchantCredentialSettings cred, IMerchantRequestSettings req, IMerchantMLESettings mle) = BuildJwtGetSettings();
            var spyFactory = new SpyLoggerFactory();

            _ = new Authorize(cred, req, mle, spyFactory);

            Assert.That(spyFactory.CreatedCategories, Is.Not.Empty,
                "The injected ILoggerFactory was never used to create a logger.");
            Assert.That(spyFactory.CreatedCategories, Does.Contain(typeof(Authorize).FullName),
                "Authorize did not request a logger for its own category from the injected factory.");
        }

        [Test]
        public void Authorize_InterfaceConstructor_InjectedLogger_ReceivesLogRecordsDuringGetToken()
        {
            (IMerchantCredentialSettings cred, IMerchantRequestSettings req, IMerchantMLESettings mle) = BuildJwtGetSettings();
            var spyFactory = new SpyLoggerFactory();
            var authorize = new Authorize(cred, req, mle, spyFactory);

            authorize.GetToken();

            Assert.That(spyFactory.Logger.Entries, Is.Not.Empty,
                "The injected logger received no log records; logging is not routed through DI.");
            Assert.That(spyFactory.Logger.Entries.Any(e => e.Level == LogLevel.Debug), Is.True,
                "Expected at least one debug record to flow to the injected logger.");
            Assert.That(spyFactory.Logger.Entries.Any(e => e.Message.Contains("Content-Type")), Is.True,
                "Expected Authorize's diagnostic output to be routed to the injected logger.");
        }

        [Test]
        public void Authorize_MerchantConfigConstructor_InjectedLoggerFactory_IsUsedToCreateAuthorizeLogger()
        {
            MerchantConfig merchantConfig = BuildHttpSignatureMerchantConfig();
            var spyFactory = new SpyLoggerFactory();

            _ = new Authorize(merchantConfig, spyFactory);

            Assert.That(spyFactory.CreatedCategories, Does.Contain(typeof(Authorize).FullName),
                "The MerchantConfig-based Authorize constructor did not use the injected factory.");
        }

        [Test]
        public void Cache_Logger_DefaultsToNullLogger_AndSupportsInjection()
        {
            ILogger original = Cache.Logger;
            try
            {
                Assert.That(Cache.Logger, Is.SameAs(NullLogger.Instance),
                    "Cache.Logger should default to NullLogger.Instance (a no-op) until a logger is injected.");

                var spyLogger = new SpyLogger();
                Cache.Logger = spyLogger;

                Assert.That(Cache.Logger, Is.SameAs(spyLogger),
                    "Cache.Logger did not return the injected logger instance.");
            }
            finally
            {
                Cache.Logger = original;
            }
        }

        private static (IMerchantCredentialSettings cred, IMerchantRequestSettings req, IMerchantMLESettings mle) BuildJwtGetSettings()
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
                { "keyPass", "testrest" },
                { "enableLog", "" },
                { "logDirectory", "" },
                { "logFileName", "" },
                { "logFileMaxSize", "" },
                { "timeout", "" },
                { "proxyAddress", "" },
                { "proxyPort", "" }
            };

            var cred = new MerchantCredentialSettings(config);
            var mle = new MerchantMLESettings(config);
            var req = new MerchantRequestSettings("GET", "/pts/v2/payments", "");
            return (cred, req, mle);
        }

        private static MerchantConfig BuildHttpSignatureMerchantConfig()
        {
            Dictionary<string, string> config = new Dictionary<string, string>
            {
                { "merchantID", "testrest" },
                { "merchantsecretKey", "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=" },
                { "merchantKeyId", "08c94330-f618-42a3-b09d-e1e43be5efda" },
                { "authenticationType", "http_signature" },
                { "keysDirectory", ResourceDir },
                { "keyFilename", "" },
                { "runEnvironment", "apitest.cybersource.com" },
                { "keyAlias", "" },
                { "keyPass", "" },
                { "enableLog", "" },
                { "logDirectory", "" },
                { "logFileName", "" },
                { "logFileMaxSize", "" },
                { "timeout", "" },
                { "proxyAddress", "" },
                { "proxyPort", "" }
            };

            return new MerchantConfig(config) { RequestType = "GET" };
        }

        /// <summary>
        /// Records every category name requested and hands back a single shared <see cref="SpyLogger"/>
        /// so tests can assert that DI wiring actually flowed through this factory.
        /// </summary>
        private sealed class SpyLoggerFactory : ILoggerFactory
        {
            private readonly List<string> _createdCategories = new List<string>();
            private readonly SpyLogger _logger = new SpyLogger();

            public IReadOnlyList<string> CreatedCategories => _createdCategories;

            public SpyLogger Logger => _logger;

            public ILogger CreateLogger(string categoryName)
            {
                _createdCategories.Add(categoryName);
                return _logger;
            }

            public void AddProvider(ILoggerProvider provider)
            {
            }

            public void Dispose()
            {
            }
        }

        /// <summary>
        /// Captures every log record it receives so tests can assert that the injected logger is used.
        /// </summary>
        private sealed class SpyLogger : ILogger
        {
            private readonly List<LogEntry> _entries = new List<LogEntry>();

            public IReadOnlyList<LogEntry> Entries => _entries;

            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                _entries.Add(new LogEntry(logLevel, formatter(state, exception), exception));
            }
        }

        private sealed class LogEntry
        {
            public LogEntry(LogLevel level, string message, Exception? exception)
            {
                Level = level;
                Message = message;
                Exception = exception;
            }

            public LogLevel Level { get; }

            public string Message { get; }

            public Exception? Exception { get; }
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new NullScope();

            private NullScope()
            {
            }

            public void Dispose()
            {
            }
        }
    }
}
