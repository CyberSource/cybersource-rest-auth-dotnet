using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.core;
using NUnit.Framework;

namespace AuthenticationSdkTests.NetCore.core
{
    /// <summary>
    /// Unit tests covering the relationship between the <see cref="MerchantCredentialSettings.UseMetaKey"/>
    /// and <see cref="MerchantCredentialSettings.PortfolioId"/> properties.
    /// <para>
    /// The two fields are coupled in two places that these tests exercise through the public constructor:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// Population: <c>PortfolioId</c> defaults to <see cref="string.Empty"/> and is only read from the
    /// configuration when <c>useMetaKey</c> is present and parses to <c>true</c>. When meta key is off,
    /// absent, or empty, a supplied <c>portfolioID</c> is ignored.
    /// </description></item>
    /// <item><description>
    /// Validation: when <c>useMetaKey</c> is <c>true</c> a missing or empty <c>portfolioID</c> is rejected;
    /// an empty <c>useMetaKey</c> is treated as <c>false</c>; a non-boolean <c>useMetaKey</c> is rejected.
    /// </description></item>
    /// </list>
    /// The first group of tests uses HTTP Signature as the carrier authentication type (simplest mandatory
    /// configuration, no file I/O) to focus on the meta-key/portfolio coupling at construction time.
    /// A second group then verifies that, when a PortfolioId is supplied with <c>useMetaKey=true</c>, it
    /// propagates into the correct location of the generated credentials:
    /// <list type="bullet">
    /// <item><description>HTTP Signature: the PortfolioId occupies the <c>v-c-merchant-id</c> slot of the signed string.</description></item>
    /// <item><description>JWT (shared secret and P12): the PortfolioId becomes the <c>iss</c> claim while <c>v-c-merchant-id</c> stays the MerchantId.</description></item>
    /// </list>
    /// </summary>
    [TestFixture]
    public class MerchantCredentialSettingsMetaKeyTests
    {
        private const string PortfolioIdValue = "PF-12345";

        // Shared credential values reused across the carrier auth types for the propagation tests.
        private const string MerchantId = "testrest";
        private const string RunEnvironment = "apitest.cybersource.com";
        private const string MerchantKeyId = "08c94330-f618-42a3-b09d-e1e43be5efda";
        private const string MerchantSecretKey = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";
        private const string RequestTarget = "/pts/v2/payments";

        // testrest.p12 -> password/alias are both "testrest"; used by the JWT+P12 propagation test.
        private const string KeyFilename = "testrest";
        private const string KeyAlias = "testrest";
        private const string KeyPass = "testrest";

        // Resolve the test 'Resource' folder relative to the test assembly output directory
        // (bin/<config>/<tfm>/ -> up three levels -> tests/ -> Resource).
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        /// <summary>
        /// Builds a minimal, valid HTTP Signature credential configuration with no meta-key keys set.
        /// Individual tests add or override <c>useMetaKey</c> / <c>portfolioID</c> to exercise the coupling.
        /// </summary>
        private static Dictionary<string, string> BaseHttpSignatureConfig()
        {
            return new Dictionary<string, string>
            {
                { "merchantID", MerchantId },
                { "authenticationType", "http_signature" },
                { "runEnvironment", RunEnvironment },
                { "merchantKeyId", MerchantKeyId },
                { "merchantsecretKey", MerchantSecretKey }
            };
        }

        #region UseMetaKey enabled -> PortfolioId is populated

        [Test]
        public void UseMetaKeyTrue_WithPortfolioId_PopulatesBothProperties()
        {
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = "true";
            config["portfolioID"] = PortfolioIdValue;

            var settings = new MerchantCredentialSettings(config);

            Assert.That(settings.UseMetaKey, Is.EqualTo("true"));
            Assert.That(settings.PortfolioId, Is.EqualTo(PortfolioIdValue),
                "When useMetaKey is true the portfolioID must be read into PortfolioId.");
        }

        [Test]
        public void UseMetaKeyTrue_MixedCase_StillPopulatesPortfolioId()
        {
            // bool.Parse / bool.TryParse are case-insensitive, so "True" enables meta key just like "true".
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = "True";
            config["portfolioID"] = PortfolioIdValue;

            var settings = new MerchantCredentialSettings(config);

            Assert.That(settings.UseMetaKey, Is.EqualTo("True"), "The raw useMetaKey string is preserved verbatim.");
            Assert.That(settings.PortfolioId, Is.EqualTo(PortfolioIdValue));
        }

        #endregion

        #region UseMetaKey disabled / absent -> PortfolioId is ignored

        [Test]
        public void UseMetaKeyFalse_WithPortfolioId_IgnoresPortfolioId()
        {
            // The coupling: PortfolioId is only read when meta key is enabled, so a portfolioID supplied
            // alongside useMetaKey=false is deliberately ignored and PortfolioId stays empty.
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = "false";
            config["portfolioID"] = PortfolioIdValue;

            var settings = new MerchantCredentialSettings(config);

            Assert.That(settings.UseMetaKey, Is.EqualTo("false"));
            Assert.That(settings.PortfolioId, Is.EqualTo(string.Empty),
                "When useMetaKey is false the portfolioID must be ignored, leaving PortfolioId empty.");
        }

        [Test]
        public void UseMetaKeyEmptyString_TreatedAsFalse_PortfolioIdIgnored()
        {
            // An empty useMetaKey is normalized to "false" by the validator (so no portfolio is required),
            // and population skips the portfolioID. The raw empty string is still preserved on the property.
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = string.Empty;
            config["portfolioID"] = PortfolioIdValue;

            var settings = new MerchantCredentialSettings(config);

            Assert.That(settings.UseMetaKey, Is.EqualTo(string.Empty));
            Assert.That(settings.PortfolioId, Is.EqualTo(string.Empty));
        }

        [Test]
        public void UseMetaKeyAbsent_LeavesUseMetaKeyNull_AndPortfolioIdEmpty()
        {
            // No meta-key keys at all: validation is skipped and PortfolioId keeps its empty default.
            var config = BaseHttpSignatureConfig();

            var settings = new MerchantCredentialSettings(config);

            Assert.That(settings.UseMetaKey, Is.Null, "An absent useMetaKey leaves the property null.");
            Assert.That(settings.PortfolioId, Is.EqualTo(string.Empty));
        }

        #endregion

        #region UseMetaKey enabled but PortfolioId missing/empty -> rejected

        [Test]
        public void UseMetaKeyTrue_WithoutPortfolioId_ThrowsKeyNotFound()
        {
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = "true";
            // portfolioID intentionally omitted

            Assert.That(
                () => new MerchantCredentialSettings(config),
                Throws.TypeOf<KeyNotFoundException>()
                      .With.Message.Contains("Portfolio ID is mandatory when useMetaKey is true"));
        }

        [Test]
        public void UseMetaKeyTrue_WithEmptyPortfolioId_ThrowsKeyNotFound()
        {
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = "true";
            config["portfolioID"] = string.Empty;

            Assert.That(
                () => new MerchantCredentialSettings(config),
                Throws.TypeOf<KeyNotFoundException>()
                      .With.Message.Contains("Portfolio ID is mandatory when useMetaKey is true"));
        }

        #endregion

        #region UseMetaKey is not a valid boolean -> rejected

        [Test]
        public void UseMetaKeyInvalidValue_ThrowsException()
        {
            // A non-boolean useMetaKey is rejected during mandatory validation regardless of portfolioID.
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = "yes";
            config["portfolioID"] = PortfolioIdValue;

            Assert.That(
                () => new MerchantCredentialSettings(config),
                Throws.TypeOf<Exception>()
                      .With.Message.Contains("Invalid value for useMetaKey"));
        }

        #endregion

        #region Mutable setters are independent passthroughs

        [Test]
        public void SetUseMetaKeyAndSetPortfolioId_AreIndependentPassthroughs()
        {
            // The useMetaKey/portfolioID coupling is enforced at construction; the mutable setters are plain
            // passthroughs that do not re-validate, so they can be set independently after the fact.
            var settings = new MerchantCredentialSettings(BaseHttpSignatureConfig());
            Assert.That(settings.UseMetaKey, Is.Null, "Precondition: base config has no useMetaKey.");
            Assert.That(settings.PortfolioId, Is.EqualTo(string.Empty), "Precondition: PortfolioId starts empty.");

            settings.SetUseMetaKey("true");
            settings.SetPortfolioId(PortfolioIdValue);

            Assert.That(settings.UseMetaKey, Is.EqualTo("true"));
            Assert.That(settings.PortfolioId, Is.EqualTo(PortfolioIdValue));
        }

        [Test]
        public void SetUseMetaKeyTrue_DoesNotValidatePortfolioId()
        {
            // Enabling meta key via the setter must not throw even though no portfolioID has been provided,
            // confirming the relationship is only validated through the constructor's validation pass.
            var settings = new MerchantCredentialSettings(BaseHttpSignatureConfig());

            Assert.That(() => settings.SetUseMetaKey("true"), Throws.Nothing);
            Assert.That(settings.UseMetaKey, Is.EqualTo("true"));
            Assert.That(settings.PortfolioId, Is.EqualTo(string.Empty));
        }

        #endregion

        #region PortfolioId propagation into generated credentials

        [Test]
        public void HttpSignature_UseMetaKey_PortfolioIdReplacesMerchantIdInSignedString()
        {
            // For HTTP Signature with meta key enabled, the PortfolioId takes the v-c-merchant-id slot of the
            // signed string (the MerchantId is no longer signed). Verify by recomputing the HMAC over a signing
            // string built with PortfolioId and matching it to the embedded signature.
            var config = BaseHttpSignatureConfig();
            config["useMetaKey"] = "true";
            config["portfolioID"] = PortfolioIdValue;

            var credentials = new MerchantCredentialSettings(config);
            Assert.That(credentials.PortfolioId, Is.EqualTo(PortfolioIdValue));

            var token = new Authorize(credentials, Request("GET", null), MleSettings()).GetSignature();

            string signingStringWithPortfolio =
                $"host: {token.HostName}\n" +
                $"date: {token.GmtDateTime}\n" +
                $"request-target: {token.HttpSignRequestTarget}\n" +
                $"v-c-merchant-id: {PortfolioIdValue}";

            Assert.That(ExtractSignature(token.SignatureParam), Is.EqualTo(ComputeHttpHmac(signingStringWithPortfolio)),
                "With useMetaKey=true the signed v-c-merchant-id value must be the PortfolioId.");

            string signingStringWithMerchantId =
                $"host: {token.HostName}\n" +
                $"date: {token.GmtDateTime}\n" +
                $"request-target: {token.HttpSignRequestTarget}\n" +
                $"v-c-merchant-id: {MerchantId}";

            Assert.That(ExtractSignature(token.SignatureParam), Is.Not.EqualTo(ComputeHttpHmac(signingStringWithMerchantId)),
                "The signature must no longer be computed over the MerchantId when meta key is enabled.");
        }

        [Test]
        public void JwtSharedSecret_UseMetaKey_PortfolioIdBecomesIssuerClaim()
        {
            // For JWT (HS256) with meta key enabled, the 'iss' claim becomes the PortfolioId while the
            // 'v-c-merchant-id' claim stays the MerchantId.
            var config = JwtSharedSecretConfig();
            config["useMetaKey"] = "true";
            config["portfolioID"] = PortfolioIdValue;

            var credentials = new MerchantCredentialSettings(config);
            Assert.That(credentials.PortfolioId, Is.EqualTo(PortfolioIdValue));

            var token = new Authorize(credentials, Request("GET", null), MleSettings()).GetToken();
            var payload = DecodeSegment(token.BearerToken.Split('.')[1]);

            Assert.That(payload["iss"]!.GetValue<string>(), Is.EqualTo(PortfolioIdValue),
                "With useMetaKey=true the JWT issuer (iss) claim must be the PortfolioId.");
            Assert.That(payload["v-c-merchant-id"]!.GetValue<string>(), Is.EqualTo(MerchantId),
                "v-c-merchant-id must remain the MerchantId even when meta key is enabled.");
        }

        [Test]
        public void JwtP12_UseMetaKey_PortfolioIdBecomesIssuerClaim_AndDoesNotThrow()
        {
            // For JWT (RS256 / P12) with meta key enabled, generating the token must not throw, and the
            // PortfolioId must surface as the 'iss' claim while 'v-c-merchant-id' stays the MerchantId.
            var config = JwtP12Config();
            config["useMetaKey"] = "true";
            config["portfolioID"] = PortfolioIdValue;

            var credentials = new MerchantCredentialSettings(config);
            Assert.That(credentials.PortfolioId, Is.EqualTo(PortfolioIdValue));

            JwtToken token = null;
            Assert.That(() => token = new Authorize(credentials, Request("GET", null), MleSettings()).GetToken(),
                Throws.Nothing, "JWT+P12 token generation must not throw when a PortfolioId is supplied.");

            var payload = DecodeSegment(token.BearerToken.Split('.')[1]);
            Assert.That(payload["iss"]!.GetValue<string>(), Is.EqualTo(PortfolioIdValue),
                "With useMetaKey=true the JWT issuer (iss) claim must be the PortfolioId.");
            Assert.That(payload["v-c-merchant-id"]!.GetValue<string>(), Is.EqualTo(MerchantId),
                "v-c-merchant-id must remain the MerchantId even when meta key is enabled.");
        }

        #endregion

        #region Settings builders for propagation tests

        private static Dictionary<string, string> JwtSharedSecretConfig()
        {
            return new Dictionary<string, string>
            {
                { "merchantID", MerchantId },
                { "authenticationType", "jwt" },
                { "jwtKeyType", "SHARED_SECRET" },
                { "runEnvironment", RunEnvironment },
                { "merchantKeyId", MerchantKeyId },
                { "merchantsecretKey", MerchantSecretKey }
            };
        }

        private static Dictionary<string, string> JwtP12Config()
        {
            return new Dictionary<string, string>
            {
                { "merchantID", MerchantId },
                { "authenticationType", "jwt" },
                { "jwtKeyType", "P12" },
                { "runEnvironment", RunEnvironment },
                { "keysDirectory", ResourceDir },
                { "keyFilename", KeyFilename },
                { "keyAlias", KeyAlias },
                { "keyPass", KeyPass }
            };
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

        #endregion

        #region Crypto / decoding helpers

        private static string ComputeHttpHmac(string signingString)
        {
            using (var hmac = new HMACSHA256(Convert.FromBase64String(MerchantSecretKey)))
            {
                return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(signingString)));
            }
        }

        private static string ExtractSignature(string signatureParam)
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
