using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using AuthenticationSdk.util;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AuthenticationSdkTests.NetCore.util
{
    /// <summary>
    /// Unit tests for <see cref="JWEUtilty"/>, the SDK's JWE decryptor used by Message Level Encryption.
    /// The tests build JWE compact tokens with an <b>independent</b> RSA-OAEP + AES-GCM encoder (so a
    /// successful decrypt proves real interop, not just symmetry with the SDK's own internal encoder),
    /// then exercise the two public decrypt entry points:
    /// <list type="bullet">
    /// <item><description><see cref="JWEUtilty.DecryptUsingRSA(RSA, string)"/> — platform RSA private-key path.</description></item>
    /// <item><description><see cref="JWEUtilty.DecryptUsingRSAParameters(RSAParameters, string)"/> — BouncyCastle path that supports RSA-OAEP-256 on every target framework.</description></item>
    /// </list>
    /// <para>
    /// The <see cref="JWEUtilty.DecryptUsingRSA(RSA, string)"/> tests use the non-exportable CNG key from
    /// <c>testrest.p12</c>, because on the .NET Framework legs the in-box <see cref="RSACryptoServiceProvider"/>
    /// returned by <see cref="RSA.Create()"/> cannot perform OAEP-256, whereas the certificate's CNG key can.
    /// The <see cref="JWEUtilty.DecryptUsingRSAParameters(RSAParameters, string)"/> tests use an ephemeral
    /// exportable key, since that path decrypts entirely with BouncyCastle and works on all frameworks.
    /// </para>
    /// </summary>
    [TestFixture]
    public class JWEUtilityTests
    {
        // Resolve the test 'Resource' folder relative to the test assembly output directory
        // (bin/<config>/<tfm>/ -> up three levels -> tests/ -> Resource).
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        private static readonly string P12Path = Path.Combine(ResourceDir, "testrest.p12");

        // testrest.p12 -> password/alias are both "testrest"; subject carries SERIALNUMBER=<Kid>.
        private const string KeyAlias = "testrest";
        private const string KeyPass = "testrest";
        private const string Kid = "5112228966230177031579";

        // Payload includes non-ASCII characters to verify UTF-8 round tripping of the cleartext.
        private const string SamplePayload =
            "{\"clientReferenceInformation\":{\"code\":\"TC-12345\"}," +
            "\"customer\":{\"name\":\"Ren\u00e9e M\u00fcller\"}}";

        // Exportable ephemeral keys for the BouncyCastle (RSAParameters) decrypt path.
        private static RSA _exportableRsa;
        private static RSA _otherRsa;

        [OneTimeSetUp]
        public void CreateEphemeralKeys()
        {
            _exportableRsa = RSA.Create();
            _exportableRsa.KeySize = 2048;

            _otherRsa = RSA.Create();
            _otherRsa.KeySize = 2048;
        }

        [OneTimeTearDown]
        public void DisposeEphemeralKeys()
        {
            _exportableRsa?.Dispose();
            _otherRsa?.Dispose();
        }

        #region DecryptUsingRSA (platform RSA private-key path)

        [Test]
        public void DecryptUsingRSA_RsaOaep256_A256Gcm_RoundTripsToOriginal()
        {
            string jwe = EncodeJwe(CertPublicParameters(), SamplePayload, alg: "RSA-OAEP-256", enc: "A256GCM");

            using (RSA privateKey = LoadTestCertificate().GetRSAPrivateKey()!)
            {
                string decrypted = JWEUtilty.DecryptUsingRSA(privateKey, jwe);
                Assert.That(decrypted, Is.EqualTo(SamplePayload));
            }
        }

        [Test]
        public void DecryptUsingRSA_RsaOaep_Sha1_RoundTripsToOriginal()
        {
            // RSA-OAEP selects SHA-1 for the key-unwrap (per RFC 7518 §4.3); verify that branch too.
            string jwe = EncodeJwe(CertPublicParameters(), SamplePayload, alg: "RSA-OAEP", enc: "A256GCM");

            using (RSA privateKey = LoadTestCertificate().GetRSAPrivateKey()!)
            {
                string decrypted = JWEUtilty.DecryptUsingRSA(privateKey, jwe);
                Assert.That(decrypted, Is.EqualTo(SamplePayload));
            }
        }

        [Test]
        public void DecryptUsingRSA_UnsupportedAlgHeader_LenientFallbackStillDecrypts()
        {
            // An unsupported "alg" makes strict header validation throw FormatException; the decryptor then
            // retries in lenient mode (skipping header validation), mirroring the legacy jose-jwt fallback.
            // The CEK is still wrapped with SHA-256 OAEP, which the lenient path's default padding matches.
            string jwe = EncodeJwe(CertPublicParameters(), SamplePayload, alg: "RSA-OAEP-CUSTOM", enc: "A256GCM");

            using (RSA privateKey = LoadTestCertificate().GetRSAPrivateKey()!)
            {
                string decrypted = JWEUtilty.DecryptUsingRSA(privateKey, jwe);
                Assert.That(decrypted, Is.EqualTo(SamplePayload),
                    "The lenient fallback must decrypt a token whose header fails strict algorithm validation.");
            }
        }

        [Test]
        public void DecryptUsingRSA_TamperedAuthTag_ThrowsInvalidCipherText()
        {
            // Flipping a byte of the GCM authentication tag must fail the integrity check rather than
            // returning altered plaintext. This is surfaced as a BouncyCastle InvalidCipherTextException.
            string jwe = EncodeJwe(CertPublicParameters(), SamplePayload, alg: "RSA-OAEP-256", enc: "A256GCM");
            string tampered = TamperAuthTag(jwe);

            using (RSA privateKey = LoadTestCertificate().GetRSAPrivateKey()!)
            {
                Assert.That(
                    () => JWEUtilty.DecryptUsingRSA(privateKey, tampered),
                    Throws.InstanceOf<InvalidCipherTextException>());
            }
        }

        #endregion

        #region DecryptUsingRSAParameters (BouncyCastle path)

        [Test]
        public void DecryptUsingRSAParameters_RsaOaep256_A256Gcm_RoundTripsToOriginal()
        {
            string jwe = EncodeJwe(_exportableRsa.ExportParameters(false), SamplePayload, alg: "RSA-OAEP-256", enc: "A256GCM");

            string decrypted = JWEUtilty.DecryptUsingRSAParameters(_exportableRsa.ExportParameters(true), jwe);

            Assert.That(decrypted, Is.EqualTo(SamplePayload));
        }

        [Test]
        public void DecryptUsingRSAParameters_WrongPrivateKey_FailsToUnwrapCek()
        {
            // A token wrapped to one key cannot be unwrapped with an unrelated key. BouncyCastle surfaces
            // this as one of two exceptions depending on the random relationship between the two moduli:
            //   - InvalidCipherTextException: the OAEP padding check fails, or
            //   - DataLengthException ("input too large for RSA cipher"): the wrapped-key integer is >= the
            //     wrong key's modulus, so the RSA core rejects it before padding is even checked.
            // Either outcome proves the wrong key cannot recover the content-encryption key.
            string jwe = EncodeJwe(_exportableRsa.ExportParameters(false), SamplePayload, alg: "RSA-OAEP-256", enc: "A256GCM");

            Assert.That(
                () => JWEUtilty.DecryptUsingRSAParameters(_otherRsa.ExportParameters(true), jwe),
                Throws.InstanceOf<InvalidCipherTextException>().Or.InstanceOf<DataLengthException>());
        }

        [Test]
        public void DecryptUsingRSAParameters_InvalidCompactSerialization_ThrowsFormatException()
        {
            // A token without exactly five dot-separated parts is rejected before any crypto runs, and the
            // failure propagates out of the strict/lenient fallback as a FormatException.
            Assert.That(
                () => JWEUtilty.DecryptUsingRSAParameters(_exportableRsa.ExportParameters(true), "only.four.parts.here"),
                Throws.TypeOf<FormatException>());
        }

        #endregion

        #region Independent JWE encoder + helpers

        /// <summary>
        /// Builds a JWE compact serialization (header.encryptedKey.iv.ciphertext.tag) using RSA-OAEP
        /// (SHA-1 for "RSA-OAEP", otherwise SHA-256) to wrap a fresh 256-bit CEK, and AES-256-GCM to
        /// encrypt the payload — independently of <see cref="JWEUtilty"/>'s own internal encoder.
        /// </summary>
        private static string EncodeJwe(RSAParameters publicParameters, string payload, string alg, string enc)
        {
            var header = new JsonObject
            {
                ["alg"] = alg,
                ["enc"] = enc,
                ["kid"] = Kid,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
            string headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));

            byte[] cek = new byte[32];
            byte[] iv = new byte[12];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(cek);
                rng.GetBytes(iv);
            }

            IDigest oaepDigest = string.Equals(alg, "RSA-OAEP", StringComparison.Ordinal)
                ? (IDigest)new Sha1Digest()
                : new Sha256Digest();

            var bcPublicKey = DotNetUtilities.GetRsaPublicKey(publicParameters);
            var oaep = new OaepEncoding(new RsaBlindedEngine(), oaepDigest);
            oaep.Init(true, bcPublicKey);
            byte[] encryptedKey = oaep.ProcessBlock(cek, 0, cek.Length);

            byte[] aad = Encoding.ASCII.GetBytes(headerEncoded);
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(cek), 128, iv, aad));
            byte[] output = new byte[gcm.GetOutputSize(payloadBytes.Length)];
            int written = gcm.ProcessBytes(payloadBytes, 0, payloadBytes.Length, output, 0);
            written += gcm.DoFinal(output, written);

            int cipherLen = written - 16;
            byte[] cipherText = new byte[cipherLen];
            byte[] authTag = new byte[16];
            Buffer.BlockCopy(output, 0, cipherText, 0, cipherLen);
            Buffer.BlockCopy(output, cipherLen, authTag, 0, 16);

            return headerEncoded
                + "." + Base64UrlEncoder.Encode(encryptedKey)
                + "." + Base64UrlEncoder.Encode(iv)
                + "." + Base64UrlEncoder.Encode(cipherText)
                + "." + Base64UrlEncoder.Encode(authTag);
        }

        private static string TamperAuthTag(string jwe)
        {
            string[] parts = jwe.Split('.');
            byte[] tag = Base64UrlEncoder.DecodeBytes(parts[4]);
            tag[0] ^= 0xFF;
            parts[4] = Base64UrlEncoder.Encode(tag);
            return string.Join(".", parts);
        }

        private static RSAParameters CertPublicParameters()
        {
            using (RSA publicKey = LoadTestCertificate().GetRSAPublicKey()!)
            {
                return publicKey.ExportParameters(false);
            }
        }

        private static X509Certificate2 LoadTestCertificate()
        {
            X509Certificate2Collection certs = Cache.FetchCachedCertificate(P12Path, KeyPass);
            return Cache.GetCertBasedOnKeyAlias(certs, KeyAlias);
        }

        #endregion
    }
}
