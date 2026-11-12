using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AuthenticationSdk.core;
using Microsoft.IdentityModel.Tokens;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AuthenticationSdk.util
{
    public static class JWEUtilty
    {
        [Obsolete("This method has been marked as Deprecated and will be removed in coming releases. Use DecryptUsingRSAParameters(RSAParameters, string) instead.", false)]
        public static string DecryptUsingPEM(MerchantConfig merchantConfig, string encodedData)
        {
            RSAParameters rsaParams = Cache.FetchCachedRSAParameters(merchantConfig);
            return DecryptUsingRSAParameters(rsaParams, encodedData);
        }

        public static string DecryptUsingRSAParameters(RSAParameters rsaParameters, string encodedData)
        {
            // Unwrap the content-encryption key with BouncyCastle directly from the raw RSA parameters.
            // This path is fully cross-platform and supports RSA-OAEP-256 on every target framework,
            // including .NET Framework, whose default RSACryptoServiceProvider cannot perform OAEP-256.
            return DecryptJwe(encodedData, (encryptedKey, alg) => UnwrapCekWithBouncyCastle(rsaParameters, encryptedKey, alg));
        }

        /// <summary>
        /// Decrypts a JWE token using an <see cref="RSA"/> private key directly, without exporting the
        /// private key material. This is required for keys that cannot be exported to plaintext — e.g.
        /// Windows CNG keys loaded from a PFX/P12 whose export policy is <c>AllowExport</c> only, for
        /// which <see cref="RSA.ExportParameters(bool)"/> throws a CryptographicException
        /// ("The requested operation is not supported."). The private-key decrypt used to unwrap the
        /// content-encryption key works regardless of the key's export policy.
        /// </summary>
        public static string DecryptUsingRSA(RSA rsaPrivateKey, string encodedData)
        {
            // Unwrap the content-encryption key by decrypting directly with the RSA private key.
            // This is a private-key operation that does NOT require exporting the key material, so
            // non-exportable Windows CNG keys (PFX/P12 with ExportPolicy = AllowExport) work correctly.
            return DecryptJwe(encodedData, (encryptedKey, alg) => rsaPrivateKey.Decrypt(encryptedKey, OaepPaddingFor(alg)));
        }

        /// <summary>
        /// Runs JWE decryption in strict mode first (validating the protected header's "alg"/"enc") and
        /// falls back to lenient mode (skipping header algorithm validation) on a FormatException.
        /// The supplied <paramref name="unwrapCek"/> delegate performs the RSA key-unwrap step, receiving
        /// the encrypted key bytes and the JWE "alg" and returning the content-encryption key.
        /// </summary>
        private static string DecryptJwe(string encodedData, Func<byte[], string, byte[]> unwrapCek)
        {
            try
            {
                // Strict mode: validate that the JWE header declares the expected alg and enc
                return DecryptJweCompact(encodedData, lenient: false, unwrapCek);
            }
            catch (FormatException)
            {
                // Lenient fallback: skip header algorithm validation
                // (mirrors the old jose-jwt fallback: JWT.Decode(data, rsa) without specifying algorithms)
                return DecryptJweCompact(encodedData, lenient: true, unwrapCek);
            }
        }

        /// <summary>
        /// Decrypts a JWE compact serialization token using RSA-OAEP or RSA-OAEP-256 + AES-256-GCM.
        /// The content-encryption key is unwrapped by the supplied <paramref name="unwrapCek"/> delegate
        /// (which receives the encrypted key bytes and the JWE "alg"), and the payload is decrypted with
        /// AES-256-GCM via BouncyCastle.Cryptography. The OAEP hash is selected from the "alg" value:
        ///   - "RSA-OAEP"     → SHA-1   (per RFC 7518 §4.3)
        ///   - "RSA-OAEP-256" → SHA-256 (per RFC 7518 §4.3)
        /// When <paramref name="lenient"/> is false, the protected header's "alg" and "enc"
        /// values are validated to be one of the supported algorithms before decryption.
        /// </summary>
        private static string DecryptJweCompact(string token, bool lenient, Func<byte[], string, byte[]> unwrapCek)
        {
            // JWE compact: header.encryptedKey.iv.ciphertext.tag
            string[] parts = token.Split('.');
            if (parts.Length != 5)
            {
                throw new FormatException("Invalid JWE compact serialization: expected 5 parts.");
            }

            string protectedHeader   = parts[0];
            byte[] encryptedKeyBytes = Base64UrlEncoder.DecodeBytes(parts[1]);
            byte[] ivBytes           = Base64UrlEncoder.DecodeBytes(parts[2]);
            byte[] cipherTextBytes   = Base64UrlEncoder.DecodeBytes(parts[3]);
            byte[] authTagBytes      = Base64UrlEncoder.DecodeBytes(parts[4]);

            // Always parse the JWE protected header to determine the actual algorithms
            string alg = null;
            string enc = null;
            byte[] headerBytes = Base64UrlEncoder.DecodeBytes(protectedHeader);
            string headerJson  = Encoding.UTF8.GetString(headerBytes);

            var headerNode = JsonNode.Parse(headerJson).AsObject();
            alg = headerNode["alg"]?.GetValue<string>();
            enc = headerNode["enc"]?.GetValue<string>();

            if (!lenient)
            {
                ValidateJweHeader(headerNode, alg, enc);
            }

            // Step 1: Unwrap the CEK using RSA-OAEP / RSA-OAEP-256 via the supplied delegate.
            byte[] cek = unwrapCek(encryptedKeyBytes, alg);

            // Step 2: Decrypt the ciphertext using AES-256-GCM
            // GCM AAD is the ASCII bytes of the protected header string (per RFC 7516)
            byte[] aad = Encoding.ASCII.GetBytes(protectedHeader);

            // BouncyCastle GCM: append the 16-byte auth tag to the ciphertext
            byte[] cipherTextWithTag = new byte[cipherTextBytes.Length + authTagBytes.Length];
            Buffer.BlockCopy(cipherTextBytes, 0, cipherTextWithTag, 0, cipherTextBytes.Length);
            Buffer.BlockCopy(authTagBytes,    0, cipherTextWithTag, cipherTextBytes.Length, authTagBytes.Length);

            var keyParam    = new KeyParameter(cek);
            var gcmParams   = new AeadParameters(keyParam, 128, ivBytes, aad);
            var gcmCipher   = new GcmBlockCipher(new AesEngine());
            gcmCipher.Init(false, gcmParams);

            byte[] plainText = new byte[gcmCipher.GetOutputSize(cipherTextWithTag.Length)];
            int len = gcmCipher.ProcessBytes(cipherTextWithTag, 0, cipherTextWithTag.Length, plainText, 0);
            len += gcmCipher.DoFinal(plainText, len);

            return Encoding.UTF8.GetString(plainText, 0, len);
        }

        /// <summary>
        /// Selects the RSA-OAEP padding for the CEK unwrap based on the JWE "alg" header:
        /// RSA-OAEP → SHA-1, RSA-OAEP-256 (or any other value) → SHA-256 (per RFC 7518 §4.3).
        /// </summary>
        private static RSAEncryptionPadding OaepPaddingFor(string alg)
            => string.Equals(alg, "RSA-OAEP", StringComparison.Ordinal)
                ? RSAEncryptionPadding.OaepSHA1
                : RSAEncryptionPadding.OaepSHA256;

        /// <summary>
        /// Unwraps the JWE content-encryption key using BouncyCastle's OAEP implementation from the
        /// supplied raw RSA parameters. Used by the <see cref="RSAParameters"/> overload so RSA-OAEP-256
        /// works on every target framework without relying on the platform RSA provider.
        /// The OAEP hash digest is selected from the JWE "alg" header (per RFC 7518 §4.3).
        /// </summary>
        private static byte[] UnwrapCekWithBouncyCastle(RSAParameters rsaParameters, byte[] encryptedKey, string alg)
        {
            IDigest oaepDigest = string.Equals(alg, "RSA-OAEP", StringComparison.Ordinal)
                ? (IDigest)new Sha1Digest()
                : new Sha256Digest();

            var bcPrivateKey = DotNetUtilities.GetRsaKeyPair(rsaParameters).Private;
            var encoding     = new OaepEncoding(new RsaBlindedEngine(), oaepDigest);
            encoding.Init(false, bcPrivateKey);
            return encoding.ProcessBlock(encryptedKey, 0, encryptedKey.Length);
        }

        /// <summary>
        /// Validates that the JWE protected header declares a supported algorithm and encryption method.
        /// Supported alg: RSA-OAEP, RSA-OAEP-256. Supported enc: A256GCM.
        /// Throws FormatException if the values are missing or unsupported.
        /// </summary>
        private static void ValidateJweHeader(JsonNode headers, string alg, string enc)
        {
            if (headers == null)
            {
                throw new FormatException("JWE protected header could not be deserialized.");
            }

            if (string.IsNullOrEmpty(alg))
            {
                throw new FormatException("JWE header is missing the 'alg' parameter.");
            }

            var supportedAlgs = new[] { "RSA-OAEP-256", "RSA-OAEP" };
            if (!supportedAlgs.Contains(alg, StringComparer.Ordinal))
            {
                throw new FormatException($"Unexpected JWE algorithm: '{alg}'. Expected '{string.Join("' or '", supportedAlgs)}'.");
            }

            if (string.IsNullOrEmpty(enc))
            {
                throw new FormatException("JWE header is missing the 'enc' parameter.");
            }

            var supportedEncs = new[] { "A256GCM", "A128GCM" };
            if (!supportedEncs.Contains(enc, StringComparer.Ordinal))
            {
                throw new FormatException($"Unexpected JWE encryption: '{enc}'. Expected '{string.Join("' or '", supportedEncs)}'.");
            }
        }

        /// <summary>
        /// Encrypts a byte payload as a JWE compact token using RSA-OAEP-256 + AES-256-GCM
        /// via BouncyCastle.Cryptography — identical output format to jose-jwt JWT.EncodeBytes.
        /// </summary>
        /// <param name="contentType">
        /// The JWE "cty" (content type) header, describing the media type of <paramref name="plainTextBytes"/>
        /// (for example, the API operation's selected request Content-Type). Omitted from the header when
        /// null or blank, preserving prior behavior for callers that do not supply it.
        /// </param>
        internal static string EncryptJweCompact(byte[] plainTextBytes, RSA rsaPublicKey, string kid, string contentType = null)
        {
            // Build the protected header
            long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var headerObj = new JsonObject
            {
                ["alg"] = "RSA-OAEP-256",
                ["enc"] = "A256GCM",
                ["kid"] = kid,
                ["iat"] = iat
            };
            if (!string.IsNullOrWhiteSpace(contentType))
            {
                headerObj["cty"] = contentType;
            }
            string headerJson = headerObj.ToJsonString(new JsonSerializerOptions{ WriteIndented = false });
            string headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));

            // Step 1: Generate a random 256-bit CEK and 96-bit IV
            byte[] cek = new byte[32];
            byte[] iv  = new byte[12];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(cek);
                rng.GetBytes(iv);
            }

            // Step 2: Wrap the CEK using RSA-OAEP-256 (BouncyCastle)
            var bcPublicKey = DotNetUtilities.GetRsaPublicKey(rsaPublicKey.ExportParameters(false));
            var rsaEngine   = new RsaBlindedEngine();
            var encoding    = new OaepEncoding(rsaEngine, new Sha256Digest());
            encoding.Init(true, bcPublicKey);
            byte[] encryptedKey = encoding.ProcessBlock(cek, 0, cek.Length);

            // Step 3: Encrypt the payload with AES-256-GCM
            // AAD is the ASCII bytes of the Base64Url-encoded protected header (per RFC 7516 §5.1 step 14)
            byte[] aad = Encoding.ASCII.GetBytes(headerEncoded);

            var keyParam  = new KeyParameter(cek);
            var gcmParams = new AeadParameters(keyParam, 128, iv, aad);
            var gcmCipher = new GcmBlockCipher(new AesEngine());
            gcmCipher.Init(true, gcmParams);

            byte[] cipherTextWithTag = new byte[gcmCipher.GetOutputSize(plainTextBytes.Length)];
            int len = gcmCipher.ProcessBytes(plainTextBytes, 0, plainTextBytes.Length, cipherTextWithTag, 0);
            len += gcmCipher.DoFinal(cipherTextWithTag, len);

            // BouncyCastle appends the 16-byte tag at the end — split them out
            int cipherLen = len - 16;
            byte[] cipherText = new byte[cipherLen];
            byte[] authTag    = new byte[16];
            Buffer.BlockCopy(cipherTextWithTag, 0,         cipherText, 0, cipherLen);
            Buffer.BlockCopy(cipherTextWithTag, cipherLen, authTag,    0, 16);

            // Step 4: Assemble the JWE compact serialization
            return headerEncoded
                + "." + Base64UrlEncoder.Encode(encryptedKey)
                + "." + Base64UrlEncoder.Encode(iv)
                + "." + Base64UrlEncoder.Encode(cipherText)
                + "." + Base64UrlEncoder.Encode(authTag);
        }
    }
}
