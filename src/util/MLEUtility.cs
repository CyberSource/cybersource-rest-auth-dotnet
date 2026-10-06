using AuthenticationSdk.core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AuthenticationSdk.util
{
    public static class MLEUtility
    {
        // Immutable no-op default. Methods that receive an ILoggerFactory create a per-call
        // local logger instead of mutating shared static state (which is not thread-safe).
        private static readonly ILogger logger = NullLogger.Instance;
        private static readonly LogUtility logUtility = new LogUtility();

        public static bool CheckIsMLEForAPI(MerchantConfig merchantConfig, string inboundMLEStatus, string operationIds)
        {
            bool isMLEForAPI = false;

            // Handle inboundMLEStatus logic
            if (string.Equals(inboundMLEStatus, "optional", StringComparison.OrdinalIgnoreCase) && merchantConfig.EnableRequestMLEForOptionalApisGlobally)
            {
                isMLEForAPI = true;
            }

            if (string.Equals(inboundMLEStatus, "mandatory", StringComparison.OrdinalIgnoreCase))
            {
                isMLEForAPI = !merchantConfig.DisableRequestMLEForMandatoryApisGlobally;
            }

            // OperationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the MLE only from map
            if (merchantConfig.InternalMapToControlRequestMLEonAPI != null && merchantConfig.InternalMapToControlRequestMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantConfig.InternalMapToControlRequestMLEonAPI.ContainsKey(operationId))
                    {
                        isMLEForAPI = merchantConfig.InternalMapToControlRequestMLEonAPI[operationId];
                        break;
                    }
                }
            }

            return isMLEForAPI;
        }

        public static object EncryptRequestPayload(MerchantConfig merchantConfig, object requestBody)
        {
            if (requestBody == null)
            {
                return null;
            }

            string payload = requestBody.ToString();
            logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_REQUEST_BEFORE_MLE + payload));

            X509Certificate2 mleCertificate = GetRequestMLECertificate(merchantConfig);

            // Handling special case : MLE Certificate is not currently available for HTTP Signature
            if (mleCertificate == null && Constants.AuthMechanismHttp.Equals(merchantConfig.AuthenticationType, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogDebug("The certificate to use for MLE for requests is not provided in the merchant configuration. Please ensure that the certificate path is provided.");
                logger.LogDebug("Currently, MLE for requests using HTTP Signature as authentication is not supported by Cybersource. By default, the SDK will fall back to non-encrypted requests.");
                return requestBody;
            }

            // If cert is still null for any other auth type, throw a descriptive error
            if (mleCertificate == null)
            {
                throw new MLEException("MLE_CERT_NOT_FOUND", "No certificate found for MLE Request. " +
                    "Please provide the Request MLE certificate file path via 'mleForRequestPublicCertPath' in merchant configuration. " +
                    "This is required when using jwtKeyType=SHARED_SECRET or when the P12 file does not contain the MLE certificate.");
            }

            string serialNumber = GetSerialNumberFromCertificate(mleCertificate, merchantConfig);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);
            var rsa = mleCertificate.GetRSAPublicKey();
            var jweToken = JWEUtilty.EncryptJweCompact(payloadBytes, rsa, serialNumber);

            string mleRequest = CreateJsonString(jweToken);
            logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_REQUEST_AFTER_MLE + mleRequest));

            return mleRequest;
        }

        private static X509Certificate2 GetRequestMLECertificate(MerchantConfig merchantConfig)
        {
            X509Certificate2 mleCertificate = Cache.GetRequestMLECertFromCache(merchantConfig);
            return mleCertificate;
        }

        private static string GetSerialNumberFromCertificate(X509Certificate2 certificate, MerchantConfig merchantConfig)
        {
            return CertificateUtility.ExtractSerialNumber(certificate);
        }

        private static string CreateJsonString(string jweToken)
        {
            var jsonObject = new { encryptedRequest = jweToken };
            return JsonSerializer.Serialize(jsonObject);
        }

        public static bool CheckIsResponseMLEForAPI(MerchantConfig merchantConfig, string operationIds)
        {
            // isMLE for response for an api is false by default
            bool isResponseMLEForAPI = false;

            if (merchantConfig.EnableResponseMleGlobally)
            {
                isResponseMLEForAPI = true;
            }

            // operationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the Response MLE only from map
            // Special Note: If API expects MLE Response mandatory and map is saying to receive non MLE response then API might throw an error from CyberSource
            if (merchantConfig.InternalMapToControlResponseMLEonAPI != null && merchantConfig.InternalMapToControlResponseMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantConfig.InternalMapToControlResponseMLEonAPI.ContainsKey(operationId))
                    {
                        isResponseMLEForAPI = merchantConfig.InternalMapToControlResponseMLEonAPI[operationId];
                        break;
                    }
                }
            }
            return isResponseMLEForAPI;
        }

        public static bool CheckIsMleEncryptedResponse(string responseBody)
        {
            if (string.IsNullOrWhiteSpace(responseBody))
            {
                return false;
            }
            try
            {
                var jsonObject = JsonSerializer.Deserialize<JsonObject>(responseBody);
                if (jsonObject == null || jsonObject.Count != 1)
                {
                    return false;
                }
                if (jsonObject.ContainsKey("encryptedResponse"))
                {
                    var value = jsonObject["encryptedResponse"];
                    return value != null && value.GetValueKind() == JsonValueKind.String;
                }
                return false;
            }
            catch
            {
                // If JSON parsing fails, it's not a valid JSON thus not a MLE response
                return false;
            }
        }
        private static string GetResponseMleToken(string mleResponseBody, ILogger logger)
        {
            try
            {
                var jsonObject = JsonSerializer.Deserialize<JsonObject>(mleResponseBody);
                return jsonObject?["encryptedResponse"]?.ToString();
            }
            catch (Exception e)
            {
                string errorMessage = $"Failed to extract MLE response token: {e.Message}";
                logger.LogError(e, errorMessage);
                throw new MLEException("DECRYPTION", errorMessage, e);
            }
        }
        private static AsymmetricAlgorithm GetMleResponsePrivateKey(MerchantConfig merchantConfig)
        {
            // First priority - if privateKey is given in merchant config return that
            if (merchantConfig.ResponseMlePrivateKey != null)
            {
                return merchantConfig.ResponseMlePrivateKey;
            }
            // Second priority - get the privateKey from merchantConfig.ResponseMlePrivateKeyFilePath
            var responseMlePrivateKey = Cache.GetMleResponsePrivateKeyFromFilePath(merchantConfig);
            return responseMlePrivateKey;
        }
        public static string DecryptMleResponsePayload(MerchantConfig merchantConfig, string mleResponseBody, ILoggerFactory loggerFactory)
        {
            ILogger logger = loggerFactory?.CreateLogger("MLEUtility") ?? NullLogger.Instance;

            if (!CheckIsMleEncryptedResponse(mleResponseBody))
            {
                throw new MLEException("VALIDATION", "Response body is not MLE encrypted.");
            }

            var mlePrivateKey = GetMleResponsePrivateKey(merchantConfig);
            string jweResponseToken = GetResponseMleToken(mleResponseBody, logger);

            if (string.IsNullOrEmpty(jweResponseToken))
            {
                // When MLE token is empty or null then fall back to non MLE encrypted response
                return mleResponseBody;
            }

            try
            {
                logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION + mleResponseBody));

                // Convert AsymmetricAlgorithm to RSA if needed
                RSA rsaKey = mlePrivateKey as RSA;
                if (rsaKey == null)
                {
                    throw new MLEException("KEY_TYPE", "MLE Response private key is not an RSA key. Only RSA keys are supported for MLE decryption.");
                }
                string decryptedResponse = JWEUtilty.DecryptUsingRSAParameters(rsaKey.ExportParameters(true), jweResponseToken);
                logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + decryptedResponse));
                return decryptedResponse;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                string errorMessage = $"MLE Response decryption failed (InvalidCipherTextException): {e.Message}. " +
                                      $"Possible reason: The provided RSA private key does not match the public key used to encrypt the message.";
                logger.LogError(e, errorMessage);
                throw new MLEException("JOSE_DECRYPTION", errorMessage, e);
            }
            catch (CryptographicException e)
            {
                string errorMessage = $"MLE Response decryption failed (CryptographicException): {e.Message}. " +
                                      "This may happen if the private key is incorrect or corrupted.";
                logger.LogError(e, errorMessage);
                throw new MLEException("CRYPTO_DECRYPTION", errorMessage, e);
            }
            catch (Exception e)
            {
                string errorMessage = $"MLE Response decryption failed: {e.Message}";
                logger.LogError(e, errorMessage);
                throw new MLEException("DECRYPTION", errorMessage, e);
            }
        }

        /// <summary>
        /// Validates and auto-extracts the Response MLE KID for JWT token generation.
        /// For CyberSource-generated P12/PFX files, attempts to extract KID automatically.
        /// For non-CyberSource files or other formats, requires manual configuration.
        /// </summary>
        /// <param name="merchantConfig">The merchant configuration</param>
        /// <returns>The validated or extracted Response MLE KID</returns>
        /// <exception cref="Exception">If KID cannot be determined</exception>
        public static string ValidateAndAutoExtractResponseMleKid(MerchantConfig merchantConfig)
        {
            // If ResponseMlePrivateKey object is provided directly, use configured responseMleKID
            if (merchantConfig.ResponseMlePrivateKey != null)
            {
                logger.LogDebug("responseMlePrivateKey is provided directly, using configured responseMleKID");
                return merchantConfig.ResponseMleKID;
            }

            logger.LogDebug("Validating responseMleKID for JWT token generation");
            string cybsKid = null;
            bool isP12File = false;

            // Check file path validity and determine if it's a P12/PFX file
            try
            {
                CertificateUtility.ValidatePathAndFile(merchantConfig.ResponseMlePrivateKeyFilePath, "responseMlePrivateKeyFilePath");
                string extension = CertificateUtility.GetFileExtension(merchantConfig.ResponseMlePrivateKeyFilePath);

                if (extension.Equals("p12", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals("pfx", StringComparison.OrdinalIgnoreCase))
                {
                    isP12File = true;
                }
            }
            catch (IOException e)
            {
                logger.LogDebug(e, "No valid private key file path provided, skipping auto-extraction");
            }

            // Attempt to extract KID from CyberSource P12/PFX file
            if (isP12File)
            {
                logger.LogDebug("P12/PFX file detected, checking if it is a CyberSource certificate");
                CachedMLEKId cachedData = Cache.GetMLEKIdDataFromCache(merchantConfig);

                if (cachedData != null)
                {
                    if (cachedData.Kid != null)
                    {
                        // KID present means it's a CyberSource P12, use it
                        cybsKid = cachedData.Kid;
                    }
                    else
                    {
                        // KID is null means either non-CyberSource P12 or extraction failed
                        logger.LogDebug("Private key file is not a CyberSource generated P12/PFX file, skipping auto-extraction");
                    }
                }
            }
            else
            {
                logger.LogDebug("Private key file is not a P12/PFX file, skipping auto-extraction");
            }

            if (cybsKid != null)
            {
                logger.LogDebug("Successfully auto-extracted responseMleKID from CyberSource P12 certificate");
            }

            string configuredKID = merchantConfig.ResponseMleKID;

            // Determine which KID to use based on what's available
            if (cybsKid == null && configuredKID == null)
            {
                throw new ConfigurationException("responseMleKID is required when response MLE is enabled. " +
                    "Could not auto-extract from certificate and no manual configuration provided. " +
                    "Please provide responseMleKID explicitly in your configuration.");
            }
            else if (cybsKid == null)
            {
                logger.LogDebug("Using manually configured responseMleKID");
                return configuredKID;
            }
            else if (configuredKID == null)
            {
                logger.LogDebug("Using auto-extracted responseMleKID from CyberSource certificate");
                return cybsKid;
            }
            else if (!cybsKid.Equals(configuredKID))
            {
                logger.LogWarning("Auto-extracted responseMleKID does not match manually configured responseMleKID. Using configured value as preference");
            }

            return configuredKID;
        }

        #region NEW METHODS
        /// <summary>
        /// Decrypts an MLE-encrypted response payload using the merchant's response private key.
        /// Validates that the response is properly MLE-encrypted, extracts the JWE token, and decrypts it using RSA.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration including the private key.</param>
        /// <param name="mleResponseBody">The MLE-encrypted response body containing the encryptedResponse token.</param>
        /// <param name="loggerFactory">Optional logger factory for logging.</param>
        /// <returns>The decrypted response payload as a string.</returns>
        /// <exception cref="Exception">Thrown when response is not MLE-encrypted, token cannot be extracted, or decryption fails due to key mismatch or corruption.</exception>
        public static string DecryptMleResponsePayload(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, string mleResponseBody, ILoggerFactory loggerFactory = null)
        {
            return DecryptMleResponsePayload(merchantCredentialSettings, merchantMLESettings, mleResponseBody, loggerFactory, CertificateCache.Default);
        }

        /// <summary>
        /// Overload that accepts an explicit certificate cache (for dependency injection / testing).
        /// <paramref name="cache"/> must not be null; call the overload without a cache parameter to use the default.
        /// </summary>
        public static string DecryptMleResponsePayload(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, string mleResponseBody, ILoggerFactory loggerFactory, ICache cache)
        {
            if (cache == null) throw new ArgumentNullException(nameof(cache));

            ILogger logger = loggerFactory?.CreateLogger("MLEUtility") ?? NullLogger.Instance;

            if (!CheckIsMleEncryptedResponse(mleResponseBody))
            {
                throw new Exception("Response body is not MLE encrypted.");
            }

            var mlePrivateKey = GetMleResponsePrivateKey(merchantCredentialSettings, merchantMLESettings, loggerFactory, cache);
            string jweResponseToken = GetResponseMleToken(mleResponseBody, logger);

            if (string.IsNullOrEmpty(jweResponseToken))
            {
                // When MLE token is empty or null then fall back to non MLE encrypted response
                return mleResponseBody;
            }

            try
            {
                logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_NETWORK_RESPONSE_BEFORE_MLE_DECRYPTION + mleResponseBody));

                // Convert AsymmetricAlgorithm to RSA if needed
                RSA rsaKey = mlePrivateKey as RSA;
                if (rsaKey == null)
                {
                    throw new Exception("MLE Response private key is not an RSA key. Only RSA keys are supported for MLE decryption.");
                }
                string decryptedResponse;
#if NETSTANDARD2_1_OR_GREATER || NET8_0_OR_GREATER
                // Generate a fresh, single-use transient password for the in-memory key round-trip.
                // This password is only used to export and immediately re-import the private key
                // within this method; it is never persisted, transmitted, or reused. Two concatenated
                // GUIDs (~244 bits) provide ample, unguessable entropy for a value that never leaves
                // this process.
                char[] tempPassword = (Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N")).ToCharArray();
                byte[] encryptedPkcs8 = null;
                try
                {
                    encryptedPkcs8 = rsaKey.ExportEncryptedPkcs8PrivateKey(tempPassword, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1));
                    using (var fullyUnlockedRSA = RSA.Create())
                    {
                        fullyUnlockedRSA.ImportEncryptedPkcs8PrivateKey(tempPassword, encryptedPkcs8, out _);
                        RSAParameters rsaParameters = fullyUnlockedRSA.ExportParameters(true);
                        try
                        {
                            decryptedResponse = JWEUtilty.DecryptUsingRSAParameters(rsaParameters, jweResponseToken);
                        }
                        finally
                        {
                            // Clear sensitive private key material from memory
                            ClearRSAParameters(ref rsaParameters);
                        }
                    }
                }
                finally
                {
                    // Clear sensitive data from memory
                    Array.Clear(tempPassword, 0, tempPassword.Length);
                    if (encryptedPkcs8 != null)
                    {
                        Array.Clear(encryptedPkcs8, 0, encryptedPkcs8.Length);
                    }
                }
#else
                // netstandard2.0 / .NET Framework do not support ExportEncryptedPkcs8PrivateKey /
                // ImportEncryptedPkcs8PrivateKey, so export the private key parameters directly and
                // clear them immediately after use.
                RSAParameters rsaParameters = rsaKey.ExportParameters(true);
                try
                {
                    decryptedResponse = JWEUtilty.DecryptUsingRSAParameters(rsaParameters, jweResponseToken);
                }
                finally
                {
                    // Clear sensitive private key material from memory
                    ClearRSAParameters(ref rsaParameters);
                }
#endif
                logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_NETWORK_RESPONSE_AFTER_MLE_DECRYPTION + decryptedResponse));
                return decryptedResponse;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                string errorMessage = $"MLE Response decryption failed (InvalidCipherTextException): {e.Message}. " +
                                      $"Possible reason: The provided RSA private key does not match the public key used to encrypt the message.";
                logger.LogError(e, errorMessage);
                throw new MLEException("JOSE_DECRYPTION", errorMessage, e);
            }
            catch (CryptographicException e)
            {
                string errorMessage = $"MLE Response decryption failed (CryptographicException): {e.Message}. " +
                                      "This may happen if the private key is incorrect or corrupted.";
                logger.LogError(e, errorMessage);
                throw new MLEException("CRYPTO_DECRYPTION", errorMessage, e);
            }
            catch (Exception e)
            {
                string errorMessage = $"MLE Response decryption failed: {e.Message}";
                logger.LogError(e, errorMessage);
                throw new MLEException("DECRYPTION", errorMessage, e);
            }
        }

        /// <summary>
        /// Retrieves the MLE response private key for decryption.
        /// Prioritizes directly provided private key objects over file-based keys.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration including the private key settings.</param>
        /// <param name="loggerFactory">Optional ILoggerFactory for logging purposes.</param>
        /// <returns>The asymmetric private key used for decrypting MLE responses, or null if not configured.</returns>
        private static AsymmetricAlgorithm GetMleResponsePrivateKey(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
        {
            return GetMleResponsePrivateKey(merchantCredentialSettings, merchantMLESettings, loggerFactory, CertificateCache.Default);
        }

        /// <summary>
        /// Overload that accepts an explicit certificate cache (for dependency injection / testing).
        /// <paramref name="cache"/> must not be null; call the overload without a cache parameter to use the default.
        /// </summary>
        private static AsymmetricAlgorithm GetMleResponsePrivateKey(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory, ICache cache)
        {
            if (cache == null) throw new ArgumentNullException(nameof(cache));

            // First priority - if privateKey is given in merchant config return that
            if (merchantMLESettings.ResponseMlePrivateKey != null)
            {
                return merchantMLESettings.ResponseMlePrivateKey;
            }
            // Second priority - get the privateKey from merchantConfig.ResponseMlePrivateKeyFilePath
            var responseMlePrivateKey = cache.GetMleResponsePrivateKeyFromFilePath(merchantCredentialSettings, merchantMLESettings, loggerFactory);
            return responseMlePrivateKey;
        }

        /// <summary>
        /// Validates and auto-extracts the Response MLE KID for JWT token generation.
        /// For CyberSource-generated P12/PFX files, attempts to extract KID automatically.
        /// For non-CyberSource files or other formats, uses manually configured KID.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials (MerchantId, UseMetaKey, PortfolioId).</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing merchant MLE configuration including ResponseMleKID and private key settings.</param>
        /// <param name="loggerFactory">Optional ILoggerFactory for logging purposes.</param>
        /// <returns>The validated or auto-extracted Response MLE KID.</returns>
        /// <exception cref="Exception">Thrown when KID cannot be determined either through auto-extraction or manual configuration.</exception>
        public static string ValidateAndAutoExtractResponseMleKid(string keyIssuer, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
        {
            return ValidateAndAutoExtractResponseMleKid(keyIssuer, merchantMLESettings, loggerFactory, CertificateCache.Default);
        }

        /// <summary>
        /// Overload that accepts an explicit certificate cache (for dependency injection / testing).
        /// <paramref name="cache"/> must not be null; call the overload without a cache parameter to use the default.
        /// </summary>
        public static string ValidateAndAutoExtractResponseMleKid(string keyIssuer, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory, ICache cache)
        {
            if (cache == null) throw new ArgumentNullException(nameof(cache));

            ILogger logger = loggerFactory?.CreateLogger("MLEUtility") ?? NullLogger.Instance;

            // If ResponseMlePrivateKey object is provided directly, use configured responseMleKID
            if (merchantMLESettings.ResponseMlePrivateKey != null)
            {
                logger.LogDebug("responseMlePrivateKey is provided directly, using configured responseMleKID");
                return merchantMLESettings.ResponseMleKID;
            }

            logger.LogDebug("Validating responseMleKID for JWT token generation");
            string cybsKid = null;
            bool isP12File = false;

            // Check file path validity and determine if it's a P12/PFX file
            try
            {
                CertificateUtility.ValidatePathAndFile(merchantMLESettings.ResponseMlePrivateKeyFilePath, "responseMlePrivateKeyFilePath", loggerFactory);
                string extension = CertificateUtility.GetFileExtension(merchantMLESettings.ResponseMlePrivateKeyFilePath);

                if (extension.Equals("p12", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals("pfx", StringComparison.OrdinalIgnoreCase))
                {
                    isP12File = true;
                }
            }
            catch (IOException e)
            {
                logger.LogDebug(e, "No valid private key file path provided, skipping auto-extraction");
            }

            // Attempt to extract KID from CyberSource P12/PFX file
            if (isP12File)
            {
                logger.LogDebug("P12/PFX file detected, checking if it is a CyberSource certificate");
                CachedMLEKId cachedData = cache.GetMLEKIdDataFromCache(keyIssuer, merchantMLESettings, loggerFactory);

                if (cachedData != null)
                {
                    if (cachedData.Kid != null)
                    {
                        // KID present means it's a CyberSource P12, use it
                        cybsKid = cachedData.Kid;
                    }
                    else
                    {
                        // KID is null means either non-CyberSource P12 or extraction failed
                        logger.LogDebug("Private key file is not a CyberSource generated P12/PFX file, skipping auto-extraction");
                    }
                }
            }
            else
            {
                logger.LogDebug("Private key file is not a P12/PFX file, skipping auto-extraction");
            }

            if (cybsKid != null)
            {
                logger.LogDebug("Successfully auto-extracted responseMleKID from CyberSource P12 certificate");
            }

            string configuredKID = merchantMLESettings.ResponseMleKID;

            // Determine which KID to use based on what's available
            if (cybsKid == null && configuredKID == null)
            {
                throw new Exception("responseMleKID is required when response MLE is enabled. " +
                    "Could not auto-extract from certificate and no manual configuration provided. " +
                    "Please provide responseMleKID explicitly in your configuration.");
            }
            else if (cybsKid == null)
            {
                logger.LogDebug("Using manually configured responseMleKID");
                return configuredKID;
            }
            else if (configuredKID == null)
            {
                logger.LogDebug("Using auto-extracted responseMleKID from CyberSource certificate");
                return cybsKid;
            }
            else if (!cybsKid.Equals(configuredKID))
            {
                logger.LogWarning("Auto-extracted responseMleKID does not match manually configured responseMleKID. Using configured value as preference");
            }

            return configuredKID;
        }

        /// <summary>
        /// Checks whether MLE should be enabled for a specific API based on merchant configuration.
        /// Evaluates the inbound MLE status (optional/mandatory) and API-specific control mappings.
        /// </summary>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE global settings and API-level control mappings.</param>
        /// <param name="inboundMLEStatus">The MLE requirement status from the API specification: "optional" or "mandatory".</param>
        /// <param name="operationIds">Comma-separated list of operation IDs (API function names) to check for MLE configuration.</param>
        /// <returns>True if MLE should be enabled for the specified API operation; otherwise, false.</returns>
        public static bool CheckIsMLEForAPI(IMerchantMLESettings merchantMLESettings, string inboundMLEStatus, string operationIds)
        {
            bool isMLEForAPI = false;

            // Handle inboundMLEStatus logic
            if (string.Equals(inboundMLEStatus, "optional", StringComparison.OrdinalIgnoreCase) && merchantMLESettings.EnableRequestMLEForOptionalApisGlobally)
            {
                isMLEForAPI = true;
            }

            if (string.Equals(inboundMLEStatus, "mandatory", StringComparison.OrdinalIgnoreCase))
            {
                isMLEForAPI = !merchantMLESettings.DisableRequestMLEForMandatoryApisGlobally;
            }

            // OperationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the MLE only from map
            if (merchantMLESettings.InternalMapToControlRequestMLEonAPI != null && merchantMLESettings.InternalMapToControlRequestMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantMLESettings.InternalMapToControlRequestMLEonAPI.ContainsKey(operationId))
                    {
                        isMLEForAPI = merchantMLESettings.InternalMapToControlRequestMLEonAPI[operationId];
                        break;
                    }
                }
            }

            return isMLEForAPI;
        }

        /// <summary>
        /// Encrypts the request payload using MLE with the merchant's public certificate.
        /// Creates a JWE token with the request body and wraps it in a JSON object with the encryptedRequest key.
        /// For HTTP Signature authentication where no certificate is available, returns the unencrypted payload.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials including authentication type.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE configuration including the public certificate settings.</param>
        /// <param name="requestBody">The request payload object to be encrypted.</param>
        /// <param name="loggerFactory">Optional logger factory for logging.</param>
        /// <returns>A JSON object containing the encrypted request if encryption is successful; otherwise, the original unencrypted request body.</returns>
        public static object EncryptRequestPayload(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, object requestBody, ILoggerFactory loggerFactory = null)
        {
            return EncryptRequestPayload(merchantCredentialSettings, merchantMLESettings, requestBody, loggerFactory, CertificateCache.Default);
        }

        /// <summary>
        /// Overload that accepts an explicit certificate cache (for dependency injection / testing).
        /// <paramref name="cache"/> must not be null; call the overload without a cache parameter to use the default.
        /// </summary>
        public static object EncryptRequestPayload(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, object requestBody, ILoggerFactory loggerFactory, ICache cache)
        {
            if (cache == null) throw new ArgumentNullException(nameof(cache));

            if (requestBody == null)
            {
                return null;
            }

            ILogger logger = loggerFactory?.CreateLogger("MLEUtility") ?? NullLogger.Instance;

            string payload = requestBody.ToString();
            logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_REQUEST_BEFORE_MLE + payload));

            X509Certificate2 mleCertificate = null;
            try
            {
                mleCertificate = GetRequestMLECertificate(merchantCredentialSettings, merchantMLESettings, loggerFactory, cache);
            }
            catch (Exception)
            {
                throw;
            }

            // Handling special case : MLE Certificate is not currently available for HTTP Signature
            if (mleCertificate == null && Constants.AuthMechanismHttp.Equals(merchantCredentialSettings.AuthenticationType, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogDebug("The certificate to use for MLE for requests is not provided in the merchant configuration. Please ensure that the certificate path is provided.");
                logger.LogDebug("Currently, MLE for requests using HTTP Signature as authentication is not supported by Cybersource. By default, the SDK will fall back to non-encrypted requests.");
                return requestBody;
            }

            // If cert is still null for any other auth type, throw error
            if (mleCertificate == null)
            {
                throw new MLEException("MLE_CERT_NOT_FOUND", "No certificate found for MLE Request. " +
                    "Please provide the Request MLE certificate file path via 'mleForRequestPublicCertPath' in merchant configuration, " +
                    "or ensure the P12 file path is correctly configured and contains the MLE certificate.");
            }

            string serialNumber = GetSerialNumberFromCertificate(mleCertificate, loggerFactory);
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
            var rsa = mleCertificate.GetRSAPublicKey();
            var jweToken = JWEUtilty.EncryptJweCompact(payloadBytes, rsa, serialNumber);


            string mleRequest = CreateJsonString(jweToken);
            logger.LogDebug(logUtility.MaskSensitiveData(Constants.LOG_REQUEST_AFTER_MLE + mleRequest));

            return mleRequest;
        }

        /// <summary>
        /// Retrieves the cached MLE request certificate from the merchant configuration and MLE settings.
        /// Used for encrypting request payloads.
        /// </summary>
        /// <param name="merchantCredentialSettings">Object of IMerchantCredentialSettings containing merchant credentials.</param>
        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE configuration including public certificate paths.</param>
        /// <param name="loggerFactory">Object of ILoggerFactory for logging purposes.</param>
        /// <returns>The X509Certificate2 used for MLE request encryption, or null if no certificate is configured.</returns>
        private static X509Certificate2 GetRequestMLECertificate(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
        {
            return GetRequestMLECertificate(merchantCredentialSettings, merchantMLESettings, loggerFactory, CertificateCache.Default);
        }

        /// <summary>
        /// Overload that accepts an explicit certificate cache (for dependency injection / testing).
        /// <paramref name="cache"/> must not be null; call the overload without a cache parameter to use the default.
        /// </summary>
        private static X509Certificate2 GetRequestMLECertificate(IMerchantCredentialSettings merchantCredentialSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory, ICache cache)
        {
            if (cache == null) throw new ArgumentNullException(nameof(cache));

            X509Certificate2 mleCertificate = null;
            try
            {
                mleCertificate = cache.GetRequestMLECertFromCache(merchantCredentialSettings, merchantMLESettings, loggerFactory);
            }
            catch (Exception)
            {

                throw;
            }
            return mleCertificate;
        }

        /// <summary>
        /// Extracts the serial number from an X509 certificate.
        /// The serial number is used as the Key ID (kid) in the JWE token header for MLE request encryption.
        /// </summary>
        /// <param name="certificate">The X509Certificate2 from which to extract the serial number.</param>
        /// <param name="loggerFactory">Object of ILoggerFactory for logging purposes.</param>
        /// <returns>The certificate's serial number as a string.</returns>
        private static string GetSerialNumberFromCertificate(X509Certificate2 certificate, ILoggerFactory loggerFactory = null)
        {
            return CertificateUtility.ExtractSerialNumber(certificate, loggerFactory);
        }

        /// <summary>
        /// Clears sensitive private key material from the given RSAParameters to avoid leaving
        /// secrets lingering in memory after decryption.
        /// </summary>
        /// <param name="parameters">The RSAParameters whose private components should be zeroed out.</param>
        private static void ClearRSAParameters(ref RSAParameters parameters)
        {
            if (parameters.D != null) Array.Clear(parameters.D, 0, parameters.D.Length);
            if (parameters.P != null) Array.Clear(parameters.P, 0, parameters.P.Length);
            if (parameters.Q != null) Array.Clear(parameters.Q, 0, parameters.Q.Length);
            if (parameters.DP != null) Array.Clear(parameters.DP, 0, parameters.DP.Length);
            if (parameters.DQ != null) Array.Clear(parameters.DQ, 0, parameters.DQ.Length);
            if (parameters.InverseQ != null) Array.Clear(parameters.InverseQ, 0, parameters.InverseQ.Length);
        }

        /// <param name="merchantMLESettings">Object of IMerchantMLESettings containing MLE global settings and API-level response control mappings.</param>
        /// <param name="operationIds">Comma-separated list of operation IDs (API function names) to check for response MLE configuration.</param>
        /// <returns>True if response MLE should be enabled for the specified API operation; otherwise, false.</returns>
        public static bool CheckIsResponseMLEForAPI(IMerchantMLESettings merchantMLESettings, string operationIds)
        {
            // isMLE for response for an api is false by default
            bool isResponseMLEForAPI = false;

            if (merchantMLESettings.EnableResponseMleGlobally)
            {
                isResponseMLEForAPI = true;
            }

            // operationIds are array as there are multiple public functions for apiCallFunction such as apiCall, apiCallAsync ..
            string[] operationArray = operationIds.Split(',');
            for (int i = 0; i < operationArray.Length; i++)
            {
                operationArray[i] = operationArray[i].Trim();
            }

            // Control the Response MLE only from map
            // Special Note: If API expects MLE Response mandatory and map is saying to receive non MLE response then API might throw an error from CyberSource
            if (merchantMLESettings.InternalMapToControlResponseMLEonAPI != null && merchantMLESettings.InternalMapToControlResponseMLEonAPI.Count > 0)
            {
                foreach (string operationId in operationArray)
                {
                    if (merchantMLESettings.InternalMapToControlResponseMLEonAPI.ContainsKey(operationId))
                    {
                        isResponseMLEForAPI = merchantMLESettings.InternalMapToControlResponseMLEonAPI[operationId];
                        break;
                    }
                }
            }
            return isResponseMLEForAPI;
        }
        #endregion
    }
}
