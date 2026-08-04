using System;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.authentication.oauth;
using AuthenticationSdk.util;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AuthenticationSdk.core
{
    /*==============================================================================
    * Provides Methods to Generate HTTP Authentication Headers of CYBS REST API's
    *===============================================================================*/
    public class Authorize
    {
        private ILogger<Authorize> _logger = NullLogger<Authorize>.Instance;
        private readonly MerchantConfig _merchantConfig;
        private readonly ILoggerFactory _loggerFactory;

        public Authorize(MerchantConfig merchantConfig, ILoggerFactory loggerFactory = null)
        {
            _merchantConfig = merchantConfig;
            _loggerFactory = loggerFactory;

            Enumerations.ValidateRequestType(_merchantConfig.RequestType);
            Enumerations.SetRequestType(_merchantConfig);

            _logger = loggerFactory?.CreateLogger<Authorize>() ?? NullLogger<Authorize>.Instance;
        }

        private void LogMerchantDetails()
        {
            try
            {
                // Using Request Target provided in the sample code/merchantconfig
                _logger.LogDebug($"Request Target: '{_merchantConfig.RequestTarget}'");

                // logging Authentication type
                _logger.LogDebug($"Authentication Type: {_merchantConfig.AuthenticationType}");

                // logging Request Type
                _logger.LogDebug($"Request Type: {_merchantConfig.RequestType}");

                // Logging all the Properties of MerchantConfig and their respective Values
                _merchantConfig.LogMerchantConfigurationProperties();
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to log merchant details");
                throw new AuthenticationException("LOG_ERROR", $"Failed to log merchant configuration details: {e.Message}", e);
            }
        }

        #region Properties
        private readonly IMerchantRequestSettings _merchantRequestSettings;
        private readonly IMerchantCredentialSettings _merchantCredentialSettings;
        private readonly IMerchantMLESettings _merchantMLESettings;
        #endregion Properties

        #region Constructor
        public Authorize(IMerchantCredentialSettings merchantCredentialSettings, IMerchantRequestSettings merchantRequestSettings, IMerchantMLESettings merchantMLESettings, ILoggerFactory loggerFactory = null)
        {
            _merchantRequestSettings = merchantRequestSettings;
            _merchantCredentialSettings = merchantCredentialSettings;
            _merchantMLESettings = merchantMLESettings;
            _loggerFactory = loggerFactory;

            _logger = loggerFactory?.CreateLogger<Authorize>() ?? NullLogger<Authorize>.Instance;
        }
        #endregion Constructor

        #region Methods
        public HttpToken GetSignature()
        {
            try
            {
                var signatureObject = (HttpToken)new HttpTokenGenerator(_merchantCredentialSettings, _merchantRequestSettings).GetToken();

                _logger.LogDebug($"v-c-merchant-id: {signatureObject.MerchantId}");
                _logger.LogDebug($"Date: {signatureObject.GmtDateTime}");
                _logger.LogDebug($"Host: {signatureObject.HostName}");

                if (_merchantRequestSettings.RequestType.Equals("GET", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogDebug("Content-Type: application/json");
                }
                else if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogDebug("Content-Type: application/hal+json");
                }

                return signatureObject;
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error occurred while generating digital signature");
                throw e;
            }
        }

        public JwtToken GetToken(bool isResponseMLEForApi = false)
        {
            try
            {
                var tokenObject = (JwtToken) new JwtTokenGenerator(_merchantCredentialSettings, _merchantRequestSettings, _merchantMLESettings, isResponseMLEForApi, _loggerFactory).GetToken();

                if (_merchantRequestSettings.RequestType.Equals("GET", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogDebug("Content-Type: application/json");
                }
                else if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogDebug("Content-Type: application/hal+json");
                }

                //logUtility.LogDebugMessage(_logger, $"Authorization : Bearer {tokenObject.BearerToken}");

                return tokenObject;
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error occurred while generating authentication token");
                throw e;
            }
        }

        public OAuthToken GetOAuthToken()
        {
            try
            {
                var tokenObject = (OAuthToken)new OAuthTokenGenerator(_merchantCredentialSettings).GetToken();

                if (_merchantRequestSettings.RequestType.Equals("GET", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogDebug("Content-Type: application/json");
                }
                else if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogDebug("Content-Type: application/hal+json");
                }

                return tokenObject;
            }
            catch (Exception e)
            {
                _logger.LogError(e, "An error occurred while generating OAuth token");
                throw e;
            }
        }
        #endregion Methods
    }
}