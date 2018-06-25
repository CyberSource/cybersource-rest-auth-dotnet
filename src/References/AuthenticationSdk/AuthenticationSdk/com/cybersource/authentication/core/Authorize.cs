using AuthenticationSdk.com.cybersource.authentication.authentication.http;
using AuthenticationSdk.com.cybersource.authentication.authentication.jwt;
using AuthenticationSdk.com.cybersource.authentication.util;
using NLog;

namespace AuthenticationSdk.com.cybersource.authentication.core
{
    public class Authorize
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();        

        public HttpToken GetSignature(MerchantConfig merchantConfig)
        {
            var signatureObj = (HttpToken)new HttpTokenGenerator(merchantConfig).GetToken();            

            if (merchantConfig.RequestType.ToUpper() == GlobalLabelParameters.GetUpperCase)                            
                Logger.Trace("{0} {1}", "Content-Type:", "application/json");           
            else if (merchantConfig.RequestType.ToUpper() == GlobalLabelParameters.PostUpperCase)                            
                Logger.Trace("{0} {1}", "Content-Type:", "application/hal+json");            

            Logger.Trace("{0} {1}", "v-c-merchant-id:", signatureObj.MerchantId);
            Logger.Trace("{0} {1}", "Date:", signatureObj.GmtDateTime);
            Logger.Trace("{0} {1}", "Host:", signatureObj.HostName);

            if (merchantConfig.RequestType.ToUpper() == GlobalLabelParameters.PostUpperCase)            
                Logger.Trace("{0} {1}", "digest:", signatureObj.Digest);
            
            Logger.Trace("{0} {1}", "signature:", signatureObj.SignatureParam);

            return signatureObj;
        }

        public JwtToken GetToken(MerchantConfig merchantConfig)
        {
            var tokenObj = (JwtToken)new JwtTokenGenerator(merchantConfig).GetToken();

            if (merchantConfig.RequestType.ToUpper() == GlobalLabelParameters.GetUpperCase)            
                Logger.Trace("{0} {1}", "Content-Type:", "application/json");
            
            else if (merchantConfig.RequestType.ToUpper() == GlobalLabelParameters.PostUpperCase)            
                Logger.Trace("{0} {1}", "Content-Type:", "application/hal+json");            

            Logger.Trace("{0} {1}", "Authorization:", tokenObj.BearerToken);

            return tokenObj;            
        }
    }
}
