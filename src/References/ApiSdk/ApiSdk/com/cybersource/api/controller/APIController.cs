using System;
using ApiSdk.com.cybersource.api.service;
using ApiSdk.com.cybersource.api.util;
using AuthenticationSdk.com.cybersource.authentication.util;
using NLog;

namespace ApiSdk.com.cybersource.api.controller
{
    public class APIController
    {        
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static Response _response;
        private static PaymentRequestService _paymentRequestService;
        
        public APIController()
        {            
            Logger.Trace("\n");
            Logger.Trace("START> =======================================");
        }

        //Controller of Payments API
        public Response Payments(MerchantConfig merchantConfig)
        {            
            //Using default Request Target (of Payments API)
            Logger.Trace("Using Request Target:'{0}'", merchantConfig.RequestTarget);
            Console.WriteLine("\n Using Request Target:'{0}'", merchantConfig.RequestTarget);

            //logging Authentication type                                              
            Logger.Trace("Authentication Type -> {0}", merchantConfig.AuthenticationType);
            Console.WriteLine("\n Authentication Type -> {0}", merchantConfig.AuthenticationType);

            //Logging all the Properties of MerchantConfig and their respective Values                                 
            Logger.Trace("MERCHCFG > {0}", (MerchantConfig.LogAllproperties(merchantConfig)));
            Console.WriteLine("\n MERCHCFG > {0}", (MerchantConfig.LogAllproperties(merchantConfig)));

            _paymentRequestService = new PaymentRequestService();

            //Controller makes a call to the respective method of the Service Class, based on the request type
            if (merchantConfig.RequestType.ToUpper() == GlobalLabelParametersAPI.GetUpperCase)
            {
                Logger.Trace("Using Get ID:'{0}'", merchantConfig.GetID);
                Console.WriteLine("Using Get ID:'{0}'", merchantConfig.GetID);
                _response = _paymentRequestService.GetResponse(merchantConfig);
            }
            else if (merchantConfig.RequestType.ToUpper() == GlobalLabelParametersAPI.PostUpperCase)
               _response = _paymentRequestService.PostResponse(merchantConfig);
            else if (merchantConfig.RequestType.ToUpper() == GlobalLabelParametersAPI.PutUpperCase)
            {
                Logger.Trace("Using Put ID:'{0}'", merchantConfig.PutID);
                Console.WriteLine("Using Put ID:'{0}'", merchantConfig.GetID);
                _response = _paymentRequestService.PutResponse(merchantConfig);
            }


            Logger.Info("v-c-correlation-id:{0}", _response.GetResponseHeaderValue(_response.Headers, "v-c-correlation-id"));
            Logger.Info("Response Code:{0}", _response.StatusCode);
            Logger.Info("Response Message:{0}", _response.Data);


            Logger.Trace("END> =======================================");

            return _response;
        }
    }
}