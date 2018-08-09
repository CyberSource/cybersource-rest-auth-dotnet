using System;
using ApiSdk.model;
using ApiSdk.service;
using AuthenticationSdk.util;
using NLog;

namespace ApiSdk.controller
{
    public class APIController
    {
        private readonly Logger _logger;        
        private readonly PaymentRequestService _paymentRequestService;

        public APIController(MerchantConfig merchantConfig)
        {
            _logger = LogManager.GetCurrentClassLogger();            
            Enumerations.ValidateRequestType(merchantConfig.RequestType);            
            Enumerations.SetRequestType(merchantConfig);
            _paymentRequestService = new PaymentRequestService(merchantConfig);
        }

        public Response GetPayment()
        {
            try
            {                
                //Call the Service to Get the Response Object          
                var response = _paymentRequestService.GetResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
                return null;
            }
        }

        public Response PostPayment()
        {
            try
            {
                //Call the Service to Get the Response Object
                var response = _paymentRequestService.PostResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
                return null;
            }
        }

        public Response PutPayment()
        {
            try
            {
                //Call the Service to Get the Response Object
                var response = _paymentRequestService.PutResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
                return null;
            }
        }

        public Response DeletePayment()
        {
            try
            {
                //Call the Service to Get the Response Object          
                var response = _paymentRequestService.DeleteResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
                return null;
            }
        }

        private  void LogResponseDetails(Response response)
        {
            _logger.Info("v-c-correlation-id:{0}", response.GetResponseHeaderValue(response.Headers, "v-c-correlation-id"));
            _logger.Info("Response Code:{0}", response.StatusCode);
            _logger.Info("Response Message:{0}", response.Data);
            _logger.Info("Status Information:{0}", response.StatusInfo);
        }
    }
}