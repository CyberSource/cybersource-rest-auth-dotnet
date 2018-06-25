namespace ApiSdk.com.cybersource.api.model
{
    public class Payments
    {
        public ClientReferenceInformation clientReferenceInformation { get; set; }
        public ProcessingInformation processingInformation { get; set; }
        public AggregatorInformation aggregatorInformation { get; set; }
        public OrderInformation orderInformation { get; set; }
        public PaymentInformation paymentInformation { get; set; }

        public Payments()
        {
            
        }
        public Payments(ClientReferenceInformation clientReferenceInformation,
            ProcessingInformation processingInformation, AggregatorInformation aggregatorInformation,
            OrderInformation orderInformation, PaymentInformation paymentInformation)
        {
            this.clientReferenceInformation = clientReferenceInformation;
            this.processingInformation = processingInformation;
            this.aggregatorInformation = aggregatorInformation;
            this.orderInformation = orderInformation;
            this.paymentInformation = paymentInformation;
        }
    }
}