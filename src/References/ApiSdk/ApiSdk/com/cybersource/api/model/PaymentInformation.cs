namespace ApiSdk.com.cybersource.api.model
{
    public class PaymentInformation
    {
        public Card card { get; set; }

        public PaymentInformation()
        {
            
        }
        public PaymentInformation(Card card)
        {
            this.card = card;
        }
    }
}