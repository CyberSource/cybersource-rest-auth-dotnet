namespace ApiSdk.com.cybersource.api.model
{
    public class AmountDetails
    {
        public string totalAmount { get; set; }
        public string currency { get; set; }

        public AmountDetails()
        {
            
        }
        public AmountDetails(string totalAmount, string currency)
        {
            this.totalAmount = totalAmount;
            this.currency = currency;
        }
    }
}