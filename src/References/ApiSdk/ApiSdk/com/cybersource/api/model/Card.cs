namespace ApiSdk.com.cybersource.api.model
{
    public class Card
    {
        public string expirationYear { get; set; }
        public string number { get; set; }
        public string securityCode { get; set; }
        public string expirationMonth { get; set; }
        public string type { get; set; }

        public Card()
        {
            
        }

        public Card(string expirationYear, string number, string securityCode, string expirationMonth, string type)
        {
            this.expirationYear = expirationYear;
            this.number = number;
            this.securityCode = securityCode;
            this.expirationMonth = expirationMonth;
            this.type = type;
        }
    }
}