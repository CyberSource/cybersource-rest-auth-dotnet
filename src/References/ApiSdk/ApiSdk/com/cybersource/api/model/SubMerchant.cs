namespace ApiSdk.com.cybersource.api.model
{
    public class SubMerchant
    {
        public string cardAcceptorID { get; set; }
        public string country { get; set; }
        public string phoneNumber { get; set; }
        public string address1 { get; set; }
        public string postalCode { get; set; }
        public string locality { get; set; }
        public string name { get; set; }
        public string administrativeArea { get; set; }
        public string region { get; set; }
        public string email { get; set; }

        public SubMerchant()
        {
            
        }
        public SubMerchant(string cardAcceptorID, string country, string phoneNumber, string address1, string postalCode,
            string locality, string name, string administrativeArea, string region, string email)
        {
            this.cardAcceptorID = cardAcceptorID;
            this.country = country;
            this.phoneNumber = phoneNumber;
            this.address1 = address1;
            this.postalCode = postalCode;
            this.locality = locality;
            this.name = name;
            this.administrativeArea = administrativeArea;
            this.region = region;
            this.email = email;
        }
    }
}