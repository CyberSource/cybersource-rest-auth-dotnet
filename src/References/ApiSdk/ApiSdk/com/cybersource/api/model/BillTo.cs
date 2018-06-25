namespace ApiSdk.com.cybersource.api.model
{
    public class BillTo
    {
        public string country { get; set; }
        public string lastName { get; set; }
        public string address2 { get; set; }
        public string address1 { get; set; }
        public string postalCode { get; set; }
        public string locality { get; set; }
        public string administrativeArea { get; set; }
        public string firstName { get; set; }
        public string phoneNumber { get; set; }
        public string district { get; set; }
        public string buildingNumber { get; set; }
        public string company { get; set; }
        public string email { get; set; }

        public BillTo()
        {
            
        }
        public BillTo(string country, string lastName, string address2, string address1, string postalCode,
            string locality, string administrativeArea, string firstName, string phoneNumber, string district,
            string buildingNumber, string company, string email)
        {
            this.country = country;
            this.lastName = lastName;
            this.address2 = address2;
            this.address1 = address1;
            this.postalCode = postalCode;
            this.locality = locality;
            this.administrativeArea = administrativeArea;
            this.firstName = firstName;
            this.phoneNumber = phoneNumber;
            this.district = district;
            this.buildingNumber = buildingNumber;
            this.company = company;
            this.email = email;
        }
    }
}