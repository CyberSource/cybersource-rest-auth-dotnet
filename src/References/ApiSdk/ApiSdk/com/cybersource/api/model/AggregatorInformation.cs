namespace ApiSdk.com.cybersource.api.model
{
    public class AggregatorInformation
    {
        public SubMerchant subMerchant { get; set; }
        public string name { get; set; }
        public string aggregatorID { get; set; }

        public AggregatorInformation()
        {
            
        }

        public AggregatorInformation(SubMerchant subMerchant, string name, string aggregatorID)
        {
            this.subMerchant = subMerchant;
            this.name = name;
            this.aggregatorID = aggregatorID;
        }
        
    }
}