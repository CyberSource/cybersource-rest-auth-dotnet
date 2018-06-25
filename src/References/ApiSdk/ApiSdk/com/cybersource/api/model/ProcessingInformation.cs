namespace ApiSdk.com.cybersource.api.model
{
    public class ProcessingInformation
    {
        public string commerceIndicator { get; set; }

        public ProcessingInformation()
        {
            
        }
        public ProcessingInformation(string commerceIndicator)
        {
            this.commerceIndicator = commerceIndicator;
        }
    }
}