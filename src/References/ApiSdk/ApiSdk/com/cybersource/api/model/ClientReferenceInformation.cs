namespace ApiSdk.com.cybersource.api.model
{
    public class ClientReferenceInformation
    {
        public string code { get; set; }

        public ClientReferenceInformation()
        {
            
        }
        public ClientReferenceInformation(string code)
        {
            this.code = code;
        }
    }
}