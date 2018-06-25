namespace ApiSdk.com.cybersource.api.model
{
    public class OrderInformation
    {
        public BillTo billTo { get; set; }
        public AmountDetails amountDetails { get; set; }

        public OrderInformation()
        {
            
        }
        public OrderInformation(BillTo billTo, AmountDetails amountDetails)
        {
            this.billTo = billTo;
            this.amountDetails = amountDetails;
        }
    }
}