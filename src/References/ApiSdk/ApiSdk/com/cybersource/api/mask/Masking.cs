using System.IO;
using System.Text.RegularExpressions;
using ApiSdk.com.cybersource.api.util;
using Newtonsoft.Json;

namespace ApiSdk.com.cybersource.api.mask
{
    public class Masking
    {        
        public string MaskMessage(string message)
        {            
            message = Regex.Replace(message, @"\s+", "");
            var serializedMessage = JsonConvert.SerializeObject(message);            
            var maskedMessage = Mask(serializedMessage);
           
            return maskedMessage;            
        }

        // Filters to be masked
        //Reading from a text file (Masking.dat)        
        private readonly string[] _filters =  File.ReadAllLines(GlobalLabelParametersAPI.MaskingDatFilePath);

        private string Mask(string item)
        {
            foreach (var filter in _filters)
            {
                var reg = string.Concat(@"(\\""", filter, @"\\"":\\""[\w|\d|.@-]+\\"")");
                item = Regex.Replace(item, reg, string.Concat(@"""\", filter, @"\:\XXXXXXX\"));
            }
            return item;
        }        
    }
}
