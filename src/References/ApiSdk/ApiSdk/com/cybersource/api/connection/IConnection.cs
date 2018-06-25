using System.Net.Http;
using AuthenticationSdk.com.cybersource.authentication.util;

namespace ApiSdk.com.cybersource.api.connection
{
    public interface IConnection
    {        
        HttpClient GetConnectionForGet(MerchantConfig merchantConfig);
        HttpClient GetConnectionForPostOrPut(MerchantConfig merchantConfig);
    }
}
