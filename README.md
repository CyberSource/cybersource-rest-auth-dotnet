# cybersource-rest-auth-dotnet

This project provides a simple C# helper class that simplifies authentication to the CyberSource REST API 

## Requirements

* .NET Framework 4.6.1
* A cybersource-rest-auth-dotnet account (see _Registration & Configuration_ section below)

_Note: Support for building the SDK with Nuget has been made. Please see the respective build processes below. 
 All initial DLLs and docs were built with NuGet, however._
 
## Dependencies

  * jose-jwt 2.4.0               : Generating Json Web Token
  * NLog 4.0.0.0                 : Logging
  * nunit-framework 3.10.1.0     : Unit Testing
  * Newtonsoft.Json 11.0.0.0     : JSON Framework
  * OpenCover 4.6.519            : Code Coverage under Unit testing


## Use Cases

The Authentication SDK works for POST, GET, PUT and DELETE requests.
It works with any one of the two authentication mechanisms, which are HTTP signature and JWT token.

> **⚠️ HTTP Signature Deprecation Notice:** HTTP Signature authentication is being deprecated. **JWT with Shared Secret** is the recommended migration path — it uses the same `merchantKeyId` and `merchantsecretKey` credentials, requires only two property changes (`authenticationType=jwt` and `jwtKeyType=SHARED_SECRET`), and enables MLE (Message Level Encryption) support that HTTP Signature does not provide.

## Configuration

To set your API credentials for an API request, configure the following information in `App.Config` file inside the `<MerchantConfig></MerchantConfig>` tags:
  
### For Http Signature Authentication (⚠️ Deprecated — migrate to JWT with Shared Secret)
  
Configure the following information in `App.Config` file
  
  * Authentication Type:  Merchant should enter `"HTTP_Signature"` for HTTP authentication mechanism.
  * Merchant ID: Merchant will provide the merchant ID, which has taken from EBC portal.
  * MerchantSecretKey: Merchant will provide the secret Key value, which has taken from EBC portal.
  * MerchantKeyId:  Merchant will provide the Key ID value, which has taken from EBC portal.
  * Enable Log: To start the log entry provide `true`, else enter `false`.
  * LogDirectory: Merchant will provide directory path where logs will be created.
  * LogMaximumSize: Merchant will provide size value for log file.
  * LogFilename: Merchant will provide log file name.
  * Use Meta Key: Set to `false`

	```
	authenticationType  = http_Signature
	merchantID          = <merchantID>
	runEnvironment      = CyberSource.Environment.SANDBOX
	merchantKeyId       = <merchantKeyId>
	merchantsecretKey   = <merchantsecretKey>
	enableLog           = true
	logDirectory        = <logDirectory>
	logMaximumSize      = <size>
	logFilename         = <logFilename>
	useMetaKey          = false
	```
### For Jwt Signature Authentication (with P12 certificate)

Configure the following information in the App.Config file
  
  * Authentication Type:  Merchant should enter `"JWT"` for JWT authentication mechanism.
  * Merchant ID: Merchant will provide the merchant ID, which has taken from EBC portal.
  * keyAlias: Alias of the Merchant ID, to be used while generating the JWT token.
  * keyPassword: Alias of the Merchant password, to be used while generating the JWT token.
  * keyfilepath: Path of the folder where the .P12 file is placed. This file has generated from the EBC portal.
  * Keys Directory: path of the directory,where keys are placed.
  * Enable Log: To start the log entry provide `true`, else enter `false`.
  * LogDirectory: Merchant will provide directory path where logs will be created.
  * LogMaximumSize: Merchant will provide size value for log file.
  * LogFilename: Merchant will provide log file name.
  * Use Meta Key: Set to `false`.

	```
	authenticationType  = Jwt
	merchantID          = <merchantID>
	runEnvironment      = CyberSource.Environment.SANDBOX
	keyAlias            = <keyAlias>
	keyPassword         = <keyPassword>
	keyFileName         = <keyFileName>
	keysDirectory       = <keysDirectory>
	enableLog           = true
	logDirectory        = <logDirectory>
	logMaximumSize      = <size>
	logFilename         = <logFilename>
	useMetaKey          = false
	```

### For JWT authentication with Shared Secret (Recommended migration from HTTP Signature)

Uses the **same** `merchantKeyId` and `merchantsecretKey` credentials as HTTP Signature. Only two properties change:

  * Authentication Type: Set to `"jwt"`.
  * jwtKeyType: Set to `"SHARED_SECRET"` to use symmetric signing (HS256) with the shared secret key.
  * Merchant ID: Merchant will provide the merchant ID, which has taken from EBC portal.
  * MerchantKeyId: Same Key ID used for HTTP Signature.
  * MerchantSecretKey: Same Secret Key used for HTTP Signature.

	```
	authenticationType  = jwt
	jwtKeyType          = SHARED_SECRET
	merchantID          = <merchantID>
	runEnvironment      = apitest.cybersource.com
	merchantKeyId       = <merchantKeyId>
	merchantsecretKey   = <merchantsecretKey>
	enableLog           = true
	logDirectory        = <logDirectory>
	logMaximumSize      = <size>
	logFilename         = <logFilename>
	useMetaKey          = false
	```

### For using MetaKey

MetaKey can be used for HTTP Signature, JWT (P12), and JWT with Shared Secret authentication.

Configure the following information in App.config file

#### For HTTP Signature Authentication (⚠️ Deprecated)

  * Authentication Type:  Merchant should enter `"HTTP"`.
  * Merchant ID: Merchant will provide the child merchant ID under the Portfolio ID, which has taken from EBC portal.
  * MerchantSecretKey: Merchant will provide the secret Meta Key value, which has taken from EBC portal.
  * MerchantKeyId:  Merchant will provide the Meta Key ID value, which has taken from EBC portal.
  * PortfolioId: Merchant will provide the Portfolio ID, taken from EBC portal.
  * Use Meta Key: Set it to `true` to use Meta Key.

	```
	authenticationType  = http_Signature
	merchantID          = <child merchantID>
	merchantKeyId       = <MetaKey merchantKeyId>
	merchantsecretKey   = <Metakey merchantsecretKey>
	useMetaKey          = true
	portfolioID         = <Portfolio ID>
	```

#### For JWT Authentication (P12)

  * Authentication Type:  Merchant should enter `"JWT"`.
  * Merchant ID: Merchant will provide the child merchant ID under the Portfolio ID, which has taken from EBC portal.
  * keyAlias: Alias of the Merchant ID, to be used while generating the JWT token.
  * keyPassword: Alias of the Portfolio ID password, to be used while generating the JWT token.
  * keyfilepath: Path of the folder where the .P12 file is placed. This file has generated from the EBC portal.
  * Use Meta Key: Set it to `true` to use Meta Key.

	```
	authenticationType  = Jwt
	merchantID          = <child merchantID>
	keyAlias            = <keyAlias>
	keyPassword         = <keyPassword>
	keyFileName         = <keyFileName>
	keysDirectory       = <keysDirectory>
	useMetaKey          = true
	```

#### For JWT Authentication with Shared Secret (Recommended)

	```
	authenticationType  = jwt
	jwtKeyType          = SHARED_SECRET
	merchantID          = <child merchantID>
	merchantKeyId       = <MetaKey Portfolio KeyId>
	merchantsecretKey   = <MetaKey Portfolio Shared Secret Key>
	useMetaKey          = true
	portfolioID         = <Portfolio ID>
	```

### Switching between the sandbox environment and the production environment

CyberSource maintains a complete sandbox environment for testing and development purposes. This sandbox environment is an exact 
duplicate of our production environment with the transaction authorization and settlement process simulated. By default, this SDK is 
configured to communicate with the sandbox environment. To switch to the production environment, set the appropriate environment 
constant in `cybs.properties` file.  For example:

	```dotnet
	// For PRODUCTION use
	  runEnvironment      = api.cybersource.com
	```

## SDK Usage Examples and Sample Code

* To get started using this SDK, it's highly recommended to download our sample code repository.
* In that respository, we have comprehensive sample code for all common uses of our API.
* Additionally, you can find details and examples of how our API is structured in our API Reference Guide.

The API Reference Guide provides examples of what information is needed for a particular request and how that information would be
formatted. Using those examples, you can easily determine what methods would be necessary to include that information in a request
using this SDK.

## Building & Testing the SDK

Build the SDK with Visual Studio 2015

------------------------

## Disclaimer

CyberSource may allow Customer to access, use, and/or test a CyberSource product or service that may still be in development or has not been market-tested (“Beta Product”) solely for the purpose of evaluating the functionality or marketability of the Beta Product (a “Beta Evaluation”). Notwithstanding any language to the contrary, the following terms shall apply with respect to Customer’s participation in any Beta Evaluation (and the Beta Product(s)) accessed thereunder): The Parties will enter into a separate form agreement detailing the scope of the Beta Evaluation, requirements, pricing, the length of the beta evaluation period (“Beta Product Form”). Beta Products are not, and may not become, Transaction Services and have not yet been publicly released and are offered for the sole purpose of internal testing and non-commercial evaluation. Customer’s use of the Beta Product shall be solely for the purpose of conducting the Beta Evaluation. Customer accepts all risks arising out of the access and use of the Beta Products. CyberSource may, in its sole discretion, at any time, terminate or discontinue the Beta Evaluation. Customer acknowledges and agrees that any Beta Product may still be in development and that Beta Product is provided “AS IS” and may not perform at the level of a commercially available service, may not operate as expected and may be modified prior to release. CYBERSOURCE SHALL NOT BE RESPONSIBLE OR LIABLE UNDER ANY CONTRACT, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE RELATING TO A BETA PRODUCT OR THE BETA EVALUATION (A) FOR LOSS OR INACCURACY OF DATA OR COST OF PROCUREMENT OF SUBSTITUTE GOODS, SERVICES OR TECHNOLOGY, (B) ANY CLAIM, LOSSES, DAMAGES, OR CAUSE OF ACTION ARISING IN CONNECTION WITH THE BETA PRODUCT; OR (C) FOR ANY INDIRECT, INCIDENTAL OR CONSEQUENTIAL DAMAGES INCLUDING, BUT NOT LIMITED TO, LOSS OF REVENUES AND LOSS OF PROFITS.
  
## License

This repository is distributed under a proprietary license.
