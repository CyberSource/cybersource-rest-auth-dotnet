# cybersource-rest-auth-dotnet
This project provides a simple C# helper class that simplifies authentication to the CyberSource REST API 

## Requirements
* .NET Framework 4.6.1
* A cybersource-rest-auth-dotnet account (see _Registration & Configuration_ section below)

_Note: Support for building the SDK with Nuget has been made. Please see the respective build processes below. 
 All initial jars and docs were built with Nuget, however._
 
 ## Dependencies
* jose-jwt 2.4.0              	: Generating Json Web Token
* NLog 4.0.0.0			: Logging
* nunit-framework 3.10.1.0	: Unit Testing
* Newtonsoft.Json 11.0.0.0	: JSON Framework
* OpenCover 4.6.519		: Code Coverage under Unit testing


## To run Aunthentication SDK

The Authentication SDK works for POST, GET, PUT and DELETE requests.
It works with any one of the two authentication mechanisms, which are HTTP signature and JWT token.

## To set your API credentials for an API request,Configure the following information in App.Config file inside the <MerchantConfig></MerchantConfig> tags:
  
  #### For Http Signature Authentication 
  
  Configure the following information in App.Config file
  
*	Authentication Type:  Merchant should enter “HTTP_Signature” for HTTP authentication mechanism.
*	Merchant ID: Merchant will provide the merchant ID, which has taken from EBC portal.
*	MerchantSecretKey: Merchant will provide the secret Key value, which has taken from EBC portal.
*	MerchantKeyId:  Merchant will provide the Key ID value, which has taken from EBC portal.
*	Enable Log: To start the log entry provide true else enter false.
*   LogDirectory :Merchant will provide directory path where logs will be created.
*   LogMaximumSize :Merchant will provide size value for log file.
*   LogFilename  :Merchant will provide log file name.


```
   authenticationType  = http_Signature
   merchantID 	       = <merchantID>
   runEnvironment      = CyberSource.Environment.SANDBOX
   merchantKeyId       = <merchantKeyId>
   merchantsecretKey   = <merchantsecretKey>
   enableLog           = true
   logDirectory        = <logDirectory>
   logMaximumSize      = <size>
   logFilename         = <logFilename>
```
  #### For Jwt Signature Authentication

  Configure the following information in the App.Config file
  
*	Authentication Type:  Merchant should enter “JWT” for JWT authentication mechanism.
*	Merchant ID: Merchant will provide the merchant ID, which has taken from EBC portal.
*	keyAlias: Alias of the Merchant ID, to be used while generating the JWT token.
*	keyPassword: Alias of the Merchant password, to be used while generating the JWT token.
*	keyfilepath: Path of the folder where the .P12 file is placed. This file has generated from the EBC portal.
*   Keys Directory: path of the directory,where keys are placed.
*	Enable Log: To start the log entry provide true else enter false.
*   LogDirectory :Merchant will provide directory path where logs will be created.
*   LogMaximumSize :Merchant will provide size value for log file.
*   LogFilename  :Merchant will provide log file name.

```
   authenticationType  = Jwt
   merchantID 	       = <merchantID>
   runEnvironment      = CyberSource.Environment.SANDBOX
   keyAlias		       = <keyAlias>
   keyPassword	       = <keyPassword>
   keyFileName         = <keyFileName>
   keysDirectory       = <keysDirectory>
   enableLog           = true
   logDirectory        = <logDirectory>
   logMaximumSize      = <size>
   logFilename         = <logFilename>
```

### Switching between the sandbox environment and the production environment
CyberSource maintains a complete sandbox environment for testing and development purposes. This sandbox environment is an exact 
duplicate of our production environment with the transaction authorization and settlement process simulated. By default, this SDK is 
configured to communicate with the sandbox environment. To switch to the production environment, set the appropriate environment 
constant in cybs.properties file.  For example:

```dotnet
// For PRODUCTION use
  runEnvironment      = CyberSource.Environment.PRODUCTION
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
  
## License
This repository is distributed under a proprietary license.
