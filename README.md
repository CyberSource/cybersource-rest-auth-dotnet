# .NET Authentication SDK

This project provides a simple C# helper library that simplifies authentication to the CyberSource REST API.

## Requirements

* A CyberSource merchant account (see _Registration & Configuration_ section below)

## Target Frameworks

* .NET Framework 4.6.1
* .NET Standard 2.0
* .NET Standard 2.1
* .NET 8.0

## Dependencies

| Dependency | Version | Usage |
|------------|---------|-------|
| BouncyCastle.Cryptography | 2.6.2 | Implementation of cryptographic algorithms and protocols |
| NLog | 5.0.0 | Log routing and management |

## Usage

The Authentication SDK works for `POST`, `GET`, `PUT` and `DELETE` requests.
It supports two authentication mechanisms, viz. HTTP Signature and JSON Web Token (JWT).

> **⚠️ HTTP Signature Deprecation Notice:** HTTP Signature authentication is being deprecated.
> 
> **[JWT with Shared Secret](#jwt-authentication-with-shared-secret-recommended-migration-from-http-signature)** is the recommended migration path — it uses the same `merchantKeyId` and `merchantsecretKey` credentials, requires only two property changes, and enables MLE (Message Level Encryption) support that HTTP Signature does not provide.

## Configuration

This section specifies the different ways in which you can provide the credentials to be used for authenticating your requests to the Cybersource REST APIs.

The properties listed below can be provided in one of the following ways:

* Add them to a section `<MerchantConfig></MerchantConfig>` in an `App.config` file
* Add them to a `Dictionary` object

You can then call on `MerchantConfig.ctor()` (older process) or `MerchantCredentialSettings.ctor()` (newer process) to pass the `Dictionary` object (or an empty `Dictionary` object if you want to use the `App.config`). This will load these properties into the SDK to allow you to utilize the functionality that the SDK provides.

For consistency, the keys for these properties is provided as part of the `MerchantConfigurationKeys` class.

### HTTP Signature Authentication (⚠️ Deprecated — migrate to JWT with Shared Secret)

* `authenticationType`: Merchant should enter `"http_signature"` for HTTP authentication mechanism.
* `merchantID`: Merchant will provide the Merchant ID, which was received from EBC portal.
* `merchantsecretKey`: Merchant will provide the Secret Key value, which was generated on EBC portal.
* `merchantKeyId`: Merchant will provide the Key ID value, which was generated on EBC portal.
* `useMetaKey`: Set to `false`

```csharp
   authenticationType  = http_signature
   merchantID          = <merchantID>
   runEnvironment      = <runEnvironment (see below)>
   merchantKeyId       = <merchantKeyId>
   merchantsecretKey   = <merchantsecretKey>
   useMetaKey          = false
```

### JWT Authentication (with P12 certificate)

* `authenticationType`:  Merchant should enter `"jwt"` for JWT authentication mechanism.
* `merchantID`: Merchant will provide the Merchant ID, which was received from EBC portal.
* `keyAlias`: Alias of the Merchant ID, to be used while generating the JWT token.
* `keyPassword`: Alias of the Merchant password, to be used while generating the JWT token.
* `keyFilename`: Name of the .P12 certificate file. This file can be generated from the EBC portal.
* `keysDirectory`: path of the directory, where `keyFileName` is placed.
* `useMetaKey`: Set to `false`

```csharp
   authenticationType  = jwt
   merchantID          = <merchantID>
   runEnvironment      = <runEnvironment (see below)>
   keyAlias            = <keyAlias>
   keyPassword         = <keyPassword>
   keyFilename         = <keyFilename>
   keysDirectory       = <keysDirectory>
   useMetaKey          = false
```

### JWT Authentication with Shared Secret (Recommended migration from HTTP Signature)

Uses the **same** `merchantKeyId` and `merchantsecretKey` credentials as HTTP Signature. Only two properties change:

```csharp
   authenticationType  = jwt
   jwtKeyType          = SHARED_SECRET
   merchantID          = <merchantID>
   runEnvironment      = <runEnvironment (see below)>
   merchantKeyId       = <merchantKeyId>
   merchantsecretKey   = <merchantsecretKey>
   useMetaKey          = false
```

### For using MetaKey

MetaKey can be used for HTTP Signature, JWT (P12), and JWT with Shared Secret authentication.

To enable metaKey, you will need to understand the following terms:

* Portfolio ID: This is the Portfolio ID (or Organization ID).
* Merchant ID: This is the ID of the transacting merchant under the specified portfolio.

#### For HTTP Signature Authentication (⚠️ Deprecated)

* `authenticationType`: Merchant should enter `"http_signature"`.
* `merchantID`: The value should correspond to the transacting merchant ID under the Portfolio ID.
* `merchantsecretKey`: Shared secret obtained for the Portfolio ID.
* `merchantKeyId`: Key ID of the shared secret obtained for the Portfolio ID.
* `portfolioID`: The value should correspond to the Portfolio ID.
* `useMetaKey`: Set it to `true` to use Meta Key.

```csharp
   authenticationType  = http_signature
   merchantID          = <transacting merchantID>
   merchantKeyId       = <MetaKey merchantKeyId>
   merchantsecretKey   = <Metakey merchantsecretKey>
   useMetaKey          = true
   portfolioID         = <Portfolio ID>
```

#### For JWT Authentication

* `authenticationType`:  Merchant should enter `"jwt"`.
* `merchantID`: The value should correspond to the transacting merchant ID under the Portfolio ID.
* `keyAlias`: Alias of the Portfolio ID, to be used while generating the JWT token.
* `keyPassword`: Password for the .P12 certificate obtained for the Portfolio ID, to be used while generating the JWT token.
* `keyFilename`: Name of the .P12 certificate file obtained for the Portfolio ID. This file has generated from the EBC portal.
* `keysDirectory`: path of the directory, where `keyFilename` is placed.
* `useMetaKey`: Set it to `true` to use Meta Key.

```csharp
   authenticationType  = Jwt
   merchantID          = <transacting merchantID>
   keyAlias            = <keyAlias>
   keyPassword         = <keyPassword>
   keyFilename         = <keyFilename>
   keysDirectory       = <keysDirectory>
   useMetaKey          = true
```

#### For JWT Authentication with Shared Secret (Recommended)

* `authenticationType`: Merchant should enter `"jwt"`.
* `jwtKeyType`: Set to `"SHARED_SECRET"` for symmetric key authentication.
* `merchantID`: The value should correspond to the transacting merchant ID under the Portfolio ID.
* `merchantsecretKey`: Shared secret obtained for the Portfolio ID.
* `merchantKeyId`: Key ID of the shared secret obtained for the Portfolio ID.
* `portfolioID`: The value should correspond to the Portfolio ID.
* `useMetaKey`: Set it to `true` to use Meta Key.

```lang-none
   authenticationType  = jwt
   jwtKeyType          = SHARED_SECRET
   merchantID          = <transacting merchantID>
   merchantKeyId       = <MetaKey Portfolio KeyId>
   merchantsecretKey   = <MetaKey Portfolio Shared Secret Key>
   useMetaKey          = true
   portfolioID         = <Portfolio ID>
```

> **Note:** MetaKey with JWT Shared Secret uses the same MetaKey credentials as HTTP Signature but authenticates via JWT, enabling MLE support.

### Switching between the sandbox environment and the production environment

CyberSource maintains a complete sandbox environment for testing and development purposes. This sandbox environment is an exact duplicate of our production environment with the transaction authorization and settlement process simulated.

By default, this SDK is configured to communicate with the sandbox environment. To switch to the production environment, set the `runEnvironment` property in the SDK Configuration, as shown in [Sample Configuration file](https://github.com/CyberSource/cybersource-rest-samples-dotnet/blob/master/Shared/Source/Configuration.cs).

For example:

```csharp
   // For TESTING use
   _configurationDictionary.Add("runEnvironment", "apitest.cybersource.com");

   // For PRODUCTION use
   // _configurationDictionary.Add("runEnvironment", "api.cybersource.com");
```

## SDK Usage Examples and Sample Code

* To get started using this SDK, it is highly recommended to download our [sample code repository](https://github.com/CyberSource/cybersource-rest-samples-dotnet).

* In that repository, we have comprehensive code samples for all common uses of our APIs.

* Additionally, you can find details and examples of how our API is structured in our [Developer Center API Reference](https://developer.cybersource.com/api/reference/api-reference.html).

The API Reference Guide provides examples of what information is needed for a particular request and how that information would be formatted. Using those examples, you can easily determine what methods would be necessary to include that information in a request using this SDK.

## License

This repository is distributed under a proprietary license.
