# JWT-Java

[![Build & Test](https://github.com/BastiaanJansen/jwt-java/actions/workflows/build.yml/badge.svg)](https://github.com/BastiaanJansen/jwt-java/actions/workflows/build.yml)
![](https://img.shields.io/github/license/BastiaanJansen/JWT-Java)
![](https://img.shields.io/github/issues/BastiaanJansen/JWT-Java)

JSON Web Token library for Java according to [RFC 7519](https://tools.ietf.org/html/rfc7519).

## Table of Contents

* [What are JSON Web Tokens?](#what-are-json-web-tokens)
    * [Header](#header)
    * [Payload](#payload)
    * [Signature](#signature)
* [Features](#features)
    * [Supported algorithms](#supported-algorithms)
* [Installation](#installation)
* [Usage](#usage)
    * [Choose algorithm](#choose-algorithm)
        * [Secrets](#secrets)
    * [Creating JWT's](#creating-jwts)
    * [Parsing JWT's](#parsing-jwts)
    * [Validating JWT's](#validating-jwts)
        * [Basic validation](#basic-validation)
        * [Custom validation](#custom-validation)
        * [Create your own validator](#create-your-own-validator)
* [Sources](#sources) 

## What are JSON Web Tokens?

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public / private key pair using RSA or ECDSA.

JSON Web Tokens consist of three parts, which are seperated with `.`'s:
* Header
* Payload
* Signature

A JWT has therefore the following structure: `xxxxx.yyyyy.zzzzz`

### Header

The header holds information about the JWT. It typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA. There are two registered header parameters:
* `typ`: Type, is used by JWT applications to declare the media type of this complete JWT
* `cty`: Content Type, is used by this specification to convey structural information about the JWT

### Payload

The second part of the token is the payload, which contains the claims. Claims are statements about an entity and additional data. Reserved claims are called registered claims. There are seven registered claims:
* `iss`: Issuer, identifies the principal that issued the JWT
* `sub`: Subject, identifies the principal that is the subject of the JWT
* `aud`: Audience, identifies the principal that is the audience of the JWT
* `exp`: Expiration Time, identifies the expiration time on or after which the JWT must not be accepted for processing
* `nbf`: Not-before, identifies the time before which the JWT must not be accepted for processing
* `iat`: Issued At, identifies the time at which the JWT was issued
* `jti`: JWT ID, provides a unique identifier for the JWT

### Signature

To create the signature part you have to take the Base64URL encoded header, the Base64URL encoded payload, a secret, the algorithm specified in the header, and sign that.

## Features

* Creating JSON Web Tokens
* Powerful JWT validation options
* Self explanatory and easy to learn API
* Fluent interfaces

### Supported algorithms

|      | SHA256             | SHA384             | SHA512             |
|------|:------------------:|:------------------:|:------------------:|
| HMAC | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark:	|
| RSA  | :heavy_check_mark:	| :heavy_check_mark: | :heavy_check_mark:	|	

## Installation

### Maven
```xml
<dependency>
    <groupId>com.github.bastiaanjansen</groupId>
    <artifactId>jwt-java</artifactId>
    <version>1.1.0</version>
</dependency>
```

### Gradle
```gradle
implementation 'com.github.bastiaanjansen:jwt-java:1.1.0'
```

## Usage

### Choose algorithm

To generate a JSON Web Token, you can use the fluent-interface builder API. But first, the builder expects an `Algorithm` instance. The `Algorithm` class has several static helper methods to create concrete `Algorithm` instances. For example, when you want to use the HMAC512 algorithm to sign your JWT's, create an `Algorithm` instance the following way:
```java
Algorithm algorithm = Algorithm.HMAC512("secret");
```

Or use another algorithm:
```java
KeyPair keyPair = // Get key pair
Algorithm algorithm = Algorithm.RSA512(keyPair);
```

For a list of available algorithms: [Supported algorithms](#supported-algorithms)

#### Secrets

##### HMAC-SHA
* `HS256` secret key must be at least 256 bits (or 32 bytes) long
* `HS384` secret key must be at least 384 bits (or 48 bytes) long
* `HS512` secret key must be at least 512 bits (or 64 bytes) long

##### RSA
All RSA algorithms require a secret which is at least 2048 bits (or 256 bytes) long.

### Creating JWT's

When you have chosen an algorithm, you can use the JWT Builder to define how the JWT must look like and sign the token:
```java

try {
  String jwt = new JWT.Builder(algorithm)
    .withIssuer("issuer")
    .withAudience("aud1", "aud2")
    .withIssuedAt(new Date())
    .withID("id")
    .withClaim("username", "BastiaanJansen") // add custom claims
    .sign();
} catch (JWTCreationException e) {
  e.printStackTrace(); // Handle error
}
```
> Signed JWT's automatically have the `typ` header claim set to "JWT"

You can also define the header and payload before hand and add them without the JWT Builder:
```java
Header header = new Header();
header.setAlgorithm("HS512");

Payload payload = new Payload();
payload.setIssuer("issuer");
payload.setAudience("aud1", "aud2");
payload.setIssuedAt(new Date());
payload.setID("id");
payload.addClaim("username", "BastiaanJansen"); // add custom claims

try {
  String jwt = new JWT(algorithm, header, payload).sign();
} catch (JWTCreationException e) {
  e.printStackTrace(); // Handle error
}
```

These two ways of creating JWT's will generate the same tokens.

You don't need to immediately sign your JWT. You can also just build a `JWT` instance. With a `JWT` instance, you can get the header, payload, algorithm and validate the token which will be covered in a later chapter. You can, for example, pass around this `JWT` instance to other objects without passing around `String` objects.

```java
// Build JWT instance
JWT jwt = new JWT.Builder(algorithm)
  .withIssuer("issuer")
  .build();
  
Header header = jwt.getHeader();
Payload payload = jwt.getPayload();
Algorithm algorithm = jwt.getAlgorithm();

try {
  // To finally sign and get JWT String
  String jwtString = jwt.sign();
} catch (JWTCreationException e) {
  e.printStackTrace(); // Handle error
}
```

### Parsing JWT's

To parse raw JWT's, you can use the `JWT.fromRawJWT()` method which expects an `Algorithm` an a raw JWT string:
```java
String rawJWT = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwianRpIjoiaWQiLCJhdWRpZW5jZSI6WyJhdWQxIiwiYXVkMiJdLCJ1c2VybmFtZSI6IkJhc3RpYWFuSmFuc2VuIn0.mu1sSfzaNKH1dJ-cC1bsrFEJiwZs7H0AhnFf5tR4D0062zsxpU90F3dMrSlbneTtrxVI3PGxJlCYN8kcfpJkpw";

Algorithm algorithm = Algorithm.HMAC512(secret);

try {
  JWT jwt = JWT.fromRawJWT(algorithm, jwt);
} catch (JWTCreationException | JWTDecodeException e) {
  e.printStackTrace(); // Handle error
}

```
When you have retrieved the `JWT` instance, you can get data from the header and payload:
```java
Header header = jwt.getHeader();
Payload payload = jwt.getPayload();

// Get data from header and payload
String alg = header.getAlgorithm();
String typ = header.getType();
String cty = header.getContentType();

String iss = payload.getIssuer();
String sub = payload.getSubject();
String jti = payload.getID();
Date iat = payload.getIssuedAt();
Date exp = payload.getExpirationTime();
Date nbf = payload.getNotBefore();
String[] audience = payload.getAudience();

String customClaim = payload.getClaim("username", String.class);

boolean hasClaim = payload.containsClaim("key");
```

### Validating JWT's

#### Basic validation

To validate a JWT, you can use a `JWTValidator`. To validate a token in it's most basic form, use the `validate()` method on a `JWT` instance:
```java
JWT jwt = JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwianRpIjoiaWQiLCJhdWRpZW5jZSI6WyJhdWQxIiwiYXVkMiJdLCJ1c2VybmFtZSI6IkJhc3RpYWFuSmFuc2VuIn0.mu1sSfzaNKH1dJ-cC1bsrFEJiwZs7H0AhnFf5tR4D0062zsxpU90F3dMrSlbneTtrxVI3PGxJlCYN8kcfpJkpw");

try {
  jwt.validate();
  
  // JWT is valid!
} catch (JWTValidationException e) {
  e.printStackTrace(); // JWT is not valid, handle error
}
```
The `validate()` method uses the `DefaultJWTValidator` class underneath. Which, by default, enforces:
* the type (typ) in header is set to "JWT"
* the signature is valid
* when set, the expiration time is not exceeded,
* when set, the not-before time is not after or equal current time,

#### Custom validation

The `DefaultJWTValidator` does also support enforcing header or payload claims. This way you can make sure that, for example, the issuer is equal to something you expect. To use this feature, use the Builder of `DefaultJWTValidator`:
```java

JWTValidator validator = new DefaultJWTValidator.Builder()
  .withAlgorithm("HS512") // Enforce the alg in the header is set to HS512
  .withIssuer("issuer")
  .withID("id")
  .withOneOfAudience("aud1", "aud2") // Enforce audience has "aud1" or "aud2"
  .withClaim("username", "BastiaanJansen") // Enforce custom claim value
  .build();

try {
  // Give the verifier as argument
  jwt.validate(validator);
  
  // Or verify directly on the verifier
  verifier.validate(jwt);
  
  // JWT is valid!
} catch (JWTValidationException e) {
  e.printStackTrace(); // JWT is not valid, handle error
}
```

Or add custom validation logic:
```java
JWTValidator validator = new DefaultJWTValidator.Builder()
  .withClaim("username", new ClaimValidator() {
      @Override
      public boolean validate(Object value) {
          return "bastiaanjansen".equalsIgnoreCase(String.valueOf(value));
      }
  })
  .build();
  
// Or use a lambda
JWTValidator validator = new DefaultJWTValidator.Builder()
  .withClaim("username", value -> "bastiaanjansen".equalsIgnoreCase(String.valueOf(value)))
  .build()
```

#### Create your own validator

If the `DefaultJWTValidator` doesn't meet your requirements, you can create your own validator:
```java

public class CustomJWTValidator implements JWTValidator {

  @Override
  public void validate(JWT jwt) throws JWTValidationException {
    // Validate JWT
  }

}

```

You can use your custom validator the same way as the `DefaultJWTValidator`:

```java
try {
  JWTValidator customValidator = new CustomJWTValidator();
  
  // Give the verifier as argument
  jwt.validate(customValidator);
  
  // Or verify directly on the verifier
  customValidator.validate(jwt);
  
  // JWT is valid!
} catch (JWTValidationException e) {
  e.printStackTrace(); // JWT is not valid, handle error
}
```

## Sources
Sources used to gather information about JSON Web Tokens:
* [RFC 7519](https://tools.ietf.org/html/rfc7519)
* [jwt.io](https://jwt.io/introduction)

[![Stargazers repo roster for @BastiaanJansen/OTP-Java](https://reporoster.com/stars/BastiaanJansen/JWT-Java)](https://github.com/BastiaanJansen/JWT-Java/stargazers)
