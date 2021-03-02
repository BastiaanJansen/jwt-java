# JWT-Java

![](https://github./BastiaanJansen/JWT-Java/workflows/Build/badge.svg)
![](https://github.com/BastiaanJansen/JWT-Java/workflows/Test/badge.svg)
![](https://img.shields.io/github/license/BastiaanJansen/JWT-Java)
![](https://img.shields.io/github/issues/BastiaanJansen/JWT-Java)

JSON Web Token library for Java according to RFC 7519.

## What are JSON Web Tokens?

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public / private key pair using RSA or ECDSA.

JSON Web Tokens consist of three parts, which are seperated with `.`'s:
* Header
* Payload
* Signature

A JWT has therefore the following structure: `xxxxx.yyyyy.zzzzz`

### Header

The header holds information about the JWT. It typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA.

### Payload

The second part of the token is the payload, which contains the claims. Claims are statements about an entity and additional data. Reserved claims are called registred claims. There are seven registred claims:
* `iss`: Issuer, identifies the principal that issued the JWT
* `sub`: Subject, identifies the principal that is the subject of the JWT
* `aud`: Audience, identifies the principal that is the audience of the JWT
* `exp`: Expiration Time, identifies the expiration time on or after which the JWT must not be accepted for processing
* `nbf`: Not-before, identifies the time before which the JWT must not be accepted for processing
* `iat`: Issued At, identifies the time at which the JWT was issued
* `jti`: JWT ID, provides a unique identifier for the JWT

### Signature

To create the signature part you have to take the Base64URL encoded header, the Base64URL encoded payload, a secret, the algorithm specified in the header, and sign that.

### Features

* Creating JSON Web Tokens
* Validating JSON Web Tokens
* Easy to learn API
* Fluent interfaces 

#### Supported algorithms

|      | SHA256             | SHA256             | SHA512             |
|------|:------------------:|:------------------:|:------------------:|
| HMAC | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark:	|
| RSA  | :heavy_check_mark:	| :heavy_check_mark: | :heavy_check_mark:	|	

## Installation

## Usage

### Choose algorithm

To generate a JSON Web Token, you can use the fluent-interface builder API. But first, the builder expects an `Algorithm` instance. The `Algorithm` class has several static helper methods to create concrete `Algorithm` instances. For example, when you want to use the HMAC512 algorithm to sign your JWT's, create an `Algorithm` instance the following way:
```java
Algorithm algorithm = Algorithm.HMAC512("secret");
```
Of course, your secret should be much longer. When using HMAC512, the secret must be 512 bits. When using HMAC256, the secret must be 256 bits. Etcetera.

### Creating JWT's

When you have chosen an algorithm, you can use the JWT Builder to define how the JWT must look like and sign the token:
```java
String jwt = new JWT.Builder(algorithm)
  .withIssuer("issuer")
  .withAudience("aud1", "aud2")
  .withIssuedAt(new Date())
  .withID("id")
  .withClaim("username", "BastiaanJansen") // add custom claims
  .sign();
```

You can also define the header and payload before hand and add them without the JWT Builder:
```java
Header header = new Header();
header.setAlgorithm("HS512");

Payload payload = new Payload();
payload.setIssuer("issuer");
payload.setAudience("aud1", "aud2");
payload.withIssuedAt(new Date());
payload.withID("id");
payload.put("username", "BastiaanJansen"); // add custom claims

String jwt = new JWT(algorithm, header, payload).sign();
```

Thesee two ways of creating JWT's will generate the same tokens.

You don't need to immediately sign your JWT. You can also just build a `JWT` instance. With a `JWT` instance, you can get the header, payload, algorithm and validate the token which will be cover in a later chapter. You can, for example, pass around this `JWT` instance to other objects without passing around `String` objects.

```java
// Build JWT instance
JWT jwt = new JWT.Builder(algorithm)
  .withIssuer("issuer")
  .build();
  
Header header = jwt.getHeader();
Payload payload = jwt.getPayload();
Algorithm algorithm = jwt.getAlgorithm();

// To finally sign and get JWT String
String jwtString = jwt.sign();
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
String alg = header.getAlgorithm(); // "HS512"
String typ = header.getType(); // "JWT"

String iss = payload.getIssuer(); // "issuer"
String sub = payload.getSubject(); // "subject"
String[] audience = payload.getAudience(); // ["aud1", "aud2"]
Object customClaim = payload.get("username"); // "BastiaanJansen"
```

### Validating JWT's
