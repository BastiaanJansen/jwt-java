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
