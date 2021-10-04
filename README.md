<h1 align="center">
  <br>
  <a href="https://www.gimly.io/"><img src="https://avatars.githubusercontent.com/u/64525639?s=200&v=4" alt="Gimly" width="180"></a>
  <br>DID SIOP auth component library for react-native 
  <br>
</h1>

This library module contains an OP (OpenID Provider) Authenticator implementation that can be used in React Native projects,  
it's basically a React Native wrapper around the ["Sphereon Self Issued OpenID Provider v2 (SIOP)" library](https://github.com/Sphereon-Opensource/did-auth-siop) 
reducing the implementation effort and troubleshooting involved with getting the SIOP library to work in a React Native environment. 

Demo project [rn-did-siop-example-app](https://github.com/Sphereon-OpenSource/rn-did-siop-example-app) implements this library.

### To build

- yarn install
- yarn build
- yarn publish (in case you want to publish the project to a private registry.)

### Usage
To use this helper library you need to implement the following:
First you create a new instance of OPAuthenticator. There are two static methods with different parameters:
```typescript
this.opAuthenticator = OPAuthenticator.newInstance(options)
```
Use this method for simplified instantiation with only the most common parameters.

````typescript
opDID: string
opKID: string
opPrivateKey: string
expiresIn: number // (optional, default is 6000ms) 
didMethod: string  // optional, IE. "ethr", "eosio". By default it is taken from the authentication requests did_methods_supported
````
When using typescript these fields are contained in class OPAuthenticatorOptions. 

or for more fine-grained control use the OP.builder() from the SIOP library:
````typescript
    this.opAuthenticator = OPAuthenticator.newInstanceFromOP(OP.builder()
        .withExpiresIn(expiresIn)
        .addDidMethod("ethr")
        .internalSignature(opPrivateKey, opDID, opKID)
        .registrationBy(PassBy.VALUE)
        .response(ResponseMode.POST)
        .build())
````
see [this openid-provider-siop section](https://github.com/Sphereon-Opensource/did-auth-siop#openid-provider-siop) for details.

The next step is to get an authentication request from the RP (Relying Party) endpoint. Method "getAuthenticationRequestFromRP" will the call the RP endpoint to 
retrieve the full authentication request based on the QR code data, it assumes you have a state identifier 
(field state) and a redirectUrl field in there. When using typescript it takes interface QRCodeValues as parameter.
(In case the entire authentication request is encoded in the QR code this step is not necessary.)

````typescript
this.authRequestURI = await this.opAuthenticator.getAuthenticationRequestFromRP(qrContent as QRCodeValues)
````
getAuthenticationRequestFromRP will return (when using typescript) and object for interface ParsedAuthenticationRequestURI. This is the input parameter for then next step:

````typescript
this.verifiedAuthenticationRequest = await this.opAuthenticator.verifyAuthenticationRequestURI(this.authRequestURI)
````

When verifyAuthenticationRequestURI method, the verification of authenticity of the request send by the RP succeeds, 
it will return an object for interface VerifiedAuthenticationRequestWithJWT.

Next there a helper method the extract DID information from the request, but this can also be done from within the VerifiedAuthenticationRequestWithJWT interface.

````typescript
const rpDid = this.opAuthenticator.rpDidFromAuthenticationRequest(this.verifiedAuthenticationRequest)
````
rpDidFromAuthenticationRequest will return class RPDID containing DID information

````typescript
export declare class RPDID {
  id: string;
  alsoKnownAs?: string[];
}
````

At this point the idea is that you present the DID information and ask the user for permission to send your DID back to the RP by using either a button or biometrics dialog.
When the user approves you can call the final method "sendAuthResponse" which will send the requested (and signed) OP did information back to the RP callback endpoint:
````typescript
 try {
  await this.opAuthenticator.sendAuthResponse(this.verifiedAuthenticationRequest as VerifiedAuthenticationRequestWithJWT)
  this.setState({message: "Login successful"})
} catch (e) {
  this.setState({message: "Error: " + e.message})
} finally {
  ...
}
````
(Except for rpDidFromAuthenticationRequest all methods will return a promise. Errors are raised using Promise.reject())
