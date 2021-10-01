<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
  <br>DID SIOP auth component library for react-native 
  <br>
</h1>

This library contains an OP Authenticator implementation that can be used in React Native projects.

Demo project [rn-did-siop-example-app}(https://github.com/Sphereon-OpenSource/rn-did-siop-example-app) implements this library.

### To build

- yarn install
- yarn build
- yarn publish (in case you want to publish the project to a private registry.)

### Usage
To use this helper library you need to implement the following:
First you create a new instance of OPAuthenticator. There are two static methods with different paramaters:
```typescript
this.opAuthenticator = OPAuthenticator.newInstance(OP_DID, OP_KID, OP_PRIVATE_KEY)
```
Use this method for simplified instantiation with only the basic DID and private key parameters, 

or
````typescript
    this.opAuthenticator = OPAuthenticator.newInstanceFromOP(OP.builder()
        .withExpiresIn(expiresIn)
        .addDidMethod("ethr")
        .internalSignature(opPrivateKey, opDID, opKID)
        .registrationBy(PassBy.VALUE)
        .response(ResponseMode.POST)
        .build())
````
For more fine-grained control use OP.builder(), see [this openid-provider-siop section](https://github.com/Sphereon-Opensource/did-auth-siop#openid-provider-siop) for details.

The next step is to get an authentication request from the RP server. (In case the entire authentication request is encoded in the QR code this step is not necessary.)

````typescript
this.authRequestURI = await this.opAuthenticator.getAuthenticationRequestFromRP(qrContent as QRCodeValues)
````
getAuthenticationRequestFromRP will return (when using typescript) and object for interface ParsedAuthenticationRequestURI. This is the input parameter for then next step:

````typescript
this.verifiedAuthenticationRequest = await this.opAuthenticator.verifyAuthenticationRequestURI(this.authRequestURI)
````

When verifyAuthenticationRequestURI, the verification of authenticity of the request succeeds, it will return an object for interface VerifiedAuthenticationRequestWithJWT. Next there a helper method the extract DID information from the request, but this can also be done from within the request interface.

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

At this point the idea is that you present the DID information and asks the user for permission to send your DID back to the RP by using either a button or biometrics dialog.
When the user approves you can call the final method:
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
