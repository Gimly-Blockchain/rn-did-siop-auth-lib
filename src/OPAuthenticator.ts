// noinspection JSUnusedGlobalSymbols

import {OP} from "@sphereon/did-auth-siop/dist/main"
import {
  ParsedAuthenticationRequestURI,
  PassBy,
  ResponseMode,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts
} from "@sphereon/did-auth-siop/dist/main/types/SIOP.types"
import fetch from 'cross-fetch'

import './shim'

import {OPAuthenticatorOptions, QRCodeValues, RPDID} from "./types/types"


export default class OPAuthenticator {

  private op: OP


  private constructor(op: OP) {
    this.op = op
  }

  public static newInstance(options: OPAuthenticatorOptions): OPAuthenticator {
    const op = OP.builder()
        .withExpiresIn(options.expiresIn || 6000)
        .addDidMethod(options.didMethod as string || "ethr")
        .internalSignature(options.opPrivateKey, options.opDID, options.opKID)
        .registrationBy(PassBy.VALUE)
        .response(ResponseMode.POST)
        .build()
    return this.newInstanceFromOP(op)
  }

  public static newInstanceFromOP(op: OP): OPAuthenticator {
    return new OPAuthenticator(op)
  }


  /* Get the authentication request URL from the RP */
  public async getAuthenticationRequestFromRP(qrCodeValues: QRCodeValues): Promise<ParsedAuthenticationRequestURI> {
    const getRequestUrl = qrCodeValues.redirectUrl + "?stateId=" + qrCodeValues.state
    if ("development" === process.env.NODE_ENV) {
      console.log("getRequestUrl", getRequestUrl)
    }
    try {
      const response = await fetch(getRequestUrl)
      if ("development" === process.env.NODE_ENV) {
        console.log("response.status", response.status)
      }
      if (response.status == 200) {
        return this.op.parseAuthenticationRequestURI(await response.text())
      } else {
        return Promise.reject("Could not fetch the request URL: " + response.statusText || await response.text())
      }
    } catch (error) {
      return Promise.reject(error.message)
    }
  }


  /* Verify the integrity of the authentication request */
  public async verifyAuthenticationRequestURI(requestURI: ParsedAuthenticationRequestURI, didMethod: string = null): Promise<VerifiedAuthenticationRequestWithJWT> {
    const didMethodsSupported = requestURI.registration.did_methods_supported as string[]
    if (!didMethodsSupported) {
      return Promise.reject(`A value for did_methods_supported is missing from the Authentication Request URI`)
    }

    let didMethods: string[]
    if (didMethodsSupported && didMethodsSupported.length) { // format did:ethr:
      didMethods = didMethodsSupported.map(value => {
        return value.split(":")[1]
      })
    } else if (didMethod != null) {
      didMethods = []
      if (didMethodsSupported.indexOf(`did:${didMethod}:`) > -1) {
        didMethods.push(didMethod)
      } else {
        return Promise.reject(`didMethod ${didMethod} is not among the supported didMethods ${didMethodsSupported}`)
      }
    }

    const options: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          didMethods: didMethods
        }
      },
      nonce: requestURI.requestPayload.nonce
    }

    try {
      return this.op.verifyAuthenticationRequest(requestURI.jwt, options)
    } catch (error) {
      console.error(error)
      return Promise.reject(error.message)
    }
  }


  /* Format the DID presentation */
  public rpDidFromAuthenticationRequest(verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT): RPDID {
    const didResolutionResult = verifiedAuthenticationRequest.didResolutionResult
    const rpDid: RPDID = new RPDID()
    rpDid.id = didResolutionResult.didDocument.id
    rpDid.alsoKnownAs = didResolutionResult.didDocument.alsoKnownAs
    return rpDid
  }


  /* Send the authentication response back to the RP */
  public async sendAuthResponse(verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT): Promise<Response> {
    try {
      const authResponse = await this.op.createAuthenticationResponseFromVerifiedRequest(verifiedAuthenticationRequest)
      const submittedResponse = await this.op.submitAuthenticationResponse(authResponse)
      if (submittedResponse.status >= 200 && submittedResponse.status < 300) {
        return submittedResponse
      } else {
        return Promise.reject(`Error ${submittedResponse.status}: ${submittedResponse.statusText || await submittedResponse.text()}`)
      }
    } catch (error) {
      return Promise.reject(error.message)
    }
  }
}