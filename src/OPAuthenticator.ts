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
        .withExpiresIn(options.expiresIn)
        .addDidMethod(options.didMethod)
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
    console.log("getRequestUrl", getRequestUrl)
    try {
      const response = await fetch(getRequestUrl)
      console.log("response.status", response.status)
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
  public async verifyAuthenticationRequestURI(requestURI: ParsedAuthenticationRequestURI): Promise<VerifiedAuthenticationRequestWithJWT> {
    const options: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          didMethods: ["ethr"]
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
    const rpdid: RPDID = new RPDID()
    rpdid.id = didResolutionResult.didDocument.id
    rpdid.alsoKnownAs = didResolutionResult.didDocument.alsoKnownAs
    return rpdid
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