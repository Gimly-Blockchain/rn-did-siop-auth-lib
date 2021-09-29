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

import {RPPresentation} from "./types/types"


export default class OPAuthenticator {

  private op: OP


  constructor(opDID: string, opPrivateKey: string) {
    this.op = OP.builder()
        .withExpiresIn(6000)
        .addDidMethod("ethr")
        .internalSignature(opPrivateKey, opDID, `${opDID}#controller`)
        .registrationBy(PassBy.VALUE)
        .response(ResponseMode.POST)
        .build()
  }

  /* Get the authentication request URL from the RP */
  public async getRequestUrl(redirectUrl: string, state: string): Promise<ParsedAuthenticationRequestURI> {
    const getRequestUrl = redirectUrl + "?stateId=" + state
    console.log("getRequestUrl", getRequestUrl)
    try {
      const response = await fetch(getRequestUrl)
      console.log("response.status", response.status)
      if (response.status == 200) {
        return this.op.parseAuthenticationRequestURI(await response.text())
      } else {
        return Promise.reject("Could not fetch the request URL: " + response.statusText || await response.text())
      }
    } catch (e) {
      return Promise.reject(e.message)
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

    return await this.op.verifyAuthenticationRequest(requestURI.jwt, options)
  }

  /* Format the DID presentation */
  public rpPresentationFromDidResolutionResult(verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT): RPPresentation {
    const didResolutionResult = verifiedAuthenticationRequest.didResolutionResult
    const rpPresentation: RPPresentation = new RPPresentation()
    rpPresentation.did = didResolutionResult.didDocument.id
    return rpPresentation
  }


  /* Send the authentication response back to the RP */
  public async sendAuthResponse(verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT): Promise<void> {
    try {
      const authResponse = await this.op.createAuthenticationResponseFromVerifiedRequest(verifiedAuthenticationRequest)
      const submittedResponse = await this.op.submitAuthenticationResponse(authResponse)
      if (submittedResponse.status == 200) {
        return
      } else {
        return Promise.reject(`Error ${submittedResponse.status}: ${submittedResponse.statusText}`)
      }
    } catch (e) {
      return Promise.reject(e.message)
    }
  }
}