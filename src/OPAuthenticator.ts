// noinspection JSUnusedGlobalSymbols

import {OP} from "@sphereon/did-auth-siop/dist/main"
import {
  ParsedAuthenticationRequestURI,
  PassBy,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts
} from "@sphereon/did-auth-siop/dist/main/types/SIOP.types"
// eslint-disable-next-line import/order
import axios from "axios"

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
        .build()
  }

  /* Get the authentication request URL from the RP */
  public async getRequestUrl(redirectUrl: string, state: string): Promise<ParsedAuthenticationRequestURI> {
    const getRequestUrl = redirectUrl + "?stateId=" + state
    console.log("getRequestUrl", getRequestUrl)
    try {
      const response = await axios.get(getRequestUrl)
      console.log("response.status", response.status)
      if (response.status == 200) {
        return this.op.parseAuthenticationRequestURI(response.data as string)
      } else {
        return Promise.reject("Could not fetch the request URL: " + response.statusText || response.data)
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
      const siopSessionResponse = await axios.post(authResponse.payload.aud, authResponse)
      if (siopSessionResponse.status == 200) {
        return
      } else {
        return Promise.reject(`Error ${siopSessionResponse.status}: ${siopSessionResponse.statusText}`)
      }
    } catch (e) {
      return Promise.reject(e.message)
    }
  }
}