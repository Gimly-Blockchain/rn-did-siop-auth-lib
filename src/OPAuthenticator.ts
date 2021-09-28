// noinspection JSUnusedGlobalSymbols

import {OP} from "@sphereon/did-auth-siop/dist/main"
import {
  ParsedAuthenticationRequestURI,
  PassBy,
  VerificationMode,
  VerifyAuthenticationRequestOpts
} from "@sphereon/did-auth-siop/dist/main/types/SIOP.types"
// eslint-disable-next-line import/order
import axios from "axios"

import './shim'
import {DIDResolutionResult} from "did-resolver"

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

  public async verifyAuthenticationRequestURI(requestURI: ParsedAuthenticationRequestURI): Promise<RPPresentation> {
    const options: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          didMethods: ["ethr"]
        }
      },
      nonce: requestURI.requestPayload.nonce
    }

    const verifiedAuthenticationRequestWithJWT = await this.op.verifyAuthenticationRequest(requestURI.jwt, options)
    return this.rpPresentationFromDidResolutionResult(verifiedAuthenticationRequestWithJWT.didResolutionResult)
  }


  private rpPresentationFromDidResolutionResult(didResolutionResult: DIDResolutionResult): RPPresentation {
    const rpPresentation: RPPresentation = new RPPresentation()
    rpPresentation.did = didResolutionResult.didDocument.id
    return rpPresentation
  }


  public async sendAuthResponse(requestURI: ParsedAuthenticationRequestURI): Promise<void> {
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
      const authResponse = await this.op.createAuthenticationResponse(requestURI.jwt, options)
      const siopSessionResponse = await axios.post(requestURI.requestPayload.redirect_uri, authResponse)
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