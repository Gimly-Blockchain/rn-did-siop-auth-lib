import {OP} from "@sphereon/did-auth-siop/dist/main"
import {
  AuthenticationResponseOpts,
  PassBy,
  ResponseMode,
  VerificationMode,
  VerifyAuthenticationRequestOpts
} from "@sphereon/did-auth-siop/dist/main/types/SIOP.types"
// eslint-disable-next-line import/order
import axios from "axios"

import './shim'
import {DIDResolutionResult} from "did-resolver"

import {AuthenticationRequestURI, RPPresentation} from "./types/types"


export default class OPAuthenticator {

  private opDID: string
  private opPrivateKey: string


  constructor(opDID: string, opPrivateKey: string) {
    this.opDID = opDID
    this.opPrivateKey = opPrivateKey
  }

// noinspection JSUnusedGlobalSymbols
  public async getRequestUrl(redirectUrl: string, state: string): Promise<AuthenticationRequestURI> {
    const getRequestUrl = redirectUrl + "?stateId=" + state
    console.log("getRequestUrl", getRequestUrl)
    try {
      const response = await axios.get(getRequestUrl)
      console.log("response.status", response.status)
      if (response.status == 200) {
        const uriDecoded = decodeURIComponent(response.data as string)
        return OPAuthenticator.objectFromURI(uriDecoded)
      } else {
        return Promise.reject("Could not fetch the request URL: " + response.statusText || response.data)
      }
    } catch (e) {
      return Promise.reject(e.message)
    }
  }

  public async verifyAuthenticationRequestURI(requestURI: AuthenticationRequestURI): Promise<RPPresentation> {
    const responseOpts: AuthenticationResponseOpts = {
      signatureType: {
        hexPrivateKey: this.opPrivateKey,
        did: this.opDID
      },
      registration: {
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
      responseMode: ResponseMode.POST,
      did: this.opDID,
      expiresIn: 2000
    }

    const verifyOpts: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          didMethods: ["ethr"]
        }
      },
      nonce: requestURI.nonce
    }

    const op = OP.fromOpts(responseOpts, verifyOpts)
    const jwt = requestURI.request
    const verifiedAuthenticationRequestWithJWT = await op.verifyAuthenticationRequest(jwt, {})
    return this.rpPresentationFromDidResolutionResult(verifiedAuthenticationRequestWithJWT.didResolutionResult)
  }


  private rpPresentationFromDidResolutionResult(didResolutionResult: DIDResolutionResult): RPPresentation {
    const rpPresentation: RPPresentation = new RPPresentation()
    rpPresentation.did = didResolutionResult.didDocument.id
    return rpPresentation
  }


  public async sendAuthResponse(requestURI: AuthenticationRequestURI): Promise<void> {
    const responseOpts: AuthenticationResponseOpts = {
      signatureType: {
        hexPrivateKey: this.opPrivateKey,
        did: this.opDID
      },
      registration: {
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
      responseMode: ResponseMode.POST,
      did: this.opDID,
      expiresIn: 2000
    }

    const verifyOpts: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          didMethods: ["ethr"]
        }
      },
      nonce: requestURI.nonce
    }

    try {
      const op = OP.fromOpts(responseOpts, verifyOpts)
      const authResponse = await op.createAuthenticationResponse(requestURI.request)
      const siopSessionResponse = await axios.post(requestURI.redirect_uri, authResponse)
      if (siopSessionResponse.status == 200) {
        return
      } else {
        return Promise.reject(`Error ${siopSessionResponse.status}: ${siopSessionResponse.statusText}`)
      }
    } catch (e) {
      return Promise.reject(e.message)
    }
  }

  private static objectFromURI(uriDecoded: string): AuthenticationRequestURI {
    return JSON.parse('{"' + uriDecoded.replace(/"/g, '\\"').replace(/&/g, '","').replace(/=/g, '":"') + '"}')
  }
}