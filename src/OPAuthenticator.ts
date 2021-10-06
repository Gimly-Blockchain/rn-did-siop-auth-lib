// noinspection JSUnusedGlobalSymbols

import {SubmissionRequirementMatch, VerifiablePresentation} from "@sphereon/pe-js"
import {VerifiableCredential} from "@sphereon/pe-js/lib/verifiablePresentation/index"
import {OP, PresentationExchange} from "@spostma/did-auth-siop/dist/main"
import {
  ParsedAuthenticationRequestURI,
  PassBy,
  ResponseMode,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts
} from "@spostma/did-auth-siop/dist/main/types/SIOP.types"
import fetch from 'cross-fetch'

import './shim'

import {AuthRequestDetails, OPAuthenticatorOptions, QRCodeValues} from "./types/types"



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
  public async getAuthenticationRequestDetails(verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT,
                                               verifiableCredentials: VerifiableCredential[]): Promise<AuthRequestDetails> {
    const authRequestDetails: AuthRequestDetails = new AuthRequestDetails()
    const didResolutionResult = verifiedAuthenticationRequest.didResolutionResult
    authRequestDetails.id = didResolutionResult.didDocument.id
    authRequestDetails.alsoKnownAs = didResolutionResult.didDocument.alsoKnownAs
    const presentationDef = verifiedAuthenticationRequest.presentationDefinition
    if (presentationDef) {
      const pex = new PresentationExchange({did: this.op.authResponseOpts.did, allVerifiableCredentials: verifiableCredentials})

      const checked = await pex.selectVerifiableCredentialsForSubmission(presentationDef)
      if (checked.errors) {
        console.error("checked failed")
      }
      const matches : SubmissionRequirementMatch[] = checked.matches
      if (matches) {
        console.log("matches")
      }

      authRequestDetails.verifiablePresentation = await pex.submissionFrom(presentationDef, verifiableCredentials)
    }
    return authRequestDetails
  }


  /* Send the authentication response back to the RP */
  public async sendAuthResponse(verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT, verifiablePresentation?: VerifiablePresentation): Promise<Response> {
    try {
      const authResponse = await this.op.createAuthenticationResponse(verifiedAuthenticationRequest, {vp: verifiablePresentation})
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