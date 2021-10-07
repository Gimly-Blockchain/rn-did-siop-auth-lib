// noinspection JSUnusedGlobalSymbols

import { OP, PresentationExchange } from '@sphereon/did-auth-siop/dist/main'
import {
  ParsedAuthenticationRequestURI,
  PassBy,
  ResponseMode,
  VerifiablePresentationResponseOpts,
  VerifiablePresentationTypeFormat,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts,
} from '@sphereon/did-auth-siop/dist/main/types/SIOP.types'
import { SubmissionRequirementMatch } from '@sphereon/pe-js'
import { VerifiableCredential } from '@sphereon/pe-js/lib/verifiablePresentation/index'
import fetch from 'cross-fetch'

import './shim'

import { AuthRequestDetails, OPAuthenticatorOptions, QRCodeValues } from './types/types'

export default class OPAuthenticator {
  private op: OP

  private constructor(op: OP) {
    this.op = op
  }

  public static newInstance(options: OPAuthenticatorOptions): OPAuthenticator {
    const op = OP.builder()
      .withExpiresIn(options.expiresIn || 6000)
      .addDidMethod((options.didMethod as string) || 'ethr')
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
    const getRequestUrl = qrCodeValues.redirectUrl + '?stateId=' + qrCodeValues.state
    if ('development' === process.env.NODE_ENV) {
      console.log('getRequestUrl', getRequestUrl)
    }
    try {
      const response = await fetch(getRequestUrl)
      if ('development' === process.env.NODE_ENV) {
        console.log('response.status', response.status)
      }
      if (response.status == 200) {
        return this.op.parseAuthenticationRequestURI(await response.text())
      } else {
        return Promise.reject('Could not fetch the request URL: ' + response.statusText || (await response.text()))
      }
    } catch (error) {
      return Promise.reject(error.message)
    }
  }

  /* Verify the integrity of the authentication request */
  public async verifyAuthenticationRequestURI(
    requestURI: ParsedAuthenticationRequestURI,
    didMethod: string = null
  ): Promise<VerifiedAuthenticationRequestWithJWT> {
    const didMethodsSupported = requestURI.registration?.did_methods_supported as string[]

    let didMethods: string[]
    if (didMethodsSupported && didMethodsSupported.length) {
      // format did:ethr:
      didMethods = didMethodsSupported.map((value) => {
        return value.split(':')[1]
      })
    } else if (didMethod != null) {
      // RP mentioned no didMethods, meaning we have to let it up to the RP to see whether it will work
      didMethods = [didMethod]
    }

    const options: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          didMethods,
        },
      },
      nonce: requestURI.requestPayload.nonce,
    }

    try {
      return this.op.verifyAuthenticationRequest(requestURI.jwt, options)
    } catch (error) {
      console.error(error)
      return Promise.reject(error.message)
    }
  }

  /* Format the DID presentation */
  public async getAuthenticationRequestDetails(
    verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT,
    verifiableCredentials: VerifiableCredential[]
  ): Promise<AuthRequestDetails> {
    let verifiablePresentations
    const presentationDefs = verifiedAuthenticationRequest.presentationDefinitions
    if (presentationDefs && presentationDefs.length > 0) {
      const pex = new PresentationExchange({
        did: this.op.authResponseOpts.did,
        allVerifiableCredentials: verifiableCredentials,
      })

      verifiablePresentations = await Promise.all(
        presentationDefs.map(async (presentationDef) => {
          const checked = await pex.selectVerifiableCredentialsForSubmission(presentationDef.definition)
          if (checked.errors && checked.errors.length > 0) {
            console.error(`checked contained errors for presentation: ${JSON.stringify(presentationDef.definition)}`)
            console.error(`errors: ${JSON.stringify(checked.errors)}`)
            throw new Error(JSON.stringify(checked.errors))
          }

          const matches: SubmissionRequirementMatch[] = checked.matches
          if (matches && matches.length > 0) {
            console.log(`matches: ${JSON.stringify(checked.matches)}`)
          } else {
            console.error(`No matches against definition for presentation: ${JSON.stringify(presentationDef.definition)}`)
            throw new Error(JSON.stringify(checked.errors))
          }

          const vp = await pex.submissionFrom(presentationDef.definition, verifiableCredentials)
          return {
            location: presentationDef.location,
            format: VerifiablePresentationTypeFormat.LDP_VP,
            presentation: vp.getRoot(),
          }
        })
      )
    }

    const didResolutionResult = verifiedAuthenticationRequest.didResolutionResult
    return {
      id: didResolutionResult.didDocument.id,
      alsoKnownAs: didResolutionResult.didDocument.alsoKnownAs,
      vpResponseOpts: verifiablePresentations,
    }
  }

  /* Send the authentication response back to the RP */
  public async sendAuthResponse(
    verifiedAuthenticationRequest: VerifiedAuthenticationRequestWithJWT,
    vp?: VerifiablePresentationResponseOpts[]
  ): Promise<Response> {
    try {
      const authResponse = await this.op.createAuthenticationResponse(verifiedAuthenticationRequest, {
        vp,
      })
      const submittedResponse = await this.op.submitAuthenticationResponse(authResponse)
      if (submittedResponse.status >= 200 && submittedResponse.status < 300) {
        return submittedResponse
      } else {
        return Promise.reject(`Error ${submittedResponse.status}: ${submittedResponse.statusText || (await submittedResponse.text())}`)
      }
    } catch (error) {
      return Promise.reject(error.message)
    }
  }
}
