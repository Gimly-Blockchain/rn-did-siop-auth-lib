import {VerifiablePresentation} from '@sphereon/pe-js'

export class OPAuthenticatorOptions {
  opDID: string
  opKID: string
  opPrivateKey: string
  expiresIn?
  didMethod?
}


export class AuthRequestDetails {
  id: string
  alsoKnownAs?: string[]
  verifiablePresentation: VerifiablePresentation
}


export interface QRCodeValues {
  state: string
  redirectUrl: string
}