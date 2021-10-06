import { VerifiablePresentationResponseOpts } from '@sphereon/did-auth-siop/dist/main/types/SIOP.types'

export class OPAuthenticatorOptions {
  opDID: string
  opKID: string
  opPrivateKey: string
  expiresIn?
  didMethod?
}

export interface AuthRequestDetails {
  id: string
  alsoKnownAs?: string[]
  vpResponseOpts: VerifiablePresentationResponseOpts[]
}

export interface QRCodeValues {
  state: string
  redirectUrl: string
}
