export class OPAuthenticatorOptions {
  opDID: string
  opKID: string
  opPrivateKey: string
  expiresIn?
  didMethod?
}


export class RPDID {
  id: string
  alsoKnownAs?: string[]
}


export interface QRCodeValues {
  state: string
  redirectUrl: string
}