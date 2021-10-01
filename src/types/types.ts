export class OPAuthenticatorOptions {
  opDID: string
  opKID: string
  opPrivateKey: string
  expiresIn = 6000
  didMethod = "ethr"
}


export class RPDID {
  id: string
  alsoKnownAs?: string[]
}


export interface QRCodeValues {
  state: string
  redirectUrl: string
}