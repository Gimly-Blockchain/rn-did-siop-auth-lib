export interface AuthenticationRequestURI {
  request: string
  redirect_uri: string
  nonce: string
}

export class RPPresentation {
  did: string
}