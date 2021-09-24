import {OP} from "@sphereon/did-auth-siop/dist/main";
import {
  AuthenticationResponseOpts,
  PassBy,
  ResponseMode,
  VerificationMode,
  VerifyAuthenticationRequestOpts
} from "@sphereon/did-auth-siop/dist/main/types/SIOP.types";
import axios from "axios"
import '../shim'

// TODO Add configuration method for the DID & private key
const HEX_KEY = "c848751f600a9b8b91e3db840d75be2304b0ec4b9b15fe77d87d3eed9a007d1a";
const DID = "did:ethr:0x8D0E24509b79AfaB3A74Be1700ebF9769796B489";

export default class OPAuthenticator {

  // noinspection JSUnusedGlobalSymbols
  public async executeLoginFlowFromQR(redirectUrl: string, state: string): Promise<void> {
    const getRequestUrl = redirectUrl + "?stateId=" + state;
    console.log("getRequestUrl", getRequestUrl);
    const response = await axios.get(getRequestUrl)
    console.log("response.status", response.status);
    if (response.status == 200) {
      const uriDecoded = decodeURIComponent(response.data as string);
      const requestURI = OPAuthenticator.objectFromURI(uriDecoded)
      await this.verifyAuthenticationRequestURI(requestURI)
      return
    } else {
      throw new Error("Could not fetch the request URL: " + response.statusText || response.data)
    }
  }

  private async verifyAuthenticationRequestURI(requestURI: any): Promise<void> {
    const responseOpts: AuthenticationResponseOpts = {
      signatureType: {
        hexPrivateKey: HEX_KEY,
        did: DID
      },
      registration: {
        registrationBy: {
          type: PassBy.VALUE,
        },
      },
      responseMode: ResponseMode.POST,
      did: DID,
      expiresIn: 2000
    };

    const verifyOpts: VerifyAuthenticationRequestOpts = {
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: {
          didMethods: ["ethr"]
        }
      },
      nonce: requestURI.nonce
    }

    const op = OP.fromOpts(responseOpts, verifyOpts);
    const jwt = requestURI.request;
    await op.verifyAuthenticationRequest(jwt, {audience: DID});
    await this.sendAuthResponse(op, jwt, requestURI);
    return
  }

  private async sendAuthResponse(op: OP, requestJwt: string, requestURI: any): Promise<void> {
    const authResponse = await op.createAuthenticationResponse(requestJwt)
    const siopSessionResponse = await axios.post(requestURI.redirect_uri, authResponse)
    if (siopSessionResponse.status == 200) {
      return
    } else {
      throw new Error(`Error ${siopSessionResponse.status}: ${siopSessionResponse.statusText}`)
    }
  }

  private static objectFromURI(uriDecoded: string): string {
    return JSON.parse('{"' + uriDecoded.replace(/"/g, '\\"').replace(/&/g, '","').replace(/=/g, '":"') + '"}');
  }
}