import {OP} from "@sphereon/did-auth-siop/dist/main";
import {VerifiedAuthenticationRequestWithJWT} from "@sphereon/did-auth-siop/dist/main/types/SIOP.types";

import {
    AuthenticationResponseOpts,
    PassBy,
    ResponseMode,
    VerificationMode,
    VerifyAuthenticationRequestOpts
} from "@sphereon/did-auth-siop/dist/main/types/SIOP.types";
import axios from "axios"
import './shim'

//const HEX_KEY = "c848751f600a9b8b91e3db840d75be2304b0ec4b9b15fe77d87d3eed9a007d1a";
//const DID = "did:ethr:0x8D0E24509b79AfaB3A74Be1700ebF9769796B489";

export default class OPAuthenticator {

    private opDID: string;
    private opPrivateKey: string;


    constructor(opDID: string, opPrivateKey: string) {
        this.opDID = opDID
        this.opPrivateKey = opPrivateKey
    }

// noinspection JSUnusedGlobalSymbols
    public async getRequestUrl(redirectUrl: string, state: string): Promise<string> {
        const getRequestUrl = redirectUrl + "?stateId=" + state;
        console.log("getRequestUrl", getRequestUrl);
        const response = await axios.get(getRequestUrl)
        console.log("response.status", response.status);
        if (response.status == 200) {
            const uriDecoded = decodeURIComponent(response.data as string);
            return OPAuthenticator.objectFromURI(uriDecoded)
        } else {
            throw new Error("Could not fetch the request URL: " + response.statusText || response.data)
        }
    }

    public async verifyAuthenticationRequestURI(requestURI: any): Promise<VerifiedAuthenticationRequestWithJWT> {
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
        return await op.verifyAuthenticationRequest(jwt, {});
    }


    public async sendAuthResponse(op: OP, requestJwt: string, redirectURI: string): Promise<void> {
        const authResponse = await op.createAuthenticationResponse(requestJwt)
        const siopSessionResponse = await axios.post(redirectURI, authResponse)
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