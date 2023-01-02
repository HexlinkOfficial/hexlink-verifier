import * as functions from "firebase-functions";
import {getEthAddressFromPublicKey, signWithKmsKey} from "./kms";
import {AuthType} from "./type";
import {verifiedByIdToken} from "./validations/idTokenValidation";
import {IDENTITY_VERIFIER_PUB_ADDR} from "./config";

export interface AuthProof {
  requestId: string,
  authType: string,
  identityType: string,
  issuedAt: number
}

export interface SignedAuthProof extends AuthProof {
  r: string,
  s: string,
  v: number
}

interface OAuthParams {
  idToken: string
}

export const genAuthProof = functions.https.onCall(
    async (data, context) => {
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }

      if (!Object.values(AuthType).includes(data.authType)) {
        return {code: 400,
          message: "Invalid auth type: " + data.authType};
      }

      switch (data.authType) {
        case AuthType[AuthType.OAuth]: {
          const params: OAuthParams = data.params;
          if (!params || !params.idToken) {
            return {code: 400,
              message: "Invalid input for OAuth validation."};
          }

          const verified = await verifiedByIdToken(params.idToken);
          if (!verified) {
            return {code: 401, message: "Invalid Token."};
          }
        }
      }

      const issuedAt = Date.now();
      const rawAuthProof: AuthProof = {
        requestId: data.requestId,
        authType: data.authType,
        identityType: data.identityType,
        issuedAt: issuedAt,
      };

      const [r, s, v] = await signWithKmsKey(
          rawAuthProof,
          IDENTITY_VERIFIER_PUB_ADDR);
      const AuthProof: SignedAuthProof = {
        ...rawAuthProof,
        r: <string>r,
        s: <string>s,
        v: <number>v,
      };

      return {code: 200, authProof: AuthProof};
    });

export const calcEthAddress = functions.https.onCall(
    async (data, context) => {
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }

      return getEthAddressFromPublicKey();
    }
);
