import * as functions from "firebase-functions";
import {getEthAddressFromPublicKey, signWithKmsKey} from "./kms";
import {AuthType} from "./type";
import {verifiedByIdToken} from "./validations/idTokenValidation";

export interface AuthProof {
  name: string,
  requestId: string,
  authType: string,
  identityType: string,
  issuedAt: number
}

export interface SignedAuthProof extends AuthProof {
  r: string,
  s: string,
  v: number,
  signature: string
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
        name: data.name,
        requestId: data.requestId,
        issuedAt: issuedAt,
        identityType: data.identityType,
        authType: data.authType,
      };

      const [r, s, v, signature] = await signWithKmsKey(
          data.keyType,
          JSON.stringify(rawAuthProof));
      const AuthProof: SignedAuthProof = {
        ...rawAuthProof,
        r: <string>r,
        s: <string>s,
        v: <number>v,
        signature: <string> signature,
      };

      return {code: 200, authProof: AuthProof};
    });

export const signWithKms = functions.https.onCall(
    async (data, context) => {
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }

      return signWithKmsKey(data.keyType, data.message);
    }
);

export const calcEthAddress = functions.https.onCall(
    async (data, context) => {
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }

      return getEthAddressFromPublicKey(data.keyType);
    }
);
