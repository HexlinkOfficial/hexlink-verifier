import * as functions from "firebase-functions";
import * as ethers from "ethers";
import {getEthAddressFromPublicKey, signWithKmsKey} from "./kms";
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
  sig: string
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

      switch (data.authType) {
        case "oauth": {
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

      const issuedAt = Math.round(Date.now() / 1000);
      const rawAuthProof: AuthProof = {
        name: data.name,
        requestId: data.requestId,
        issuedAt: issuedAt,
        identityType: data.identityType,
        authType: data.authType,
      };

      const message = ethers.utils.keccak256(
          ethers.utils.defaultAbiCoder.encode(
              ["bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
              [ethers.utils.formatBytes32String(rawAuthProof.name),
                ethers.utils.formatBytes32String(rawAuthProof.requestId),
                rawAuthProof.issuedAt,
                ethers.utils.formatBytes32String(rawAuthProof.identityType),
                ethers.utils.formatBytes32String(rawAuthProof.authType)]
          )
      );

      const [r, s, v, sig] = await signWithKmsKey(
          data.keyType, message);
      const AuthProof: SignedAuthProof = {
        ...rawAuthProof,
        r: <string>r,
        s: <string>s,
        v: <number>v,
        sig: <string>sig,
      };

      return {code: 200, authProof: AuthProof};
    });

export const signWithKms = functions.https.onCall(
    async (data, context) => {
      /*
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }
      */

      return signWithKmsKey(data.keyType, data.message);
    }
);

export const calcEthAddress = functions.https.onCall(
    async (data, context) => {
      /*
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }
      */

      return getEthAddressFromPublicKey(data.keyType);
    }
);
