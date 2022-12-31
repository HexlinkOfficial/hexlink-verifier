import * as functions from "firebase-functions";
import {getEthAddressFromPublicKey, signWithKmsKey} from "./kms";
import {IdentityType, AuthType} from "./type";
import {
  verifiedByIdToken,
  verifyFollowingStatus,
  verifyRetweetStatus,
} from "./validation";

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
  idToken: string,
  accessToken?: string,
  secret?: string,
  source?: string,
  target?: string,
  retweetRequired?: boolean, // false by default
  tweetId?: string
}

export const genAuthProof = functions.https.onCall(
    async (data, context) => {
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }

      // validation
      let verified = null;
      switch (data.authType) {
        case AuthType[AuthType.OAuth]: {
          const params: OAuthParams = data.params;
          if (!params || !params.idToken) {
            return {code: 400,
              message: "Invalid input for IdToken validation."};
          }

          verified = await verifiedByIdToken(params.idToken);
          if (!verified) {
            return {code: 401, message: "Invalid Token."};
          }

          if (data.identityType === IdentityType[IdentityType.Twitter]) {
            if (!params.accessToken || !params.secret || !params.source ||
              !params.target) {
              return {code: 400,
                message: "Invalid input for Twitter validation."};
            }

            verified = await verifyFollowingStatus(
                params.accessToken!,
                params.secret!,
                params.source!,
                params.target!);

            if (!verified) {
              return {code: 401, message: "The user is not a follower."};
            }

            if (params.retweetRequired && params.tweetId) {
              verified = await verifyRetweetStatus(
                  params.source!,
                  params.tweetId!);
            }
            if (!verified) {
              return {code: 401,
                message: "The user hasn't retweeted the required tweet."};
            }
          }
        }
      }

      // create AuthProf
      const issuedAt = Date.now();
      const rawAuthProof: AuthProof = {
        requestId: data.requestId,
        authType: data.authType,
        identityType: data.identityType,
        issuedAt: issuedAt,
      };

      // sign AuthProof
      const [r, s, v] = await signWithKmsKey(rawAuthProof, data.address);
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
