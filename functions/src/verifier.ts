import * as functions from "firebase-functions";
import {getAuth} from "firebase-admin/auth";
import * as kms from "@google-cloud/kms";
import {KMS_CONFIG} from "./config";
import * as crypto from "crypto";
import * as crc32c from "fast-crc32c";
import * as ethers from "ethers";
import * as asn1 from "asn1.js";

export enum AuthType {
  OAuth
}

export enum IdentityType {
  Email
}

export interface AuthProof {
  requestId: string,
  authType: string,
  identityType: IdentityType | null,
  issuedAt: number,
}

export interface SignedAuthProof extends AuthProof {
  r: string,
  s: string,
  v: number
}

const client = new kms.KeyManagementServiceClient();

const versionName = client.cryptoKeyVersionPath(
    KMS_CONFIG.projectId,
    KMS_CONFIG.locationId,
    KMS_CONFIG.keyRingId,
    KMS_CONFIG.keyId,
    KMS_CONFIG.versionId
);

const EcdsaSigAsnParse = asn1.define("EcdsaSig", function(this: any) {
  this.seq().obj(
      this.key("r").int(),
      this.key("s").int(),
  );
});

const signWithKmsKey = async function(
    rawAuthProof: AuthProof,
    address: string
) {
  const hash = crypto.createHash("sha256");
  const message = JSON.stringify(rawAuthProof);
  hash.update(message);
  const digest = hash.digest();

  const digestCrc32c = crc32c.calculate(digest);

  const [signResponse] = await client.asymmetricSign({
    name: versionName,
    digest: {
      sha256: digest,
    },
    digestCrc32c: {
      value: digestCrc32c,
    },
  });

  if (signResponse.name !== versionName) {
    throw new Error("AsymmetricSign: request corrupted in-transit");
  }
  if (!signResponse.verifiedDigestCrc32c) {
    throw new Error("AsymmetricSign: request corrupted in-transit");
  }
  if (!signResponse.signature || !signResponse.signatureCrc32c ||
    crc32c.calculate(<string>signResponse.signature) !==
    Number(signResponse.signatureCrc32c.value)
  ) {
    throw new Error("AsymmetricSign: response corrupted in-transit");
  }

  const [r, s] = await calculateRS(signResponse.signature as Buffer);
  const v = calculateRecoveryParam(
      digest,
      r,
      s,
      address);

  return [r, s, v];
};

const calculateRS = async function(signature: Buffer) {
  const decoded = EcdsaSigAsnParse.decode(signature, "der");
  const r = "0x" + decoded.r.toString("hex");
  let s = ethers.BigNumber.from("0x" + decoded.s.toString("hex"));

  const secp256k1N = ethers.BigNumber.from(
      "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
  );
  const secp256k1halfN = secp256k1N.div(ethers.BigNumber.from(2));

  if (s.gt(secp256k1halfN)) {
    s = secp256k1N.sub(s);
  }

  return [r, s.toHexString()];
};

const calculateRecoveryParam = (
    digest: Buffer,
    r: string,
    s: string,
    address: string
) => {
  let v: number;
  for (v = 0; v <= 1; v++) {
    const recoveredEthAddr = ethers.utils.recoverAddress(
        digest,
        {r, s, v}
    ).toLowerCase();

    if (recoveredEthAddr != address.toLowerCase()) {
      continue;
    }

    return v;
  }

  throw new Error("Failed to calculate recovery param");
};

const verifiedByOAuth = async function(idToken: string) {
  return await getAuth().verifyIdToken(idToken);
};

export const genAuthProof = functions.https.onCall(
    async (data, context) => {
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }

      let verified = null;
      let identityType = null;
      switch (data.authType) {
        case AuthType[AuthType.OAuth]: {
          if (data.params.has("idToken")) {
            verified = await verifiedByOAuth(data.params.get("idToken"));
            if (!verified) {
              return {code: 401, message: "Unauthorized Token"};
            }
            identityType = IdentityType.Email;
          }
        }
      }

      const issuedAt = Date.now();
      const rawAuthProof: AuthProof = {
        requestId: data.requestId,
        authType: data.authType,
        identityType: identityType,
        issuedAt: issuedAt,
      };

      // sign authProof
      const [r, s, v] = await signWithKmsKey(rawAuthProof, data.address);
      const AuthProof: SignedAuthProof = {
        ...rawAuthProof,
        r: <string>r,
        s: <string>s,
        v: <number>v,
      };

      return {code: 200, authProof: AuthProof};
    });

const getPublicKey = async function() {
  const [publicKey] = await client.getPublicKey({
    name: versionName,
  });

  if (publicKey.name !== versionName) {
    throw new Error("GetPublicKey: request corrupted in-transit");
  }
  if (publicKey.pemCrc32c &&
    crc32c.calculate(publicKey.pem || "") !== Number(publicKey.pemCrc32c.value)
  ) {
    throw new Error("GetPublicKey: response corrupted in-transit");
  }

  return publicKey;
};

export const calcEthAddress = functions.https.onCall(
    async (data, context) => {
      const uid = context.auth?.uid;
      if (!uid) {
        return {code: 401, message: "Unauthorized Call"};
      }

      const publicKey = await getPublicKey();
      const publicKeyPem = publicKey.pem || "";
      const publicKeyDer = crypto.createPublicKey(publicKeyPem)
          .export({format: "der", type: "spki"});
      const rawXY = publicKeyDer.subarray(-64);

      const hashXY = ethers.utils.keccak256(rawXY);
      const address = "0x" + hashXY.slice(-40);

      return address;
    }
);
