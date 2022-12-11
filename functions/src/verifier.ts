import * as functions from "firebase-functions";
import { getAuth } from "firebase-admin/auth";
import * as kms from "@google-cloud/kms";
import { KMS_CONFIG } from "./config";
import * as crypto from "crypto";
import * as crc32c from "fast-crc32c";
import * as ethers from "ethers";
import { ecdsaRecover, signatureImport, signatureNormalize } from "secp256k1";

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
  r: Uint8Array,
  s: Uint8Array,
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

const signWithKmsKey = async function(rawAuthProof: AuthProof, chainId: number) {
  const hash = crypto.createHash('sha256');
  hash.update(JSON.stringify(rawAuthProof));
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
    throw new Error('AsymmetricSign: request corrupted in-transit');
  }
  if (!signResponse.verifiedDigestCrc32c) {
    throw new Error('AsymmetricSign: request corrupted in-transit');
  }
  if (!signResponse.signature || !signResponse.signatureCrc32c ||
    crc32c.calculate(<string>signResponse.signature) !==
    Number(signResponse.signatureCrc32c.value)
  ) {
    throw new Error('AsymmetricSign: response corrupted in-transit');
  }

  const publicKey = await getPublicKey();
  const publicKeyPem = publicKey.pem!;
  const publicKeyDer = crypto.createPublicKey(publicKeyPem).export({format: 'der', type: 'spki'});
  const pubKeyBuf = publicKeyDer.subarray(publicKeyDer.length-65)

  let _64 = signatureImport(<Uint8Array>signResponse.signature);
  const normalized = signatureNormalize(_64); 
  const r = normalized.slice(0, 32);
  const s = normalized.slice(32, 64);
  const recId = await calculateRecoveryId(normalized, digest, pubKeyBuf); 
  const v = await calculateV(chainId, recId); 

  return [r, s, v];
}

const calculateRecoveryId = async function(signature: Uint8Array, hash: Buffer, uncompressPubKey: Buffer) {
  let recId = -1;

  for (let i = 0; i < 4; i++) {
    // try with a recoveryId of i
    const rec = ecdsaRecover(signature, i, hash, false);
    if (Buffer.compare(rec, uncompressPubKey) == 0) {
      recId = i;
      break;
    }
  }
  if (recId == -1)
    throw new Error("Impossible to calculare the recovery id. should not happen");
  return recId;
}

const calculateV = async function(chainId: number, recovery: number) {
  if (!chainId || typeof chainId === 'number') {
    // return legacy type ECDSASignature (deprecated in favor of ECDSASignatureBuffer to handle large chainIds)
    if (chainId && !Number.isSafeInteger(chainId)) {
      throw new Error('The provided number is greater than MAX_SAFE_INTEGER (please use an alternative input type)');
    }

    const v = chainId ? recovery + (chainId * 2 + 35) : recovery + 27;
    return v;
  } else {
    throw new Error("Other chainId type not implemented");
  }
}

const verifiedByOAuth = async function(idToken: string) {
  return await getAuth().verifyIdToken(idToken);
}

export const genAuthProof = functions.https.onCall(
  async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) {
      return {code: 401, message: "Unauthorized Call"};
    }

    let verified = null;
    let identityType = null;
    switch(data.authType) {
      case AuthType[AuthType.OAuth]: {
        if(data.params.has('idToken')) {
          verified = await verifiedByOAuth(data.params.get('idToken'));
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
    let [r, s, v] = await signWithKmsKey(rawAuthProof, data.chainId);
    const AuthProof: SignedAuthProof = {
      ...rawAuthProof,
      r: <Uint8Array>r,
      s: <Uint8Array>s,
      v: <number>v
    }

    return {code:200, authProof: AuthProof};
});

const getPublicKey = async function() {
  const [publicKey] = await client.getPublicKey({
    name: versionName,
  });

  const crc32c = require('fast-crc32c');
  if (publicKey.name !== versionName) {
    throw new Error('GetPublicKey: request corrupted in-transit');
  }
  if (publicKey.pemCrc32c && crc32c.calculate(publicKey.pem) !== Number(publicKey.pemCrc32c.value)) {
    throw new Error('GetPublicKey: response corrupted in-transit');
  }

  return publicKey;
}

export const calcEthAddress = functions.https.onCall(
  async (data, context) => {
    const uid = context.auth?.uid;
    if (!uid) {
      return {code: 401, message: "Unauthorized Call"};
    }

    const publicKey = await getPublicKey();
    const publicKeyPem = publicKey.pem!;
    const publicKeyDer = crypto.createPublicKey(publicKeyPem).export({format: 'der', type: 'spki'});
    const rawXY = publicKeyDer.subarray(-64);

    const hashXY = ethers.utils.keccak256(rawXY);
    const hashBuf = Buffer.from(hashXY, 'hex');
    const address = hashBuf.subarray(-20).toString('hex').toLowerCase();

    const addressHash = ethers.utils.keccak256(address);
    const addressHashHex = Buffer.from(addressHash, 'hex').toString('hex');

    let addressChecksum = '';
    for (var i = 0; i < address.length; i++){
      if (parseInt(addressHashHex[i], 16) > 7) {
        addressChecksum += address[i].toUpperCase();
      } else {
        addressChecksum += address[i];
      }
    }

    return addressChecksum;
  }
)