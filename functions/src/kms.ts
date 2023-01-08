import * as kms from "@google-cloud/kms";
import * as asn1 from "asn1.js";
import * as crypto from "crypto";
import * as ethers from "ethers";
import * as crc32c from "fast-crc32c";
import {KMS_KEY_TYPE, KMS_CONFIG, KMS_CONFIG_TYPE} from "./config";

const client = new kms.KeyManagementServiceClient();

const getPublicKey = async function(versionName: string) {
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

const getVersionName = async function(keyType: string) {
  if (!Object.values(KMS_KEY_TYPE).includes(keyType)) {
    throw new Error("Invalid key type: " + keyType +
        ", while getting version name.");
  }

  const config: KMS_CONFIG_TYPE = KMS_CONFIG.get(keyType)!;
  return client.cryptoKeyVersionPath(
      config.projectId,
      config.locationId,
      config.keyRingId,
      config.keyId,
      config.versionId
  );
};

export const getEthAddressFromPublicKey = async function(keyType: string) {
  const versionName = await getVersionName(keyType);
  const publicKey = await getPublicKey(versionName);
  const publicKeyPem = publicKey.pem || "";
  const publicKeyDer = crypto.createPublicKey(publicKeyPem)
      .export({format: "der", type: "spki"});
  const rawXY = publicKeyDer.subarray(-64);

  const hashXY = ethers.utils.keccak256(rawXY);
  const address = "0x" + hashXY.slice(-40);

  return address;
};

export const signWithKmsKey = async function(
    keyType:string,
    message: string
) {
  const hash = crypto.createHash("sha256");
  hash.update(message);
  const digest = hash.digest();

  const digestCrc32c = crc32c.calculate(digest);

  const versionName = await getVersionName(keyType);
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

  const address = KMS_CONFIG.get(keyType)!.publicAddress;
  const [r, s] = await calculateRS(signResponse.signature as Buffer);
  const v = calculateRecoveryParam(
      digest,
      r,
      s,
      address);

  const ref = parseInt("0x80", 16);
  const signature = "0x" + v + (r.length + ref).toString(16) +
      r + (s.length + ref).toString(16) + s;
  return [r, s, v, signature];
};

const EcdsaSigAsnParse = asn1.define("EcdsaSig", function(this: any) {
  this.seq().obj(
      this.key("r").int(),
      this.key("s").int(),
  );
});

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

    return v + 27;
  }

  throw new Error("Failed to calculate recovery param");
};
