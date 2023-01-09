import * as kms from "@google-cloud/kms";
import * as asn1 from "asn1.js";
import * as crypto from "crypto";
import * as ethers from "ethers";
import * as crc32c from "fast-crc32c";
import * as BN from "bn.js";
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
    message: string) {
  const messageEthHash = await toEthSignedMessageHash(message);
  const digestBuffer = Buffer.from(ethers.utils.arrayify(messageEthHash));

  const signature = await getKmsSignature(digestBuffer, keyType);
  const address = KMS_CONFIG.get(keyType)!.publicAddress;
  const [r, s] = await calculateRS(signature as Buffer);
  const v = calculateRecoveryParam(
      digestBuffer,
      r,
      s,
      address);
  const rHex = r.toString("hex");
  const sHex = s.toString("hex");
  const sig = "0x" + rHex + sHex + v.toString(16);

  return sig;
};

const toEthSignedMessageHash = async function(messageHex: string) {
  return ethers.utils.keccak256(
      ethers.utils.solidityPack(["string", "bytes32"],
          ["\x19Ethereum Signed Message:\n32", messageHex]));
};

const getKmsSignature = async function(digestBuffer: Buffer, keyType: string) {
  const digestCrc32c = crc32c.calculate(digestBuffer);
  const versionName = await getVersionName(keyType);

  const [signResponse] = await client.asymmetricSign({
    name: versionName,
    digest: {
      sha256: digestBuffer,
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

  return signResponse.signature as Buffer;
};

const EcdsaSigAsnParse = asn1.define("EcdsaSig", function(this: any) {
  this.seq().obj(
      this.key("r").int(),
      this.key("s").int(),
  );
});

const calculateRS = async function(signature: Buffer) {
  const decoded = EcdsaSigAsnParse.decode(signature, "der");
  const r: BN = decoded.r;
  let s: BN = decoded.s;

  const secp256k1N = new BN(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      16
  );
  const secp256k1halfN = secp256k1N.div(new BN(2));

  if (s.gt(secp256k1halfN)) {
    s = secp256k1N.sub(s);
  }

  return [r, s];
};

const calculateRecoveryParam = (
    msg: Buffer,
    r: BN,
    s: BN,
    address: string
) => {
  let v: number;
  for (v = 0; v <= 1; v++) {
    const recoveredEthAddr = ethers.utils.recoverAddress(
        `0x${msg.toString("hex")}`,
        {
          r: `0x${r.toString("hex")}`,
          s: `0x${s.toString("hex")}`,
          v,
        }
    ).toLowerCase();

    if (recoveredEthAddr != address.toLowerCase()) {
      continue;
    }

    return v + 27;
  }

  throw new Error("Failed to calculate recovery param");
};
