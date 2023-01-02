import * as functions from "firebase-functions";

const secrets = functions.config().doppler;
export const KMS_CONFIG = {
  projectId: secrets.VITE_FIREBASE_PROJECT_ID,
  locationId: secrets.IDENTITY_VERIFIER_LOCATION_ID,
  keyRingId: secrets.IDENTITY_VERIFIER_KEY_RING_ID,
  keyId: secrets.IDENTITY_VERIFIER_KEY_ID,
  versionId: secrets.IDENTITY_VERIFIER_VERSION_ID,
};

export const IDENTITY_VERIFIER_PUB_ADDR = secrets.IDENTITY_VERIFIER_PUB_ADDR;
