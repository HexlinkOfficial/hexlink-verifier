import * as functions from "firebase-functions";

export const KMS_CONFIG = {
  projectId: "bridge23-27764",
  locationId: "global",
  keyRingId: "operator",
  keyId: "operatorkey",
  versionId: "1",
};

const secrets = functions.config().doppler;
export const TWITTER_CONFIG_1 = {
  twitterApiKey: secrets.TWITTER_API_KEY_1,
  twitterApiSecret: secrets.TWITTER_API_SECRET_1,
  twitterAccessKey: secrets.TWITTER_ACCESS_KEY_1,
  twitterAccessSecret: secrets.TWITTER_ACCESS_SECRET_1,
};
