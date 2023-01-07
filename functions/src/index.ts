import * as admin from "firebase-admin";
import * as functions from "firebase-functions";

const secrets = functions.config().doppler || {};

const credential = secrets.GOOGLE_CREDENTIAL_JSON;
let params;
if (credential) {
  const serviceAccount = JSON.parse(credential);
  params = {
    credential: admin.credential.cert(serviceAccount),
  };
} else {
  params = functions.config().firebase;
}

admin.initializeApp(params);
admin.firestore().settings({ignoreUndefinedProperties: true});

import {
  genAuthProof,
  calcEthAddress,
  signWithKms,
} from "./verifier";

exports.genAuthProof = genAuthProof;
exports.calcEthAddress = calcEthAddress;
exports.signWithKms = signWithKms;
