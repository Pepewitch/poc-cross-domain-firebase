import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

admin.initializeApp();
const origins = [
  "https://poc-cross-domain-firebase.vercel.app",
  "https://poc-cross-domain-firebase-git-master-skpepe134.vercel.app",
];

export const login = functions.https.onRequest(async (request, response) => {
  console.log("COOKIE", JSON.stringify(request.cookies));
  console.log("BODY", JSON.stringify(request.body));
  console.log("ORIGINS", request.headers.origin);
  if (origins.includes(request.headers.origin as string)) {
    response.set("Access-Control-Allow-Origin", request.headers.origin);
  }
  response.set("Access-Control-Allow-Credentials", "true");
  response.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");

  const expiresIn = 60 * 60 * 24 * 365 * 1000; // set for a year
  const sessionCookie = await admin
    .auth()
    .createSessionCookie(request.body.idToken, { expiresIn });
  response.cookie("__session", sessionCookie, {
    maxAge: expiresIn,
    httpOnly: true,
    secure: true,
    domain: ".vercel.app",
  });

  response.send({ success: true });
});

export const status = functions.https.onRequest(async (request, response) => {
  console.log("COOKIE", JSON.stringify(request.cookies));
  console.log("ORIGINS", request.headers.origin);
  if (origins.includes(request.headers.origin as string)) {
    response.set("Access-Control-Allow-Origin", request.headers.origin);
  }
  response.set("Access-Control-Allow-Credentials", "true");
  response.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  
  const sessionCookie: string = request.cookies?.__session || "";
  const decodedIdToken = await admin
    .auth()
    .verifySessionCookie(sessionCookie, true);
  const customToken = await admin.auth().createCustomToken(decodedIdToken.uid);
  response.send({ customToken });
});
