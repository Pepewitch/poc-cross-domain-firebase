import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

admin.initializeApp();

export const login = functions.https.onRequest(async (request, response) => {
  if (request.method !== "POST") {
    response.status(400).send("Please send a POST request");
    return;
  }
  const expiresIn = 60 * 60 * 24 * 365 * 1000; // set for a year
  const sessionCookie = await admin
    .auth()
    .createSessionCookie(request.body.idToken, { expiresIn });
  response.cookie("__session", sessionCookie, {
    maxAge: expiresIn,
    httpOnly: true,
    secure: true,
    domain: '.vercel.app'
  });
  response.header("Access-Control-Allow-Origin: *");
  response.header('Access-Control-Allow-Credentials: true')
  response.send({ success: true });
});

export const status = functions.https.onRequest(async (request, response) => {
  const sessionCookie: string = request.cookies.__session || "";
  const decodedIdToken = await admin
    .auth()
    .verifySessionCookie(sessionCookie, true);
  const customToken = await admin.auth().createCustomToken(decodedIdToken.uid);
  response.header("Access-Control-Allow-Origin: *");
  response.header('Access-Control-Allow-Credentials: true')
  response.send({ customToken });
});
