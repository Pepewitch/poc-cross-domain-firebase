import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

// const createSessionCookieVerifier = require("firebase-admin/lib/auth/token-verifier");

admin.initializeApp();

const origins = [
  "https://poc-cross-domain-firebase.anypoc.app",
  "https://poc-cross-domain-firebase2.anypoc.app",
];

export const login = functions.https.onRequest(async (request, response) => {
  if (origins.includes(request.headers.origin as string)) {
    response.set("Access-Control-Allow-Origin", request.headers.origin);
  }
  response.set("Access-Control-Allow-Credentials", "true");
  response.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  response.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.set("Access-Control-Max-Age", "86400");
  response.set("Cache-Control", "private");

  if (request.method === "OPTIONS") {
    response.sendStatus(200);
    return;
  }

  try {
    const expiresIn = 60 * 60 * 24 * 5 * 1000; // set for 5 days
    const sessionCookie = await admin
      .auth()
      .createSessionCookie(request.body.idToken, { expiresIn });
    response.cookie("__session", sessionCookie, {
      maxAge: expiresIn,
      httpOnly: true,
      secure: true,
      domain: ".anypoc.app",
      sameSite: "none",
    });

    response.status(200).send({ success: true });
  } catch (error) {
    console.log(error);
    if (error instanceof Error) {
      response.status(500).send({ message: error.message });
      return;
    }
    response.sendStatus(500);
    return;
  }
});

const getCookie = (cookie?: string): { [key: string]: string } => {
  if (!cookie) return {};
  return cookie
    .split(";")
    .map((each) => each.trim().split("="))
    .reduce((p, c) => ({ ...p, [c[0]]: c[1] }), {});
};

export const status = functions.https.onRequest(async (request, response) => {
  if (origins.includes(request.headers.origin as string)) {
    response.set("Access-Control-Allow-Origin", request.headers.origin);
  }
  response.set("Access-Control-Allow-Credentials", "true");
  response.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  response.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.set("Access-Control-Max-Age", "86400");
  response.set("Cache-Control", "private");

  try {
    const cookie = getCookie(request.headers.cookie);
    const sessionCookie: string = cookie.__session || "";
    const decodedIdToken = await admin
      .auth()
      .verifySessionCookie(sessionCookie, true);
    const customToken = await admin
      .auth()
      .createCustomToken(decodedIdToken.uid);
    response.status(200).send({ customToken });
  } catch (error) {
    console.log(error);
    if (error instanceof Error) {
      response.status(500).send({ message: error.message });
      return;
    }
    response.sendStatus(500);
    return;
  }
});

export const ping = functions.https.onRequest((request, response) => {
  response.cookie("PING", "PONG");
  response.send("PONG");
});
