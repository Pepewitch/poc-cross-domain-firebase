import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import { createSessionCookieVerifier } from "firebase-admin/lib/auth/token-verifier";
import {
  verifyJwtSignature,
  ALGORITHM_RS256,
} from "firebase-admin/lib/utils/jwt";
import { getCookie, getKeyCallback } from "./helper";
import { hashSync } from "bcrypt";

admin.initializeApp();
const sessionCookieVerifier = createSessionCookieVerifier(admin.app());

const origins = [
  "https://poc-cross-domain-firebase.anypoc.app",
  "https://poc-cross-domain-firebase2.anypoc.app",
];

const cookieMaxExpires = new Date(2147483647000);

export const csrf = functions.https.onRequest(async (request, response) => {
  if (origins.includes(request.headers.origin as string)) {
    response.set("Access-Control-Allow-Origin", request.headers.origin);
  }
  response.set("Access-Control-Allow-Credentials", "true");
  response.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.set("Access-Control-Max-Age", "86400");
  response.set("Cache-Control", "private");

  if (request.method === "OPTIONS") {
    response.sendStatus(200);
    return;
  }

  try {
    await admin.auth().verifyIdToken(request.body.idToken);
    const csrfToken = hashSync(request.body.idToken, 5);
    response.cookie("csrf_token", csrfToken, {
      expires: cookieMaxExpires,
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

  const { csrf_token: cookieCsrf } = getCookie();
  const csrf = request.headers["x-csrf-token"];
  console.log("HEADER", JSON.stringify(request.headers));
  if (!csrf || !cookieCsrf || csrf !== cookieCsrf) {
    response.status(401).send("UNAUTHORIZED REQUEST!");
    return;
  }

  try {
    const expiresIn = 300 * 1000; // set for 5 min (minimum) to test `ignoreExpiration`
    // const expiresIn = 60 * 60 * 24 * 14 * 1000; // set for 2 weeks (maximum)
    const sessionCookie = await admin
      .auth()
      .createSessionCookie(request.body.idToken, { expiresIn });
    response.cookie("__session", sessionCookie, {
      expires: cookieMaxExpires,
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

export const logout = functions.https.onRequest(async (request, response) => {
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
    const cookie = getCookie(request.headers.cookie);
    const { uid } = await verifySessionCookieExtended(cookie.__session);

    await admin.auth().revokeRefreshTokens(uid);
    response.clearCookie("__session", {
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

type DecodedSessionToken = {
  header: { alg: "RS256"; kid: string };
  payload: admin.auth.DecodedIdToken;
};

const verifySessionCookieExtended = async (sessionCookie: string) => {
  const projectId = await sessionCookieVerifier.ensureProjectId();
  const decodedToken: DecodedSessionToken =
    await sessionCookieVerifier.safeDecode(sessionCookie);
  sessionCookieVerifier.verifyContent(decodedToken, projectId);

  try {
    await verifyJwtSignature(
      sessionCookie,
      getKeyCallback(sessionCookieVerifier.signatureVerifier.keyFetcher),
      { algorithms: [ALGORITHM_RS256], ignoreExpiration: true }
    );
  } catch (err) {
    throw sessionCookieVerifier.mapJwtErrorToAuthError(err);
  }
  return { ...decodedToken.payload, uid: decodedToken.payload.sub };
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
    // const decodedIdToken = await admin
    //   .auth()
    //   .verifySessionCookie(sessionCookie, true);
    const decodedIdToken = await verifySessionCookieExtended(sessionCookie);
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
  response.send("PONG");
});
