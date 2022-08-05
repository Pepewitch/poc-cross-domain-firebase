import * as jwt from "jsonwebtoken";

interface KeyFetcher {
  fetchPublicKeys(): Promise<{ [key: string]: string }>;
}
const NO_MATCHING_KID_ERROR_MESSAGE = "no-matching-kid-error";
const NO_KID_IN_HEADER_ERROR_MESSAGE = "no-kid-in-header-error";

/**
 * Provides a callback to fetch public keys.
 *
 * @param fetcher - KeyFetcher to fetch the keys from.
 * @returns A callback function that can be used to get keys in `jsonwebtoken`.
 */
export function getKeyCallback(fetcher: KeyFetcher): jwt.GetPublicKeyOrSecret {
  return (header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) => {
    if (!header.kid) {
      callback(new Error(NO_KID_IN_HEADER_ERROR_MESSAGE));
    }
    const kid = header.kid || "";
    fetcher
      .fetchPublicKeys()
      .then((publicKeys) => {
        if (!Object.prototype.hasOwnProperty.call(publicKeys, kid)) {
          callback(new Error(NO_MATCHING_KID_ERROR_MESSAGE));
        } else {
          callback(null, publicKeys[kid]);
        }
      })
      .catch((error) => {
        callback(error);
      });
  };
}

export const getCookie = (cookie?: string): { [key: string]: string } => {
  if (!cookie) return {};
  return cookie
    .split(";")
    .map((each) => each.trim().split("="))
    .reduce((p, c) => ({ ...p, [c[0]]: c[1] }), {});
};
