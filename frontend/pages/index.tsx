import axios from "axios";
import {
  signInWithEmailAndPassword,
  User,
  createUserWithEmailAndPassword,
  signInWithCustomToken,
} from "firebase/auth";
import { useEffect, useState } from "react";
import { auth } from "../constants/firebase";

// const BASE_URL = "https://poc-cross-domain-firebase.web.app";
const BASE_URL = "https://poc-cross-domain-firebase-api2.anypoc.app";
axios.defaults.withCredentials = true;

const syncCookieSession = async (idToken: string) => {
  await axios.post(`${BASE_URL}/sign-in`, {
    idToken,
  });
};

const Signup = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const signup = async () => {
    setLoading(true);
    try {
      const cred = await createUserWithEmailAndPassword(auth, email, password);
      await syncCookieSession(await cred.user.getIdToken());
      setEmail("");
      setPassword("");
    } catch (error) {
      alert(error.message);
    } finally {
      setLoading(false);
    }
  };
  return (
    <form
      className="flex p-2 flex-col"
      onSubmit={(e) => {
        e.preventDefault();
        signup();
      }}
    >
      <h1 className="mb-2 font-bold">Register new user</h1>
      <input
        className="p-1 border mb-2 rounded-md"
        disabled={loading}
        value={email}
        placeholder="Email"
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        className="p-1 border mb-2 rounded-md"
        disabled={loading}
        value={password}
        type="password"
        placeholder="Password"
        onChange={(e) => setPassword(e.target.value)}
      />
      <button
        disabled={loading}
        type="submit"
        className="p-1 border text-white bg-blue-700 rounded-md"
      >
        {loading ? "Registering..." : "Register"}
      </button>
    </form>
  );
};

const getCookie = (cookie?: string): { [key: string]: string } => {
  if (!cookie) return {};
  return cookie
    .split(";")
    .map((each) => each.trim().split("="))
    .reduce((p, c) => ({ ...p, [c[0]]: c[1] }), {});
};

const Signin = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const signin = async () => {
    setLoading(true);
    try {
      const cred = await signInWithEmailAndPassword(auth, email, password);
      await syncCookieSession(await cred.user.getIdToken());
      setEmail("");
      setPassword("");
    } catch (error) {
      alert(error.message);
    } finally {
      setLoading(false);
    }
  };
  return (
    <form
      className="flex p-2 flex-col"
      onSubmit={(e) => {
        e.preventDefault();
        signin();
      }}
    >
      <h1 className="mb-2 font-bold">Sign in</h1>
      <input
        className="p-1 border mb-2 rounded-md"
        disabled={loading}
        value={email}
        placeholder="Email"
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        className="p-1 border mb-2 rounded-md"
        disabled={loading}
        value={password}
        type="password"
        placeholder="Password"
        onChange={(e) => setPassword(e.target.value)}
      />
      <button
        disabled={loading}
        type="submit"
        className="p-1 border text-white bg-blue-700 rounded-md"
      >
        {loading ? "Signing in..." : "Sign in"}
      </button>
    </form>
  );
};

export default function Home() {
  const [currentUser, setCurrentUser] = useState<User>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    auth.onAuthStateChanged((user) => {
      setCurrentUser(user);
    });
  }, []);
  useEffect(() => {
    const syncUser = async () => {
      try {
        setLoading(true);
        const { data } = await axios.get(`${BASE_URL}/sync`);
        if (data.customToken) {
          await signInWithCustomToken(auth, data.customToken);
        }
      } catch (error) {
        await auth.signOut();
        console.error(error);
      } finally {
        setLoading(false);
      }
    };
    syncUser();
  }, []);
  const logout = async () => {
    await axios.post(`${BASE_URL}/sign-out`, {
      idToken: await currentUser.getIdToken(),
    });
    auth.signOut();
  };
  return (
    <div className="flex p-2 flex-col items-center max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold underline mb-6">
        PoC Cross domain Firebase!
      </h1>
      <div className="mb-6">
        <h2>
          First domain:{" "}
          <a
            className="underline text-blue-700"
            target="_blank"
            rel="noreferrer"
            href="https://poc-cross-domain-firebase.anypoc.app"
          >
            https://poc-cross-domain-firebase.anypoc.app
          </a>
        </h2>
        <h2>
          Second domain:{" "}
          <a
            className="underline text-blue-700"
            target="_blank"
            rel="noreferrer"
            href="https://poc-cross-domain-firebase2.anypoc.app"
          >
            https://poc-cross-domain-firebase2.anypoc.app
          </a>
        </h2>
      </div>
      <p className="mb-4 text-xl">
        {loading ? (
          <>Loading...</>
        ) : currentUser ? (
          <>
            You logged in with{" "}
            <span className="text-red-700 font-bold underline">
              {currentUser.email}
            </span>
          </>
        ) : (
          "You have not logged in"
        )}
      </p>
      {!!currentUser && (
        <button
          className="bg-red-700 text-white rounded-md p-2 w-48 mb-6"
          onClick={logout}
        >
          Logout
        </button>
      )}
      {!loading && !currentUser && (
        <div className="grid w-full grid-cols-2">
          <div>
            <Signup />
          </div>
          <div>
            <Signin />
          </div>
        </div>
      )}
    </div>
  );
}
