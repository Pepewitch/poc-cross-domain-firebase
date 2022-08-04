import axios from "axios";
import {
  signInWithEmailAndPassword,
  User,
  createUserWithEmailAndPassword,
  signInWithCustomToken,
} from "firebase/auth";
import { useEffect, useState } from "react";
import { auth } from "../constants/firebase";

const BASE_URL =
  "https://us-central1-poc-cross-domain-firebase.cloudfunctions.net";

const Signup = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const signup = async () => {
    setLoading(true);
    try {
      await createUserWithEmailAndPassword(auth, email, password);
      setEmail("");
      setPassword("");
      alert(`Register ${email} successful!`);
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

const Signin = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const signin = async () => {
    setLoading(true);
    try {
      const cred = await signInWithEmailAndPassword(auth, email, password);
      await axios.post(
        `${BASE_URL}/login`,
        {
          idToken: await cred.user.getIdToken(),
        },
        { withCredentials: true }
      );
      setEmail("");
      setPassword("");
      alert(`Sign in as ${email} successful!`);
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
  useEffect(() => {
    auth.onAuthStateChanged((user) => {
      setCurrentUser(user);
    });
  }, []);
  useEffect(() => {
    const syncUser = async () => {
      try {
        const { data } = await axios.get(`${BASE_URL}/status`, {
          withCredentials: true,
        });
        if (data.customToken) {
          await signInWithCustomToken(auth, data.customToken);
        }
      } catch (error) {
        console.error(error);
      }
    };
    syncUser();
  }, []);
  return (
    <div className="flex p-2 flex-col items-center max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold underline mb-6">
        PoC Cross domain Firebase!
      </h1>
      <p className="mb-4 text-xl">
        {currentUser ? (
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
          onClick={() => auth.signOut()}
        >
          Logout
        </button>
      )}
      <div className="grid w-full grid-cols-2">
        <div>
          <Signup />
        </div>
        <div>
          <Signin />
        </div>
      </div>
    </div>
  );
}
