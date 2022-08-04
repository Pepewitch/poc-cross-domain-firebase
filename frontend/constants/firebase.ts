// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAuth, setPersistence, inMemoryPersistence } from "firebase/auth";

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyDWce4Catb6RvxNoM7OqlBYokQutnhSH4o",
  authDomain: "poc-cross-domain-firebase.firebaseapp.com",
  projectId: "poc-cross-domain-firebase",
  storageBucket: "poc-cross-domain-firebase.appspot.com",
  messagingSenderId: "485336828550",
  appId: "1:485336828550:web:758171cf2394888d4c9f07",
  measurementId: "G-BQB27Z7QHL",
};

// Initialize Firebase
export const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
setPersistence(auth, inMemoryPersistence)