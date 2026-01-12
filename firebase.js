// Import the functions you need from the SDKs you need
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-analytics.js";
import { getAuth, connectAuthEmulator } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js";
import { getFirestore, connectFirestoreEmulator } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyCKeMA-Fsm0RYnZHAJ9k6qlqptAsevLqnk",
  authDomain: "time-capsule-88cf6.firebaseapp.com",
  projectId: "time-capsule-88cf6",
  storageBucket: "time-capsule-88cf6.firebasestorage.app",
  messagingSenderId: "462781247320",
  appId: "1:462781247320:web:1c21249d153f9625047f2d",
  measurementId: "G-LX6RY9ZCJ5"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Analytics with error handling
try {
  getAnalytics(app);
} catch (err) {
  console.warn("Analytics initialization failed:", err);
}

// Initialize Auth
export const auth = getAuth(app);

// Disable IndexedDB persistence to avoid backing store errors
if (typeof window !== "undefined" && "indexedDB" in window) {
  try {
    // Disable IndexedDB
    Object.defineProperty(window.indexedDB, "open", {
      value: function() {
        throw new Error("IndexedDB disabled for this app");
      }
    });
  } catch (err) {
    console.warn("Could not disable IndexedDB:", err);
  }
}

// Initialize Firestore
export const db = getFirestore(app);

// Disable Firestore persistence to avoid IndexedDB issues
try {
  import("https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js")
    .then(module => {
      if (module.disablePersistence) {
        module.disablePersistence(db).catch(err => {
          console.warn("Could not disable Firestore persistence:", err);
        });
      }
    })
    .catch(err => console.warn("Could not import Firestore module:", err));
} catch (err) {
  console.warn("Firestore persistence handling skipped:", err);
}

export default app;