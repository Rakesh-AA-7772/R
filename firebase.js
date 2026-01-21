// firebase.js
// Minimal Firebase initialization — NO Analytics, NO IndexedDB monkey-patching.

import { initializeApp } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyCKeMA-Fsm0RYnZHAJ9k6qlqptAsevLqnk",
  authDomain: "time-capsule-88cf6.firebaseapp.com",
  projectId: "time-capsule-88cf6",
  storageBucket: "time-capsule-88cf6.firebasestorage.app",
  messagingSenderId: "462781247320",
  appId: "1:462781247320:web:1c21249d153f9625047f2d",
  measurementId: "G-LX6RY9ZCJ5"
};

// Initialize Firebase app (no analytics)
const app = initializeApp(firebaseConfig);

// Auth and Firestore exports (simple, stable)
export const auth = getAuth(app);
export const db = getFirestore(app);

export default app;
