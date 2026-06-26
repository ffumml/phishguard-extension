// firebase-config.js - Конфигурация Firebase
// ЗАРЕГИСТРИРУЙТЕСЬ на https://console.firebase.google.com/

// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyCc_ywD71yMSXc9Pf_oLjbMB0I7jYhhWYA",
  authDomain: "click-45f0b.firebaseapp.com",
  projectId: "click-45f0b",
  storageBucket: "click-45f0b.firebasestorage.app",
  messagingSenderId: "127847051924",
  appId: "1:127847051924:web:efbfadd974fee7aa543a81",
  measurementId: "G-L50Q3L63M7"
};


// Инициализация Firebase
importScripts('https://www.gstatic.com/firebasejs/10.7.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.7.0/firebase-auth-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore-compat.js');

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

// Настройка для Service Worker
if (typeof window === 'undefined') {
  // Для background.js (Service Worker)
  self.auth = auth;
  self.db = db;
}