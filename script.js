import { auth, db } from "./firebase.js";
import * as PreviousEntriesModule from "./previous-entries.js";

import {
  signInWithEmailAndPassword,
  onAuthStateChanged,
  setPersistence,
  inMemoryPersistence,
  browserSessionPersistence
} from "https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js";

import {
  collection,
  addDoc,
  query,
  orderBy,
  getDocs,
  serverTimestamp,
  doc,
  setDoc,
  deleteDoc,
  updateDoc,
  where
} from "https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js";

/* ================= SECURITY: CSRF TOKENS ================= */

let csrfToken = null;

function generateCSRFToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  csrfToken = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  sessionStorage.setItem('csrfToken', csrfToken);
  return csrfToken;
}

function validateCSRFToken() {
  const stored = sessionStorage.getItem('csrfToken');
  return stored && stored === csrfToken;
}

// Generate CSRF token immediately on script load
generateCSRFToken();

/* ================= ENCRYPTION HELPERS ================= */

function deriveKey(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  return crypto.subtle.digest("SHA-256", data).then(buf => new Uint8Array(buf));
}

export async function encryptText(text, password) {
  const key = await deriveKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const data = encoder.encode(text);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    data
  );

  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...combined));
}

export async function decryptText(encryptedData, password) {
  try {
    const key = await deriveKey(password);
    const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      encrypted
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (err) {
    console.error("Decryption failed:", err);
    return null;
  }
}

/* ================= IMAGE HANDLING ================= */

let selectedImages = [];
let editingImages = [];

function handleImageUpload(fileInput, previewContainer, imageArray) {
  fileInput.addEventListener("change", (e) => {
    imageArray.length = 0;
    previewContainer.innerHTML = "";

    Array.from(e.target.files).forEach(file => {
      // Validate file size (max 5MB per image)
      if (file.size > 5 * 1024 * 1024) {
        alert("Image too large. Max 5MB per image.");
        return;
      }

      if (file.type.startsWith("image/")) {
        const reader = new FileReader();
        reader.onload = (event) => {
          imageArray.push(event.target.result);
          const img = document.createElement("img");
          img.src = event.target.result;
          img.className = "image-preview";
          const wrapper = document.createElement("div");
          wrapper.className = "preview-wrapper";
          wrapper.appendChild(img);
          previewContainer.appendChild(wrapper);
        };
        reader.readAsDataURL(file);
      }
    });
  });
}

export function sanitizeInput(input) {
  return input
    .replace(/[<>]/g, "")
    .trim()
    .substring(0, 500);
}

function sanitizeEmail(email) {
  return email.toLowerCase().trim();
}

/* ================= ENHANCED PASSWORD VALIDATION ================= */

function validatePassword(password) {
  const errors = [];
  if (password.length < 8) errors.push("At least 8 characters");
  if (!/[A-Z]/.test(password)) errors.push("One uppercase letter");
  if (!/[a-z]/.test(password)) errors.push("One lowercase letter");
  if (!/[0-9]/.test(password)) errors.push("One number");
  if (!/[!@#$%^&*]/.test(password)) errors.push("One special character (!@#$%^&*)");
  return errors;
}

/* ================= AUTO-LOGOUT TIMER ================= */

let inactivityTimer = null;
let warningTimer = null;
const INACTIVITY_WARNING_TIME = 14 * 60 * 1000;
const INACTIVITY_LOGOUT_TIME = 15 * 60 * 1000;

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  clearTimeout(warningTimer);

  const warningModal = document.getElementById("inactivityWarning");
  if (warningModal) {
    warningModal.classList.add("hidden");
  }

  warningTimer = setTimeout(() => {
    showInactivityWarning();
  }, INACTIVITY_WARNING_TIME);

  inactivityTimer = setTimeout(() => {
    window.logout();
  }, INACTIVITY_LOGOUT_TIME);
}

function showInactivityWarning() {
  const modal = document.getElementById("inactivityWarning");
  if (modal) {
    modal.classList.remove("hidden");
    let countdown = 60;
    const countdownEl = document.getElementById("countdownSeconds");

    const interval = setInterval(() => {
      countdown--;
      if (countdownEl) countdownEl.textContent = countdown;
      if (countdown <= 0) clearInterval(interval);
    }, 1000);
  }
}

function setupActivityListeners() {
  const capsule = document.getElementById("capsule");
  if (!capsule || capsule.classList.contains("hidden")) return;

  ["mousedown", "keydown", "scroll", "touchstart"].forEach(event => {
    document.addEventListener(event, resetInactivityTimer, { passive: true });
  });

  resetInactivityTimer();
}

/* ================= SECURITY: RATE LIMITING ================= */

const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

function checkLoginRateLimit(email) {
  const now = Date.now();
  const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: 0, lockedUntil: 0 };

  if (attempts.lockedUntil > now) {
    const remainingMin = Math.ceil((attempts.lockedUntil - now) / 1000 / 60);
    throw new Error(`Too many login attempts. Try again in ${remainingMin} minutes.`);
  }

  if (now - attempts.lastAttempt > LOCKOUT_DURATION) {
    attempts.count = 0;
  }

  attempts.count++;
  attempts.lastAttempt = now;

  if (attempts.count > MAX_ATTEMPTS) {
    attempts.lockedUntil = now + LOCKOUT_DURATION;
    throw new Error("Too many login attempts. Account locked for 15 minutes.");
  }

  loginAttempts.set(email, attempts);
}

function clearLoginAttempts(email) {
  loginAttempts.delete(email);
}

/* ================= PAGE NAVIGATION ================= */

function showPage(pageId) {
  document.querySelectorAll(".page").forEach(p => p.classList.add("hidden"));
  const page = document.getElementById(pageId);
  if (page) page.classList.remove("hidden");
}

function showEntryContent(contentId) {
  document.querySelectorAll(".entry-content").forEach(c => c.classList.add("hidden"));
  const content = document.getElementById(contentId);
  if (content) content.classList.remove("hidden");
}

/* ================= SEARCH & FILTER ================= */

export function searchEntries(query, entries) {
  if (!query.trim()) return entries;
  const lowerQuery = query.toLowerCase();
  return entries.filter(entry => 
    entry.text.toLowerCase().includes(lowerQuery) ||
    (entry.tags && entry.tags.some(tag => tag.toLowerCase().includes(lowerQuery)))
  );
}

/* ================= EXPORT TO PDF ================= */

export async function exportEntriesToJSON() {
  const user = auth.currentUser;
  if (!user) {
    alert("Not authenticated");
    return;
  }

  try {
    const entriesRef = collection(db, "users", user.uid, "entries");
    const snapshot = await getDocs(query(entriesRef, orderBy("createdAt", "desc")));
    
    const entries = [];
    for (const doc of snapshot.docs) {
      const data = doc.data();
      let text = data.text;
      
      if (data.encrypted) {
        text = await decryptText(data.text, window.currentPassword) || "[Unable to decrypt]";
      }

      const dateObj = data.createdAt?.toDate ? data.createdAt.toDate() : new Date();
      entries.push({
        date: dateObj.toISOString(),
        text: text,
        tags: data.tags || []
      });
    }

    const json = JSON.stringify(entries, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `time-capsule-backup-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Export error:", err);
    alert("Failed to export entries.");
  }
}

/* ================= ENTRY STATISTICS ================= */

export async function getEntryStats() {
  const user = auth.currentUser;
  if (!user) return null;

  try {
    const entriesRef = collection(db, "users", user.uid, "entries");
    const snapshot = await getDocs(entriesRef);

    let totalEntries = 0;
    let totalWords = 0;
    let totalImages = 0;
    const tags = new Map();

    for (const doc of snapshot.docs) {
      const data = doc.data();
      totalEntries++;
      
      let text = data.text;
      if (data.encrypted) {
        text = await decryptText(data.text, window.currentPassword) || "";
      }
      totalWords += text.split(/\s+/).filter(w => w.length > 0).length;
      totalImages += (data.images || []).length;

      if (data.tags) {
        data.tags.forEach(tag => {
          tags.set(tag, (tags.get(tag) || 0) + 1);
        });
      }
    }

    return {
      totalEntries,
      totalWords,
      totalImages,
      topTags: Array.from(tags.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5)
    };
  } catch (err) {
    console.error("Stats error:", err);
    return null;
  }
}

/* ================= LOGIN ================= */

window.login = async function () {
  // Regenerate and validate CSRF token on each login attempt
  generateCSRFToken();
  
  const emailEl = document.getElementById("email");
  const passwordEl = document.getElementById("password");
  const loginErrorEl = document.getElementById("loginError");
  const enterBtn = document.getElementById("enterCapsuleBtn");

  if (!emailEl || !passwordEl || !loginErrorEl) return;

  const email = sanitizeEmail(emailEl.value);
  const password = passwordEl.value;

  if (!email || !password) {
    loginErrorEl.textContent = "Email and password are required";
    return;
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    loginErrorEl.textContent = "Invalid email format";
    return;
  }

  const passwordErrors = validatePassword(password);
  if (passwordErrors.length > 0) {
    loginErrorEl.textContent = `Password must contain: ${passwordErrors.join(", ")}`;
    return;
  }

  enterBtn.disabled = true;
  enterBtn.textContent = "Logging in...";
  loginErrorEl.textContent = "";

  try {
    checkLoginRateLimit(email);
    await setPersistence(auth, inMemoryPersistence);
    await signInWithEmailAndPassword(auth, email, password);
    clearLoginAttempts(email);
    emailEl.value = "";
    passwordEl.value = "";
  } catch (err) {
    console.error("Login error:", err.code, err.message);
    loginErrorEl.textContent = err.message || "Login failed. Check your credentials.";
  } finally {
    enterBtn.disabled = false;
    enterBtn.textContent = "Enter Capsule";
  }
};

/* ================= LOGOUT ================= */

window.logout = async function () {
  try {
    clearTimeout(inactivityTimer);
    clearTimeout(warningTimer);
    csrfToken = null;
    sessionStorage.clear();
    await auth.signOut();
  } catch (err) {
    console.error("Logout error:", err);
    alert("Logout failed");
  }
};

/* ================= AUTH STATE ================= */

window.currentPassword = null;

onAuthStateChanged(auth, async (user) => {
  const loginBox = document.getElementById("login-box");
  const capsule = document.getElementById("capsule");

  if (user) {
    if (loginBox) loginBox.classList.add("hidden");
    if (capsule) capsule.classList.remove("hidden");
    window.currentPassword = user.email;
    // Don't regenerate token here, it's already created

    try {
      await setDoc(
        doc(db, "users", user.uid),
        { createdAt: serverTimestamp(), lastLogin: serverTimestamp() },
        { merge: true }
      );
    } catch (err) {
      console.error("User doc error:", err);
    }

    showPage("writePage");
    showEntryContent("todayContent");
    loadEntries();
    setupActivityListeners();
  } else {
    if (loginBox) loginBox.classList.remove("hidden");
    if (capsule) capsule.classList.add("hidden");
    window.currentPassword = null;
  }
});

/* ================= SAVE ENTRY ================= */

window.saveEntry = async function () {
  const user = auth.currentUser;
  if (!user) {
    alert("Not authenticated");
    return;
  }

  const entryEl = document.getElementById("entry");
  const tagsEl = document.getElementById("entryTags");
  if (!entryEl) return;

  const text = sanitizeInput(entryEl.value);
  if (!text) return;

  try {
    const encrypted = await encryptText(text, window.currentPassword);
    const tags = tagsEl ? tagsEl.value.split(",").map(t => t.trim()).filter(t => t) : [];
    
    const entriesRef = collection(db, "users", user.uid, "entries");
    await addDoc(entriesRef, {
      text: encrypted,
      images: selectedImages,
      tags: tags,
      createdAt: serverTimestamp(),
      encrypted: true,
      wordCount: text.split(/\s+/).length
    });

    entryEl.value = "";
    if (tagsEl) tagsEl.value = "";
    selectedImages = [];
    const charCountEl = document.getElementById("charCount");
    if (charCountEl) charCountEl.textContent = "0";
    const previewEl = document.getElementById("imagePreviewContainer");
    if (previewEl) previewEl.innerHTML = "";
    const imageUploadEl = document.getElementById("imageUpload");
    if (imageUploadEl) imageUploadEl.value = "";

    loadEntries();
  } catch (err) {
    console.error("Save entry error:", err);
    alert("Failed to save entry. Please try again.");
  }
};

/* ================= LOAD ENTRIES ================= */

async function loadEntries() {
  const user = auth.currentUser;
  if (!user) return;

  const entriesEl = document.getElementById("entries");
  if (!entriesEl) return;

  entriesEl.innerHTML = "";

  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const entriesRef = collection(db, "users", user.uid, "entries");
    const q = query(
      entriesRef,
      where("createdAt", ">=", today),
      where("createdAt", "<", tomorrow),
      orderBy("createdAt", "desc")
    );

    const snapshot = await getDocs(q);

    if (snapshot.empty) {
      entriesEl.innerHTML = '<p style="color: #64748b; text-align: center;">No entries today yet. Start writing!</p>';
      return;
    }

    snapshot.forEach(docSnap => {
      renderEntryCard(docSnap, entriesEl);
    });
  } catch (err) {
    console.error("Load entries error:", err);
  }
}

async function renderEntryCard(docSnap, container) {
  const data = docSnap.data();
  let displayText = data.text;

  if (data.encrypted) {
    displayText = await decryptText(data.text, window.currentPassword);
    if (!displayText) {
      displayText = "[Unable to decrypt entry]";
    }
  }

  const dateObj = data.createdAt?.toDate ? data.createdAt.toDate() : new Date();
  const formatted = dateObj.toLocaleString(undefined, {
    weekday: "short",
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });

  const card = document.createElement("div");
  card.className = "entry-card";

  let imagesHtml = "";
  if (data.images && data.images.length > 0) {
    imagesHtml = `
      <div class="entry-images">
        ${data.images.map(img => `<img src="${img}" alt="Entry image" class="entry-img">`).join("")}
      </div>
    `;
  }

  let tagsHtml = "";
  if (data.tags && data.tags.length > 0) {
    tagsHtml = `<div class="entry-tags">${data.tags.map(tag => `<span class="tag">${sanitizeInput(tag)}</span>`).join("")}</div>`;
  }

  card.innerHTML = `
    <small>${formatted}</small>
    <p>${sanitizeInput(displayText)}</p>
    ${tagsHtml}
    ${imagesHtml}
    <div class="entry-actions">
      <button class="btn-action edit-btn" data-id="${docSnap.id}">Edit</button>
      <button class="btn-action delete-btn" data-id="${docSnap.id}">Delete</button>
    </div>
  `;

  const editBtn = card.querySelector(".edit-btn");
  const deleteBtn = card.querySelector(".delete-btn");

  if (editBtn) editBtn.addEventListener("click", () => openEditModal(docSnap.id, displayText, data.images || [], data.tags || []));
  if (deleteBtn) deleteBtn.addEventListener("click", () => deleteEntry(docSnap.id));

  container.appendChild(card);
}

/* ================= EDIT ENTRY ================= */

export async function openEditModal(entryId, currentText, currentImages = [], currentTags = []) {
  const modal = document.getElementById("editModal");
  const textarea = document.getElementById("editEntryText");
  const charCount = document.getElementById("editCharCount");
  const previewContainer = document.getElementById("editImagePreviewContainer");
  const tagsEl = document.getElementById("editEntryTags");

  if (!modal || !textarea || !charCount || !previewContainer) return;

  textarea.value = currentText;
  charCount.textContent = currentText.length;
  if (tagsEl) tagsEl.value = currentTags.join(", ");
  editingImages = [...currentImages];
  previewContainer.innerHTML = "";

  currentImages.forEach(img => {
    const imgEl = document.createElement("img");
    imgEl.src = img;
    imgEl.className = "image-preview";
    const wrapper = document.createElement("div");
    wrapper.className = "preview-wrapper";
    wrapper.appendChild(imgEl);
    previewContainer.appendChild(wrapper);
  });

  modal.classList.remove("hidden");

  const saveBtn = document.getElementById("saveEditBtn");
  const cancelBtn = document.getElementById("cancelEditBtn");
  const modalClose = document.querySelector(".modal-close");

  if (saveBtn) saveBtn.onclick = () => saveEdit(entryId);
  if (cancelBtn) cancelBtn.onclick = closeEditModal;
  if (modalClose) modalClose.onclick = closeEditModal;

  textarea.addEventListener("input", (e) => {
    charCount.textContent = e.target.value.length;
  });
}

function closeEditModal() {
  const modal = document.getElementById("editModal");
  if (modal) modal.classList.add("hidden");
}

export async function saveEdit(entryId) {
  const user = auth.currentUser;
  if (!user) return;

  const editTextarea = document.getElementById("editEntryText");
  const editTagsEl = document.getElementById("editEntryTags");
  if (!editTextarea) return;

  const newText = sanitizeInput(editTextarea.value);
  if (!newText) return;

  try {
    const encrypted = await encryptText(newText, window.currentPassword);
    const tags = editTagsEl ? editTagsEl.value.split(",").map(t => t.trim()).filter(t => t) : [];
    
    const entryRef = doc(db, "users", user.uid, "entries", entryId);
    await updateDoc(entryRef, {
      text: encrypted,
      images: editingImages,
      tags: tags,
      updatedAt: serverTimestamp(),
      wordCount: newText.split(/\s+/).length
    });

    closeEditModal();
    loadEntries();
    if (PreviousEntriesModule && PreviousEntriesModule.loadPreviousEntries) {
      PreviousEntriesModule.loadPreviousEntries();
    }
  } catch (err) {
    console.error("Edit error:", err);
    alert("Failed to update entry.");
  }
}

/* ================= DELETE ENTRY ================= */

export async function deleteEntry(entryId) {
  if (!confirm("Are you sure you want to delete this entry?")) return;

  const user = auth.currentUser;
  if (!user) return;

  try {
    const entryRef = doc(db, "users", user.uid, "entries", entryId);
    await deleteDoc(entryRef);
    loadEntries();
    if (PreviousEntriesModule && PreviousEntriesModule.loadPreviousEntries) {
      PreviousEntriesModule.loadPreviousEntries();
    }
  } catch (err) {
    console.error("Delete error:", err);
    alert("Failed to delete entry.");
  }
}

/* ================= EVENT BINDINGS ================= */

document.addEventListener("DOMContentLoaded", () => {
  // Login
  const loginBtn = document.getElementById("enterCapsuleBtn");
  if (loginBtn) {
    loginBtn.addEventListener("click", window.login);
  }

  // Save entry
  const saveBtn = document.getElementById("saveEntryBtn");
  if (saveBtn) {
    saveBtn.addEventListener("click", window.saveEntry);
  }

  // Logout
  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", window.logout);
  }

  // Entry tabs
  const todayTabBtn = document.getElementById("todayTabBtn");
  const previousTabBtn = document.getElementById("previousTabBtn");
  if (todayTabBtn) {
    todayTabBtn.addEventListener("click", () => {
      showEntryContent("todayContent");
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      todayTabBtn.classList.add("active");
      loadEntries();
    });
  }
  if (previousTabBtn) {
    previousTabBtn.addEventListener("click", () => {
      showEntryContent("previousContent");
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      previousTabBtn.classList.add("active");
      if (PreviousEntriesModule && PreviousEntriesModule.loadPreviousEntries) {
        PreviousEntriesModule.loadPreviousEntries();
      }
    });
  }

  // Character count
  const entryEl = document.getElementById("entry");
  if (entryEl) {
    entryEl.addEventListener("input", (e) => {
      const charCountEl = document.getElementById("charCount");
      if (charCountEl) charCountEl.textContent = e.target.value.length;
    });
  }

  // Image uploads
  const imageUpload = document.getElementById("imageUpload");
  const previewContainer = document.getElementById("imagePreviewContainer");
  if (imageUpload && previewContainer) {
    handleImageUpload(imageUpload, previewContainer, selectedImages);
  }

  const editImageUpload = document.getElementById("editImageUpload");
  const editPreviewContainer = document.getElementById("editImagePreviewContainer");
  if (editImageUpload && editPreviewContainer) {
    handleImageUpload(editImageUpload, editPreviewContainer, editingImages);
  }

  // Statistics button
  const statsBtn = document.getElementById("statsBtn");
  if (statsBtn) {
    statsBtn.addEventListener("click", async () => {
      const stats = await getEntryStats();
      if (stats) {
        alert(`📊 Your Statistics\n\nTotal Entries: ${stats.totalEntries}\nTotal Words: ${stats.totalWords}\nTotal Images: ${stats.totalImages}`);
      }
    });
  }

  // Export button
  const exportBtn = document.getElementById("exportBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", exportEntriesToJSON);
  }

  // Search functionality
  const searchInput = document.getElementById("searchEntries");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      // Filter displayed entries based on search
      const query = e.target.value;
      const cards = document.querySelectorAll(".entry-card");
      cards.forEach(card => {
        const text = card.textContent.toLowerCase();
        card.style.display = text.includes(query.toLowerCase()) ? "block" : "none";
      });
    });
  }

  // Inactivity warning - stay logged button
  const stayLoggedBtn = document.getElementById("stayLoggedBtn");
  if (stayLoggedBtn) {
    stayLoggedBtn.addEventListener("click", () => {
      const modal = document.getElementById("inactivityWarning");
      if (modal) modal.classList.add("hidden");
      resetInactivityTimer();
    });
  }

  // Back to write button
  const backToWriteBtn = document.getElementById("backToWriteBtn");
  if (backToWriteBtn) {
    backToWriteBtn.addEventListener("click", () => {
      showPage("writePage");
      showEntryContent("todayContent");
      const modal = document.getElementById("inactivityWarning");
      if (modal) modal.classList.add("hidden");
      resetInactivityTimer();
    });
  }
});

function detectStorageAvailability() {
  try {
    const test = "__storage_test__";
    localStorage.setItem(test, test);
    localStorage.removeItem(test);
    return true;
  } catch (e) {
    console.warn("Storage not available:", e);
    return false;
  }
}

const isStorageAvailable = detectStorageAvailability();
if (!isStorageAvailable) {
  console.warn("⚠️ Running in private/incognito mode or storage is disabled");
}
/* =========================
  ADD-ON: Multi-device-safe image upload (append only)
  - Do NOT remove or edit existing code; this block only adds behavior.
  ========================= */

(async function addMultiDeviceImageSupport() {
  // dynamic import for auth persistence and storage APIs (so we don't modify your top imports)
  const authMod = await import("https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js").catch(()=>null);
  const storageMod = await import("https://www.gstatic.com/firebasejs/12.7.0/firebase-storage.js").catch(()=>null);

  // Try to set browserLocalPersistence now (best-effort; won't throw if unavailable)
  try {
    if (authMod && authMod.browserLocalPersistence) {
      await setPersistence(auth, authMod.browserLocalPersistence);
      console.log("Persistence set to browserLocalPersistence (add-on).");
    }
  } catch (e) {
    console.warn("Could not enforce browserLocalPersistence (add-on):", e);
  }

  // small helper: wait until auth is ready (avoid upload race)
  function ensureAuthReady(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      if (auth.currentUser) return resolve(auth.currentUser);
      const unsub = auth.onAuthStateChanged(user => {
        if (user) {
          unsub();
          resolve(user);
        }
      });
      setTimeout(() => {
        try { unsub(); } catch {}
        reject(new Error("Auth not ready"));
      }, timeoutMs);
    });
  }

  // store File objects separately (we don't remove your selectedImages array)
  // This is an additive array that won't break existing logic.
  if (typeof window.selectedImageFiles === "undefined") {
    window.selectedImageFiles = [];
  }

  // If your page already had an <input id="imageUpload">, add a listener that also
  // captures the raw File objects into selectedImageFiles (in addition to your existing base64 logic).
  try {
    const imageUploadEl = document.getElementById("imageUpload");
    if (imageUploadEl) {
      imageUploadEl.addEventListener("change", (e) => {
        window.selectedImageFiles = Array.from(e.target.files || []).filter(f => f && f.type && f.type.startsWith("image/"));
        // keep existing behavior untouched — this add-on only duplicates File objects for proper upload
      });
    }
  } catch (e) {
    console.warn("Add-on: image input hookup failed", e);
  }

  // compress File -> Blob helper (client-side)
  async function compressImageFileToBlob(file, maxWidth = 1200, quality = 0.75) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = reject;
      reader.onload = () => {
        const img = new Image();
        img.onerror = reject;
        img.onload = () => {
          const scale = Math.min(1, maxWidth / img.width);
          const canvas = document.createElement("canvas");
          canvas.width = Math.round(img.width * scale);
          canvas.height = Math.round(img.height * scale);
          const ctx = canvas.getContext("2d");
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          canvas.toBlob((blob) => {
            if (!blob) return reject(new Error("Canvas conversion failed"));
            resolve(blob);
          }, "image/jpeg", quality);
        };
        img.src = reader.result;
      };
      reader.readAsDataURL(file);
    });
  }

  // Upload mixed array (strings are passed through, File objects are compressed+uploaded)
  async function uploadFilesAndGetUrlsMixed(mixedArray = [], userUid, docId) {
    if (!storageMod) throw new Error("Storage module not available");
    const storage = storageMod.getStorage();
    const uploadPromises = [];
    const urls = [];

    for (const item of mixedArray) {
      if (!item) continue;
      if (typeof item === "string") {
        // already a URL (existing behavior)
        urls.push(item);
        continue;
      }
      // File object -> compress -> upload
      if (item instanceof File) {
        uploadPromises.push((async () => {
          try {
            const blob = await compressImageFileToBlob(item, 1200, 0.78);
            const safeName = `${Date.now()}_${item.name.replace(/\s+/g,'_')}`;
            const path = `users/${userUid}/entries/${docId}/${safeName}`;
            const ref = storageMod.ref(storage, path);
            await storageMod.uploadBytes(ref, blob);
            const durl = await storageMod.getDownloadURL(ref);
            urls.push(durl);
          } catch (err) {
            console.error("Add-on: file upload failed for", item.name, err);
            // continue without failing entire batch
          }
        })());
      }
    }

    await Promise.all(uploadPromises);
    return urls;
  }

  // Wrap your saveEntry without removing it:
  // - if selectedImageFiles has files, do storage upload flow (create placeholder doc, upload, update)
  // - otherwise, call the original saveEntry (keeps your prior base64 behavior)
  try {
    const originalSave = window.saveEntry;
    window.saveEntry = async function wrappedSaveEntry(...args) {
      // ensure auth ready before trying anything (fixes multi-device race)
      let user;
      try {
        user = await ensureAuthReady(7000); // wait up to 7s
      } catch (err) {
        // If auth not ready, fallback to original behavior (which may fail) but we surface message
        console.warn("Add-on: auth not ready before saveEntry:", err);
        return originalSave && originalSave.apply(this, args);
      }

      // If there are real File objects selected, use storage upload flow
      if (Array.isArray(window.selectedImageFiles) && window.selectedImageFiles.length > 0 && storageMod) {
        try {
          // replicate your saveEntry's validation (minimal)
          const entryEl = document.getElementById("entry");
          if (!entryEl) return;
          const text = sanitizeInput(entryEl.value);
          if (!text) return;

          // Prepare tags similar to your code
          const tagsEl = document.getElementById("entryTags");
          const tags = tagsEl ? tagsEl.value.split(",").map(t => t.trim()).filter(t => t) : [];

          // encrypt text (reuse your function)
          const encrypted = await encryptText(text, window.currentPassword || user.email);

          // create placeholder doc to get id (we use addDoc then update)
          const entriesRef = collection(db, "users", user.uid, "entries");
          const placeholderRef = await addDoc(entriesRef, { createdAt: serverTimestamp(), placeholder: true });

          // upload files to Storage using the placeholder id path
          const uploadedUrls = await uploadFilesAndGetUrlsMixed(window.selectedImageFiles, user.uid, placeholderRef.id);

          // finalize doc with full data
          await updateDoc(placeholderRef, {
            text: encrypted,
            images: uploadedUrls,
            tags,
            createdAt: serverTimestamp(),
            encrypted: true,
            wordCount: text.split(/\s+/).filter(w => w).length,
            placeholder: false
          });

          // clear UI (non-destructive to your other arrays)
          entryEl.value = "";
          if (tagsEl) tagsEl.value = "";
          window.selectedImageFiles = [];
          const previewEl = document.getElementById("imagePreviewContainer");
          if (previewEl) previewEl.innerHTML = "";
          const imageUploadEl = document.getElementById("imageUpload");
          if (imageUploadEl) imageUploadEl.value = "";

          // reload entries using your function
          if (typeof loadEntries === "function") loadEntries();

          return;
        } catch (err) {
          console.error("Add-on: storage upload flow failed:", err);
          // fallback to original saveEntry in case something unexpected happened
          return originalSave && originalSave.apply(this, args);
        }
      }

      // No File objects => call original saveEntry (keeps your previous behavior)
      return originalSave && originalSave.apply(this, args);
    };
    console.log("Add-on: saveEntry wrapped to support multi-device image uploads.");
  } catch (e) {
    console.warn("Add-on: could not wrap saveEntry:", e);
  }

  // Wrap edit/saveEdit similarly so edits with new File objects get uploaded to Storage
  try {
    // locate original saveEdit function (it might be exported, but in browser it's available globally)
    const originalSaveEdit = window.saveEdit || (typeof saveEdit === "function" ? saveEdit : null);
    if (originalSaveEdit) {
      window.saveEdit = async function wrappedSaveEdit(entryId, ...rest) {
        // ensure auth ready
        let user;
        try {
          user = await ensureAuthReady(7000);
        } catch (err) {
          console.warn("Add-on: auth not ready before saveEdit:", err);
          return originalSaveEdit.apply(this, [entryId, ...rest]);
        }

        // editingImages may contain File objects (we added a handler for edit input earlier)
        if (Array.isArray(editingImages) && editingImages.some(i => i instanceof File) && storageMod) {
          try {
            // encrypt new text if present in the edit modal
            const editTextarea = document.getElementById("editEntryText");
            const newText = editTextarea ? sanitizeInput(editTextarea.value) : null;
            if (!newText) return;

            const encrypted = await encryptText(newText, window.currentPassword || user.email);
            const editTagsEl = document.getElementById("editEntryTags");
            const tags = editTagsEl ? editTagsEl.value.split(",").map(t => t.trim()).filter(t => t) : [];

            // Upload any File objects in editingImages to storage under entryId
            const uploadedUrls = await uploadFilesAndGetUrlsMixed(editingImages, user.uid, entryId);

            // update doc
            const entryRef = doc(db, "users", user.uid, "entries", entryId);
            await updateDoc(entryRef, {
              text: encrypted,
              images: uploadedUrls,
              tags,
              updatedAt: serverTimestamp(),
              wordCount: newText.split(/\s+/).filter(w => w).length
            });

            // close modal and reload
            if (typeof closeEditModal === "function") closeEditModal();
            if (typeof loadEntries === "function") loadEntries();
            if (PreviousEntriesModule && PreviousEntriesModule.loadPreviousEntries) {
              PreviousEntriesModule.loadPreviousEntries();
            }
            return;
          } catch (err) {
            console.error("Add-on: saveEdit storage flow failed:", err);
            return originalSaveEdit.apply(this, [entryId, ...rest]);
          }
        }

        // fallback
        return originalSaveEdit.apply(this, [entryId, ...rest]);
      };
      console.log("Add-on: saveEdit wrapped to support file uploads for edits.");
    }
  } catch (e) {
    console.warn("Add-on: could not wrap saveEdit:", e);
  }

  // small safety: ensure editing image input also sets editingImages to File objects
  try {
    const editImageInput = document.getElementById("editImageUpload");
    if (editImageInput) {
      editImageInput.addEventListener("change", (e) => {
        // keep your preview logic intact; also store raw files for upload
        editingImages = Array.from(e.target.files || []).filter(f => f && f.type && f.type.startsWith("image/"));
      });
    }
  } catch (e) {
    console.warn("Add-on: edit image hookup failed", e);
  }

  // final note
  console.log("Add-on: multi-device image support initialized (append-only).");
})();
/* =========================
  ADD-ON: Ensure entry images display (append-only)
  - No existing functions are modified.
  - Add this at the end of script.js.
  ========================= */

async function tryResolveStorageUrl(maybeUrlOrPath) {
  // dynamic import so we don't change existing imports
  try {
    const storageMod = await import("https://www.gstatic.com/firebasejs/12.7.0/firebase-storage.js");
    const storage = storageMod.getStorage();

    // if already an http(s) URL, return it unchanged
    if (/^https?:\/\//i.test(maybeUrlOrPath)) return maybeUrlOrPath;

    // if it's a gs:// URL, use refFromURL
    if (/^gs:\/\//i.test(maybeUrlOrPath)) {
      try {
        const ref = storageMod.refFromURL(storage, maybeUrlOrPath);
        return await storageMod.getDownloadURL(ref);
      } catch (e) {
        console.warn("tryResolveStorageUrl: refFromURL failed", e);
      }
    }

    // treat as a path under the bucket (like "users/UID/entries/ID/file.jpg")
    try {
      const ref = storageMod.ref(storage, maybeUrlOrPath);
      return await storageMod.getDownloadURL(ref);
    } catch (e) {
      console.warn("tryResolveStorageUrl: ref(path) failed", e);
    }

  } catch (err) {
    console.warn("tryResolveStorageUrl: storage module import failed", err);
  }
  return null;
}

// Walk newly rendered entries in container and ensure images load. If a URL fails, try to resolve via Storage.
async function ensureImagesDisplayed(containerEl = null) {
  try {
    const container = containerEl || document.getElementById("entries");
    if (!container) return;

    // find each card's images-block and attempt to validate/load each image
    const entryCards = Array.from(container.querySelectorAll(".entry-card"));
    for (const card of entryCards) {
      // log images field if present on the card element dataset (for debugging)
      // Note: this logs whatever the server returned when rendering; keep for debugging
      const imgs = Array.from(card.querySelectorAll(".entry-images img"));
      for (const imgEl of imgs) {
        // if image already loaded OK, skip
        if (imgEl.complete && imgEl.naturalWidth > 0) continue;

        const src = imgEl.getAttribute("src") || "";
        console.log("ensureImagesDisplayed: checking img src:", src);

        // attach onload/onerror handlers to show fallback / debug
        imgEl.onload = () => {
          imgEl.classList.remove("image-loading");
          imgEl.classList.add("image-loaded");
        };
        imgEl.onerror = async () => {
          console.warn("ensureImagesDisplayed: image failed to load:", src);

          // Try resolving via storage rules if the src looks like a storage path or gs:// or not http
          const resolved = await tryResolveStorageUrl(src);
          if (resolved) {
            console.log("ensureImagesDisplayed: resolved storage url ->", resolved);
            imgEl.src = resolved; // retry with resolved url
            return;
          }

          // final fallback: replace with a small inline placeholder so UI isn't empty
          imgEl.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(
            `<svg xmlns='http://www.w3.org/2000/svg' width='300' height='180'>
               <rect width='100%' height='100%' fill='#111827'/>
               <text x='50%' y='50%' fill='#94A3B8' font-size='14' dominant-baseline='middle' text-anchor='middle'>Image unavailable</text>
             </svg>`
          );
        };

        // trigger a manual re-check by resetting src (only if src exists)
        if (src) {
          // quick "touch" to re-trigger load if browser previously failed
          const tmp = imgEl.src;
          imgEl.src = "";
          // small delay to allow onerror handler to run if needed
          setTimeout(() => { imgEl.src = tmp; }, 50);
        }
      }
    }
  } catch (err) {
    console.error("ensureImagesDisplayed error:", err);
  }
}

// --- Hook this into your existing loadEntries flow ---
// Find this block in your code inside loadEntries() where you have:
//    snapshot.forEach(docSnap => { renderEntryCard(docSnap, entriesEl); });
// Add the following line IMMEDIATELY AFTER that for-loop (inside loadEntries):
//
//    // ensure images show (add-on)
//    await ensureImagesDisplayed(entriesEl);
//
//
// If you prefer not to modify loadEntries directly, append this small watcher that runs after loadEntries completes:
(function watchForLoadEntriesAndEnsureImages() {
  // whenever loadEntries is called, it updates #entries; we detect DOM changes and fix images
  const entriesContainer = document.getElementById("entries");
  if (!entriesContainer) return;

  const observer = new MutationObserver((mutations) => {
    // basic debounce
    if (observer._timer) clearTimeout(observer._timer);
    observer._timer = setTimeout(() => {
      ensureImagesDisplayed(entriesContainer).catch(console.error);
    }, 120);
  });

  observer.observe(entriesContainer, { childList: true, subtree: true });
})();

