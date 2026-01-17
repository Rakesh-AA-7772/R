import { auth, db } from "./firebase.js";
import {
  collection,
  query,
  orderBy,
  getDocs,
  where
} from "https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js";

import { decryptText } from "./crypto.js";

export async function loadPreviousEntries() {
  const user = auth.currentUser;
  if (!user) return;

  const container = document.getElementById("previousEntries");
  if (!container) return;

  container.innerHTML = "";

  try {
    // Today start (midnight)
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const entriesRef = collection(db, "users", user.uid, "entries");
    const q = query(
      entriesRef,
      where("createdAt", "<", today),
      orderBy("createdAt", "desc")
    );

    const snapshot = await getDocs(q);

    if (snapshot.empty) {
      container.innerHTML = `
        <p style="text-align:center;color:#94a3b8">
          No previous entries found 📭
        </p>
      `;
      return;
    }

    for (const docSnap of snapshot.docs) {
      const data = docSnap.data();

      let text = data.text;
      if (data.encrypted) {
        text = await decryptText(data.text, window.currentPassword);
        if (!text) text = "[Unable to decrypt]";
      }

      const date = data.createdAt?.toDate
        ? data.createdAt.toDate()
        : new Date();

      const formatted = date.toLocaleString(undefined, {
        weekday: "short",
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      });

      const card = document.createElement("div");
      card.className = "entry-card";

      let imagesHTML = "";
      if (data.images?.length) {
        imagesHTML = `
          <div class="entry-images">
            ${data.images.map(img =>
              `<img src="${img}" class="entry-img">`
            ).join("")}
          </div>
        `;
      }

      card.innerHTML = `
        <small>${formatted}</small>
        <p>${text}</p>
        ${imagesHTML}
      `;

      container.appendChild(card);
    }

  } catch (err) {
    console.error("Previous entries load error:", err);
    container.innerHTML = "<p>Error loading entries</p>";
  }
}
