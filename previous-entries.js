import { auth, db } from "./firebase.js";
import { collection, getDocs, query, orderBy } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js";
import { decryptText } from "./script.js";

let allEntries = [];
let currentSortOrder = "newest";

export async function loadPreviousEntries() {
  const user = auth.currentUser;
  if (!user) return;

  const listEl = document.getElementById("previousEntriesList");
  if (!listEl) return;

  listEl.innerHTML = "";

  try {
    const entriesRef = collection(db, "users", user.uid, "entries");
    const q = query(entriesRef, orderBy("createdAt", "desc"));
    const snapshot = await getDocs(q);

    allEntries = [];
    for (const docSnap of snapshot.docs) {
      const data = docSnap.data();
      let text = data.text;
      
      if (data.encrypted) {
        text = await decryptText(data.text, window.currentPassword) || "[Unable to decrypt]";
      }

      allEntries.push({
        id: docSnap.id,
        text: text,
        images: data.images || [],
        tags: data.tags || [],
        createdAt: data.createdAt?.toDate?.() || new Date(),
        wordCount: text.split(/\s+/).length
      });
    }

    renderPreviousEntries();
  } catch (err) {
    console.error("Load previous entries error:", err);
  }
}

function renderPreviousEntries() {
  const listEl = document.getElementById("previousEntriesList");
  if (!listEl) return;

  let sorted = [...allEntries];
  
  switch (currentSortOrder) {
    case "oldest":
      sorted.sort((a, b) => a.createdAt - b.createdAt);
      break;
    case "largest":
      sorted.sort((a, b) => b.wordCount - a.wordCount);
      break;
    case "smallest":
      sorted.sort((a, b) => a.wordCount - b.wordCount);
      break;
    case "newest":
    default:
      sorted.sort((a, b) => b.createdAt - a.createdAt);
  }

  listEl.innerHTML = "";
  if (sorted.length === 0) {
    listEl.innerHTML = '<p style="color: #64748b; text-align: center;">No previous entries yet.</p>';
    return;
  }

  sorted.forEach(entry => renderEntryCard(entry, listEl));
}

function renderEntryCard(entry, container) {
  const formatted = entry.createdAt.toLocaleString(undefined, {
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
  if (entry.images && entry.images.length > 0) {
    imagesHtml = `
      <div class="entry-images">
        ${entry.images.map(img => `<img src="${img}" alt="Entry image" class="entry-img">`).join("")}
      </div>
    `;
  }

  let tagsHtml = "";
  if (entry.tags && entry.tags.length > 0) {
    tagsHtml = `<div class="entry-tags">${entry.tags.map(tag => `<span class="tag">${tag}</span>`).join("")}</div>`;
  }

  card.innerHTML = `
    <small>${formatted}</small>
    <p>${entry.text.substring(0, 200)}${entry.text.length > 200 ? "..." : ""}</p>
    ${tagsHtml}
    ${imagesHtml}
    <div class="entry-actions">
      <button class="btn-action edit-btn" data-id="${entry.id}">Edit</button>
      <button class="btn-action delete-btn" data-id="${entry.id}">Delete</button>
    </div>
  `;

  container.appendChild(card);
}

export function setSortOrder(order) {
  currentSortOrder = order;
  renderPreviousEntries();
}
