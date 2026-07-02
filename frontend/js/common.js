// common.js
// Shared data & helper functions used across all pages of Asad Milk Shop.

// Change this if you deploy the backend somewhere else.
const API_BASE = "http://localhost:3000/api";

// All 7 products offered by Asad Milk Shop.
// unit = the unit of measure used for pricing (liter / kg / glass / bottle)
const PRODUCTS = [
  {id: "milk",
    name: "Milk",
    urdu: "دودھ",
    unit: "Liter",
    price: 220,
    minQty: 1,
    maxQty: 50,
    image: "images/milk.png"
  },
  {
    id: "yogurt",
    name: "Yogurt",
    urdu: "دہی",
    unit: "Kg",
    price: 250,
    minQty: 1,
    maxQty: 50,
    image: "images/yogurt.png"
  },
  {
    id: "rabri",
    name: "Rabri Doodh",
    urdu: "ربڑی دودھ",
    unit: "Glass",
    price: 150,
    minQty: 1,
    maxQty: 50,
    image: "images/rabri.png"
  },
  {
    id: "doodh-bottle",
    name: "Doodh ki Bottle",
    urdu: "دودھ کی بوتلیں",
    unit: "Bottle",
    price: 100,
    minQty: 1,
    maxQty: 50,
    image: "images/doodh-bottle.png"
  },
  {
    id: "gagrala",
    name: "Gagrala",
    urdu: "گجریلا",
    unit: "Kg",
    price: 800,
    minQty: 1,
    maxQty: 50,
    image: "images/gagrala.png"
  },
  {
    id: "son-halwa",
    name: "Son Halwa",
    urdu: "سوہن حلوہ",
    unit: "Kg",
    price: 1000,
    minQty: 1,
    maxQty: 50,
    image: "images/son-halwa.png"
  },
  {
    id: "khir",
    name: "Khir",
    urdu: "کھیر",
    unit: "Kg",
    price: 700,
    minQty: 1,
    maxQty: 50,
    image: "images/khir.png"
  }
];

// ---------- Auth helpers (login token handling) ----------
function getToken() {
  return localStorage.getItem("asad_token");
}

function getUser() {
  return JSON.parse(localStorage.getItem("asad_user") || "null");
}

function isLoggedIn() {
  return !!getToken() && !!getUser();
}

function saveSession(token, user) {
  localStorage.setItem("asad_token", token);
  localStorage.setItem("asad_user", JSON.stringify(user));
}

function clearSession() {
  localStorage.removeItem("asad_token");
  localStorage.removeItem("asad_user");
}

// ---------- Navbar mobile toggle ----------
function initNavbarToggle() {
  const toggleBtn = document.getElementById("navToggle");
  const links = document.getElementById("navLinks");
  if (toggleBtn && links) {
    toggleBtn.addEventListener("click", () => {
      links.classList.toggle("open");
    });
  }
}

// ---------- Highlight logged in user in navbar ----------
function updateAuthNav() {
  const authLink = document.getElementById("authNavLink");
  if (!authLink) return;
  const user = getUser();
  if (user && isLoggedIn()) {
    authLink.textContent = "Hi, " + user.full_name.split(" ")[0] + " (Logout)";
    authLink.href = "#";
    authLink.onclick = (e) => {
      e.preventDefault();
      if (confirm("Logout from your account?")) {
        clearSession();
        location.reload();
      }
    };
  }
}

// ---------- Scroll reveal animation (.reveal elements) ----------
function initScrollReveal() {
  const items = document.querySelectorAll(".reveal:not(.visible)");
  if (!items.length) return;

  if (!("IntersectionObserver" in window)) {
    items.forEach(el => el.classList.add("visible"));
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15 });

  items.forEach(el => observer.observe(el));
}

document.addEventListener("DOMContentLoaded", () => {
  initNavbarToggle();
  updateAuthNav();
  initScrollReveal();
});
