/**
 * auth.js — handles login and registration form submissions.
 *
 * Both forms POST JSON to the API, store the returned JWT in
 * localStorage, and redirect to the dashboard on success.
 */

const API = "";  // same origin

// Helper: show an error or success message inside the given element
function showMsg(el, msg, isError = true) {
  el.textContent = msg;
  el.classList.remove("hidden");
  if (isError) {
    el.classList.add("alert-error");
    el.classList.remove("alert-success");
  } else {
    el.classList.add("alert-success");
    el.classList.remove("alert-error");
  }
}

// ---------------------------------------------------------------------------
// Login form
// ---------------------------------------------------------------------------
const loginForm = document.getElementById("login-form");
if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errorEl = document.getElementById("error-msg");
    errorEl.classList.add("hidden");

    const body = {
      username: document.getElementById("username").value.trim(),
      password: document.getElementById("password").value,
    };

    try {
      const res = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        showMsg(errorEl, data.detail || "Login failed.");
        return;
      }
      // Store token and redirect
      localStorage.setItem("token", data.access_token);
      window.location.href = "/dashboard";
    } catch {
      showMsg(errorEl, "Network error. Please try again.");
    }
  });
}

// ---------------------------------------------------------------------------
// Register form
// ---------------------------------------------------------------------------
const registerForm = document.getElementById("register-form");
if (registerForm) {
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errorEl   = document.getElementById("error-msg");
    const successEl = document.getElementById("success-msg");
    errorEl.classList.add("hidden");
    successEl.classList.add("hidden");

    const body = {
      username: document.getElementById("username").value.trim(),
      email:    document.getElementById("email").value.trim(),
      password: document.getElementById("password").value,
    };

    try {
      const res = await fetch(`${API}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        showMsg(errorEl, data.detail || "Registration failed.");
        return;
      }
      showMsg(successEl, "Account created! Redirecting to login…", false);
      setTimeout(() => window.location.href = "/login", 1500);
    } catch {
      showMsg(errorEl, "Network error. Please try again.");
    }
  });
}
