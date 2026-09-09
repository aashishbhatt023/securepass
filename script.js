"use strict";

/**
 * SecurePass — script.js
 *
 * SECURITY NOTE FOR READERS:
 * This file never sends the password anywhere except, on explicit user
 * action, the first 5 characters of its SHA-1 hash to the HIBP range API.
 * It never writes the password (or its full hash) to localStorage,
 * sessionStorage, cookies, the URL, or console.log/console.error.
 * Search this file for "PLAINTEXT BOUNDARY" comments to see the one place
 * the raw password is read, and how far it is allowed to travel.
 */

(() => {
  /* ------------------------------------------------------------------ *
   * 1. DOM references
   * ------------------------------------------------------------------ */

  const passwordInput = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-visibility");
  const eyeOpen = document.getElementById("eye-open");
  const eyeClosed = document.getElementById("eye-closed");

  const scoreNumberEl = document.getElementById("score-number");
  const strengthBadge = document.getElementById("strength-badge");
  const meterBar = document.getElementById("meter-bar");
  const meterBarWrap = document.getElementById("meter-bar-wrap");

  const checklistEl = document.getElementById("checklist");
  const entropyValueEl = document.getElementById("entropy-value");
  const entropyBarEl = document.getElementById("entropy-bar");

  const breachBtn = document.getElementById("breach-btn");
  const breachResultEl = document.getElementById("breach-result");
  const recommendationsEl = document.getElementById("recommendations");

  /* ------------------------------------------------------------------ *
   * 2. Small demonstration dictionary
   *
   * This is intentionally NOT exhaustive. A real breach/weak-password
   * dictionary has millions of entries (rockyou.txt-scale lists run to
   * ~14M+ passwords). Shipping that to a static client-side site would be
   * both impractical (multi-hundred-MB payload) and would itself leak
   * information about detection thresholds. For V1 this small list only
   * demonstrates the *mechanism*; real coverage instead comes from the
   * HIBP breach-corpus check below, which covers 600M+ real passwords
   * without requiring a local dictionary at all.
   * ------------------------------------------------------------------ */

  const COMMON_PASSWORDS = new Set([
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "password", "password1", "password123", "qwerty", "qwerty123",
    "111111", "123123", "abc123", "letmein", "monkey", "dragon",
    "iloveyou", "admin", "welcome", "login", "starwars", "sunshine",
    "princess", "football", "baseball", "trustno1", "000000", "abcdef",
    "abcdefg", "qazwsx", "zaq12wsx", "passw0rd", "changeme",
  ]);

  const KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
  ];

  /* ------------------------------------------------------------------ *
   * 3. Character-class + pattern analysis
   * ------------------------------------------------------------------ */

  function analyzeCharacterClasses(pw) {
    const hasLower = /[a-z]/.test(pw);
    const hasUpper = /[A-Z]/.test(pw);
    const hasNumber = /[0-9]/.test(pw);
    const hasSpecial = /[^a-zA-Z0-9]/.test(pw);

    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNumber) poolSize += 10;
    if (hasSpecial) poolSize += 33; // approx printable ASCII specials

    return { hasLower, hasUpper, hasNumber, hasSpecial, poolSize };
  }

  // Detects runs of 3+ identical characters, e.g. "aaa", "111"
  function detectRepeats(pw) {
    const matches = pw.match(/(.)\1{2,}/g);
    return matches ? matches.length : 0;
  }

  // Detects 3+ character ascending/descending sequences ("abc", "321")
  // and known keyboard-row runs ("qwerty", "asdf").
  function detectSequential(pw) {
    let count = 0;
    const lower = pw.toLowerCase();

    for (let i = 0; i < lower.length - 2; i++) {
      const a = lower.charCodeAt(i);
      const b = lower.charCodeAt(i + 1);
      const c = lower.charCodeAt(i + 2);
      if ((b === a + 1 && c === b + 1) || (b === a - 1 && c === b - 1)) {
        count++;
      }
    }

    for (const row of KEYBOARD_ROWS) {
      for (let i = 0; i <= row.length - 3; i++) {
        const chunk = row.slice(i, i + 3);
        if (lower.includes(chunk)) count++;
      }
    }

    return count;
  }

  function detectDictionaryMatch(pw) {
    const lower = pw.toLowerCase();
    if (COMMON_PASSWORDS.has(lower)) return true;
    // Strip trailing digits/punctuation ("password123!" -> "password")
    const stripped = lower.replace(/[\d\W]+$/g, "");
    if (COMMON_PASSWORDS.has(stripped)) return true;
    for (const word of COMMON_PASSWORDS) {
      if (word.length >= 5 && lower.includes(word)) return true;
    }
    return false;
  }

  /* ------------------------------------------------------------------ *
   * 4. Entropy
   *
   * entropy (bits) = length x log2(character_pool_size)
   *
   * This treats every character as independently random from the
   * observed pool, which real human-chosen passwords are NOT — see
   * README "Security Design" for why this is an upper-bound estimate,
   * not a measurement of actual guessing resistance.
   * ------------------------------------------------------------------ */

  function calculateEntropyBits(pw, poolSize) {
    if (pw.length === 0 || poolSize < 2) return 0;
    return pw.length * Math.log2(poolSize);
  }

  /* ------------------------------------------------------------------ *
   * 5. Scoring engine (0-100)
   * ------------------------------------------------------------------ */

  function scorePassword(pw) {
    const classes = analyzeCharacterClasses(pw);
    const entropyBits = calculateEntropyBits(pw, classes.poolSize);

    // Base score: entropy-driven, saturating at 100 bits -> 100 points.
    // This is what lets a long unique passphrase outscore a short
    // "every character type" password, per spec.
    let score = Math.min(100, entropyBits);

    const repeats = detectRepeats(pw);
    const sequences = detectSequential(pw);
    const dictionaryHit = detectDictionaryMatch(pw);

    if (dictionaryHit) score -= 40;
    if (repeats > 0) score -= Math.min(30, repeats * 15);
    if (sequences > 0) score -= Math.min(30, sequences * 15);

    // Hard ceiling for very short passwords regardless of character variety.
    if (pw.length > 0 && pw.length < 8) score = Math.min(score, 20);

    score = Math.max(0, Math.min(100, Math.round(score)));

    const checks = {
      length: pw.length >= 12,
      upper: classes.hasUpper,
      lower: classes.hasLower,
      number: classes.hasNumber,
      special: classes.hasSpecial,
      pattern: repeats === 0 && sequences === 0 && !dictionaryHit,
    };

    return { score, entropyBits, checks, classes, repeats, sequences, dictionaryHit };
  }

  function classify(score, hasPassword) {
    if (!hasPassword) return { level: "empty", label: "Enter a password" };
    if (score < 20) return { level: "very-weak", label: "Very Weak" };
    if (score < 40) return { level: "weak", label: "Weak" };
    if (score < 60) return { level: "moderate", label: "Moderate" };
    if (score < 80) return { level: "strong", label: "Strong" };
    return { level: "very-strong", label: "Very Strong" };
  }

  /* ------------------------------------------------------------------ *
   * 6. Recommendations
   * ------------------------------------------------------------------ */

  function buildRecommendations(analysis, pw) {
    const recs = [];
    if (!pw) {
      return ["Enter a password above to see personalized recommendations."];
    }

    if (pw.length < 12) recs.push("Increase password length to at least 12 characters.");
    if (!analysis.classes.hasUpper || !analysis.classes.hasLower) {
      recs.push("Mix uppercase and lowercase letters.");
    }
    if (!analysis.classes.hasNumber) recs.push("Add numbers.");
    if (!analysis.classes.hasSpecial) recs.push("Add special characters (e.g. ! @ # % *).");
    if (analysis.sequences > 0) recs.push("Avoid predictable sequences like \"abc\" or \"qwerty\".");
    if (analysis.repeats > 0) recs.push("Avoid repeating the same character multiple times in a row.");
    if (analysis.dictionaryHit) recs.push("Avoid common or easily guessable passwords.");

    recs.push("Never reuse this password on another account.");
    recs.push("Consider using a password manager to generate and store unique passwords.");

    return recs;
  }

  /* ------------------------------------------------------------------ *
   * 7. UI rendering — safe DOM manipulation only (no innerHTML with
   *    user-controlled data; checklist/recommendation copy below is
   *    static text we author, never the password itself).
   * ------------------------------------------------------------------ */

  function renderAnalysis(pw) {
    const hasPassword = pw.length > 0;
    const analysis = scorePassword(pw);
    const { level, label } = classify(analysis.score, hasPassword);

    scoreNumberEl.textContent = String(analysis.score);
    strengthBadge.textContent = label;
    strengthBadge.dataset.level = level;

    meterBar.style.width = `${analysis.score}%`;
    meterBar.dataset.level = level;
    meterBarWrap.setAttribute("aria-valuenow", String(analysis.score));

    // Checklist
    for (const li of checklistEl.children) {
      const key = li.dataset.check;
      const pass = hasPassword ? !!analysis.checks[key] : false;
      li.dataset.pass = String(pass);
      li.querySelector(".check-icon").textContent = pass ? "✓" : "–";
    }

    // Entropy
    const bits = Math.round(analysis.entropyBits * 10) / 10;
    entropyValueEl.textContent = hasPassword ? String(bits) : "0";
    entropyBarEl.style.width = `${Math.min(100, (analysis.entropyBits / 100) * 100)}%`;

    // Recommendations (static strings only — never the password)
    const recs = buildRecommendations(analysis, pw);
    recommendationsEl.replaceChildren(
      ...recs.map((text) => {
        const li = document.createElement("li");
        li.textContent = text;
        return li;
      })
    );

    // Breach button availability
    breachBtn.disabled = !hasPassword;

    // Clear any stale breach result when the password changes
    breachResultEl.replaceChildren();

    return analysis;
  }

  /* ------------------------------------------------------------------ *
   * 8. Show / hide password
   * ------------------------------------------------------------------ */

  toggleBtn.addEventListener("click", () => {
    const showing = passwordInput.type === "text";
    passwordInput.type = showing ? "password" : "text";
    toggleBtn.setAttribute("aria-pressed", String(!showing));
    toggleBtn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    eyeOpen.hidden = !showing ? false : true;
    eyeClosed.hidden = !showing ? true : false;
  });

  /* ------------------------------------------------------------------ *
   * 9. Live analysis (debounced) — input event never logs pw.value
   * ------------------------------------------------------------------ */

  let debounceHandle = null;
  passwordInput.addEventListener("input", () => {
    clearTimeout(debounceHandle);
    debounceHandle = setTimeout(() => {
      // PLAINTEXT BOUNDARY: pw exists only in this local scope/closure
      // chain for the duration of scoring, and is never assigned to a
      // module-level variable, storage API, or network call here.
      const pw = passwordInput.value;
      renderAnalysis(pw);
    }, 120);
  });

  // Initial render (empty state)
  renderAnalysis("");

  /* ------------------------------------------------------------------ *
   * 10. SHA-1 via Web Crypto API
   * ------------------------------------------------------------------ */

  async function sha1Hex(message) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("WEB_CRYPTO_UNAVAILABLE");
    }
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const digest = await window.crypto.subtle.digest("SHA-1", data);
    return [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }

  /* ------------------------------------------------------------------ *
   * 11. HIBP k-anonymity range lookup
   * ------------------------------------------------------------------ */

  async function checkHibpRange(prefix, suffix) {
    const url = `https://api.pwnedpasswords.com/range/${prefix}`;
    let response;
    try {
      response = await fetch(url, {
        method: "GET",
        headers: { "Add-Padding": "true" }, // HIBP feature: pads response to resist size-based inference
      });
    } catch (networkErr) {
      throw new Error("NETWORK_ERROR");
    }

    if (response.status === 429) throw new Error("RATE_LIMITED");
    if (!response.ok) throw new Error("API_ERROR");

    let text;
    try {
      text = await response.text();
    } catch {
      throw new Error("INVALID_RESPONSE");
    }

    // Response format per line: "SUFFIX:COUNT\r\n"
    const lines = text.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [lineSuffix, countStr] = trimmed.split(":");
      if (!lineSuffix || countStr === undefined) continue;
      if (lineSuffix.toUpperCase() === suffix) {
        const count = parseInt(countStr, 10);
        return { found: true, count: Number.isFinite(count) ? count : null };
      }
    }
    return { found: false, count: 0 };
  }

  /* ------------------------------------------------------------------ *
   * 12. Breach-check button handler
   * ------------------------------------------------------------------ */

  function renderBreachResult(kind, headline, sub) {
    breachResultEl.replaceChildren();
    const wrap = document.createElement("div");
    wrap.className = `result-line ${kind}`;

    const main = document.createElement("span");
    main.textContent = headline;
    wrap.appendChild(main);

    if (sub) {
      const subEl = document.createElement("span");
      subEl.className = "result-sub";
      subEl.textContent = sub;
      main.appendChild(document.createElement("br"));
      main.appendChild(subEl);
    }

    breachResultEl.appendChild(wrap);
  }

  breachBtn.addEventListener("click", async () => {
    // PLAINTEXT BOUNDARY: this is the only function in the app that reads
    // the password for the breach flow. It is hashed on the very next
    // line and the plaintext variable falls out of scope once this
    // handler returns; it is never stored, logged, or sent over the network.
    const pw = passwordInput.value;

    if (!pw) {
      renderBreachResult("error", "Enter a password first.");
      return;
    }

    breachBtn.disabled = true;
    const originalLabel = breachBtn.textContent;
    breachBtn.textContent = "Checking…";
    renderBreachResult("error", "Hashing locally and querying HIBP…");

    try {
      const fullHash = await sha1Hex(pw); // full hash stays local
      const prefix = fullHash.slice(0, 5);
      const suffix = fullHash.slice(5); // only `prefix` is ever sent, never `suffix` or `fullHash`

      const result = await checkHibpRange(prefix, suffix);

      if (result.found) {
        const times = result.count !== null ? result.count.toLocaleString() : "an unknown number of";
        renderBreachResult(
          "found",
          "⚠ This password has appeared in known breaches.",
          `Seen approximately ${times} time(s) in the Pwned Passwords dataset. This password should not be used for any account — create a new unique password.`
        );
      } else {
        renderBreachResult(
          "clear",
          "✓ This password was not found in the Pwned Passwords dataset.",
          "This does not guarantee the password has never been compromised — only that it wasn't found in this dataset at the time of the request."
        );
      }
    } catch (err) {
      // Never include `pw`, `fullHash`, or any derived secret in error text.
      const messages = {
        WEB_CRYPTO_UNAVAILABLE: "Your browser doesn't support the cryptographic functions needed for a local, private breach check.",
        NETWORK_ERROR: "Couldn't reach the breach-check service. Check your connection and try again.",
        RATE_LIMITED: "Too many requests right now — please wait a moment and try again.",
        API_ERROR: "The breach-check service returned an error. Please try again shortly.",
        INVALID_RESPONSE: "Received an unexpected response from the breach-check service.",
      };
      const friendly = messages[err.message] || "Something went wrong while checking for breaches. Please try again.";
      renderBreachResult("error", friendly);
    } finally {
      breachBtn.disabled = !passwordInput.value;
      breachBtn.textContent = originalLabel;
    }
  });
})();
