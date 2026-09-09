# SecurePass — Password Strength Checker & Breach Alert

A privacy-focused, fully client-side web application that analyzes password strength locally and checks for known breaches using the Have I Been Pwned (HIBP) Pwned Passwords API — without ever transmitting your password or its full hash.

**Live demo:** _add your Netlify URL here after deploying_

---

## 1. Project Overview

SecurePass is an educational cybersecurity portfolio project. It lets a user type a password into the browser and, entirely on their own device:

- Scores the password's strength (0–100)
- Classifies it (Very Weak → Very Strong)
- Estimates its entropy in bits
- Flags common weaknesses (short length, repeats, sequences, common passwords)
- Optionally checks — on explicit click — whether the password has appeared in known data breaches, using HIBP's k-anonymity range API, which never receives the plaintext password or the full hash

There is no backend, no database, no accounts, and no analytics. It is a static site: `index.html` + `style.css` + `script.js`, deployable anywhere that serves static files.

---

## 2. Features

- Local password strength scoring (0–100) with a visual meter
- Strength classification: Very Weak, Weak, Moderate, Strong, Very Strong
- Character-class checklist (length, uppercase, lowercase, numbers, special characters, pattern-freedom)
- Entropy estimate (`length × log2(pool size)`)
- Show/hide password toggle (keyboard accessible)
- Breach detection via HIBP Pwned Passwords, using SHA-1 + k-anonymity so only 5 hash characters ever leave the browser
- Context-aware recommendations, escalated if the password is found in a breach
- Visible, accurate privacy notice
- No password storage, logging, URL exposure, or analytics — anywhere
- Dark, accessible, responsive dashboard UI

---

## 3. Architecture

```
User
 ↓
Browser
 ↓
Local Password Analysis   (length, character classes, patterns, dictionary check)
 ↓
SHA-1 Hash                (Web Crypto API, computed locally — only on "Check Breach Status")
 ↓
First 5 Characters        (the "prefix")
 ↓
HIBP Range API            (GET https://api.pwnedpasswords.com/range/{prefix})
 ↓
Returned Hash Suffixes    (~400-800 candidate suffixes sharing that prefix)
 ↓
Local Comparison          (does our suffix appear in the returned list?)
 ↓
Breach Result             (found + approx. count, or not found)
```

No server of ours sits anywhere in this diagram. The only third-party network calls are to `api.pwnedpasswords.com`, and only after the user explicitly clicks "Check Breach Status."

---

## 4. Security Design

**Hashing.** The password is hashed with SHA-1 using the browser-native Web Crypto API (`crypto.subtle.digest`). This happens entirely in memory, client-side.

**Why SHA-1 here specifically:** HIBP's Pwned Passwords API is keyed by SHA-1 for historical/compatibility reasons, and the security of the *lookup* doesn't depend on SHA-1's collision resistance — it depends on k-anonymity (below). SHA-1 is **not** used, and must never be used, to *store* passwords in a real system. For storing passwords server-side, use a slow, salted, memory-hard algorithm such as Argon2id, bcrypt, or scrypt. SHA-1 is fast and unsalted, which is exactly wrong for storage but irrelevant to this lookup's privacy properties.

**k-anonymity.** Only the first 5 hex characters of the 40-character SHA-1 hash are sent to HIBP. Thousands of different passwords share any given 5-character prefix, so HIBP's server receives a query it cannot map back to a specific password — it can only see "someone is checking one of ~400-800 possibilities in this bucket." The actual suffix comparison happens locally, in `script.js`, after the response is received.

**Why the plaintext password is never transmitted:** there is simply no code path in `script.js` that sends `passwordInput.value` (or any variable derived from it before hashing) over the network. The only network call (`checkHibpRange`) receives just the 5-character prefix as a string literal template.

**Why the complete hash isn't transmitted:** the same reasoning — `checkHibpRange(prefix, suffix)` only builds the request URL from `prefix`; `suffix` and the full hash are used solely for the local `Array`/string comparison against HIBP's response.

**Client-side processing.** All scoring, entropy calculation, and pattern detection run synchronously in the browser with no network dependency at all.

**No password storage.** The app does not write to `localStorage`, `sessionStorage`, cookies, or any client-side database. Nothing about the password persists after a page reload.

---

## 5. Threat Model

| Threat | Addressed by SecurePass? | Notes |
|---|---|---|
| Password interception in transit (to SecurePass) | ✅ Partially | Netlify serves over HTTPS; the HIBP call is HTTPS too. Only a 5-char prefix would ever be visible to a network observer. |
| Weak/guessable passwords | ✅ | Strength engine flags short length, low variety, dictionary matches, sequences, and repeats. |
| Password reuse | ✅ (advisory only) | Recommendations always warn against reuse; SecurePass cannot technically detect reuse across sites. |
| Brute-force attacks | ⚠️ Partially | Entropy estimate gives a rough guessing-resistance signal; it is not a guarantee against advanced offline attacks. |
| Dictionary attacks | ⚠️ Partially | A small demonstration dictionary is checked locally; a real attacker's dictionary is far larger (see Limitations). |
| Breached credentials | ✅ | HIBP Pwned Passwords check covers 600M+ real-world breached passwords. |
| Malicious browser extensions | ❌ Not addressed | A malicious extension with page access can read any input field, including this one. No web app can fully defend against this. |
| Compromised device/browser | ❌ Not addressed | If the OS or browser itself is compromised (keylogger, malware), no client-side privacy design can protect the password. |
| SecurePass's own code being malicious/modified | ⚠️ User must verify | Since this is open source, users/reviewers can read `script.js` directly to confirm no exfiltration exists — that transparency is the main mitigation. |

---

## 6. Limitations

- **HIBP is not the entire universe of breaches.** It's a large, well-maintained aggregation, but it cannot include breaches that haven't been discovered, disclosed, or ingested yet.
- **A password not found does not mean it is safe.** It only means it wasn't in the dataset at the time of the request.
- **Entropy is an estimate**, based on an idealized "every character is independently random from the observed pool" model. Real human-chosen passwords are far more predictable than this formula assumes (e.g., "Password1!" has high formula-entropy but is trivially guessable) — the strength engine's pattern/dictionary penalties exist specifically to compensate for this gap, but they cannot catch everything.
- **Strength scoring is heuristic**, not a cryptographic guarantee. It's meant to guide better choices, not certify unbreakability.
- **The local common-password dictionary is small** (a few dozen entries) and exists to demonstrate the mechanism, not to provide comprehensive dictionary-attack coverage. Real attacker dictionaries (e.g., rockyou.txt-derived lists) contain millions of entries.
- **Client-side applications have inherent limitations** — see Threat Model above regarding compromised browsers/devices/extensions.
- **A compromised device or browser can defeat every privacy protection described here.** Client-side privacy design (no logging, no storage, minimal network calls) protects against *this app* leaking data — it cannot protect against an already-compromised environment.

---

## 7. Deployment (Netlify)

1. Push this project to a GitHub repository (see Section 8).
2. Go to [app.netlify.com](https://app.netlify.com) and sign in.
3. Click **Add new site → Import an existing project**.
4. Choose GitHub and select your `securepass` repository.
5. Build settings: leave **Build command** empty and set **Publish directory** to the repository root (`.` / `/`) — this is a static site with no build step.
6. Click **Deploy site**. Netlify will give you a `*.netlify.app` URL over HTTPS automatically.
7. (Optional) Add a custom domain under **Site configuration → Domain management**.

No environment variables or secrets are required — the app has none.

---

## 8. GitHub

```bash
cd securepass
git init
git add .
git commit -m "Initial commit: SecurePass v1"
git branch -M main
git remote add origin https://github.com/<your-username>/securepass.git
git push -u origin main
```

---

## 9. Testing

Manual test cases to run before/after any change:

| # | Case | Expected Result |
|---|---|---|
| 1 | Empty password | Score shows 0, badge reads "Enter a password," Breach button disabled |
| 2 | Very short password (e.g. `ab1`) | Score capped low (≤20), classified "Very Weak," length checklist item fails |
| 3 | Strong unique password (e.g. `Tr@il-Ember-92!Quorum`) | High score, "Strong"/"Very Strong," all/most checklist items pass |
| 4 | Very long passphrase, lowercase only (e.g. `correct horse battery staple forest`) | High entropy and good score despite lacking uppercase/numbers/special — demonstrates length > variety |
| 5 | Common password (e.g. `password123`) | Low score, "pattern" checklist item fails, dictionary-based recommendation shown |
| 6 | Known-breached password (e.g. `123456`) | Breach check returns "found," shows approximate count, strong warning recommendation |
| 7 | Strong, likely non-breached random password | Breach check returns "not found," with the accurate caveat text shown |
| 8 | Network failure (disable network, click "Check Breach Status") | Friendly network-error message, no stack trace or raw error exposed |
| 9 | Rapid repeated breach-check clicks | Button disables during request; no duplicate/overlapping requests |
| 10 | Inspect DevTools Network tab during breach check | Only request is to `api.pwnedpasswords.com/range/<5 chars>` — confirm no password/hash in the URL or request body |
| 11 | Inspect Application tab (localStorage/sessionStorage/cookies) | Confirm empty / no password-related keys after use |
| 12 | Keyboard-only navigation | Tab to input, toggle show/hide with Enter/Space, reach and activate breach-check button, focus rings visible throughout |

---

## 10. Future Improvements

- Better password-strength estimation (e.g. zxcvbn-style pattern matching)
- Larger, curated local common-password detection list
- Password manager integration / "generate a strong password" helper
- Security headers (CSP, `X-Content-Type-Options`, `Referrer-Policy`) configured at the Netlify edge
- A strict Content Security Policy limiting connect-src to `api.pwnedpasswords.com`
- Automated security testing (e.g. static analysis, dependency scanning, Playwright-based E2E privacy checks that assert no network calls contain the password)
- A future backend architecture (if ever needed) — kept explicitly out of scope for v1 by design
- Optional email breach monitoring using an authenticated HIBP breach API (would require a backend/proxy, since that endpoint requires an API key that must not be exposed client-side)

---

## Assumptions

- Users are running a modern browser with Web Crypto API support (Chrome, Firefox, Safari, Edge — all current versions).
- HIBP's public range API remains free, unauthenticated, and available at `https://api.pwnedpasswords.com/range/{prefix}`.
- "Educational portfolio project" scope — not intended as a production authentication component.

## What should NOT be carried into production

- **Do not** use SHA-1 for password storage — ever. Use Argon2id/bcrypt/scrypt with per-user salts.
- **Do not** assume "not found in HIBP" means a password is safe to accept without other policy checks (minimum length, rate-limited login attempts, MFA, etc.).
- **Do not** treat the small local dictionary as sufficient weak-password protection in a real signup flow — use a maintained, much larger list or a service designed for this.
- **Do not** skip server-side validation just because client-side checks exist — client-side JavaScript can always be bypassed or disabled.
- **Do not** deploy without HTTPS enforced (Netlify does this by default, but confirm it if self-hosting elsewhere).

---

## License

This project is for educational/portfolio use. Breach data is provided by [Have I Been Pwned](https://haveibeenpwned.com/), used under their [Pwned Passwords API terms](https://haveibeenpwned.com/API/v3#AcceptableUse).
