/**
 * Minimal server-rendered HTML for the interactive login and consent pages.
 * No template engine (no new dependency); every interpolated value is HTML-
 * escaped. These pages are dev-facing (production delegates authentication to
 * an external IdP, P2.5), but consent + deny are real FAPI2 flow steps.
 */

/** Escape for HTML text/attribute contexts. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function page(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title></head>
<body>${body}</body></html>`;
}

export interface LoginView {
  action: string;
  interactionId: string;
  csrfToken: string;
  users: readonly string[];
  error?: string;
}

/** Dev login form: pick/enter a username. POSTs to the login action. */
export function renderLogin(v: LoginView): string {
  const options = v.users
    .map((u) => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`)
    .join("");
  const err = v.error ? `<p role="alert">${escapeHtml(v.error)}</p>` : "";
  return page(
    "Sign in",
    `<main><h1>Sign in (dev)</h1>${err}
<form method="post" action="${escapeHtml(v.action)}">
<input type="hidden" name="interaction_id" value="${escapeHtml(v.interactionId)}">
<input type="hidden" name="csrf" value="${escapeHtml(v.csrfToken)}">
<label>User
${v.users.length ? `<select name="username" id="username">${options}</select>` : `<input name="username" id="username">`}
</label>
<button type="submit" id="login">Continue</button>
</form></main>`,
  );
}

export interface ConsentView {
  action: string;
  interactionId: string;
  csrfToken: string;
  clientName: string;
  scopes: readonly string[];
  subject: string;
}

/** Consent screen: shows client + requested scopes, approve/deny buttons. */
export function renderConsent(v: ConsentView): string {
  const scopeItems = v.scopes.map((s) => `<li>${escapeHtml(s)}</li>`).join("");
  return page(
    "Authorize",
    `<main><h1>Authorize ${escapeHtml(v.clientName)}</h1>
<p>Signed in as <strong>${escapeHtml(v.subject)}</strong>.</p>
<p><strong>${escapeHtml(v.clientName)}</strong> is requesting access to:</p>
<ul>${scopeItems}</ul>
<form method="post" action="${escapeHtml(v.action)}">
<input type="hidden" name="interaction_id" value="${escapeHtml(v.interactionId)}">
<input type="hidden" name="csrf" value="${escapeHtml(v.csrfToken)}">
<button type="submit" name="decision" value="approve" id="approve">Approve</button>
<button type="submit" name="decision" value="deny" id="deny">Deny</button>
</form></main>`,
  );
}

/** A plain error page for interaction problems that cannot be redirected. */
export function renderError(message: string): string {
  return page("Error", `<main><h1>Request problem</h1><p>${escapeHtml(message)}</p></main>`);
}
