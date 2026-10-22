// The CION portal's page: the operator's console for the nodes' asks, the
// nodes and hosts admitted, the auth keys that admit hosts onto the nodes
// they name, and the passkeys. Every string a joiner, host, or client
// supplied reaches the page as text, through h() or textContent, never as
// markup.
"use strict";

const POLL_MS = 5000;
const MINUTE = 60e3;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
// Below 23 hours left, a node is an hour past its renewal threshold.
const NOT_RENEWING = 23 * HOUR;

const TABS = { nodes: "Nodes", hosts: "Hosts", keys: "Auth keys", settings: "Settings" };
// The list endpoint behind each tab.
const LISTS = {
  nodes: "/admin/api/nodes",
  hosts: "/admin/api/hosts",
  keys: "/admin/api/keys",
  settings: "/admin/api/passkeys",
};
const BOUNDARIES = {
  enrollment: ["Enrollment", "amber"],
  voting: ["Core vote", "violet"],
};
const ROLES = {
  founder: ["Founder", "blue"],
  core: ["Core", "blue-outline"],
  normal: ["Normal", "muted-outline"],
};
const KEY_STATES = { spent: "Spent", revoked: "Revoked", expired: "Expired" };
// The endpoints answering without a session, whose 401 signs nobody out.
const PUBLIC_API = /^\/admin\/api\/(session|setup\/|login\/)/;

// The setup link carries its token in the fragment, which no request line
// carries; the token leaves the address bar as soon as it is read.
const setupToken = location.hash.slice(1);
if (location.hash) history.replaceState(null, "", location.pathname + location.search);

let tab = "nodes";
let data = {}; // the last response of each tab's list endpoint
let refreshSeq = 0;
let refreshError = "";
let pollTimer = 0;
let toastTimer = 0;
let openMenu = null; // {menu, button} while a row's menu is open
let confirmRun = null; // the confirm dialog's action, answering its toast

// ---- DOM helpers ----

const $ = selector => document.querySelector(selector);

// Flattens children, dropping null, undefined, and false.
const present = children => children.flat(Infinity).filter(child => child != null && child !== false);

// Creates an element. Function attributes bind listeners under their on*
// names; children append as nodes or as text, never parsed as markup.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs ?? {})) {
    if (typeof value === "function") el.addEventListener(name.slice(2), value);
    else if (value === true) el.setAttribute(name, "");
    else if (value != null && value !== false) el.setAttribute(name, value);
  }
  el.append(...present(children));
  return el;
}

// Replaces an element's children. Focus moves to the new control with the
// same data-key, so a poll's re-render keeps the operator's place.
function update(el, ...children) {
  const key = el.contains(document.activeElement) ? document.activeElement.dataset.key : undefined;
  el.replaceChildren(...present(children));
  if (key) el.querySelector(`[data-key="${CSS.escape(key)}"]`)?.focus({ preventScroll: true });
}

// Interleaves the parts present with a separator.
function join(parts, separator = " · ") {
  return parts.filter(Boolean).flatMap((part, i) => (i > 0 ? [separator, part] : [part]));
}

const badge = (text, tone) => h("span", { class: `badge badge-${tone}` }, text);
const mono = text => h("span", { class: "mono" }, text);
const dash = () => h("span", { class: "muted" }, "—");
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

// Shortens a key to its first six and last four characters; the tooltip
// holds it whole.
function shortKey(key, cls = "mono") {
  return h("span", { class: cls, title: key }, key.length > 12 ? `${key.slice(0, 6)}…${key.slice(-4)}` : key);
}

// Parses an RFC 3339 timestamp, cutting Go's nanoseconds to the
// milliseconds every browser's Date.parse reads.
const parseTime = iso => Date.parse(iso.replace(/(\.\d{3})\d+/, "$1"));

// Formats a timestamp relative to now: "just now", "2 min ago", "in 2 days".
function relativeTime(iso) {
  const ms = parseTime(iso) - Date.now();
  const abs = Math.abs(ms);
  if (abs < 45e3) return "just now";
  let span;
  if (abs < 59.5 * MINUTE) span = `${Math.round(abs / MINUTE)} min`;
  else if (abs < 36 * HOUR) span = plural(Math.round(abs / HOUR), "hour");
  else if (abs < 60 * DAY) span = plural(Math.round(abs / DAY), "day");
  else return new Date(parseTime(iso)).toLocaleDateString(undefined, { dateStyle: "medium" });
  return ms < 0 ? `${span} ago` : `in ${span}`;
}

// A relative time whose tooltip holds the absolute one.
function timeEl(iso, prefix = "") {
  return h("time", { datetime: iso, title: new Date(parseTime(iso)).toLocaleString() }, prefix + relativeTime(iso));
}

// A timestamp as a short date and time: "Oct 22, 3:41 PM".
const dateTime = iso =>
  new Date(parseTime(iso)).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

// Reports whether any field contains the query, ignoring case.
function matches(query, fields) {
  const needle = query.trim().toLowerCase();
  return !needle || fields.some(field => field?.toLowerCase().includes(needle));
}

// Fills a table body with rows, or with one row saying why there are none.
function fillTable(tbody, rows, message) {
  const columns = tbody.closest("table").tHead.rows[0].cells.length;
  update(tbody, rows.length > 0 ? rows : h("tr", { class: "empty" }, h("td", { colspan: columns }, message)));
}

// The text a table shows with no rows: loading, no match, or none at all.
function emptyText(list, query, none) {
  if (!list) return "Loading…";
  return query.trim() ? "Nothing matches the search." : none;
}

// ---- API ----

// Aborts an action whose session ended; the sign-in view shows already.
class SignedOut extends Error {}

// Calls the portal's JSON API, answering the decoded body, or null for 204.
async function request(method, path, body) {
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
  } catch {
    throw new Error("Can't reach the core.");
  }
  if (response.status === 401 && !PUBLIC_API.test(path)) {
    if (!$("#app-view").hidden) toast("The session ended. Sign in again.");
    showSignIn();
    throw new SignedOut();
  }
  if (!response.ok) throw new Error(await failure(response));
  return response.status === 204 ? null : response.json();
}

// Reads the message of a failed response's {"error": "..."} body.
async function failure(response) {
  try {
    const { error } = await response.json();
    if (error) return error;
  } catch {
    // Not the API's JSON: the status speaks for it.
  }
  return `The core answered ${response.status} ${response.statusText}`.trim();
}

const get = path => request("GET", path);
const post = (path, body = {}) => request("POST", path, body);
const del = path => request("DELETE", path);

// ---- Feedback ----

// Shows a short message at the bottom of the page. A modal dialog renders in
// the top layer and leaves the rest of the page inert, so the toast joins an
// open one to stay visible and announced.
function toast(message, tone = "info") {
  const el = $("#toast");
  (document.querySelector("dialog[open]") ?? document.body).append(el);
  el.textContent = message;
  el.className = `toast toast-${tone} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), tone === "error" ? 6000 : 3000);
}

// Reports a failure, save an ended session, which the sign-in view explains.
function report(err) {
  if (!(err instanceof SignedOut)) toast(err.message, "error");
}

// Runs an operator's action with its button disabled until it settles.
async function act(button, action) {
  button.disabled = true;
  try {
    await action();
  } catch (err) {
    report(err);
  } finally {
    button.disabled = false;
  }
}

// ---- Passkeys ----

// Base64url without padding: the encoding of the server's binary fields.
const fromB64url = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const toB64url = buffer =>
  btoa(Array.from(new Uint8Array(buffer), b => String.fromCharCode(b)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const decodeIds = credentials => (credentials ?? []).map(c => ({ ...c, id: fromB64url(c.id) }));

function requirePasskeys() {
  if (!window.PublicKeyCredential) throw new Error("This browser doesn't support passkeys.");
}

// Runs the browser's passkey prompt, answering null when the operator
// dismissed it or it timed out.
async function browserCredential(call) {
  try {
    return await call();
  } catch (err) {
    if (err.name === "NotAllowedError") {
      toast("The passkey prompt was dismissed or timed out.");
      return null;
    }
    if (err.name === "InvalidStateError") throw new Error("This authenticator holds a passkey for this console already.");
    throw err;
  }
}

// Registers a passkey: begin's options go to the browser, the credential it
// creates goes to finish. Answers whether the ceremony completed.
async function register(base, body) {
  requirePasskeys();
  const { publicKey } = await post(`${base}/begin`, body);
  const cred = await browserCredential(() =>
    navigator.credentials.create({
      publicKey: {
        ...publicKey,
        challenge: fromB64url(publicKey.challenge),
        user: { ...publicKey.user, id: fromB64url(publicKey.user.id) },
        excludeCredentials: decodeIds(publicKey.excludeCredentials),
      },
    }));
  if (!cred) return false;
  await post(`${base}/finish`, {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: toB64url(cred.response.clientDataJSON),
      attestationObject: toB64url(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
  });
  return true;
}

// Signs in with a discoverable passkey. Answers whether the ceremony
// completed.
async function login() {
  requirePasskeys();
  const { publicKey } = await post("/admin/api/login/begin", {});
  const cred = await browserCredential(() =>
    navigator.credentials.get({
      publicKey: {
        ...publicKey,
        challenge: fromB64url(publicKey.challenge),
        allowCredentials: decodeIds(publicKey.allowCredentials),
      },
    }));
  if (!cred) return false;
  await post("/admin/api/login/finish", {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: toB64url(cred.response.clientDataJSON),
      authenticatorData: toB64url(cred.response.authenticatorData),
      signature: toB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? toB64url(cred.response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  });
  return true;
}

// ---- Views ----

// Shows one of the page's views: setup, signin, or app.
function showView(name) {
  for (const view of ["setup", "signin", "app"]) $(`#${view}-view`).hidden = view !== name;
}

// Loads the session and shows the view it calls for.
async function loadSession() {
  const session = await get("/admin/api/session");
  for (const el of document.querySelectorAll("[data-domain]")) el.textContent = session.domain;
  if (session.setup) showView("setup");
  else if (session.signedIn) showApp();
  else showSignIn();
}

// Shows the sign-in view, leaving nothing of the console behind.
function showSignIn() {
  clearInterval(pollTimer);
  refreshSeq++; // drops the refreshes in flight
  closeMenu();
  for (const dialog of document.querySelectorAll("dialog[open]")) dialog.close();
  data = {};
  document.title = "CION";
  showView("signin");
}

// Shows the console at the tab the address names, polling it while the
// page is visible.
function showApp() {
  if (location.pathname === "/admin/setup") history.replaceState(null, "", "/admin/");
  showView("app");
  selectTab(tabFromPath());
  clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    if (document.visibilityState === "visible") refresh();
  }, POLL_MS);
}

// The tab the address names: /admin/<tab>, the nodes at any other path.
function tabFromPath() {
  const name = location.pathname.replace(/^\/admin\/?/, "").replace(/\/$/, "");
  return Object.hasOwn(TABS, name) ? name : "nodes";
}

// Shows a tab from the data at hand, then refreshes it.
function selectTab(name) {
  tab = name;
  for (const link of document.querySelectorAll("[data-tab]")) {
    if (link.dataset.tab === name) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  for (const view of Object.keys(TABS)) $(`#${view}-view`).hidden = view !== name;
  closeMenu();
  renderCounts();
  renderView();
  refresh();
}

function signIn(event) {
  act(event.currentTarget, async () => {
    if (await login()) await loadSession();
  });
}

function signOut(event) {
  act(event.currentTarget, async () => {
    await post("/admin/api/logout");
    showSignIn();
  });
}

// ---- Data ----

// Fetches the open tab's list beside the node list, whose asks the tab
// count needs and whose nodes the auth keys name, and renders them unless
// the operator is mid-interaction.
async function refresh() {
  const seq = ++refreshSeq;
  const names = [...new Set(["nodes", tab])];
  try {
    const lists = await Promise.all(names.map(name => get(LISTS[name])));
    if (seq !== refreshSeq) return; // a later refresh supersedes this one
    names.forEach((name, i) => (data[name] = lists[i]));
    refreshError = "";
    renderCounts();
    if (canRender()) renderView();
  } catch (err) {
    // A failing poll reports its failure once, not every five seconds.
    if (seq !== refreshSeq || err instanceof SignedOut || err.message === refreshError) return;
    refreshError = err.message;
    toast(err.message, "error");
  }
}

// Reports whether a poll may re-render the view: never under an open menu
// or dialog, nor while the operator holds a text selection in it.
function canRender() {
  if (openMenu || document.querySelector("dialog[open]")) return false;
  const selection = document.getSelection();
  return selection.isCollapsed || !$("#app-view").contains(selection.anchorNode);
}

// Counts the pending asks on the Nodes tab and in the page's title.
function renderCounts() {
  const pending = (data.nodes?.asks ?? []).filter(ask => ask.state === "pending").length;
  const count = $('[data-tab="nodes"] .count');
  count.hidden = pending === 0;
  count.replaceChildren(String(pending), h("span", { class: "sr-only" }, " pending"));
  document.title = `${pending > 0 ? `(${pending}) ` : ""}${TABS[tab]} · CION`;
}

// Renders the open tab from the data at hand.
function renderView() {
  switch (tab) {
    case "nodes":
      return renderNodes(data.nodes);
    case "hosts":
      return renderHosts(data.hosts);
    case "keys":
      return renderKeys(data.keys);
    default:
      return renderSettings(data.settings);
  }
}

// ---- Asks ----

// Renders the nodes' asks — enrollments and core votes: the pending and
// approved ones in the amber card above the table, pending first, and the
// rejected ones in the card below.
function renderAsks(asks) {
  const open = asks
    .filter(ask => ask.state !== "rejected")
    .sort((a, b) => (a.state === "approved") - (b.state === "approved"));
  const rejected = asks.filter(ask => ask.state === "rejected");
  const pending = open.filter(ask => ask.state === "pending").length;
  update($("#nodes-asks"), open.length > 0 && h("div", { class: "card card-amber" },
    h("div", { class: "card-head" }, pending > 0 ? `Needs approval · ${pending}` : "Approved"),
    open.map(askRow)));
  update($("#nodes-rejected"), rejected.length > 0 && h("div", { class: "card card-rejected" },
    h("div", { class: "card-head" }, "Rejected"),
    rejected.map(rejectedRow)));
}

// An ask's identity: the ISD-AS the node claims, or the core presenting
// the vote.
const askIdentity = ask => h("span", { class: "id" }, ask.claim);

// One pending or approved ask: its identity and facts, and while it pends,
// the decision.
function askRow(ask) {
  const [kind, tone] = BOUNDARIES[ask.boundary];
  const approved = ask.state === "approved";
  return h("div", { class: "ask" },
    h("div", { class: "ask-main" },
      h("div", { class: "ask-title" },
        askIdentity(ask),
        badge(kind, tone),
        approved && badge("Approved", "green")),
      h("div", { class: "ask-facts" }, askFacts(ask))),
    approved
      ? h("span", { class: "ask-note", title: `The approval lapses ${relativeTime(ask.until)}.` }, "admitted at its next retry")
      : h("div", { class: "ask-actions" },
        h("button", {
          class: "btn btn-sm",
          "data-key": `reject:${ask.id}`,
          onclick: event => decide(event.currentTarget, ask, "reject"),
        }, "Reject"),
        h("button", {
          class: "btn btn-sm btn-primary",
          "data-key": `approve:${ask.id}`,
          onclick: event => decide(event.currentTarget, ask, "approve"),
        }, "Approve")));
}

// The facts under an ask: its keys, source, and attempts.
function askFacts(ask) {
  const keyList = join(ask.keys.map(key => shortKey(key)), ", ");
  return join([
    ask.keys.length > 0 && (ask.boundary === "voting" ? [`adds ${plural(ask.keys.length, "key")}: `, keyList] : keyList),
    ask.source && `from ${ask.source}`,
    `first seen ${relativeTime(ask.firstSeen)}`,
    plural(ask.attempts, "attempt"),
  ]);
}

// One rejected ask, with the approval that undoes the rejection.
function rejectedRow(ask) {
  return h("div", { class: "ask" },
    badge("Rejected", "red"),
    askIdentity(ask),
    h("span", { class: "ask-meta" }, join([
      ask.source && `from ${ask.source}`,
      `last seen ${relativeTime(ask.lastSeen)}`,
      `denied until ${dateTime(ask.until)}`,
    ])),
    h("button", {
      class: "btn btn-sm",
      "data-key": `approve:${ask.id}`,
      onclick: event => decide(event.currentTarget, ask, "approve"),
    }, "Approve"));
}

// Approves or rejects an ask; verdict names the endpoint.
function decide(button, ask, verdict) {
  act(button, async () => {
    await post(`/admin/api/asks/${encodeURIComponent(ask.id)}/${verdict}`);
    toast(verdict === "approve" ? "Approved: admitted at its next retry" : "Rejected");
    await refresh();
  });
}

// ---- Nodes ----

function renderNodes(list) {
  renderAsks(list?.asks ?? []);
  const query = $("#nodes-filter").value;
  const nodes = (list?.nodes ?? []).filter(node => matches(query, [node.ia, node.key, node.overlay, node.endpoint]));
  fillTable($("#nodes-rows"), nodes.map(nodeRow), emptyText(list, query, "No node holds a chain from this core yet."));
}

// One node: its ISD-AS and role, key, overlay, endpoint, issued addresses,
// and certificate.
function nodeRow(node) {
  return h("tr", null,
    h("td", null, h("div", { class: "id" }, node.ia), h("div", { class: "below" }, badge(...ROLES[node.role]))),
    h("td", null, shortKey(node.key)),
    h("td", null, node.overlay ? mono(node.overlay) : dash()),
    h("td", null, node.endpoint ? mono(node.endpoint) : dash()),
    h("td", null, node.overlay ? `${node.issued} / ${node.capacity}` : dash()),
    h("td", null, certificate(node.expires)));
}

// The certificate's expiry, flagged once the node is past renewing it.
function certificate(expires) {
  const left = parseTime(expires) - Date.now();
  return h("div", { class: "cert" },
    timeEl(expires, left < 0 ? "expired " : "expires "),
    left < NOT_RENEWING && badge("Not renewing", "amber"));
}

// ---- Hosts ----

function renderHosts(list) {
  const available = list?.available !== false;
  $("#hosts-unavailable").hidden = available;
  for (const el of $("#hosts-view").querySelectorAll("[data-coordination]")) el.hidden = !available;
  if (!available) return;
  const query = $("#hosts-filter").value;
  const hosts = (list?.hosts ?? []).filter(host =>
    matches(query, [host.addr, host.hostname, host.os, host.nodeKey, host.machineKey, host.owner, host.endpoint, host.note]));
  fillTable($("#hosts-rows"), hosts.map(hostRow), emptyText(list, query, "No host holds an address yet."));
}

// One host: its address and claims, keys, the node it connects to, its
// approval, and its presence, with its menu.
function hostRow(host) {
  const claims = [host.hostname, host.os].filter(Boolean).join(" · ");
  return h("tr", null,
    h("td", null, h("div", { class: "id" }, host.addr), claims && h("div", { class: "below claim" }, `claims ${claims}`)),
    h("td", null, h("div", null, shortKey(host.nodeKey)), h("div", { class: "below muted" }, shortKey(host.machineKey))),
    h("td", null, connectsTo(host.owner, host.endpoint)),
    h("td", null, approval(host.note)),
    h("td", null, presence(host)),
    h("td", { class: "cell-action" }, h("button", {
      class: "icon-btn",
      "aria-label": `Actions for ${host.addr}`,
      "aria-haspopup": "menu",
      "aria-expanded": "false",
      "data-key": `menu:${host.nodeKey}`,
      onclick: event => toggleMenu(event.currentTarget, [{ label: "Remove…", danger: true, action: () => removeHost(host) }]),
    }, "⋯")));
}

// A node hosts connect to: its ISD-AS above its host endpoint.
function connectsTo(ia, endpoint) {
  return [h("div", { class: "mono" }, ia), endpoint && h("div", { class: "below muted mono" }, endpoint)];
}

// The note the host was admitted with, without the portal's own prefix: an
// auth key's in green, any other muted.
function approval(note) {
  if (!note) return dash();
  const tone = note.startsWith("portal auth key") ? "green" : "muted";
  return h("span", { class: `badge badge-${tone}`, title: note }, note.replace(/^portal /, ""));
}

// The host's presence: connected now, else when it was last seen, else
// unseen since the core started.
function presence(host) {
  if (host.connected) return h("span", { class: "presence" }, h("span", { class: "dot", "aria-hidden": "true" }), "Connected");
  return h("span", { class: "muted" }, host.lastSeen ? timeEl(host.lastSeen) : "Not seen since restart");
}

// Releases a host's address once the operator confirms.
function removeHost(host) {
  confirmAction({
    title: `Remove ${host.addr}?`,
    message: "Its registry entry is deleted and the address is released. Its node drops the peer within 30 seconds. " +
      "The client can join again only with an auth key that still admits it.",
    label: "Remove",
    run: async () => {
      await del(`/admin/api/hosts/${encodeURIComponent(host.nodeKey)}`);
      return `Removed: ${host.addr} is free`;
    },
  });
}

// ---- Auth keys ----

function renderKeys(list) {
  fillTable($("#keys-rows"), (list?.keys ?? []).map(keyRow), emptyText(list, "", "No auth keys yet."));
}

// One auth key, with the node its hosts connect to, and Revoke while it is
// active and its state after.
function keyRow(key) {
  return h("tr", null,
    h("td", null, mono(key.id)),
    h("td", null, key.description || dash()),
    h("td", null, keyNode(key)),
    h("td", null, badge(key.reusable ? "Reusable" : "One use", "muted")),
    h("td", { class: "muted" }, timeEl(key.created)),
    h("td", { class: "muted" }, timeEl(key.expires)),
    h("td", null, String(key.uses)),
    h("td", { class: "cell-action" }, key.state === "active"
      ? h("button", { class: "link", "data-key": `revoke:${key.id}`, onclick: () => revokeKey(key) }, "Revoke")
      : badge(KEY_STATES[key.state], "muted")));
}

// The node a key's hosts connect to — the founding core where the key names
// none — above its host endpoint while the node is listed.
function keyNode(key) {
  const node = (data.nodes?.nodes ?? []).find(n => (key.node ? n.ia === key.node : n.role === "founder"));
  return connectsTo(node?.ia ?? key.node ?? "founding core", node?.endpoint);
}

function revokeKey(key) {
  confirmAction({
    title: `Revoke ${key.id}?`,
    message: "No host can register with it from now on. Hosts it admitted already keep their addresses.",
    label: "Revoke",
    run: async () => {
      await del(`/admin/api/keys/${encodeURIComponent(key.id)}`);
      return `Revoked ${key.id}`;
    },
  });
}

// Opens the key dialog once the nodes a key can name are fresh.
function openKeyDialog(event) {
  act(event.currentTarget, async () => {
    const { nodes } = await get(LISTS.nodes);
    const form = $("#key-form");
    form.reset();
    fillNodes(form.elements.node, nodes);
    form.hidden = false;
    $("#key-result").hidden = true;
    $("#key-dialog").showModal();
  });
}

// Offers the nodes holding a slice, each with its host endpoint and free
// addresses, the founding core selected.
function fillNodes(select, nodes) {
  const serving = nodes.filter(node => node.overlay && node.endpoint);
  update(select, serving.length > 0
    ? serving.map(node => h("option", { value: node.ia, selected: node.role === "founder" },
      `${node.ia} · ${node.endpoint} · ${node.capacity - node.issued} free`))
    : h("option", { value: "" }, "No node serves hosts yet"));
}

// Mints the key, then shows it in place of the form, the one time it is
// shown, beside the node its hosts connect to.
function submitKey(event) {
  event.preventDefault();
  const fields = event.currentTarget.elements;
  act(event.submitter, async () => {
    const { key, node, endpoint } = await post("/admin/api/keys", {
      description: fields.description.value.trim(),
      reusable: fields.reusable.checked,
      days: fields.days.valueAsNumber,
      node: fields.node.value,
    });
    $("#key-form").hidden = true;
    $("#key-value").textContent = key;
    $("#key-node").textContent = `${node} · ${endpoint}`;
    $("#key-result").hidden = false;
    $("#key-copy").focus();
    refresh();
  });
}

// Copies the minted key, or selects it for the keyboard where the clipboard
// is out of reach.
async function copyKey() {
  const code = $("#key-value");
  try {
    await navigator.clipboard.writeText(code.textContent);
    toast("Copied the key");
  } catch {
    document.getSelection().selectAllChildren(code);
    toast("The key is selected: copy it with your keyboard");
  }
}

// ---- Settings ----

function renderSettings(list) {
  const passkeys = list?.passkeys ?? [];
  const last = passkeys.length === 1;
  fillTable($("#passkeys-rows"), passkeys.map(passkey => passkeyRow(passkey, last)), emptyText(list, "", "No passkeys."));
}

// One passkey, whose Remove is disabled while it is the last.
function passkeyRow(passkey, last) {
  return h("tr", null,
    h("td", null, passkey.name),
    h("td", { class: "muted" }, timeEl(passkey.created)),
    h("td", { class: "muted" }, passkey.lastUsed ? timeEl(passkey.lastUsed) : dash()),
    h("td", { class: "cell-action" }, h("button", {
      class: "link",
      "data-key": `remove:${passkey.id}`,
      disabled: last,
      title: last ? "The last passkey can't be removed." : null,
      onclick: () => removePasskey(passkey),
    }, "Remove")));
}

function removePasskey(passkey) {
  confirmAction({
    title: `Remove “${passkey.name}”?`,
    message: "It can no longer sign in to this console.",
    label: "Remove",
    run: async () => {
      await del(`/admin/api/passkeys/${encodeURIComponent(passkey.id)}`);
      return `Removed “${passkey.name}”`;
    },
  });
}

function openPasskeyDialog() {
  $("#passkey-form").reset();
  $("#passkey-dialog").showModal();
}

// The form's own submission closes the dialog. The ceremony starts inside
// the submit event, whose user activation the browser's prompt requires.
function submitPasskey(event) {
  const name = event.currentTarget.elements.name.value.trim();
  act($("#add-passkey"), async () => {
    if (await register("/admin/api/passkeys", { name })) {
      toast(`Added “${name}”`);
      await refresh();
    }
  });
}

// Registers the first passkey with the logged setup token.
function submitSetup(event) {
  event.preventDefault();
  const fields = event.currentTarget.elements;
  act(event.submitter, async () => {
    if (await register("/admin/api/setup", { token: fields.token.value.trim(), name: fields.name.value.trim() })) {
      toast("Passkey created");
      await loadSession();
    }
  });
}

// ---- Menu and confirmation ----

// Opens a row's menu under its button, or closes it when open already.
function toggleMenu(button, items) {
  const reopen = openMenu?.button !== button;
  closeMenu();
  if (!reopen) return;
  const menu = h("div", { class: "menu", role: "menu" }, items.map(item => h("button", {
    class: item.danger ? "menu-item danger" : "menu-item",
    role: "menuitem",
    onclick: () => {
      closeMenu(true);
      item.action();
    },
  }, item.label)));
  button.after(menu);
  const rect = button.getBoundingClientRect();
  const fitsBelow = rect.bottom + 4 + menu.offsetHeight <= window.innerHeight;
  menu.style.top = `${fitsBelow ? rect.bottom + 4 : rect.top - 4 - menu.offsetHeight}px`;
  menu.style.left = `${Math.max(8, rect.right - menu.offsetWidth)}px`;
  button.setAttribute("aria-expanded", "true");
  openMenu = { menu, button };
  menu.querySelector("button").focus({ preventScroll: true });
}

// Closes the open menu, handing focus back to its button on request.
function closeMenu(refocus = false) {
  if (!openMenu) return;
  const { menu, button } = openMenu;
  openMenu = null;
  menu.remove();
  button.setAttribute("aria-expanded", "false");
  if (refocus) button.focus();
}

// Asks the operator to confirm a destructive action. The dialog stays open,
// its button disabled, while run's request is in flight; run answers the
// toast reporting its success.
function confirmAction({ title, message, label, run }) {
  $("#confirm-title").textContent = title;
  $("#confirm-message").textContent = message;
  $("#confirm-ok").textContent = label;
  confirmRun = run;
  $("#confirm-dialog").showModal();
}

function submitConfirm(event) {
  event.preventDefault();
  act(event.submitter, async () => {
    const done = await confirmRun();
    $("#confirm-dialog").close();
    toast(done);
    await refresh();
  });
}

// ---- Wiring ----

for (const link of document.querySelectorAll("[data-tab]")) {
  link.addEventListener("click", event => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    if (location.pathname !== link.pathname) history.pushState(null, "", link.pathname);
    selectTab(link.dataset.tab);
  });
}
window.addEventListener("popstate", () => {
  if (!$("#app-view").hidden) selectTab(tabFromPath());
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && !$("#app-view").hidden) refresh();
});
document.addEventListener("pointerdown", event => {
  if (openMenu && !openMenu.menu.contains(event.target) && !openMenu.button.contains(event.target)) closeMenu();
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape") closeMenu(true);
});
document.addEventListener("scroll", () => closeMenu(), true);
window.addEventListener("resize", () => closeMenu());

for (const button of document.querySelectorAll("[data-action=sign-out]")) button.addEventListener("click", signOut);
for (const button of document.querySelectorAll("[data-action=generate-key]")) button.addEventListener("click", openKeyDialog);
for (const button of document.querySelectorAll("[data-close]")) {
  button.addEventListener("click", () => button.closest("dialog").close());
}
for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("close", () => {
    if (canRender()) renderView();
  });
}
for (const input of document.querySelectorAll("input[type=search]")) input.addEventListener("input", () => renderView());

$("#signin").addEventListener("click", signIn);
$("#setup-form").addEventListener("submit", submitSetup);
$("#key-form").addEventListener("submit", submitKey);
$("#key-copy").addEventListener("click", copyKey);
$("#add-passkey").addEventListener("click", openPasskeyDialog);
$("#passkey-form").addEventListener("submit", submitPasskey);
$("#confirm-form").addEventListener("submit", submitConfirm);
$("#setup-form").elements.token.value = setupToken;
$("#login-hint").textContent = `tailscale up --login-server=${location.origin} --auth-key=<key>`;

loadSession().catch(err => {
  showView("signin");
  report(err);
});
