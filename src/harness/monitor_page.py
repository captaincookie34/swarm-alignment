"""The monitor's single page. Plain HTML, CSS and JS, with nothing loaded from the network."""

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harness Monitor</title>
<style>
:root {
  --bg: #0d1117; --panel: #161b22; --panel-2: #1c232c; --line: #2a323d; --text: #e6edf3; --muted: #8b949e;
  --ok: #3fb950; --warn: #d29922; --danger: #f85149; --accent: #58a6ff; --quiet: #6e7681;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; background: var(--bg); color: var(--text);
  font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif; }
header { display: flex; align-items: center; gap: 14px; padding: 12px 18px; border-bottom: 1px solid var(--line);
  background: var(--panel); position: sticky; top: 0; z-index: 2; flex-wrap: wrap; }
header h1 { font-size: 16px; margin: 0; letter-spacing: .2px; }
header h1 span { color: var(--muted); font-weight: 400; }
select, button, textarea, input { font: inherit; color: var(--text); }
select { background: var(--panel-2); border: 1px solid var(--line); border-radius: 6px; padding: 5px 8px; font-family: var(--mono); font-size: 12px; max-width: 320px; }
label.toggle { color: var(--muted); font-size: 13px; display: flex; gap: 6px; align-items: center; cursor: pointer; }
.pill { font-family: var(--mono); font-size: 12px; padding: 3px 10px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted); }
.pill.live { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 50%, transparent); }
.pill.live::before { content: ""; display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--ok);
  margin-right: 6px; animation: pulse 1.4s infinite; vertical-align: 1px; }
@keyframes pulse { 50% { opacity: .25; } }
.note { margin-left: auto; color: var(--muted); font-size: 12px; }
.note code { font-family: var(--mono); color: var(--text); }
main { display: grid; grid-template-columns: minmax(340px, 420px) 1fr; grid-template-rows: minmax(0, 1fr) auto;
  gap: 14px; padding: 14px 18px; height: calc(100vh - 58px); }
section { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; display: flex; flex-direction: column; min-height: 0; }
section > h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); margin: 0;
  padding: 10px 14px; border-bottom: 1px solid var(--line); display: flex; align-items: center; gap: 8px; }
section > h2 .count { font-family: var(--mono); color: var(--text); text-transform: none; letter-spacing: 0; }
.scroll { overflow-y: auto; min-height: 0; flex: 1; }
#agents .agent { padding: 8px 14px 8px 8px; border-bottom: 1px solid var(--line); cursor: pointer; position: relative; display: flex; }
#agents .agent .body { flex: 1; min-width: 0; padding-left: 4px; }
.g { width: 20px; flex: none; position: relative; margin: -8px 0; }
.g.line::before, .g.conn::before { content: ""; position: absolute; left: 9px; top: 0; bottom: 0; border-left: 2px solid var(--tree); }
.g.conn.end::before { bottom: auto; height: 21px; }
.g.conn::after { content: ""; position: absolute; left: 9px; top: 19px; width: 10px; border-top: 2px solid var(--tree); }
.fullid { font-family: var(--mono); font-size: 12px; margin-top: 4px; word-break: break-all; line-height: 1.35; }
.idk { color: var(--quiet); } .idr { color: var(--text); } .idp { color: var(--accent); font-weight: 700; }
.lineage { font-size: 12px; color: var(--muted); margin-top: 2px; }
.lineage b { color: var(--text); font-weight: 600; font-family: var(--mono); }
.gen { font-size: 11px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; color: var(--muted); }
.legend { padding: 8px 14px; font-size: 12px; color: var(--muted); border-bottom: 1px solid var(--line); background: var(--panel-2); }
.legend code { font-family: var(--mono); font-size: 11.5px; }
#kill-list { font-family: var(--mono); font-size: 12px; background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; max-height: 140px; overflow-y: auto; }
#kill-list div { word-break: break-all; padding: 1px 0; }
#agents .agent:hover { background: var(--panel-2); }
#agents .agent.selected { background: color-mix(in srgb, var(--accent) 10%, var(--panel)); box-shadow: inset 3px 0 var(--accent); }
#agents .agent.revoked { opacity: .72; }
#agents .agent.revoked .id { text-decoration: line-through; text-decoration-color: var(--danger); }
.row { display: flex; align-items: center; gap: 8px; }
.dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
.id { font-family: var(--mono); font-size: 13px; font-weight: 600; }
.badge { font-size: 11px; padding: 1px 7px; border-radius: 4px; font-weight: 600; text-transform: uppercase; letter-spacing: .4px; }
.badge.active { background: color-mix(in srgb, var(--ok) 18%, transparent); color: var(--ok); }
.badge.revoked { background: color-mix(in srgb, var(--danger) 20%, transparent); color: var(--danger); }
.badge.threat { background: var(--danger); color: #fff; }
.badge.done { background: var(--panel-2); color: var(--muted); }
.meta { color: var(--muted); font-size: 12px; margin-top: 3px; font-family: var(--mono); }
.last { color: var(--text); font-size: 12px; margin-top: 3px; font-family: var(--mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.task { color: var(--muted); font-size: 12px; margin-top: 3px; display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden; }
button.kill { margin-left: auto; background: transparent; border: 1px solid color-mix(in srgb, var(--danger) 60%, transparent); color: var(--danger);
  border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 600; cursor: pointer; }
button.kill:hover { background: var(--danger); color: #fff; }
.stats { display: flex; flex-wrap: wrap; column-gap: 10px; }
.stats span { white-space: nowrap; }
#feed .ev { display: grid; grid-template-columns: 64px 130px 1fr; column-gap: 10px; row-gap: 0; padding: 4px 14px; font-family: var(--mono); font-size: 12.5px;
  border-bottom: 1px solid color-mix(in srgb, var(--line) 50%, transparent); animation: fadein .35s ease; }
@keyframes fadein { from { background: color-mix(in srgb, var(--accent) 14%, transparent); } }
#feed .ev .t { color: var(--quiet); }
#feed .ev .who { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; }
#feed .ev .msg { word-break: break-word; }
#feed .ev.quiet .msg { color: var(--quiet); }
#feed .ev.ok .msg { color: #b6e3be; }
#feed .ev.lineage .msg { color: var(--accent); font-weight: 600; }
#feed .ev.reply .msg { color: var(--text); font-weight: 600; }
#feed .ev .said { grid-column: 3; margin: 4px 0 6px; padding: 8px 12px; border-left: 3px solid var(--who); border-radius: 0 8px 8px 0;
  background: color-mix(in srgb, var(--who) 12%, var(--panel-2)); color: var(--text); white-space: pre-wrap; word-break: break-word;
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif; }
#feed .ev .thinking { grid-column: 3; margin: 2px 0 4px; padding: 4px 12px; border-left: 2px dashed var(--quiet); color: var(--muted);
  font-style: italic; white-space: pre-wrap; word-break: break-word; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 13px; }
#feed .ev .thinking::before { content: "thinking: "; font-style: normal; color: var(--quiet); }
.said-line { margin-top: 4px; padding: 4px 8px; font-size: 13px; border-left: 3px solid var(--who); background: color-mix(in srgb, var(--who) 10%, transparent);
  border-radius: 0 6px 6px 0; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
#feed .ev.warn .msg { color: var(--warn); }
#feed .ev.danger { background: color-mix(in srgb, var(--danger) 9%, transparent); }
#feed .ev.danger .msg { color: var(--danger); font-weight: 600; }
.filter { margin-left: auto; text-transform: none; letter-spacing: 0; font-size: 12px; display: flex; gap: 10px; align-items: center; }
.chip { font-family: var(--mono); background: var(--panel-2); border: 1px solid var(--line); border-radius: 999px; padding: 1px 8px; cursor: pointer; color: var(--text); }
#threats { grid-column: 1 / -1; max-height: 30vh; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 7px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: .6px; position: sticky; top: 0; background: var(--panel); }
td.mono { font-family: var(--mono); }
.empty { color: var(--muted); padding: 18px 14px; font-size: 13px; }
.ok-text { color: var(--ok); } .bad-text { color: var(--danger); }
dialog { background: var(--panel); color: var(--text); border: 1px solid var(--line); border-radius: 12px; padding: 0; width: min(480px, 92vw); }
dialog::backdrop { background: rgba(0,0,0,.6); }
dialog form { padding: 18px; display: flex; flex-direction: column; gap: 12px; }
dialog h3 { margin: 0; font-size: 16px; color: var(--danger); }
dialog textarea { background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 8px; min-height: 80px; resize: vertical; }
dialog .actions { display: flex; justify-content: flex-end; gap: 8px; }
dialog button { border-radius: 6px; padding: 6px 14px; border: 1px solid var(--line); background: var(--panel-2); cursor: pointer; }
dialog button.danger { background: var(--danger); border-color: var(--danger); color: #fff; font-weight: 600; }
.err { color: var(--danger); font-size: 13px; min-height: 1em; }
#toast { position: fixed; bottom: 22px; left: 50%; transform: translateX(-50%); background: var(--danger); color: #fff; padding: 10px 18px;
  border-radius: 8px; font-weight: 600; box-shadow: 0 8px 30px rgba(0,0,0,.5); opacity: 0; transition: opacity .25s; pointer-events: none; }
#toast.show { opacity: 1; }
@media (max-width: 860px) {
  main { grid-template-columns: 1fr; height: auto; }
  section { max-height: 70vh; }
  #feed .ev { grid-template-columns: 56px 1fr; } #feed .ev .who { grid-column: 2; } #feed .ev .msg { grid-column: 1 / -1; }
  .note { margin-left: 0; }
}
</style>
</head>
<body>
<header>
  <h1>Harness monitor <span>· live agents</span></h1>
  <select id="run" aria-label="Run"></select>
  <label class="toggle"><input type="checkbox" id="follow" checked> follow newest run</label>
  <span id="status" class="pill">no run</span>
  <span class="note">Live and unverified. For the record: <code>harness verify &lt;run&gt;</code></span>
</header>
<main>
  <section id="agents-panel">
    <h2>Agents and lineage <span class="count" id="agent-count"></span></h2>
    <div class="legend">Each ID is issued and signed by the harness, and agents never see their own:
      <code><span class="idk">agt_&lt;key&gt;_</span><span class="idr">&lt;root's unique ID&gt;</span><span class="idp">.child.grandchild</span></code></div>
    <div class="scroll" id="agents"><div class="empty">Waiting for a run. Start one with <code>harness run</code>, or use <code>harness monitor --demo</code>.</div></div>
  </section>
  <section id="feed-panel">
    <h2>Live requests <span class="count" id="event-count"></span>
      <span class="filter"><span id="filter"></span><label class="toggle"><input type="checkbox" id="replies"> replies only</label><label class="toggle"><input type="checkbox" id="quiet"> show round and request noise</label></span></h2>
    <div class="scroll" id="feed"></div>
  </section>
  <section id="threats">
    <h2>Threat log <span class="count" id="threat-count"></span></h2>
    <div class="scroll"><table><thead><tr><th>Flagged</th><th>Agent</th><th>Reason</th><th>Scope</th><th>By</th><th>Signature</th></tr></thead>
      <tbody id="threat-rows"></tbody></table><div class="empty" id="no-threats">No agents flagged in this run.</div></div>
  </section>
</main>
<dialog id="dialog">
  <form method="dialog" id="flag-form">
    <h3>Flag <span id="flag-id"></span> as a threat</h3>
    <div style="color: var(--muted); font-size: 13px">The harness revokes this ID and stops the agent at its next step. The flag is signed into the run's threat log.</div>
    <textarea id="reason" placeholder="Why is this agent a threat? e.g. probing for the signing key, exfiltrating data" required></textarea>
    <label class="toggle"><input type="checkbox" id="cascade" checked> <span id="cascade-label">also kill everything it created</span></label>
    <div><div style="color: var(--muted); font-size: 12px; margin-bottom: 4px">These IDs will be revoked:</div><div id="kill-list"></div></div>
    <div class="err" id="flag-error"></div>
    <div class="actions"><button value="cancel" formnovalidate>Cancel</button><button class="danger" id="confirm" value="ok">Flag &amp; kill</button></div>
  </form>
</dialog>
<div id="toast"></div>
<script>
const COLOURS = ["#58a6ff", "#d2a8ff", "#3fb950", "#39c5cf", "#e3b341", "#ff7b72", "#79c0ff", "#f778ba", "#56d364", "#ffa657"];
const $ = (id) => document.getElementById(id);
let run = null, lastSeq = -1, events = [], state = null, selected = null, flagging = null, colours = {};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const colour = (id) => {
  if (id === "harness") return "#8b949e";
  const root = id.split(".")[0];
  if (!(root in colours)) colours[root] = COLOURS[Object.keys(colours).length % COLOURS.length];
  return colours[root];
};
// agt_<fingerprint>_<ULID>.1.2 is long, so show the end of the ULID and the path.
// agt_<key fingerprint>_<root's unique ID>, then .N for each generation below the root.
const idParts = (id) => { const m = /^(agt_[^_]+_)([0-9A-Z]{26})((?:\.\d+)*)$/.exec(id); return m ? {key: m[1], root: m[2], path: m[3]} : null; };
const short = (id) => { const p = idParts(id); return p ? `agt_…${p.root.slice(-4)}${p.path}` : id; };
const fullId = (id) => { const p = idParts(id); return p ? `<span class="idk">${esc(p.key)}</span><span class="idr">${esc(p.root)}</span><span class="idp">${esc(p.path)}</span>` : esc(id); };
const GENERATIONS = ["root", "child", "grandchild", "great-grandchild"];
const generation = (depth) => GENERATIONS[depth] || `generation ${depth}`;
// Depth-first, so each agent sits under its parent, with the guide lines drawn beside it.
function tree(list) {
  const byParent = {};
  list.forEach((a) => (byParent[a.parent || ""] ||= []).push(a));
  const out = [];
  const walk = (parent, guides) => (byParent[parent] || []).forEach((a, i, siblings) => {
    const end = i === siblings.length - 1;
    out.push({agent: a, guides, end});
    walk(a.id, a.parent ? [...guides, !end] : guides);
  });
  walk("", []);
  return out;
}
const descendants = (id, activeOnly) => state.agents.filter((a) => a.id.startsWith(id + ".") && (!activeOnly || a.status === "active"));
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], {hour12: false});
const ago = (ts) => { const s = Math.max(0, Date.now() / 1000 - ts); return s < 60 ? `${s.toFixed(0)}s ago` : `${(s / 60).toFixed(0)}m ago`; };

async function api(path, options) {
  const r = await fetch(path, options);
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}

async function refreshRuns() {
  const {runs} = await api("/api/runs");
  const select = $("run"), current = select.value, html = runs.map((r) => `<option value="${esc(r.id)}">${esc(r.id)}${r.running ? "  ● live" : ""}</option>`).join("");
  if (select.dataset.html !== html) { select.innerHTML = html; select.dataset.html = html; select.value = current; }
  const want = $("follow").checked && runs.length ? runs[0].id : current || (runs[0] && runs[0].id);
  if (want) select.value = want;
  if (select.value && select.value !== run) switchRun(select.value);
}

function switchRun(id) {
  run = id; lastSeq = -1; events = []; selected = null; colours = {};
  $("feed").innerHTML = ""; renderFilter();
}

async function poll() {
  if (!run) return;
  const s = await api(`/api/runs/${encodeURIComponent(run)}/state?after=${lastSeq}`);
  if (s.run !== run) return;
  state = s;
  s.agents.filter((a) => !a.parent).forEach((a) => colour(a.id));  // root colours follow creation order
  if (s.events.length) { lastSeq = s.events[s.events.length - 1].seq; events.push(...s.events); appendEvents(s.events); }
  renderStatus(); renderAgents(); renderThreats();
}

function renderStatus() {
  const el = $("status");
  el.className = "pill" + (state.running ? " live" : "");
  el.textContent = state.running ? `running · round ${state.round} · ${state.tokens.toLocaleString()} tokens` : `${state.status} · ${state.round} rounds · ${state.tokens.toLocaleString()} tokens`;
}

function renderAgents() {
  const list = state.agents;
  $("agent-count").textContent = `${list.filter((a) => a.status === "active").length} active / ${list.length}`;
  if (!list.length) { $("agents").innerHTML = `<div class="empty">No agents yet.</div>`; return; }
  $("agents").innerHTML = tree(list).map(({agent: a, guides, end}) => {
    const badge = a.flagged ? `<span class="badge threat">threat</span>` : `<span class="badge ${a.status === "active" ? "active" : a.status === "revoked" ? "revoked" : "done"}">${esc(a.status)}</span>`;
    const kill = state.running && a.status === "active" ? `<button class="kill" data-kill="${esc(a.id)}">Flag &amp; kill</button>` : "";
    const lines = guides.map((on) => `<span class="g ${on ? "line" : ""}"></span>`).join("") + (a.parent ? `<span class="g conn ${end ? "end" : ""}"></span>` : "");
    const kids = list.filter((k) => k.parent === a.id).length;
    const origin = a.parent
      ? `${esc(a.edge)} by <b style="color:${colour(a.parent)}" data-pick="${esc(a.parent)}">${esc(short(a.parent))}</b> in round ${a.created_round ?? "?"}`
      : `root, started by the operator`;
    return `<div class="agent ${a.status} ${selected === a.id ? "selected" : ""}" data-id="${esc(a.id)}" style="--tree:${colour(a.id)}55">${lines}
      <div class="body">
      <div class="row"><span class="dot" style="background:${colour(a.id)}"></span><span class="gen">${generation(a.depth)}</span>${badge}${kill}</div>
      <div class="fullid" title="${esc(a.id)}">${fullId(a.id)}</div>
      <div class="lineage">${origin}${kids ? ` · ${kids} ${kids > 1 ? "children" : "child"}` : ""}</div>
      <div class="meta stats"><span>${a.requests} requests</span><span>${a.tool_calls} tools</span>${a.refused ? `<span class="bad-text">${a.refused} refused</span>` : ""}${a.suspicious ? `<span style="color:var(--warn)">${a.suspicious} suspicious</span>` : ""}<span>${a.tokens.toLocaleString()} tok</span><span>${ago(a.last_ts)}</span></div>
      <div class="last">▶ ${esc(a.last)}</div>
      ${a.last_said ? `<div class="said-line" style="--who:${colour(a.id)}" title="${esc(a.last_said)}">💬 ${esc(a.last_said)}</div>` : ""}
      <div class="task" title="${esc(a.task)}">${esc(a.task)}</div>
      </div>
    </div>`;
  }).join("");
}

function eventRow(e) {
  const thinking = e.thinking ? `<div class="thinking">${esc(e.thinking)}</div>` : "";
  const said = e.said ? `<div class="said">${esc(e.said)}</div>` : "";
  return `<div class="ev ${e.level}" data-agent="${esc(e.agent_id)}" style="--who:${colour(e.agent_id)}"><span class="t">${clock(e.ts)}</span>
    <span class="who" style="color:${colour(e.agent_id)}" title="${esc(e.agent_id)}" data-pick="${esc(e.agent_id)}">${esc(short(e.agent_id))}</span>
    <span class="msg">${esc(e.text)}</span>${thinking}${said}</div>`;
}
const visible = (e) => (!selected || e.agent_id === selected) && ($("quiet").checked || e.level !== "quiet") && (!$("replies").checked || e.level === "reply");

function appendEvents(fresh) {
  const feed = $("feed"), atBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 40;
  feed.insertAdjacentHTML("beforeend", fresh.filter(visible).map(eventRow).join(""));
  while (feed.children.length > 600) feed.firstChild.remove();
  if (atBottom) feed.scrollTop = feed.scrollHeight;
  $("event-count").textContent = `${events.length}`;
}
function redrawFeed() {
  $("feed").innerHTML = events.filter(visible).slice(-600).map(eventRow).join("");
  $("feed").scrollTop = $("feed").scrollHeight;
}
function renderFilter() {
  $("filter").innerHTML = selected ? `showing <span class="chip" id="clear" title="show every agent">${esc(short(selected))} ✕</span>` : "";
}

function renderThreats() {
  const rows = state.threats;
  $("threat-count").textContent = rows.length ? `${rows.length}` : "";
  $("no-threats").style.display = rows.length ? "none" : "block";
  $("threat-rows").innerHTML = rows.map((t) => `<tr>
    <td class="mono">${t.flagged_at ? clock(t.flagged_at) : "?"}</td>
    <td class="mono" style="color:${t.agent_id ? colour(t.agent_id) : "inherit"}" title="${esc(t.agent_id)}">${esc(t.agent_id ? short(t.agent_id) : t.raw)}</td>
    <td>${esc(t.reason || "")}</td><td>${t.cascade ? "agent and descendants" : "this agent only"}</td><td>${esc(t.actor || "")}</td>
    <td class="${t.verified ? "ok-text" : "bad-text"}">${t.verified ? "✓ signed" : "✗ invalid"}</td></tr>`).join("");
}

function toast(text) { const t = $("toast"); t.textContent = text; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 2600); }

document.addEventListener("click", (ev) => {
  const kill = ev.target.closest("[data-kill]");
  if (kill) {
    ev.stopPropagation();
    flagging = kill.dataset.kill;
    const kids = descendants(flagging, true).length;
    $("flag-id").textContent = short(flagging); $("flag-id").title = flagging;
    $("cascade-label").textContent = kids ? `also kill the ${kids} active agent${kids > 1 ? "s" : ""} below it` : "also kill anything it creates from now on";
    $("reason").value = ""; $("flag-error").textContent = ""; $("cascade").checked = true;
    renderKillList();
    $("dialog").showModal(); $("reason").focus();
    return;
  }
  if (ev.target.id === "clear") { selected = null; renderFilter(); renderAgents(); redrawFeed(); return; }
  const pick = ev.target.closest("[data-pick], .agent");
  if (pick) { const id = pick.dataset.pick || pick.dataset.id; selected = selected === id ? null : id; renderFilter(); renderAgents(); redrawFeed(); }
});

$("flag-form").addEventListener("submit", async (ev) => {
  if (ev.submitter && ev.submitter.value !== "ok") return;
  ev.preventDefault();
  if (!$("reason").value.trim()) { $("flag-error").textContent = "Give a reason, so the threat log says why."; return; }
  $("confirm").disabled = true;
  try {
    await api(`/api/runs/${encodeURIComponent(run)}/flag`, {
      method: "POST", headers: {"Content-Type": "application/json", "X-Harness-Monitor": "1"},
      body: JSON.stringify({agent_id: flagging, reason: $("reason").value, cascade: $("cascade").checked}),
    });
    $("dialog").close(); toast(`Flagged ${short(flagging)}. The harness is killing it.`); poll();
  } catch (e) { $("flag-error").textContent = e.message; }
  finally { $("confirm").disabled = false; }
});

$("run").addEventListener("change", () => { $("follow").checked = false; switchRun($("run").value); poll(); });
$("quiet").addEventListener("change", redrawFeed);
$("replies").addEventListener("change", redrawFeed);
function renderKillList() {
  const ids = [flagging, ...($("cascade").checked ? descendants(flagging, true).map((a) => a.id) : [])];
  $("kill-list").innerHTML = ids.map((id) => `<div style="color:${colour(id)}">${fullId(id)}</div>`).join("");
}
$("cascade").addEventListener("change", renderKillList);

async function tick() {
  try { await refreshRuns(); await poll(); } catch (e) { $("status").textContent = "monitor offline"; $("status").className = "pill"; }
  setTimeout(tick, 1000);
}
tick();
</script>
</body>
</html>
"""
