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
[hidden] { display: none !important; }
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
button.start { background: var(--accent); color: #0d1117; border: 0; border-radius: 6px; padding: 6px 14px; font-weight: 700; cursor: pointer; }
button.start:hover { filter: brightness(1.1); }
.fields { display: grid; grid-template-columns: 1fr 140px 110px; gap: 10px; }
.fields label { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--muted); }
.fields input { background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 6px 8px; font-family: var(--mono); font-size: 12.5px; }
.hint { color: var(--muted); font-size: 12px; }
.hint code { font-family: var(--mono); color: var(--text); }
#toast.info { background: var(--accent); color: #0d1117; }
button.trace-btn { background: transparent; border: 1px solid var(--line); color: var(--accent); border-radius: 6px; padding: 3px 9px; font-size: 12px; cursor: pointer; }
button.trace-btn:hover { border-color: var(--accent); }
#drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(760px, 96vw); background: var(--panel); border-left: 1px solid var(--line);
  box-shadow: -20px 0 50px rgba(0,0,0,.45); transform: translateX(105%); transition: transform .2s ease; z-index: 5; display: flex; flex-direction: column; }
#drawer.open { transform: none; }
#drawer header { position: static; }
#drawer .close { margin-left: auto; background: transparent; border: 1px solid var(--line); border-radius: 6px; padding: 4px 10px; cursor: pointer; }
#trace { overflow-y: auto; padding: 14px 18px 40px; }
.tsec { margin-bottom: 14px; }
.tsec h4 { margin: 0 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: .7px; color: var(--muted); }
.kv { display: grid; grid-template-columns: 110px 1fr; gap: 4px 12px; font-size: 13px; }
.kv > span:nth-child(odd) { color: var(--muted); }
pre.block { margin: 4px 0 0; padding: 8px 10px; background: var(--bg); border: 1px solid var(--line); border-radius: 8px; white-space: pre-wrap;
  word-break: break-word; font: 12.5px/1.45 var(--mono); max-height: 360px; overflow-y: auto; }
.tool-chip { display: inline-block; font-family: var(--mono); font-size: 12px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 4px; padding: 0 6px; margin: 0 4px 4px 0; }
.step { border-left: 2px solid var(--line); padding: 2px 0 10px 14px; margin-left: 4px; position: relative; }
.step::before { content: ""; position: absolute; left: -6px; top: 6px; width: 10px; height: 10px; border-radius: 50%; background: var(--line); }
.step.reply::before { background: var(--who); } .step.danger::before { background: var(--danger); } .step.prompt::before { background: var(--text); }
.step .head { font-size: 12.5px; color: var(--muted); }
.step .head b { color: var(--text); }
.step.danger .head b { color: var(--danger); }
.step .said { margin-top: 4px; padding: 8px 12px; border-left: 3px solid var(--who); border-radius: 0 8px 8px 0; background: color-mix(in srgb, var(--who) 12%, var(--panel-2)); white-space: pre-wrap; word-break: break-word; }
#feed-panel h2 { gap: 4px; }
.tab { background: transparent; border: 0; border-bottom: 2px solid transparent; color: var(--muted); font: inherit; text-transform: uppercase;
  letter-spacing: .8px; font-size: 12px; padding: 2px 8px 4px; cursor: pointer; }
.tab.on { color: var(--text); border-bottom-color: var(--accent); }
#convo { padding: 14px 18px; }
.c { margin: 0 0 8px; }
.cwho { font-size: 12px; font-weight: 700; margin-bottom: 3px; }
.cname { cursor: pointer; font-weight: 700; }
.cname:hover { text-decoration: underline; }
.bubble { display: inline-block; max-width: min(760px, 100%); padding: 9px 13px; border-radius: 4px 14px 14px 14px; white-space: pre-wrap; word-break: break-word;
  background: color-mix(in srgb, var(--who) 14%, var(--panel-2)); border: 1px solid color-mix(in srgb, var(--who) 35%, transparent); font-size: 14.5px; line-height: 1.5; }
.c.you { text-align: right; }
.c.you .bubble { background: color-mix(in srgb, var(--accent) 22%, var(--panel-2)); border-color: color-mix(in srgb, var(--accent) 45%, transparent); border-radius: 14px 4px 14px 14px; text-align: left; }
.c.tool { font: 12.5px/1.5 var(--mono); color: var(--muted); }
.c.tool .res { color: #b6e3be; } .c.tool.bad .res { color: var(--warn); }
.c.spawn { padding: 8px 12px; border: 1px dashed color-mix(in srgb, var(--accent) 60%, transparent); border-radius: 10px; background: color-mix(in srgb, var(--accent) 7%, transparent); font-size: 13px; }
.c.spawn .sub { color: var(--muted); font-size: 12.5px; margin-top: 3px; white-space: pre-wrap; }
.c.msg { font-size: 13.5px; } .c.msg .content { color: var(--text); white-space: pre-wrap; }
.c.danger { color: var(--danger); font-weight: 600; font-size: 13.5px; }
.c.think { color: var(--muted); font-style: italic; font-size: 13px; white-space: pre-wrap; }
.c.end { color: var(--muted); font-size: 12.5px; }
.c.sep { text-align: center; color: var(--muted); font-size: 12px; margin: 14px 0; border-top: 1px solid var(--line); padding-top: 8px; }
#convo.focus .c { opacity: .28; transition: opacity .15s; }
#convo.focus .c.hl { opacity: 1; }
#convo.focus .c.hl .bubble { box-shadow: 0 0 0 2px var(--who); }
#convo.focus .c.hl:not(:has(.bubble)) { background: color-mix(in srgb, var(--who) 10%, transparent); border-radius: 6px; padding: 2px 6px; }
#convo .sel-note { position: sticky; top: -14px; z-index: 1; margin: -14px -18px 10px; padding: 6px 18px; background: var(--panel-2); border-bottom: 1px solid var(--line); font-size: 12.5px; color: var(--muted); }
#composer { border-top: 1px solid var(--line); padding: 10px 14px 12px; display: flex; flex-direction: column; gap: 8px; }
#composer[hidden] { display: none; }
#prompt { background: var(--bg); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; resize: vertical; font-size: 14px; line-height: 1.5; min-height: 64px; }
#prompt:focus { outline: none; border-color: var(--accent); }
#prompt:disabled { opacity: .55; }
.crow { display: flex; align-items: center; gap: 8px; }
.crow .hint { margin-right: auto; }
.hint a { color: var(--accent); }
#settings .fields { margin-bottom: 6px; }
#toast { position: fixed; bottom: 22px; left: 50%; transform: translateX(-50%); background: var(--danger); color: #fff; padding: 10px 18px;
  border-radius: 8px; font-weight: 600; box-shadow: 0 8px 30px rgba(0,0,0,.5); opacity: 0; transition: opacity .25s; pointer-events: none; }
#toast.show { opacity: 1; }
@media (max-width: 1500px) { .note { display: none; } }
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
  <button class="start" id="new-run">＋ New run</button>
  <select id="run" aria-label="Run"></select>
  <label class="toggle"><input type="checkbox" id="follow" checked> follow newest run</label>
  <span id="status" class="pill">no run</span>
  <span class="note">Live and unverified. For the record: <code>harness verify &lt;run&gt;</code></span>
</header>
<main>
  <section id="agents-panel">
    <h2>Agents and lineage <span class="count" id="agent-count"></span></h2>
    <div class="legend">Each ID is issued and signed by the harness, and agents never see their own:
      <code><span class="idk">agt_&lt;key&gt;_</span><span class="idr">&lt;unique ID&gt;</span></code>. IDs say nothing about lineage: who created whom comes from the signed ledger.</div>
    <div class="scroll" id="agents"><div class="empty">No run yet. Type a prompt on the right and press Enter, or start one with <code>harness run</code> in a terminal.</div></div>
  </section>
  <section id="feed-panel">
    <h2><button class="tab on" data-tab="convo">Conversation</button><button class="tab" data-tab="feed">All events <span class="count" id="event-count"></span></button>
      <span class="filter"><span id="filter"></span><span id="feed-filters" hidden style="display:flex;gap:10px"><label class="toggle"><input type="checkbox" id="replies"> replies only</label><label class="toggle"><input type="checkbox" id="quiet"> show round and request noise</label></span></span></h2>
    <div class="scroll" id="convo"><div class="empty" id="convo-empty">Press Enter below to give the agent its prompt. Its replies, tool calls and the helpers it spawns appear here, and the agents panel shows each one. Click a name for its full trace.</div></div>
    <div class="scroll" id="feed" hidden></div>
    <form id="composer">
      <textarea id="prompt" rows="4" placeholder="Give the agent a prompt…"></textarea>
      <div class="crow">
        <span class="hint" id="composer-hint">Enter to start · Shift+Enter for a new line · <a href="#" id="use-default">use the default prompt</a></span>
        <button type="button" class="trace-btn" id="settings-toggle">⚙ Settings</button>
        <button class="start" id="send">Start ▶</button>
      </div>
      <div id="settings" hidden>
        <div class="fields">
          <label>Model<input id="start-model"></label>
          <label>Token cap for the run<input id="start-tokens" type="number" min="1000" step="1000"></label>
          <label>Seconds per write<input id="start-pace" type="number" min="0" max="10" step="0.5"></label>
        </div>
        <div class="hint">The agent gets <code>write_line(text, notebook)</code>, <code>spawn_agent</code> and <code>send_message</code>. Up to 4 agents, 2 generations deep. <span id="start-cost"></span></div>
      </div>
      <div class="err" id="start-error"></div>
    </form>
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
<aside id="drawer" aria-label="Full trace">
  <header><h1 id="drawer-title">Full trace</h1><button class="close" id="drawer-close">Close ✕</button></header>
  <div id="trace"></div>
</aside>
<div id="toast"></div>
<script>
const COLOURS = ["#58a6ff", "#d2a8ff", "#3fb950", "#39c5cf", "#e3b341", "#ff7b72", "#79c0ff", "#f778ba", "#56d364", "#ffa657"];
const $ = (id) => document.getElementById(id);
let run = null, lastSeq = -1, events = [], state = null, selected = null, flagging = null, colours = {};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const colour = (id) => {
  if (id === "harness") return "#8b949e";
  if (!(id in colours)) colours[id] = COLOURS[Object.keys(colours).length % COLOURS.length];  // one colour per agent
  return colours[id];
};
// agt_<key fingerprint>_<ULID> is long, so show the end of the ULID. Every agent has its own ULID;
// only older runs add a .1.2 path after it, which is kept.
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
const agentById = (id) => state && state.agents.find((a) => a.id === id);
// Lineage comes from each agent's parent, as the ledger records it; IDs carry none.
const isUnder = (id, ancestor) => { for (let a = agentById(id); a && a.parent; a = agentById(a.parent)) if (a.parent === ancestor) return true; return false; };
const descendants = (id, activeOnly) => state.agents.filter((a) => isUnder(a.id, id) && (!activeOnly || a.status === "active"));
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
  if (composing) return;  // a blank page for a new prompt: don't jump back to an old run
  const want = $("follow").checked && runs.length ? runs[0].id : current || (runs[0] && runs[0].id);
  if (want) select.value = want;
  if (select.value && select.value !== run) switchRun(select.value);
}

function switchRun(id) {
  run = id; lastSeq = -1; events = []; selected = null; colours = {}; convoStarts = {}; youShown = false;
  $("feed").innerHTML = ""; $("convo").innerHTML = ""; renderFilter();
}

async function poll() {
  if (!run) return;
  const s = await api(`/api/runs/${encodeURIComponent(run)}/state?after=${lastSeq}`);
  if (s.run !== run) return;
  state = s;
  s.agents.forEach((a) => colour(a.id));  // colours follow creation order, so they don't change between refreshes
  if (s.events.length) { lastSeq = s.events[s.events.length - 1].seq; events.push(...s.events); appendEvents(s.events); }
  renderStatus(); renderAgents(); renderThreats(); composerState();
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
    const kill = (state.running && a.status === "active" ? `<button class="kill" data-kill="${esc(a.id)}">Flag &amp; kill</button>` : "")
      + `<button class="trace-btn" data-trace="${esc(a.id)}" style="${state.running && a.status === "active" ? "" : "margin-left:auto"}">Full trace</button>`;
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

let convoStarts = {}, youShown = false;
const rootAgent = () => state && state.agents.find((a) => !a.parent);
function speaker(id) {
  const r = rootAgent();
  if (id === "harness") return "harness";
  if (r && id === r.id) return "agent";
  if (r && isUnder(id, r.id)) return `helper ${agentById(id).path}`;
  return short(id);
}
function convoRow(e) {
  const who = e.agent_id, depth = (agentById(who) || {}).depth || 0;
  const name = (id) => `<span class="cname" style="color:${colour(id)}" data-pick="${esc(id)}" title="Highlight ${esc(id)}">${esc(speaker(id))}</span>`;
  const involved = [who, ...(e.to || []), ...(e.child ? [e.child] : [])].join(" ");
  const row = (cls, inner) => `<div class="c ${cls}" data-agents="${esc(involved)}" style="--who:${colour(who)};margin-left:${depth * 30}px">${inner}</div>`;
  if (e.type === "model.response") {
    return (e.thinking ? row("think", `${name(who)} is thinking: ${esc(e.thinking)}`) : "")
      + (e.said ? row("", `<div class="cwho">${name(who)}</div><div class="bubble">${esc(e.said)}</div>`) : "");
  }
  if (e.type === "action.start") { convoStarts[e.call_id] = e.call; return ""; }
  if (e.type === "action.end" && e.level === "lineage") {
    const child = e.child && state.agents.find((a) => a.id === e.child);
    if (!child) return row("spawn", `⑂ ${name(who)} ${esc(e.text)}`);
    return row("spawn", `⑂ ${name(who)} spawned ${name(child.id)} <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">${esc(child.id)}</span>
      <div class="sub">task: ${esc(child.task)}</div><div class="sub">tools: ${esc(child.tools.join(", "))}</div>`);
  }
  if (e.type === "action.end") {
    if (e.tool === "send_message" && e.status === "ok") return "";
    const call = convoStarts[e.call_id] || e.tool;
    return row(`tool ${e.status === "ok" ? "" : "bad"}`, `· ${name(who)} ${esc(call)} <span class="res">→ ${esc(e.text.replace(/^◀ \S+ /, ""))}</span>`);
  }
  if (e.type === "message.sent") {
    if (who === "harness") return "";
    return row("msg", `✉ ${name(who)} → ${(e.to || []).map(name).join(", ")}: <span class="content">${esc(e.content)}</span>`);
  }
  if (e.type === "agent.end") {
    if (e.level === "danger") return row("danger", `☠ ${name(who)} was killed and has stopped`);
    return rootAgent() && who === rootAgent().id ? "" : row("end", `${name(who)} finished`);
  }
  if (e.type === "agent.revoked") return row("danger", `☠ ${name(who)}: ${esc(e.text.replace(/^☠ /, ""))}`);
  if (e.level === "danger" || e.level === "warn") return row("danger", `${name(who)} ${esc(e.text)}`);
  if (e.type === "run.end") return `<div class="c sep">${esc(e.text)}</div>`;
  return "";
}
function appendConvo(fresh) {
  const box = $("convo"), atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  const root = rootAgent();
  if (!youShown && root) {
    box.innerHTML = `<div class="c you" data-agents="${esc(root.id)}"><div class="cwho" style="color:var(--accent)">you</div><div class="bubble">${esc(root.task)}</div></div>`;
    youShown = true;
  }
  box.insertAdjacentHTML("beforeend", fresh.map(convoRow).join(""));
  highlight();
  if (atBottom) box.scrollTop = box.scrollHeight;
}
// Clicking an agent highlights everything it said, did or received, and dims the rest.
function highlight() {
  const box = $("convo");
  box.classList.toggle("focus", !!selected);
  box.querySelectorAll(".c[data-agents]").forEach((row) => row.classList.toggle("hl", !!selected && row.dataset.agents.split(" ").includes(selected)));
  const first = selected && box.querySelector(".c.hl");
  if (first && !highlight.scrolled) { first.scrollIntoView({block: "nearest"}); highlight.scrolled = true; }
}
function appendEvents(fresh) {
  appendConvo(fresh);
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
  $("filter").innerHTML = selected ? `highlighting <span class="chip" id="clear" title="clear" style="color:${colour(selected)}">${esc(speaker(selected))} ✕</span>` : "";
  highlight.scrolled = false;
  highlight();
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

function toast(text, kind = "") { const t = $("toast"); t.textContent = text; t.className = `show ${kind}`; setTimeout(() => t.classList.remove("show"), 2600); }

let defaults = null, composing = false;
function costHint() {
  const cap = Number($("start-tokens").value) || 0, model = $("start-model").value.trim();
  $("start-cost").textContent = model.endsWith("claude-haiku-5.5")
    ? `Claude Haiku 5.5 costs $0.10 per million input tokens and $0.50 per million output, and most tokens here are input, so a run that hits the ${cap.toLocaleString()} token cap costs about $${(cap * 0.11 / 1e6).toFixed(3)}.`
    : `The run stops at ${cap.toLocaleString()} tokens. Check this model's price with its provider.`;
}
async function loadDefaults() {
  defaults = await api("/api/defaults");
  $("prompt").value ||= defaults.task;
  $("start-model").value ||= defaults.model;
  $("start-tokens").value ||= defaults.max_tokens;
  $("start-pace").value ||= defaults.pace;
  costHint();
}
function composerState() {
  const busy = !!(state && state.busy);  // only a page-started run blocks the next one
  $("prompt").disabled = $("send").disabled = busy;
  $("prompt").placeholder = busy ? "The agents are working. Flag one on the left to stop it, or wait for the run to end." : "Give the agent a prompt…";
  $("composer-hint").firstChild.textContent = busy ? "A run you started is still going · " : "Enter to start · Shift+Enter for a new line · ";
}
async function startRun() {
  const task = $("prompt").value.trim();
  if (!task) { $("start-error").textContent = "Type a prompt first."; return; }
  $("send").disabled = true; $("start-error").textContent = "Starting…";
  try {
    const {run: id} = await api("/api/start", {
      method: "POST", headers: {"Content-Type": "application/json", "X-Harness-Monitor": "1"},
      body: JSON.stringify({task, model: $("start-model").value, max_tokens: Number($("start-tokens").value), pace: Number($("start-pace").value)}),
    });
    composing = false; $("start-error").textContent = ""; $("prompt").value = ""; $("follow").checked = true; switchRun(id); showTab("convo"); poll();
  } catch (e) { $("start-error").textContent = e.message; $("send").disabled = false; }
}
$("composer").addEventListener("submit", (ev) => { ev.preventDefault(); startRun(); });
$("prompt").addEventListener("keydown", (ev) => { if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); startRun(); } });
$("use-default").addEventListener("click", (ev) => { ev.preventDefault(); $("prompt").value = defaults.task; $("prompt").focus(); });
$("settings-toggle").addEventListener("click", () => { $("settings").hidden = !$("settings").hidden; });
$("start-tokens").addEventListener("input", costHint);
$("start-model").addEventListener("input", costHint);
$("new-run").addEventListener("click", () => {
  if (state && state.busy) { toast("Wait for the run you started to end, or flag its agents, before starting another.", "info"); return; }
  composing = true; $("follow").checked = false; run = null; state = null; youShown = false; showTab("convo");
  $("convo").innerHTML = `<div class="empty">Press Enter below to give the agent its prompt.</div>`;
  $("agents").innerHTML = ""; $("threat-rows").innerHTML = "";
  $("prompt").value ||= defaults ? defaults.task : ""; composerState(); $("prompt").focus();
});
function showTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("on", t.dataset.tab === name));
  $("convo").hidden = $("composer").hidden = name !== "convo";
  $("feed").hidden = $("feed-filters").hidden = name !== "feed";
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showTab(t.dataset.tab)));
loadDefaults().then(() => $("prompt").focus());

let tracing = null;
const pretty = (v) => { if (typeof v === "string") { try { return JSON.stringify(JSON.parse(v), null, 2); } catch { return v; } } return JSON.stringify(v, null, 2); };
function step(cls, who, head, body = "") {
  return `<div class="step ${cls}" style="--who:${colour(who)}"><div class="head">${head}</div>${body}</div>`;
}
function renderTrace(t) {
  const c = t.config || {}, me = t.id;
  $("drawer-title").innerHTML = `<span style="color:${colour(me)}">${esc(generation(t.depth || 0))}</span> <span style="font-family:var(--mono);font-size:13px">${fullId(me)}</span>`;
  const origin = t.parent ? `${esc(t.edge)} by <span style="color:${colour(t.parent)};font-family:var(--mono)">${fullId(t.parent)}</span> in round ${t.created_round}` : "root, started by the operator";
  let html = `<div class="tsec"><h4>Created</h4><div class="kv">
    <span>how</span><span>${origin}</span>
    <span>model</span><span style="font-family:var(--mono)">${esc(c.model)}</span>
    <span>tools</span><span>${(c.tools || []).map((x) => `<span class="tool-chip">${esc(x)}</span>`).join("") || "none"}</span>
    <span>config hash</span><span style="font-family:var(--mono);font-size:12px">${esc(t.config_hash)}</span>
    ${t.children.length ? `<span>children</span><span>${t.children.map((k) => `<a href="#" data-trace="${esc(k)}" style="color:${colour(k)};font-family:var(--mono)">${esc(short(k))}</a>`).join(" · ")}</span>` : ""}
  </div></div>
  <div class="tsec"><h4>System prompt</h4><pre class="block">${esc(c.system_prompt)}</pre></div>
  <div class="tsec"><h4>Task</h4><pre class="block">${esc(t.task)}</pre></div>
  ${c.memory ? `<div class="tsec"><h4>Memory</h4><pre class="block">${esc(c.memory)}</pre></div>` : ""}
  ${t.revocations.map((r) => `<div class="tsec"><h4 style="color:var(--danger)">Revoked</h4><div>${esc(r.of === me ? "This agent" : "Its ancestor " + short(r.of))} was revoked by ${esc(r.by)} in round ${r.round}: ${esc(r.reason)}</div></div>`).join("")}
  <div class="tsec"><h4>Every step, in order</h4>`;
  for (const s of t.steps) {
    const p = s.payload, at = `<span style="font-family:var(--mono)">${clock(s.ts)} · round ${s.round}</span>`;
    if (s.type === "model.request") {
      for (const part of p.parts) {
        if (part.part_kind === "user-prompt") html += step("prompt", me, `${at} · <b>prompt to the model</b>`, `<pre class="block">${esc(part.content)}</pre>`);
        else if (part.part_kind === "tool-return") continue;  // the same text as the "harness ran" step above it
        else html += step("", me, `${at} · <b>${esc(part.part_kind)}</b>`, `<pre class="block">${esc(pretty(part.content))}</pre>`);
      }
    } else if (s.type === "model.response") {
      const tokens = (p.input_tokens || 0) + (p.output_tokens || 0);
      for (const part of p.parts) {
        if (part.part_kind === "thinking") html += step("", me, `${at} · <b>model thinking</b>`, `<pre class="block" style="font-style:italic">${esc(part.content)}</pre>`);
        else if (part.part_kind === "text") html += step("reply", me, `${at} · <b>model replied</b> · ${tokens.toLocaleString()} tokens · ${esc(p.model || "")}`, `<div class="said">${esc(part.content)}</div>`);
        else if (part.part_kind === "tool-call") html += step("reply", me, `${at} · <b>model calls ${esc(part.tool_name)}</b> · ${tokens.toLocaleString()} tokens`, `<pre class="block">${esc(pretty(part.args))}</pre>`);
      }
    } else if (s.type === "action.end") {
      const ok = p.status === "ok";
      html += step(ok ? "" : "danger", me, `${at} · harness ran <b>${esc(p.tool)}</b>: ${esc(p.status)}`, `<pre class="block">${esc(pretty(ok ? p.result : p.reason || p.message || p.error || ""))}</pre>`);
    } else if (s.type === "action.refused") {
      html += step("danger", me, `${at} · <b>refused ${esc(p.tool || p.kind)}</b>: ${esc(p.reason)}`);
    } else if (s.type === "message.sent") {
      const from = p.from || s.agent_id;
      html += step("", me, `${at} · <b>message</b> ${from === me ? "to " + p.to.map(short).join(", ") : "from " + short(from)}`, `<pre class="block">${esc(p.content)}</pre>`);
    } else if (s.type === "agent.revoked") {
      html += step("danger", me, `${at} · <b>killed</b>: ${esc(p.reason || "revoked")}`);
    } else if (s.type === "agent.end") {
      html += step(p.status === "revoked" ? "danger" : "", me, `${at} · <b>ended: ${esc(p.status)}</b>`, p.output ? `<pre class="block">${esc(p.output)}</pre>` : "");
    } else if (s.type === "model.error" && p.error !== "cancelled") {
      html += step("danger", me, `${at} · <b>model error</b>: ${esc(p.error)}`, `<pre class="block">${esc(p.message || "")}</pre>`);
    }
  }
  const box = $("trace"), first = !box.innerHTML, atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  box.innerHTML = html + `</div>`;
  if (first) box.scrollTop = 0;  // open at how the agent was created
  else if (atBottom) box.scrollTop = box.scrollHeight;
}
async function refreshTrace() {
  if (!tracing || !run) return;
  try { renderTrace(await api(`/api/runs/${encodeURIComponent(run)}/agents/${encodeURIComponent(tracing)}/trace`)); } catch (e) { $("trace").textContent = e.message; }
}
function openTrace(id) { tracing = id; $("drawer").classList.add("open"); $("trace").innerHTML = ""; refreshTrace(); }
$("drawer-close").addEventListener("click", () => { tracing = null; $("drawer").classList.remove("open"); });
document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && tracing) $("drawer-close").click(); });
setInterval(() => { if (tracing && state && state.running) refreshTrace(); }, 1500);

document.addEventListener("click", (ev) => {
  const traceBtn = ev.target.closest("[data-trace]");
  if (traceBtn) { ev.preventDefault(); ev.stopPropagation(); openTrace(traceBtn.dataset.trace); return; }
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

$("run").addEventListener("change", () => { composing = false; $("follow").checked = false; switchRun($("run").value); poll(); });
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
if (location.hash === "#new") $("prompt").focus();
const traceHash = /^#trace=(.+)$/.exec(location.hash);  // e.g. #trace=agt_… opens that agent's trace once it exists
if (traceHash) setTimeout(() => openTrace(decodeURIComponent(traceHash[1])), 1500);
const selectHash = /^#select=(.+)$/.exec(location.hash);  // e.g. #select=agt_… highlights that agent
if (selectHash) setTimeout(() => { selected = decodeURIComponent(selectHash[1]); renderFilter(); renderAgents(); redrawFeed(); }, 1500);  // a link that opens straight to New run
</script>
</body>
</html>
"""
