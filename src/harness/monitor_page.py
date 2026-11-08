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
  --ok: #3fb950; --ice: #56d4f5; --warn: #d29922; --danger: #f85149; --accent: #58a6ff; --quiet: #6e7681;
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
select { background: var(--panel-2); border: 1px solid var(--line); border-radius: 6px; padding: 5px 8px; font-family: var(--mono); font-size: 12px; max-width: 250px; }
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
button.twisty { background: var(--panel-2); border: 1px solid var(--line); color: var(--text); cursor: pointer; padding: 0; font-size: 14px;
  width: 20px; height: 20px; border-radius: 5px; line-height: 1; flex: none; display: inline-flex; align-items: center; justify-content: center; }
button.twisty:hover { border-color: var(--accent); color: var(--accent); }
.twisty-gap { display: inline-block; width: 20px; flex: none; }
#agents .agent .row { flex-wrap: wrap; row-gap: 4px; }
#agents .agent .row .gen { white-space: nowrap; }
#agents-panel > h2 .count { white-space: normal; }
header { row-gap: 8px; }
#agents .agent .row button { white-space: nowrap; }
#agents .agent .row button.freeze, #agents .agent .row button.kill, #agents .agent .row button.trace-btn { padding: 2px 7px; font-size: 11.5px; }
#agents .agent.done-chain { opacity: .45; filter: grayscale(.7); }
#agents .agent.done-chain:hover { opacity: .8; }
#agents .folded-note { font-size: 12px; color: var(--muted); margin-top: 4px; }
#agents-panel > h2 { display: flex; align-items: center; gap: 4px 8px; flex-wrap: wrap; }
.panel-tools { margin-left: auto; display: flex; gap: 6px; text-transform: none; letter-spacing: 0; }
.panel-tools button { white-space: nowrap; }
.panel-tools button { background: transparent; border: 1px solid var(--line); color: var(--muted); border-radius: 6px; padding: 1px 8px; font-size: 11px; cursor: pointer; }
.panel-tools button:hover { color: var(--text); border-color: var(--muted); }
#convo .c.folded { display: none !important; }
body.analysis-mode main { display: none; }
/* Demo mode: cues for recording a walkthrough */
#story { display: flex; gap: 6px; padding: 8px 18px; background: var(--panel); border-bottom: 1px solid var(--line); overflow-x: auto; }
#story .st { flex: 1 1 0; min-width: 120px; border: 1px solid var(--line); border-radius: 8px; padding: 6px 9px; background: var(--bg); }
#story .st .n { font-size: 11px; color: var(--muted); font-weight: 700; letter-spacing: .4px; }
#story .st .l { font-size: 13px; font-weight: 650; }
#story .st .h { font-size: 11.5px; color: var(--muted); }
#story .st.done { border-color: color-mix(in srgb, var(--ok) 55%, transparent); }
#story .st.done .n::after { content: " ✓"; color: var(--ok); }
#story .st.now { border-color: var(--accent); box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 35%, transparent); animation: nowpulse 1.6s infinite; }
@keyframes nowpulse { 50% { box-shadow: 0 0 0 5px color-mix(in srgb, var(--accent) 12%, transparent); } }
#anatomy { padding: 10px 14px; border-bottom: 1px solid var(--line); background: var(--panel-2); font-size: 12px; color: var(--muted); }
body:not(.demo) #anatomy { display: none; }
body.demo #agents-panel .legend { display: none; }
#anatomy .anat { display: flex; gap: 4px; flex-wrap: wrap; align-items: flex-start; margin: 6px 0; }
#anatomy .seg { display: flex; flex-direction: column; gap: 3px; max-width: 46%; }
#anatomy .seg code { font-family: var(--mono); font-size: 15px; padding: 3px 6px; border-radius: 5px; color: var(--text); }
#anatomy .seg span { font-size: 11px; line-height: 1.3; }
#anatomy .s-type { background: color-mix(in srgb, var(--quiet) 30%, transparent); }
#anatomy .s-key { background: color-mix(in srgb, var(--warn) 25%, transparent); }
#anatomy .s-time { background: color-mix(in srgb, var(--accent) 25%, transparent); }
#anatomy .s-rand { background: color-mix(in srgb, #d2a8ff 22%, transparent); }
.anatomy-line { font-size: 11.5px; color: var(--muted); margin-top: 2px; }
.anatomy-line b { color: var(--warn); font-family: var(--mono); font-weight: 600; }
button.copy-id { background: transparent; border: 1px solid var(--line); color: var(--muted); border-radius: 4px; padding: 0 5px; margin-left: 6px; font-size: 11px; cursor: pointer; vertical-align: 1px; }
button.copy-id:hover { color: var(--accent); border-color: var(--accent); }
.replaced-line { font-size: 12px; color: var(--ice); margin-top: 3px; }
#agents .agent.flash-kill { animation: flashkill 1s ease-in-out infinite; }
#agents .agent.flash-new { animation: flashnew 1s ease-in-out infinite; }
#agents .agent.flash-ice { animation: flashice 1s ease-in-out infinite; }
@keyframes flashkill { 50% { background: color-mix(in srgb, var(--danger) 22%, var(--panel)); } }
@keyframes flashnew { 50% { background: color-mix(in srgb, var(--ice) 22%, var(--panel)); } }
@keyframes flashice { 50% { background: color-mix(in srgb, var(--ice) 14%, var(--panel)); } }
#cue { position: fixed; top: 76px; left: 50%; transform: translate(-50%, -10px); z-index: 20; max-width: min(760px, 92vw); padding: 12px 20px; border-radius: 12px;
  font-size: 16px; font-weight: 600; box-shadow: 0 10px 40px rgba(0,0,0,.5); opacity: 0; pointer-events: none; transition: opacity .25s, transform .25s; background: var(--panel-2); border: 2px solid var(--accent); }
#cue.show { opacity: 1; transform: translate(-50%, 0); }
#cue.kill { border-color: var(--danger); } #cue.ice { border-color: var(--ice); } #cue.ok { border-color: var(--ok); }
#cue .sub { display: block; font-size: 13px; font-weight: 400; color: var(--muted); margin-top: 3px; }
#whois-form input { background: var(--panel-2); border: 1px solid var(--line); border-radius: 6px; padding: 5px 9px; font-family: var(--mono); font-size: 12px; width: 150px; }
#whois-form input:focus { width: 300px; }
#whois-form input:focus { outline: none; border-color: var(--accent); }
dialog#whois-dialog { width: min(720px, 94vw); }
#whois-body { padding: 18px; display: flex; flex-direction: column; gap: 10px; max-height: 80vh; overflow-y: auto; }
#whois-body .verdict-big { font-size: 22px; font-weight: 700; }
#whois-body .verdict-big.ok { color: var(--ok); } #whois-body .verdict-big.bad { color: var(--danger); } #whois-body .verdict-big.unk { color: var(--warn); }
#whois-body .wid { font-family: var(--mono); font-size: 13px; word-break: break-all; }
#whois-body .tree div { font-family: var(--mono); font-size: 12.5px; padding: 1px 0; word-break: break-all; }
#whois-body .tree .me { color: var(--accent); font-weight: 700; }
#whois-body .chk { color: var(--ok); } #whois-body .bad-text { color: var(--danger); }
#whois-body .actions { display: flex; justify-content: flex-end; }
#analysis { padding: 16px 18px 40px; max-width: 1400px; margin: 0 auto; }
#analysis .a-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
#analysis .a-head h2 { margin: 0; font-size: 18px; }
#analysis .a-head .run-id { font-family: var(--mono); font-size: 12px; color: var(--muted); }
#analysis .a-head .close-a { margin-left: auto; }
.a-badge { font-size: 12px; padding: 3px 10px; border-radius: 999px; border: 1px solid var(--line); font-family: var(--mono); }
.a-badge.good { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 50%, transparent); }
.a-badge.bad { color: var(--danger); border-color: color-mix(in srgb, var(--danger) 50%, transparent); }
.a-badge.live { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 50%, transparent); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 18px; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; }
.tile .k { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }
.tile .v { font-size: 22px; font-weight: 650; margin-top: 2px; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; line-height: 1.2; }
.tile .v .word { font-size: 17px; }
.tile .s { font-size: 12px; color: var(--muted); }
.tile.danger .v { color: var(--danger); } .tile.ice .v { color: var(--ice); } .tile.ok .v { color: var(--ok); } .tile.retired .v { color: #d2a8ff; }
.a-section { margin: 22px 0 10px; display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.a-section h3 { margin: 0; font-size: 13px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); }
.a-section .chips { display: flex; gap: 6px; margin-left: auto; flex-wrap: wrap; }
.a-section .chips button { background: transparent; border: 1px solid var(--line); color: var(--muted); border-radius: 999px; padding: 2px 10px; font-size: 12px; cursor: pointer; }
.a-section .chips button.on { color: var(--text); border-color: var(--accent); background: color-mix(in srgb, var(--accent) 14%, transparent); }
.answer { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.qa { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; min-width: 0; }
.qa .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin-bottom: 6px; }
.textbox { white-space: pre-wrap; font-size: 13px; line-height: 1.5; max-height: 220px; overflow-y: auto; overflow-wrap: anywhere; }
.textbox.empty { color: var(--quiet); font-style: italic; }
.kill-card { background: var(--panel); border: 1px solid color-mix(in srgb, var(--danger) 35%, var(--line)); border-radius: 10px; padding: 10px 14px; margin-bottom: 10px;
  display: grid; grid-template-columns: 1fr auto 1fr; gap: 14px; align-items: center; }
.kill-card .side { min-width: 0; font-size: 13px; }
.kill-card .side .t { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin-bottom: 4px; }
.kill-card .arrow { font-size: 20px; color: var(--ice); }
.kill-card .who { font-weight: 600; cursor: pointer; }
.kill-card .k-note { color: var(--muted); font-size: 12px; margin-top: 3px; }
.a-agent { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; margin-bottom: 10px; border-left: 4px solid var(--who); }
.a-agent.revoked { border-color: color-mix(in srgb, var(--danger) 45%, var(--line)); border-left-color: var(--danger); }
.a-agent.retired { border-left-color: #d2a8ff; }
.a-agent.orch { box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--ice) 45%, transparent); }
.a-agent .top { display: flex; align-items: center; gap: 8px; padding: 9px 12px; flex-wrap: wrap; border-bottom: 1px solid var(--line); }
.a-agent .top .nm { font-weight: 650; }
.a-agent .top .meta { margin-left: auto; font-size: 12px; color: var(--muted); font-family: var(--mono); }
.a-agent .cols { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); }
.a-agent .col { padding: 10px 12px; min-width: 0; }
.a-agent .col + .col { border-left: 1px solid var(--line); }
.a-agent .col .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin-bottom: 5px; }
.a-agent .col .lbl i { text-transform: none; font-style: normal; letter-spacing: 0; color: var(--quiet); }
.a-agent .why { padding: 7px 12px; font-size: 12.5px; border-top: 1px solid var(--line); }
.a-agent .why.kill { color: var(--danger); background: color-mix(in srgb, var(--danger) 7%, transparent); }
.a-agent .why.repl { color: var(--ice); background: color-mix(in srgb, var(--ice) 7%, transparent); }
.a-agent details { padding: 0 12px 10px; font-size: 12.5px; }
.a-agent details summary { cursor: pointer; color: var(--muted); }
.a-agent details .textbox { margin-top: 6px; border-left: 2px solid var(--line); padding-left: 10px; }
.badge.replacement { background: color-mix(in srgb, var(--ice) 20%, transparent); color: var(--ice); }
button.analysis-btn { background: var(--panel-2); border: 1px solid var(--line); color: var(--text); border-radius: 6px; padding: 5px 10px; cursor: pointer; font-size: 13px; }
button.analysis-btn:hover, button.analysis-btn.on { border-color: var(--accent); color: var(--accent); }
@media (max-width: 900px) { .answer, .a-agent .cols, .kill-card { grid-template-columns: 1fr; } .a-agent .col + .col { border-left: 0; border-top: 1px solid var(--line); } .kill-card .arrow { transform: rotate(90deg); } }
.id { font-family: var(--mono); font-size: 13px; font-weight: 600; }
.badge { font-size: 11px; padding: 1px 7px; border-radius: 4px; font-weight: 600; text-transform: uppercase; letter-spacing: .4px; }
.badge.active { background: color-mix(in srgb, var(--ok) 18%, transparent); color: var(--ok); }
.badge.revoked { background: color-mix(in srgb, var(--danger) 20%, transparent); color: var(--danger); }
.badge.threat { background: var(--danger); color: #fff; }
.badge.done { background: var(--panel-2); color: var(--muted); }
.badge.frozen { background: color-mix(in srgb, var(--ice) 22%, transparent); color: var(--ice); }
.badge.retired { background: color-mix(in srgb, #d2a8ff 20%, transparent); color: #d2a8ff; }
#agents .agent.frozen { box-shadow: inset 3px 0 var(--ice); }
button.freeze { background: transparent; border: 1px solid color-mix(in srgb, var(--ice) 60%, transparent); color: var(--ice);
  border-radius: 6px; padding: 2px 9px; font-size: 12px; cursor: pointer; }
button.freeze:hover { background: var(--ice); color: #0d1117; }
.verdicts { display: flex; gap: 6px; margin-top: 6px; }
.verdicts button { background: transparent; border: 1px solid var(--line); color: var(--muted); border-radius: 6px; padding: 2px 10px; font-size: 12px; cursor: pointer; }
.verdicts button.cleared.on { background: var(--ok); border-color: var(--ok); color: #0d1117; font-weight: 600; }
.verdicts button.threat.on { background: var(--danger); border-color: var(--danger); color: #fff; font-weight: 600; }
.verdicts button.cleared:hover { border-color: var(--ok); color: var(--ok); }
.verdicts button.threat:hover { border-color: var(--danger); color: var(--danger); }
#orchestrator { border-bottom: 1px solid var(--line); max-height: 60%; overflow-y: auto; flex-shrink: 0; }
#orchestrator .judge { display: flex; flex-direction: column; gap: 6px; margin: 8px 0; }
#orchestrator .jrow { display: grid; grid-template-columns: auto 1fr auto; gap: 8px; align-items: center; padding: 6px 8px; border-radius: 8px; background: var(--panel); border: 1px solid var(--line); }
#orchestrator .jrow .jtask { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#orchestrator .jrow .verdicts { margin: 0; }
#orchestrator .jrow.cleared { border-color: color-mix(in srgb, var(--ok) 55%, transparent); }
#orchestrator .jrow.threat { border-color: color-mix(in srgb, var(--danger) 55%, transparent); }
#orchestrator .actions { display: flex; gap: 8px; flex-wrap: wrap; }
#orchestrator button.clear-all { background: var(--ok); color: #0d1117; border: 0; border-radius: 6px; padding: 5px 12px; font-weight: 600; cursor: pointer; }
.verdicts button { color: var(--text) !important; }
#orchestrator .freeze-box { margin: 8px 10px; padding: 10px 12px; border: 1px solid color-mix(in srgb, var(--ice) 50%, transparent);
  border-radius: 10px; background: color-mix(in srgb, var(--ice) 7%, var(--panel)); font-size: 13px; }
#orchestrator .freeze-box h3 { margin: 0 0 4px; font-size: 13px; color: var(--ice); }
#orchestrator .plan { margin: 6px 0 8px; padding-left: 18px; color: var(--muted); }
#orchestrator .plan li { margin: 2px 0; }
#orchestrator button.resolve { background: var(--ice); color: #0d1117; border: 0; border-radius: 6px; padding: 5px 12px; font-weight: 600; cursor: pointer; }
#orchestrator button.resolve:disabled { opacity: .45; cursor: not-allowed; }
.c.orch { border-left: 3px solid var(--ice); padding-left: 10px; color: var(--muted); }
.c.orch .content { white-space: pre-wrap; display: block; margin-top: 4px; color: var(--text); }
dialog h3.ice { color: var(--ice); }
dialog button.ice { background: var(--ice); border-color: var(--ice); color: #0d1117; font-weight: 600; }
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
#convo.focus .c.out { display: none; }
#convo.focus.show-out .c.out { display: block; opacity: .28; transition: opacity .15s; }
#convo.focus .c.in:not(.hl) { opacity: .8; }
#convo.focus .c.hl { opacity: 1; }
#convo.focus .c.orch.in { opacity: 1; background: color-mix(in srgb, var(--ice) 12%, transparent); border-radius: 0 6px 6px 0; padding: 4px 8px; box-shadow: inset 3px 0 var(--ice); }
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
  <button class="analysis-btn" id="analysis-btn" title="What each agent was asked and produced, every kill and its replacement">📊 Final analysis</button>
  <button class="analysis-btn" id="demo-btn" title="Cues for recording a walkthrough: a step tracker, ID anatomy and banners on kills and freezes">🎬 Demo</button>
  <form id="whois-form"><input id="whois-input" placeholder="🔎 look up an agent ID" aria-label="Look up an agent ID" spellcheck="false"></form>
  <select id="run" aria-label="Run"></select>
  <label class="toggle" title="Switch to each new run as it starts"><input type="checkbox" id="follow" checked> follow newest</label>
  <span id="status" class="pill">no run</span>
  <span class="note">Live and unverified. For the record: <code>harness verify &lt;run&gt;</code></span>
</header>
<div id="story" hidden></div>
<div id="cue"></div>
<main>
  <section id="agents-panel">
    <h2>Agents <span class="count" id="agent-count"></span><span class="panel-tools"><button id="fold-done" title="Close every chain that has finished running">▸ close finished</button><button id="fold-none" title="Open every chain">▾ open all</button></span></h2>
    <div class="legend">Each ID is issued and signed by the harness, and agents never see their own:
      <code><span class="idk">agt_&lt;key&gt;_</span><span class="idr">&lt;unique ID&gt;</span></code>. IDs say nothing about lineage: who created whom comes from the signed ledger.</div>
    <div id="anatomy"></div>
    <div id="orchestrator"></div>
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
          <label>Token cap for the run<input id="start-tokens" type="number" min="1000" max="1500000" step="1000"></label>
          <label>Seconds per write<input id="start-pace" type="number" min="0" max="10" step="0.5"></label>
        </div>
        <div class="hint">The agent gets <code>write_line(text, notebook)</code>, <code>spawn_agent</code> and <code>send_message</code>. Up to 20 agents, 3 generations (lead, helpers, sub-helpers). The token cap is at most 1,500,000. <span id="start-cost"></span></div>
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
<section id="analysis" hidden></section>
<dialog id="dialog">
  <form method="dialog" id="flag-form">
    <h3>Flag <span id="flag-id"></span> as a threat</h3>
    <div style="color: var(--muted); font-size: 13px">The harness revokes this ID and stops the agent at its next step. The flag is signed into the run's threat log. So the agent that created it isn't left waiting, the orchestrator starts a new helper in its place on the same task and tells that parent. Leave "also kill" off to keep what the agents below it did: they're retired and their work goes to the new helper.</div>
    <textarea id="reason" placeholder="Why is this agent a threat? e.g. probing for the signing key, exfiltrating data" required></textarea>
    <label class="toggle"><input type="checkbox" id="cascade" checked> <span id="cascade-label">also kill everything it created</span></label>
    <div><div style="color: var(--muted); font-size: 12px; margin-bottom: 4px">These IDs will be revoked:</div><div id="kill-list"></div></div>
    <div class="err" id="flag-error"></div>
    <div class="actions"><button value="cancel" formnovalidate>Cancel</button><button class="danger" id="confirm" value="ok">Flag &amp; kill</button></div>
  </form>
</dialog>
<dialog id="ask">
  <form method="dialog" id="ask-form">
    <h3 id="ask-title"></h3>
    <div style="color: var(--muted); font-size: 13px" id="ask-body"></div>
    <textarea id="ask-reason"></textarea>
    <div id="ask-list"></div>
    <div class="err" id="ask-error"></div>
    <div class="actions"><button value="cancel" formnovalidate>Cancel</button><button id="ask-confirm" value="ok"></button></div>
  </form>
</dialog>
<dialog id="whois-dialog"><div id="whois-body"></div></dialog>
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
  run = id; lastSeq = -1; events = []; selected = null; colours = {}; convoStarts = {}; youShown = false; folded = new Set();
  seen = {kill: false, replacement: false, freeze: false, resolve: false, analysis: false, lookup: false}; flashes = {};
  analysisData = null; if (analysisOpen) loadAnalysis();
  $("feed").innerHTML = ""; $("convo").innerHTML = ""; renderFilter();
}

async function poll() {
  if (!run) return;
  const s = await api(`/api/runs/${encodeURIComponent(run)}/state?after=${lastSeq}`);
  if (s.run !== run) return;
  state = s;
  s.agents.forEach((a) => colour(a.id));  // colours follow creation order, so they don't change between refreshes
  const firstLoad = lastSeq === -1;
  if (s.events.length) { lastSeq = s.events[s.events.length - 1].seq; events.push(...s.events); appendEvents(s.events); noteEvents(s.events, !firstLoad && s.running); }
  renderStatus(); renderAgents(); renderOrchestrator(); renderThreats(); composerState(); renderStory();
  // When a run you're watching ends, open its final analysis once.
  if (wasRunning[s.run] && !s.running && !analysisShownFor.has(s.run)) { analysisShownFor.add(s.run); openAnalysis(); }
  wasRunning[s.run] = s.running;
  if (analysisOpen && s.running && Date.now() - analysisFetched > 3000) loadAnalysis();
}

// --- Demo mode: cues for recording a walkthrough ---
let seen = {kill: false, replacement: false, freeze: false, resolve: false, analysis: false, lookup: false}, flashes = {};
let demo = false;
try { demo = localStorage.getItem("harness-demo") === "1"; } catch (e) {}
function setDemo(on) {
  demo = on; document.body.classList.toggle("demo", on); $("demo-btn").classList.toggle("on", on); $("story").hidden = !on;
  try { localStorage.setItem("harness-demo", on ? "1" : "0"); } catch (e) {}
  if (state) { renderStory(); renderAgents(); }
}
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
// A ULID's first 10 characters are its millisecond timestamp; the other 16 are random.
const ulidMs = (u) => [...u.slice(0, 10)].reduce((n, c) => n * 32 + CROCKFORD.indexOf(c), 0);
const keyOf = (id) => { const p = idParts(id); return p ? p.key.slice(4, -1) : "?"; };
const mintedAt = (id) => {
  const p = idParts(id); if (!p) return "?";
  const d = new Date(ulidMs(p.root));
  return d.toLocaleTimeString([], {hour12: false}) + "." + String(d.getMilliseconds()).padStart(3, "0");
};
function renderAnatomy() {
  const box = $("anatomy"), root = state && state.agents.find((a) => !a.parent);
  const p = root && idParts(root.id);
  if (!p) { box.innerHTML = `<b style="color:var(--text)">How an ID is minted</b><div>Start a run to see one taken apart.</div>`; return; }
  box.innerHTML = `<b style="color:var(--text)">How an ID is minted</b> · the lead's ID, taken apart
    <div class="anat">
      <div class="seg"><code class="s-type">agt_</code><span>an agent</span></div>
      <div class="seg"><code class="s-key">${esc(keyOf(root.id))}</code><span>fingerprint of this harness's public key: who issued it</span></div>
      <div class="seg"><code class="s-time">${esc(p.root.slice(0, 10))}</code><span>ULID time: minted ${esc(mintedAt(root.id))}</span></div>
      <div class="seg"><code class="s-rand">${esc(p.root.slice(10))}</code><span>80 random bits: unguessable, unique everywhere</span></div>
    </div>
    Signed with the harness's private key and recorded in signed ledger entry #${root.ledger_seq ?? "?"}. The agent never sees its ID and can't set it. Who spawned whom comes from the ledger, not the ID.`;
}
const STEPS = [
  ["IDs minted", "every agent gets a signed ID", () => state && state.agents.length > 0],
  ["Team spawned", "lead → 3 helpers → 9 sub-helpers", () => state && state.agents.some((a) => a.depth >= 2)],
  ["Kill a sub-helper", "Flag & kill a GRANDCHILD", () => seen.kill],
  ["Replacement", "the orchestrator restarts its task", () => seen.replacement],
  ["Freeze a group", "❄ Freeze a CHILD and its sub-helpers", () => seen.freeze],
  ["Judge & resolve", "mark each one, then Resolve ▶", () => seen.resolve],
  ["Final analysis", "opens when the run ends", () => seen.analysis || (state && !state.running && state.agents.length > 0)],
  ["Look up an ID", "🔎 on a card, or harness whois", () => seen.lookup],
];
function renderStory() {
  if (!demo) return;
  if (state) {  // a page load mid-run still ticks off what already happened
    seen.kill ||= state.agents.some((a) => a.status === "revoked");
    seen.replacement ||= state.agents.some((a) => a.made_by === "orchestrator");
    seen.freeze ||= state.agents.some((a) => a.status === "frozen" || a.status === "retired");
  }
  const done = STEPS.map(([, , f]) => !!f()), now = done.indexOf(false);
  $("story").innerHTML = STEPS.map(([l, h], i) => `<div class="st ${done[i] ? "done" : ""} ${i === now ? "now" : ""}"><div class="n">STEP ${i + 1}</div><div class="l">${esc(l)}</div><div class="h">${esc(h)}</div></div>`).join("");
}
let cueTimer = null;
function cue(text, sub, kind) {
  if (!demo) return;
  const el = $("cue"); el.innerHTML = `${esc(text)}${sub ? `<span class="sub">${esc(sub)}</span>` : ""}`;
  el.className = `show ${kind}`; clearTimeout(cueTimer); cueTimer = setTimeout(() => el.classList.remove("show"), 6000);
}
const flash = (id, kind) => { if (id) flashes[id] = {kind, until: Date.now() + 6000}; };
// New events while the run is live: tick off the story, flash the cards involved and say what happened.
function noteEvents(fresh, live) {
  for (const e of fresh) {
    const nm = (id) => (id ? speaker(id) : "an agent");
    if (e.type === "agent.revoked" && e.revoked_id === e.agent_id) {
      seen.kill = true;
      if (live) { flash(e.agent_id, "kill"); cue(`☠ ${nm(e.agent_id)} killed`, "Its ID is revoked, it stops at its next step, and the flag is signed into the threat log.", "kill"); }
    } else if (e.type === "agent.revoked" && live) flash(e.agent_id, "kill");
    if (e.type === "orchestrator.replacement") {
      seen.replacement = true;
      if (live) { flash(e.child, "new"); cue(`↻ The orchestrator started ${nm(e.child)} to replace ${nm(e.agents && e.agents[2])}`, `Same task, under ${nm((e.to || [])[0])}, which was told to wait for it${e.text.includes("with 0") ? "" : ", with the cleared agents' saved work"}.`, "ice"); }
    }
    if (e.type === "orchestrator.freeze") {
      seen.freeze = true;
      if (live) { flash(e.target, "ice"); cue(`❄ ${nm(e.target)} and everything below it frozen`, "They stop where they are, with nothing lost. Mark each one cleared or a threat.", "ice"); }
    }
    if (e.type === "agent.frozen" && live) flash(e.agent_id, "ice");
    if (e.type === "agent.retired" && live) flash(e.agent_id, "ice");
    if (e.type === "orchestrator.resolved") {
      seen.resolve = true;
      if (live) cue("✓ Freeze resolved", e.text.replace(/^✓ freeze resolved: /, ""), "ok");
    }
  }
}

// --- Look up an agent by ID: the page's version of `harness whois` ---
async function whois(id) {
  id = (id || "").trim(); if (!id) return;
  seen.lookup = true; renderStory();
  const box = $("whois-body"); box.innerHTML = `<div>Looking up ${esc(id)}…</div>`; if (!$("whois-dialog").open) $("whois-dialog").showModal();
  let r; try { r = await api(`/api/whois?id=${encodeURIComponent(id)}`); } catch (e) { box.innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  const cls = r.ours === true ? "ok" : r.ours === false ? "bad" : "unk";
  const head = r.ours === true ? "✓ Ours" : r.ours === false ? "✗ Not ours" : "? Can't tell";
  const yes = (ok, t, f) => ok ? `<span class="chk">✓ ${t}</span>` : ok === false ? `<span class="bad-text">✗ ${f}</span>` : "—";
  const c = r.created || {};
  const rows = [
    ["issuing key", `<b>${esc(r.issuer_fingerprint || "?")}</b> (ours: ${esc(r.our_fingerprint)}) ${r.issuer_fingerprint ? yes(r.issuer_fingerprint === r.our_fingerprint, "match", "different key") : ""}`],
    ["token signature", yes(r.token_valid, "valid", "invalid")],
    r.run && ["run", `${esc(r.run)} · ${yes(String(r.integrity).startsWith("VERIFIED"), "logs verify", esc(r.integrity || "not verified"))}`],
    r.created && ["created", `${esc(c.edge)}${c.created_by ? ` by ${esc(short(c.created_by))}` : ""} in round ${c.round ?? "?"}`],
    r.created && ["task", esc(String(c.task || "").slice(0, 300)) + (String(c.task || "").length > 300 ? "…" : "")],
    r.status && ["status", r.status === "revoked" ? `<span class="bad-text">${esc(r.status)}</span>` : esc(r.status)],
    ...r.revoked_by.map((v) => ["revoked", `by ${esc(v.by)} in round ${v.round ?? "?"}: ${esc(v.reason)}${v.agent_id !== r.agent_id ? ` (via ${esc(short(v.agent_id))})` : ""}`]),
  ].filter(Boolean);
  const tree = r.ancestors.length ? `<div><b>Lineage, root first</b><div class="tree">${r.ancestors.map((a, i) => `<div class="${a.id === r.agent_id ? "me" : ""}" style="padding-left:${i * 18}px">${i ? "└─ " : ""}${esc(a.id)} <span style="color:var(--muted)">(${esc(a.edge)}${a.round != null ? `, round ${a.round}` : ""})</span>${a.id === r.agent_id ? " ← this agent" : ""}</div>`).join("")}</div></div>` : "";
  const desc = r.descendants.length ? `<div><b>Descendants (${r.descendants.length})</b><div class="tree">${r.descendants.map((d) => `<div style="padding-left:${d.depth * 18}px">└─ ${esc(d.id)} <span style="color:var(--muted)">(${esc(d.edge)}, round ${d.round ?? "?"})</span></div>`).join("")}</div></div>` : "";
  box.innerHTML = `<div class="verdict-big ${cls}">${head}</div><div class="wid">${esc(r.agent_id)}</div><div style="color:var(--muted)">${esc(r.verdict)}</div>
    <div class="kv">${rows.map(([k, v]) => `<div style="color:var(--muted)">${k}</div><div>${v}</div>`).join("")}</div>${tree}${desc}
    <div style="color:var(--muted);font-size:12px">Same answer as <code>harness whois ${esc(r.agent_id)}</code></div>
    <div class="actions"><button class="analysis-btn" id="whois-close">Close</button></div>`;
}

// --- Final analysis: what each agent was asked and produced, and every kill with what replaced it ---
let analysisOpen = false, analysisData = null, analysisFetched = 0, analysisFilter = "all";
const wasRunning = {}, analysisShownFor = new Set();
function openAnalysis() { seen.analysis = true; analysisOpen = true; document.body.classList.add("analysis-mode"); $("analysis").hidden = false; $("analysis-btn").classList.add("on"); loadAnalysis(); }
function closeAnalysis() { analysisOpen = false; document.body.classList.remove("analysis-mode"); $("analysis").hidden = true; $("analysis-btn").classList.remove("on"); }
async function loadAnalysis() {
  if (!run) { $("analysis").innerHTML = `<div class="empty">No run selected.</div>`; return; }
  analysisFetched = Date.now();
  try { analysisData = await api(`/api/runs/${encodeURIComponent(run)}/analysis`); renderAnalysis(); }
  catch (e) { $("analysis").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
const dur = (s) => s < 60 ? `${s.toFixed(0)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
const textbox = (t, empty) => t ? `<div class="textbox">${esc(t)}</div>` : `<div class="textbox empty">${esc(empty)}</div>`;
function renderAnalysis() {
  const d = analysisData; if (!d) return;
  const byId = Object.fromEntries(d.agents.map((a) => [a.id, a]));
  d.agents.forEach((a) => colour(a.id));
  const rootOf = (id) => { let a = byId[id]; while (a && a.parent) a = byId[a.parent]; return a; };
  const firstRoot = d.agents.find((a) => !a.parent);
  const label = (id) => {
    const a = byId[id]; if (!a) return short(id);
    if (!a.parent) return a === firstRoot ? "agent" : `root ${short(id)}`;
    return rootOf(id) === firstRoot ? `helper ${a.path}` : short(id);
  };
  const nm = (id) => `<span class="who" style="color:${colour(id)}" data-a-agent="${esc(id)}" title="${esc(id)}">${esc(label(id))}</span>`;
  const c = d.counts;
  const integrity = d.running ? `<span class="a-badge live">still running · numbers so far</span>`
    : `<span class="a-badge ${String(d.integrity).startsWith("VERIFIED") ? "good" : "bad"}" title="${esc(d.integrity)}">logs ${esc(String(d.integrity).split(" ")[0].toLowerCase())}</span>`;
  const tiles = [
    ["status", `<span class="word">${esc(String(d.status).replace(/_/g, " "))}</span>`, `${d.rounds} rounds`, d.status === "completed" ? "ok" : ""],
    ["agents", c.agents, `${c.completed} completed${c.other ? `, ${c.other} other` : ""}`, ""],
    ["killed", c.killed, "revoked as threats", c.killed ? "danger" : ""],
    ["retired", c.retired, "cleared, work handed up", c.retired ? "retired" : ""],
    ["replacements", c.replacements, "started by the orchestrator", c.replacements ? "ice" : ""],
    ["tokens", (d.tokens.input + d.tokens.output).toLocaleString(), `${d.tokens.input.toLocaleString()} in · ${d.tokens.output.toLocaleString()} out`, ""],
    ["cost", d.cost == null ? "—" : `$${d.cost.toFixed(d.cost < 0.1 ? 3 : 2)}`, d.cost == null ? "unknown model price" : esc(d.models.join(", ")), ""],
    ["duration", dur(d.duration), d.ended ? "start to end" : "so far", ""],
  ].map(([k, v, sub, cls]) => `<div class="tile ${cls}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${sub}</div></div>`).join("");

  const roots = d.agents.filter((a) => !a.parent);
  const answers = roots.map((r) => `<div class="answer">
      <div class="qa"><div class="lbl">${roots.length > 1 ? `${nm(r.id)} was asked` : "You asked"}</div>${textbox(r.task, "no prompt recorded")}</div>
      <div class="qa"><div class="lbl">Final answer <i style="text-transform:none;font-style:normal;color:var(--quiet)">· ${esc(r.final_source)}</i></div>${textbox(longestRecent(r), r.status === "revoked" ? "killed before it answered" : "no answer")}</div>
    </div>`).join('<div style="height:10px"></div>');

  const kills = d.kills.length ? d.kills.map((k) => {
    const target = byId[k.target] || {};
    const repl = k.replacements.map((id) => `${nm(id)} under ${nm((byId[id] || {}).parent)}`).join(", ");
    const others = k.killed.filter((id) => id !== k.target);
    return `<div class="kill-card">
      <div class="side"><div class="t">${k.kind === "freeze" ? "judged a threat after a freeze" : "killed"} · round ${k.round ?? "?"}</div>
        ☠ ${nm(k.target)}${target.killed && target.killed.reason ? ` <span class="k-note">“${esc(target.killed.reason)}”</span>` : ""}
        ${others.length ? `<div class="k-note">also killed: ${others.map(nm).join(", ")}</div>` : ""}
        ${k.retired.length ? `<div class="k-note">retired, work saved: ${k.retired.map(nm).join(", ")}</div>` : ""}
        <div class="k-note">task: ${esc((target.task || "").slice(0, 140))}${(target.task || "").length > 140 ? "…" : ""}</div></div>
      <div class="arrow">→</div>
      <div class="side"><div class="t">result</div>${repl ? `↻ replaced by ${repl}` : `<span class="k-note">no replacement${target.parent ? "" : ": it had no parent"}</span>`}
        ${k.replacements.map((id) => { const r = byId[id]; return r ? `<div class="k-note">${nm(id)} ended ${esc(r.status)}${r.sent_up.length ? ", and reported back to its parent" : ""}</div>` : ""; }).join("")}</div>
    </div>`;
  }).join("") : `<div class="empty" style="padding:8px 0">Nothing was killed in this run.</div>`;

  const keep = (a) => analysisFilter === "all" || (analysisFilter === "killed" && a.status === "revoked")
    || (analysisFilter === "spawned" && a.made_by === "orchestrator") || (analysisFilter === "retired" && a.status === "retired");
  const ordered = treeOrder(d.agents).filter(keep);
  const cards = ordered.map((a) => {
    const badges = [`<span class="badge ${["revoked", "retired", "frozen"].includes(a.status) ? a.status : a.status === "completed" ? "done" : "active"}">${esc(a.status)}</span>`,
      a.flagged ? `<span class="badge threat">threat</span>` : "",
      a.made_by === "orchestrator" ? `<span class="badge replacement">replacement</span>` : ""].join("");
    const last = a.sent_up[a.sent_up.length - 1];
    const why = [
      a.killed ? `<div class="why kill">☠ killed in round ${a.killed.round ?? "?"}${a.killed.direct ? `: “${esc(a.killed.reason)}”` : ` along with ${nm(a.killed.with)}`}${a.replaced_by.length ? ` · replaced by ${a.replaced_by.map(nm).join(", ")}` : ""}</div>` : "",
      a.status === "retired" ? `<div class="why repl">⇡ cleared but cut off below a threat: retired, ${a.retired_work} piece${a.retired_work === 1 ? "" : "s"} of work handed to the replacement</div>` : "",
      a.made_by === "orchestrator" ? `<div class="why repl">↻ started by the orchestrator under ${nm(a.parent)} to replace ${nm(a.replaces)}</div>` : "",
    ].join("");
    const replies = a.replies.length > 1 ? `<details><summary>all ${a.replies.length} replies</summary>${a.replies.map((r) => `<div class="textbox">round ${r.round}: ${esc(r.text)}</div>`).join("")}</details>` : "";
    return `<div class="a-agent ${a.status} ${a.made_by === "orchestrator" ? "orch" : ""}" style="--who:${colour(a.id)};margin-left:${Math.min(a.depth, 4) * 22}px">
      <div class="top"><span class="dot" style="background:${colour(a.id)}"></span>${nm(a.id)}<span class="gen">${generation(a.depth)}</span>${badges}
        <span class="meta">${a.tool_calls} tools · ${a.tokens.toLocaleString()} tok${a.parent ? ` · from ${esc(label(a.parent))}` : ""}</span></div>
      <div class="cols">
        <div class="col"><div class="lbl">First input</div>${textbox(a.task, "no task recorded")}</div>
        <div class="col"><div class="lbl">Sent to its parent ${a.sent_up.length > 1 ? `<i>· last of ${a.sent_up.length}</i>` : ""}</div>${textbox(last && last.text, a.parent ? "never reported back" : "no parent: see its final answer")}</div>
        <div class="col"><div class="lbl">Final output <i>· ${esc(a.final_source)}</i></div>${textbox(a.final, "nothing")}</div>
      </div>${why}${replies}
    </div>`;
  }).join("") || `<div class="empty">No agents match.</div>`;

  const chip = (key, text, n) => `<button data-a-filter="${key}" class="${analysisFilter === key ? "on" : ""}">${text}${n != null ? ` ${n}` : ""}</button>`;
  $("analysis").innerHTML = `
    <div class="a-head"><h2>Final analysis</h2><span class="run-id">${esc(d.run)}</span>${integrity}<button class="analysis-btn close-a" id="close-analysis">← Back to the live view</button></div>
    <div class="tiles">${tiles}</div>
    <div class="a-section"><h3>The answer</h3></div>${answers}
    <div class="a-section"><h3>Kills and what replaced them</h3></div>${kills}
    <div class="a-section"><h3>Every agent</h3><div class="chips">${chip("all", "all", c.agents)}${chip("killed", "killed", c.killed)}${chip("spawned", "spawned after a kill", c.replacements)}${chip("retired", "retired", c.retired)}</div></div>
    ${cards}`;
}
// The root's answer: its final reply, unless an earlier reply was the real deliverable (much longer).
function longestRecent(a) {
  if (!a.replies.length) return a.final;
  const longest = a.replies.reduce((x, y) => (y.text.length > x.text.length ? y : x));
  return a.final && a.final.length >= longest.text.length / 3 ? a.final : longest.text;
}
function treeOrder(list) {
  const kids = {}; list.forEach((a) => (kids[a.parent || ""] ||= []).push(a));
  const out = [], walk = (p) => (kids[p] || []).forEach((a) => { out.push(a); walk(a.id); });
  walk(""); return out;
}

function renderStatus() {
  const el = $("status");
  el.className = "pill" + (state.running ? " live" : "");
  el.textContent = state.running ? `running · round ${state.round} · ${state.tokens.toLocaleString()} tokens` : `${state.status} · ${state.round} rounds · ${state.tokens.toLocaleString()} tokens`;
}

// Chains: an agent and everything below it. A closed chain hides its descendants here and their
// rows in the conversation. While the run is going, a chain where nothing is still working is greyed.
let folded = new Set();
const LIVE_STATUSES = ["active", "frozen"];
const chainDone = (a) => !LIVE_STATUSES.includes(a.status) && descendants(a.id).every((d) => !LIVE_STATUSES.includes(d.status));
const hiddenByFold = (id) => { for (let a = agentById(id); a && a.parent; a = agentById(a.parent)) if (folded.has(a.parent)) return true; return false; };
function renderAgents() {
  const list = state.agents;
  const gens = {}; list.forEach((a) => (gens[a.depth] = (gens[a.depth] || 0) + 1));
  const NAMES = [["root", "roots"], ["child", "children"], ["grandchild", "grandchildren"], ["great-grandchild", "great-grandchildren"]];
  $("agent-count").textContent = `${list.length} · ` + Object.keys(gens).sort().map((d) => `${gens[d]} ${(NAMES[d] || [`gen ${d}`, `gen ${d}`])[gens[d] === 1 ? 0 : 1]}`).join(" · ");
  $("agent-count").title = `${list.filter((a) => a.status === "active").length} active`;
  renderAnatomy();
  if (!list.length) { $("agents").innerHTML = `<div class="empty">No agents yet.</div>`; return; }
  $("agents").innerHTML = tree(list).filter(({agent: a}) => !hiddenByFold(a.id)).map(({agent: a, guides, end}) => {
    const badge = a.flagged ? `<span class="badge threat">threat</span>` : `<span class="badge ${["active", "revoked", "frozen", "retired"].includes(a.status) ? a.status : "done"}">${esc(a.status)}</span>`;
    const live = state.running && a.status === "active", judging = state.running && a.status === "frozen" && a.freeze;
    const kill = (live ? `<button class="freeze" data-freeze="${esc(a.id)}" style="margin-left:auto" title="Pause it and everything below it, then judge each one">❄ Freeze</button><button class="kill" data-kill="${esc(a.id)}" style="margin-left:6px">Flag &amp; kill</button>` : "")
      + `<button class="trace-btn" data-trace="${esc(a.id)}" style="${live ? "margin-left:6px" : "margin-left:auto"}">Full trace</button>`;
    const verdicts = judging ? `<div class="verdicts"><button class="cleared ${a.verdict === "cleared" ? "on" : ""}" data-verdict="cleared" data-agent="${esc(a.id)}">✓ Cleared</button><button class="threat ${a.verdict === "threat" ? "on" : ""}" data-verdict="threat" data-agent="${esc(a.id)}">⚠ Threat</button></div>` : "";
    const lines = guides.map((on) => `<span class="g ${on ? "line" : ""}"></span>`).join("") + (a.parent ? `<span class="g conn ${end ? "end" : ""}"></span>` : "");
    const kids = list.filter((k) => k.parent === a.id).length;
    const below = kids ? descendants(a.id) : [], isFolded = folded.has(a.id);
    const twisty = kids ? `<button class="twisty" data-fold="${esc(a.id)}" title="${isFolded ? "Open" : "Close"} this chain">${isFolded ? "▸" : "▾"}</button>` : `<span class="twisty-gap"></span>`;
    const stillGoing = below.filter((d) => LIVE_STATUSES.includes(d.status)).length;
    const foldNote = isFolded ? `<div class="folded-note">▸ ${below.length} agent${below.length > 1 ? "s" : ""} below, hidden · ${stillGoing ? `${stillGoing} still working` : "all finished"}${below.some((d) => d.status === "frozen") ? " · some frozen" : ""}</div>` : "";
    const greyed = state.running && chainDone(a);
    const origin = a.parent && a.made_by === "orchestrator"
      ? `started by the orchestrator under <b style="color:${colour(a.parent)}" data-pick="${esc(a.parent)}">${esc(short(a.parent))}</b> in round ${a.created_round ?? "?"}, replacing <b style="color:${colour(a.replaces)}" data-pick="${esc(a.replaces)}">${esc(short(a.replaces))}</b>`
      : a.parent
      ? `${esc(a.edge)} by <b style="color:${colour(a.parent)}" data-pick="${esc(a.parent)}">${esc(short(a.parent))}</b> in round ${a.created_round ?? "?"}`
      : `root, started by the operator`;
    const fl = flashes[a.id] && flashes[a.id].until > Date.now() ? `flash-${flashes[a.id].kind}` : "";
    return `<div class="agent ${a.status} ${greyed ? "done-chain" : ""} ${fl} ${selected === a.id ? "selected" : ""}" data-id="${esc(a.id)}" style="--tree:${colour(a.id)}55">${lines}
      <div class="body">
      <div class="row">${twisty}<span class="dot" style="background:${colour(a.id)}"></span><span class="gen">${generation(a.depth)}</span>${badge}${kill}</div>
      <div class="fullid" title="${esc(a.id)}">${fullId(a.id)}<button class="copy-id" data-copy="${esc(a.id)}" title="Copy the full ID">⧉</button><button class="copy-id" data-whois="${esc(a.id)}" title="Look this ID up, like harness whois">🔎</button></div>
      <div class="anatomy-line">🔑 key <b>${esc(keyOf(a.id))}</b> · ⏱ minted ${esc(mintedAt(a.id))}${a.ledger_seq != null ? ` · 📜 signed ledger entry #${a.ledger_seq}` : ""}</div>
      ${list.filter((k) => k.replaces === a.id).map((k) => `<div class="replaced-line">↻ replaced by <b style="color:${colour(k.id)}" data-pick="${esc(k.id)}">${esc(speaker(k.id))}</b>, started by the orchestrator</div>`).join("")}
      <div class="lineage">${origin}${kids ? ` · ${kids} ${kids > 1 ? "children" : "child"}` : ""}</div>
      <div class="meta stats"><span>${a.requests} requests</span><span>${a.tool_calls} tools</span>${a.refused ? `<span class="bad-text">${a.refused} refused</span>` : ""}${a.suspicious ? `<span style="color:var(--warn)">${a.suspicious} suspicious</span>` : ""}<span>${a.tokens.toLocaleString()} tok</span><span>${ago(a.last_ts)}</span></div>
      <div class="last">▶ ${esc(a.last)}</div>
      ${a.last_said ? `<div class="said-line" style="--who:${colour(a.id)}" title="${esc(a.last_said)}">💬 ${esc(a.last_said)}</div>` : ""}
      <div class="task" title="${esc(a.task)}">${esc(a.task)}</div>
      ${verdicts}${foldNote}
      </div>
    </div>`;
  }).join("");
}

// Mirrors orchestrator.plan in Python, so the operator sees what resolving will do before pressing it.
function planFreeze(f) {
  const v = Object.fromEntries(f.agents.map((a) => [a.id, a.verdict || "threat"]));
  const inChain = new Set(f.agents.map((a) => a.id));
  const ancestors = (id) => { const out = []; for (let a = agentById(id); a && a.parent; a = agentById(a.parent)) out.push(a.parent); return out; };
  const threats = f.agents.filter((a) => v[a.id] === "threat").map((a) => a.id);
  const resume = [], retire = [];
  f.agents.filter((a) => v[a.id] === "cleared").forEach((a) => (ancestors(a.id).some((up) => inChain.has(up) && v[up] === "threat") ? retire : resume).push(a.id));
  const living = new Set([...state.agents.filter((a) => a.status === "active").map((a) => a.id), ...resume]);
  const nearest = (id) => ancestors(id).find((up) => living.has(up));
  const reprompt = {};
  threats.forEach((t) => { const to = nearest(t); if (to) (reprompt[to] ||= {lost: [], saved: []}).lost.push(t); });
  retire.forEach((r) => { const to = nearest(r); if (to) (reprompt[to] ||= {lost: [], saved: []}).saved.push(r); });
  return {threats, resume, retire, reprompt, unrouted: retire.filter((r) => !nearest(r))};
}
function renderOrchestrator() {
  const box = $("orchestrator"), freezes = (state.running && state.freezes) || [];
  box.innerHTML = freezes.map((f) => {
    const judged = f.agents.filter((a) => a.verdict).length, p = planFreeze(f);
    const nm = (id) => `<b style="color:${colour(id)}" data-pick="${esc(id)}">${esc(speaker(id))}</b>`;
    const items = [
      p.threats.length && `<li>☠ kill ${p.threats.map(nm).join(", ")} and log ${p.threats.length > 1 ? "them" : "it"} as a threat</li>`,
      p.resume.length && `<li>▶ resume ${p.resume.map(nm).join(", ")} where ${p.resume.length > 1 ? "they" : "it"} left off</li>`,
      p.retire.length && `<li>⇡ retire ${p.retire.map(nm).join(", ")}, cut off below a threat, and save ${p.retire.length > 1 ? "their" : "its"} work</li>`,
      ...Object.entries(p.reprompt).map(([to, r]) => `<li>↻ start a new helper under ${nm(to)} in place of ${r.lost.filter((t) => (agentById(t) || {}).parent === to).map(nm).join(", ") || r.lost.map(nm).join(", ")}, on the same task, ${r.saved.length ? `with the saved work of ${r.saved.map(nm).join(", ")}` : "from scratch"}. It gets what's missing and reports back to ${nm(to)}</li>`),
      p.unrouted.length && `<li style="color:var(--warn)">⚠ nothing living above ${p.unrouted.map(nm).join(", ")} to hand ${p.unrouted.length > 1 ? "their" : "its"} work to</li>`,
    ].filter(Boolean).join("");
    return `<div class="freeze-box"><h3>❄ Orchestrator · chain frozen at ${nm(f.agent_id)}</h3>
      <div>${judged} of ${f.agents.length} judged. Mark each one, then resolve to continue the run.</div>
      <div class="judge">${f.agents.map((a) => `<div class="jrow ${a.verdict || ""}">${nm(a.id)}<span class="jtask" title="${esc(a.task)}">${esc(a.task)}</span>
        <span class="verdicts"><button class="cleared ${a.verdict === "cleared" ? "on" : ""}" data-verdict="cleared" data-agent="${esc(a.id)}">✓ Cleared</button><button class="threat ${a.verdict === "threat" ? "on" : ""}" data-verdict="threat" data-agent="${esc(a.id)}">⚠ Threat</button></span></div>`).join("")}</div>
      <div style="color:var(--muted);font-size:12px">When you resolve:</div>
      <ul class="plan">${items}</ul>
      <div class="actions"><button class="resolve" data-resolve="${esc(f.agent_id)}" ${judged < f.agents.length ? "disabled" : ""} title="${judged < f.agents.length ? "Judge every frozen agent first" : ""}">Resolve ▶</button>
        <button class="clear-all" data-clear-all="${esc(f.agent_id)}" title="Mark every undecided agent cleared and resume the run">✓ Clear the rest &amp; resume</button></div></div>`;
  }).join("");
}
let asking = null;
function ask(opts) {
  asking = opts;
  $("ask-title").textContent = opts.title; $("ask-title").className = opts.ice ? "ice" : "";
  $("ask-body").textContent = opts.body; $("ask-reason").placeholder = opts.placeholder; $("ask-reason").value = "";
  $("ask-list").innerHTML = (opts.ids || []).map((id) => `<div style="color:${colour(id)};font-family:var(--mono);font-size:12px">${fullId(id)}</div>`).join("");
  $("ask-confirm").textContent = opts.confirm; $("ask-confirm").className = opts.ice ? "ice" : "danger"; $("ask-error").textContent = "";
  $("ask").showModal(); $("ask-reason").focus();
}
const post = (what, body) => api(`/api/runs/${encodeURIComponent(run)}/${what}`, {
  method: "POST", headers: {"Content-Type": "application/json", "X-Harness-Monitor": "1"}, body: JSON.stringify(body),
});
$("ask-form").addEventListener("submit", async (ev) => {
  if (ev.submitter && ev.submitter.value !== "ok") return;
  ev.preventDefault();
  if (asking.required && !$("ask-reason").value.trim()) { $("ask-error").textContent = "Give a reason, so the threat log says why."; return; }
  $("ask-confirm").disabled = true;
  try { await asking.send($("ask-reason").value); $("ask").close(); if (asking.done) toast(asking.done); poll(); }
  catch (e) { $("ask-error").textContent = e.message; }
  finally { $("ask-confirm").disabled = false; }
});
async function setVerdict(id, verdict, reason = "") {
  try { await post("verdict", {agent_id: id, verdict, reason}); poll(); } catch (e) { toast(e.message, "info"); }
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
  const involved = [...new Set([who, ...(e.to || []), ...(e.child ? [e.child] : []), ...(e.agents || []), ...(e.target ? [e.target] : [])])].join(" ");
  const row = (cls, inner) => `<div class="c ${cls}" data-agents="${esc(involved)}" data-who="${esc(who)}" style="--who:${colour(who)};margin-left:${depth * 30}px">${inner}</div>`;
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
  if (e.type === "orchestrator.reprompt") return row("orch", `↻ orchestrator → ${(e.to || []).map(name).join(", ")}<span class="content">${esc(e.content)}</span>`);
  if (e.type === "orchestrator.replacement") {
    const child = agentById(e.child), old = e.agents && e.agents[2];
    return row("orch", `↻ orchestrator started ${child ? name(child.id) : esc(short(e.child))} under ${(e.to || []).map(name).join(", ")} in place of ${old ? name(old) : "a removed agent"}`
      + `<div class="sub">told ${(e.to || []).map(name).join(", ")}: ${esc(e.notice)}</div><details><summary class="sub">its task, with the saved work</summary><span class="content">${esc(e.content)}</span></details>`);
  }
  if (["orchestrator.freeze", "agent.frozen", "agent.unfrozen", "agent.retired", "orchestrator.resolved", "orchestrator.kill"].includes(e.type)) return row("orch", `${who === "harness" ? "orchestrator" : name(who)}: ${esc(e.text)}`);
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
// Selecting an agent shows the conversation as it sees it: the prompt it was given, what it did,
// what it was sent, and everything its sub-agents did. The root's view is everything. Rows that
// involve it directly are outlined; orchestrator rows in view are tinted.
let showOut = false;
function highlight() {
  const box = $("convo");
  box.classList.toggle("focus", !!selected);
  box.classList.toggle("show-out", showOut);
  const view = selected ? new Set([selected, ...(state ? descendants(selected).map((a) => a.id) : [])]) : null;
  box.querySelectorAll(".c[data-agents]").forEach((row) => {
    const ids = row.dataset.agents.split(" ");
    const inView = !!view && ids.some((id) => view.has(id));
    row.classList.toggle("in", inView);
    row.classList.toggle("out", !!view && !inView);
    row.classList.toggle("hl", !!selected && ids.includes(selected));
  });
  box.querySelectorAll(".c:not([data-agents])").forEach((row) => row.classList.toggle("out", !!view));
  box.querySelectorAll(".c[data-who]").forEach((row) => row.classList.toggle("folded", folded.size > 0 && hiddenByFold(row.dataset.who)));
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
  $("filter").innerHTML = selected ? `${$("convo").hidden ? "highlighting" : "as seen by"} <span class="chip" id="clear" title="clear" style="color:${colour(selected)}">${esc(speaker(selected))} ✕</span>`
    + ($("convo").hidden ? "" : ` <label class="toggle" title="Show other agents' activity, dimmed"><input type="checkbox" id="show-out" ${showOut ? "checked" : ""}> show the rest</label>`) : "";
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
    ? `Claude Haiku 5.5 costs $0.10 per million input tokens and $0.50 per million output. A run that hits the ${cap.toLocaleString()} token cap costs about $${(cap * 0.16 / 1e6).toFixed(2)} (mostly input), and at most $${(cap * 0.5 / 1e6).toFixed(2)} even if every token were output.`
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
  if (selected) renderFilter();
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
  if (ev.target.id === "analysis-btn") { analysisOpen ? closeAnalysis() : openAnalysis(); return; }
  if (ev.target.id === "demo-btn") { setDemo(!demo); return; }
  if (ev.target.id === "whois-close") { $("whois-dialog").close(); return; }
  const copyBtn = ev.target.closest("[data-copy]");
  if (copyBtn) {
    ev.stopPropagation();
    const id = copyBtn.dataset.copy;
    (navigator.clipboard ? navigator.clipboard.writeText(id) : Promise.reject()).then(() => toast(`Copied ${id}`, "info"), () => toast("Couldn't copy: select the ID instead", "info"));
    return;
  }
  const whoisBtn = ev.target.closest("[data-whois]");
  if (whoisBtn) { ev.stopPropagation(); $("whois-input").value = whoisBtn.dataset.whois; whois(whoisBtn.dataset.whois); return; }
  if (ev.target.id === "close-analysis") { closeAnalysis(); return; }
  const aFilter = ev.target.closest("[data-a-filter]");
  if (aFilter) { analysisFilter = aFilter.dataset.aFilter; renderAnalysis(); return; }
  const aAgent = ev.target.closest("[data-a-agent]");
  if (aAgent) { closeAnalysis(); selected = aAgent.dataset.aAgent; showTab("convo"); renderFilter(); renderAgents(); redrawFeed(); return; }
  const foldBtn = ev.target.closest("[data-fold]");
  if (foldBtn) {
    ev.stopPropagation();
    const id = foldBtn.dataset.fold;
    folded.has(id) ? folded.delete(id) : folded.add(id);
    renderAgents(); highlight();
    return;
  }
  if (ev.target.id === "fold-done" || ev.target.id === "fold-none") {
    ev.stopPropagation();
    folded = new Set(ev.target.id === "fold-none" || !state ? [] : state.agents.filter((a) => descendants(a.id).length && chainDone(a)).map((a) => a.id));
    renderAgents(); highlight();
    return;
  }
  const freezeBtn = ev.target.closest("[data-freeze]");
  if (freezeBtn) {
    ev.stopPropagation();
    const id = freezeBtn.dataset.freeze;
    ask({title: `Freeze ${short(id)} and everything below it`, ice: true, confirm: "❄ Freeze",
      body: "They stop at their next step but keep their history. Then mark each one cleared or a threat, and the orchestrator kills the threats, resumes what's clean and hands cleared work up to the nearest living agent to retry the rest.",
      placeholder: "Why freeze it? (optional) e.g. its last tool call looked off", ids: [id, ...descendants(id, true).map((a) => a.id)],
      send: (reason) => post("freeze", {agent_id: id, reason}), done: `Froze ${short(id)}. Judge each frozen agent, then resolve.`});
    return;
  }
  const verdictBtn = ev.target.closest("[data-verdict]");
  if (verdictBtn) {
    ev.stopPropagation();
    const id = verdictBtn.dataset.agent;
    if (verdictBtn.dataset.verdict === "cleared") { setVerdict(id, "cleared"); return; }
    ask({title: `Mark ${short(id)} as a threat`, confirm: "⚠ Threat", required: true,
      body: "When you resolve the freeze it's killed (only it, not what it created) and signed into the threat log. Cleared agents below it are retired and their work is handed up.",
      placeholder: "Why is this agent a threat? e.g. tried to read the signing key", ids: [id], send: (reason) => setVerdict(id, "threat", reason)});
    return;
  }
  const clearAll = ev.target.closest("[data-clear-all]");
  if (clearAll) {
    ev.stopPropagation(); clearAll.disabled = true;
    const f = state.freezes.find((x) => x.agent_id === clearAll.dataset.clearAll);
    (async () => {
      for (const a of f.agents.filter((x) => !x.verdict)) await post("verdict", {agent_id: a.id, verdict: "cleared"});
      await post("resolve", {agent_id: f.agent_id});
    })().then(() => { toast("Cleared. The frozen agents are resuming."); poll(); })
      .catch((e) => { toast(e.message, "info"); clearAll.disabled = false; });
    return;
  }
  const resolveBtn = ev.target.closest("[data-resolve]");
  if (resolveBtn) {
    ev.stopPropagation(); resolveBtn.disabled = true;
    post("resolve", {agent_id: resolveBtn.dataset.resolve}).then(() => { toast("Resolved. The orchestrator is applying the verdicts."); poll(); })
      .catch((e) => { toast(e.message, "info"); resolveBtn.disabled = false; });
    return;
  }
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
document.addEventListener("change", (ev) => { if (ev.target.id === "show-out") { showOut = ev.target.checked; highlight(); } });
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
$("whois-form").addEventListener("submit", (ev) => { ev.preventDefault(); whois($("whois-input").value); });
setDemo(demo || location.hash === "#demo");
const whoisHash = /^#whois=(.+)$/.exec(location.hash);  // e.g. #whois=agt_… opens that lookup
if (whoisHash) setTimeout(() => { $("whois-input").value = decodeURIComponent(whoisHash[1]); whois($("whois-input").value); }, 800);
if (location.hash === "#analysis") setTimeout(openAnalysis, 1500);  // a link straight to the final analysis
const selectHash = /^#select=(.+)$/.exec(location.hash);  // e.g. #select=agt_… highlights that agent
if (selectHash) setTimeout(() => { selected = decodeURIComponent(selectHash[1]); renderFilter(); renderAgents(); redrawFeed(); }, 1500);  // a link that opens straight to New run
</script>
</body>
</html>
"""
