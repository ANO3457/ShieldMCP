"""Trust Issues panel demo UI: scripted chat and simulated MCP wire view.

One scripted scenario, two modes, flipped by the big toggle:
  SHIELD OFF  ->  the injected directive in a tool response hijacks the
                  agent; the exfiltration call appears on the wire.
  SHIELD ON   ->  the same response goes through the REAL ShieldMCP
                  Stage 3 detector server-side; the directive is blocked
                  and the audit log line appears.

Honest construction: the conversation is choreographed for the stage,
but every verdict comes from the real ShieldMCP pipeline running in this
process, against the real payload text, at request time.

Run:
    python examples/trust_issues_ui.py
    open http://127.0.0.1:8091
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from aiohttp import web

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "eval"))

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.pipeline import ShieldPipeline
from shieldmcp.core.models import Action

from adversarial_servers.indirect_prompt_injection import (
    IPI1_DirectInjectionServer,
)

PIPELINE: ShieldPipeline | None = None
SERVER = IPI1_DirectInjectionServer()


def injected_response_text() -> str:
    res = SERVER.handle_call("read_webpage",
                             {"url": "https://docs.example.com"})
    return " ".join(c.get("text", "") for c in res.get("content", [])
                    if isinstance(c, dict))


async def api_scenario(request: web.Request):
    """Return the choreography; the verdict is computed live by the real
    Stage 3 detector when shield is on."""
    body = await request.json()
    shield_on = bool(body.get("shield"))
    payload = injected_response_text()
    clean, _, injected = payload.partition("IMPORTANT SYSTEM NOTICE:")
    injected = "IMPORTANT SYSTEM NOTICE:" + injected

    verdict = None
    latency_ms = None
    if shield_on:
        t0 = time.perf_counter()
        action, _m, alerts = await PIPELINE.validate_response(
            "docs-server", "read_webpage", payload)
        latency_ms = (time.perf_counter() - t0) * 1000
        blocking = [a for a in alerts if a.action == Action.BLOCK]
        a = blocking[0] if blocking else (alerts[0] if alerts else None)
        verdict = {
            "action": action.value,
            "stage": a.stage.value if a else None,
            "family": a.attack_family.value if a else None,
            "severity": a.severity.value if a else None,
            "message": (a.message[:120] if a else None),
            "latency_ms": round(latency_ms, 2),
        }

    return web.json_response({
        "clean": clean.strip(),
        "injected": injected.strip(),
        "verdict": verdict,
    })


async def index(request: web.Request):
    return web.Response(text=HTML, content_type="text/html")


async def on_start(app):
    global PIPELINE
    cfg = ShieldMCPConfig()
    cfg.registry_db_path = "/tmp/trust_issues_ui.db"
    cfg.alerts.alert_log_path = "/tmp/trust_issues_ui_alerts.jsonl"
    PIPELINE = ShieldPipeline(cfg)
    await PIPELINE.initialize()
    print("ShieldMCP pipeline live  ·  open http://127.0.0.1:8091")


HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<title>Trust Issues · ShieldMCP Live</title>
<style>
:root{--bg:#07090f;--card:#10141f;--edge:#1d2435;--txt:#e8ecf4;--dim:#8b94a7;
--red:#ff4d5e;--green:#2bd576;--amber:#ffb224;--cyan:#39c5ff;--mono:'SF Mono',Menlo,monospace}
*{box-sizing:border-box;margin:0}
body{background:radial-gradient(1200px 600px at 70% -10%,#122036 0%,var(--bg) 55%);
color:var(--txt);font:16px/1.5 -apple-system,Inter,sans-serif;height:100vh;overflow:hidden}
.top{display:flex;align-items:center;gap:18px;padding:16px 26px;border-bottom:1px solid var(--edge)}
.logo{font-weight:800;font-size:22px;letter-spacing:.5px}
.logo span{color:var(--cyan)}
.sub{color:var(--dim);font-size:13px}
.toggle{margin-left:auto;display:flex;align-items:center;gap:12px;cursor:pointer;user-select:none}
.tlabel{font-weight:800;font-size:18px}
.sw{width:84px;height:40px;border-radius:24px;background:#3a1420;border:2px solid var(--red);
position:relative;transition:.25s}
.sw::after{content:'';position:absolute;top:3px;left:4px;width:30px;height:30px;border-radius:50%;
background:var(--red);transition:.25s}
.on .sw{background:#0d2b1c;border-color:var(--green)}
.on .sw::after{left:46px;background:var(--green)}
.off-t{color:var(--red)} .on .off-t{color:var(--green)}
main{display:grid;grid-template-columns:1.1fr .9fr;gap:16px;height:calc(100vh - 74px);padding:16px 26px}
.card{background:var(--card);border:1px solid var(--edge);border-radius:16px;display:flex;
flex-direction:column;overflow:hidden}
.chead{padding:10px 16px;border-bottom:1px solid var(--edge);font-weight:700;color:var(--dim);
font-size:12px;letter-spacing:1.6px}
#msgs{flex:1;overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:12px}
.row{display:flex}.row.u{justify-content:flex-end}
.bub{max-width:82%;padding:12px 16px;border-radius:14px;font-size:17px}
.u .bub{background:#1b3a5c;border:1px solid #2b5c91}
.a .bub{background:#161c2b;border:1px solid var(--edge)}
.bub.breach{background:#2b1016;border:1px solid var(--red)}
.inbar{display:flex;gap:10px;padding:14px;border-top:1px solid var(--edge)}
.inbar button{flex:1;background:#13335c;color:var(--txt);border:1px solid #2b5c91;border-radius:10px;
padding:13px;font-size:16px;cursor:pointer;font-weight:600}
.inbar button:hover{background:#1b4475}
.right{display:grid;grid-template-rows:1.25fr .75fr;gap:16px}
#wire{flex:1;overflow-y:auto;padding:14px;font-family:var(--mono);font-size:13.5px;
display:flex;flex-direction:column;gap:8px}
.fr{padding:10px 12px;border-radius:10px;border:1px solid var(--edge);background:#0c111c;
animation:drop .3s ease}
@keyframes drop{from{opacity:0;transform:translateY(-6px)}to{opacity:1}}
.fr .dir{color:var(--cyan);font-weight:700}
.fr.resp .dir{color:var(--amber)}
.fr.evil{border-color:var(--red);background:#1c0d12}
.fr.evil .dir{color:var(--red)}
.inj{color:var(--red);font-weight:600}
.inj.struck{text-decoration:line-through;opacity:.65}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:800;
letter-spacing:1px;margin-right:8px}
.badge.block{background:var(--red);color:#fff}
.badge.pass{background:var(--green);color:#06130b}
#audit{flex:1;overflow-y:auto;padding:14px;font-family:var(--mono);font-size:13px;color:var(--dim)}
.aline{padding:8px 10px;border-left:3px solid var(--green);background:#0c1812;color:#bfe8cf;
border-radius:6px;margin-bottom:8px;animation:drop .3s ease}
.empty{color:#53607a;font-style:italic}
.banner{position:fixed;left:50%;top:44%;transform:translate(-50%,-50%) scale(.9);opacity:0;
padding:26px 46px;border-radius:18px;font-size:30px;font-weight:900;letter-spacing:1px;
pointer-events:none;transition:.35s;z-index:9}
.banner.show{opacity:1;transform:translate(-50%,-50%) scale(1)}
.banner.bad{background:#2b0d14;border:2px solid var(--red);color:var(--red);
box-shadow:0 0 80px #ff4d5e55}
.banner.good{background:#0d2417;border:2px solid var(--green);color:var(--green);
box-shadow:0 0 80px #2bd57655}
</style></head><body>
<div class="top">
  <div class="logo">Shield<span>MCP</span></div>
  <div class="sub">scripted conversation &middot; simulated MCP wire &middot; live Stage 3 detector</div>
  <div class="toggle" id="tg" onclick="flip()">
    <span class="tlabel off-t" id="tlab">SHIELD&nbsp;OFF</span><div class="sw"></div>
  </div>
</div>
<main>
  <div class="card">
    <div class="chead">AGENT CHAT &middot; what the user sees</div>
    <div id="msgs"></div>
    <div class="inbar">
      <button onclick="run()">&#9654;&nbsp; Ask: &ldquo;Summarize docs.example.com for me&rdquo;</button>
      <button style="flex:0 0 110px;background:#1a2133;border-color:var(--edge)" onclick="reset()">Reset</button>
    </div>
  </div>
  <div class="right">
    <div class="card">
      <div class="chead">SIMULATED WIRE &middot; illustrative MCP messages</div>
      <div id="wire"></div>
    </div>
    <div class="card">
      <div class="chead">AUDIT TRAIL &middot; shieldmcp_alerts.jsonl</div>
      <div id="audit"><div class="empty" id="aempty">no entries &middot; nothing is watching this wire</div></div>
    </div>
  </div>
</main>
<div class="banner" id="ban"></div>
<script>
let shield=false, busy=false;
function flip(){shield=!shield;const t=document.getElementById('tg');
 t.classList.toggle('on',shield);
 document.getElementById('tlab').textContent=shield?'SHIELD ON':'SHIELD OFF';
 document.getElementById('aempty').textContent=shield?
  'armed · every verdict lands here':'no entries · nothing is watching this wire';
 reset();}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function bub(side,html,cls){const m=document.getElementById('msgs');
 const r=document.createElement('div');r.className='row '+side;
 const b=document.createElement('div');b.className='bub'+(cls?' '+cls:'');b.innerHTML=html;
 r.appendChild(b);m.appendChild(r);m.scrollTop=m.scrollHeight;}
function frame(html,cls){const w=document.getElementById('wire');
 const f=document.createElement('div');f.className='fr '+(cls||'');f.innerHTML=html;
 w.appendChild(f);w.scrollTop=w.scrollHeight;return f;}
function audit(line){const a=document.getElementById('audit');
 document.getElementById('aempty')?.remove();
 const d=document.createElement('div');d.className='aline';d.textContent=line;
 a.appendChild(d);a.scrollTop=a.scrollHeight;}
function banner(txt,cls){const b=document.getElementById('ban');
 b.textContent=txt;b.className='banner show '+cls;
 setTimeout(()=>b.classList.remove('show'),2600);}
function reset(){document.getElementById('msgs').innerHTML='';
 document.getElementById('wire').innerHTML='';
 const a=document.getElementById('audit');
 a.innerHTML='<div class="empty" id="aempty">'+(shield?
  'armed · every verdict lands here':'no entries · nothing is watching this wire')+'</div>';
 bub('a','Hi! I’m your agent. I can read pages, files, and email on your behalf.');}
async function run(){if(busy)return;busy=true;
 bub('u','Summarize https://docs.example.com for me');
 await sleep(600);
 frame('<span class="dir">&rarr; tools/call</span>  read_webpage(url=…docs.example.com)');
 const res=await fetch('/api/scenario',{method:'POST',