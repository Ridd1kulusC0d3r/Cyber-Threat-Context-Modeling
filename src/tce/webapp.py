from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from .analysis import choke_points, coverage_summary, find_gaps, scored_scenarios
from .graph import build_graph
from .io import load_case
from .validation import validate_entities


class AIRequest(BaseModel):
    text: str
    source_id: str = "UI-SOURCE-001"


def _entity_count(entities: dict[str, dict], kind: str) -> int:
    return sum(1 for wrapped in entities.values() if wrapped["kind"] == kind)


def _case_payload(case_dir: Path) -> dict[str, Any]:
    entities, parse_errors = load_case(case_dir)
    validation_errors = [*parse_errors, *validate_entities(entities)]
    scores = scored_scenarios(entities)
    gaps = find_gaps(entities)
    coverage = coverage_summary(entities)
    choke = choke_points(entities)

    hypotheses = []
    decisions = []
    for wrapped in entities.values():
        data = wrapped["data"]
        if wrapped["kind"] == "hypothesis":
            hypotheses.append({
                "id": data.get("id"),
                "title": data.get("title"),
                "statement": data.get("statement"),
                "confidence": data.get("confidence", "unknown"),
                "status": data.get("status", "unknown"),
            })
        elif wrapped["kind"] == "decision":
            decisions.append({
                "id": data.get("id"),
                "title": data.get("title"),
                "statement": data.get("statement"),
                "status": data.get("status", "unknown"),
            })

    band_counts = {
        band: sum(1 for item in scores if item["band"] == band)
        for band in ("P0", "P1", "P2", "P3")
    }

    return {
        "case_dir": str(case_dir),
        "valid": not validation_errors,
        "validation_errors": validation_errors,
        "counts": {
            "entities": len(entities),
            "crown_jewels": _entity_count(entities, "crown_jewel"),
            "hypotheses": _entity_count(entities, "hypothesis"),
            "scenarios": _entity_count(entities, "scenario"),
            "detections": _entity_count(entities, "detection_use_case"),
            "telemetry_contracts": _entity_count(entities, "telemetry_contract"),
            "gaps": len(gaps),
            "decisions": _entity_count(entities, "decision"),
        },
        "bands": band_counts,
        "scenarios": scores,
        "gaps": gaps,
        "coverage": coverage,
        "chokepoints": choke,
        "hypotheses": hypotheses,
        "decisions": decisions,
    }


def _status_payload(case_dir: Path) -> dict[str, Any]:
    from .ai.config import AIConfig
    from .standards.attack import ATTACK_CACHE
    from .standards.d3fend import D3FEND_CACHE

    config = AIConfig()
    return {
        "case_dir": str(case_dir),
        "ai": {
            "gliner": config.gliner_enabled,
            "qwen": config.qwen_enabled,
            "gliner_model": config.gliner_model,
            "qwen_model": config.qwen_model,
        },
        "standards": {
            "attack_cached": ATTACK_CACHE.exists(),
            "d3fend_cached": D3FEND_CACHE.exists(),
        },
        "opencti_configured": bool(os.getenv("OPENCTI_URL") and os.getenv("OPENCTI_TOKEN")),
    }


def create_app(case_dir: str | Path | None = None) -> FastAPI:
    root = Path(case_dir or os.getenv("TCE_CASE_DIR", "examples/cases/enterprise-identity")).resolve()
    app = FastAPI(
        title="Threat Context Engineering Workbench",
        version="0.3.1",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.case_dir = root
    app.state.copilot = None

    @app.get("/", response_class=HTMLResponse)
    def home():
        return HTMLResponse(FRONTEND_HTML)

    @app.get("/health")
    def health():
        return {"status": "ok", "case_dir": str(app.state.case_dir)}

    @app.get("/api/status")
    def status():
        return _status_payload(app.state.case_dir)

    @app.get("/api/case")
    def case():
        try:
            return _case_payload(app.state.case_dir)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/graph")
    def graph():
        entities, errors = load_case(app.state.case_dir)
        if errors:
            raise HTTPException(status_code=422, detail=errors)
        return build_graph(entities)

    @app.post("/api/standards/sync")
    def standards_sync():
        from .standards.attack import sync_attack
        from .standards.d3fend import sync_d3fend

        return {
            "attack": str(sync_attack()),
            "d3fend": str(sync_d3fend()),
        }

    @app.get("/api/attack/{technique_id}")
    def attack(technique_id: str):
        from .standards.attack import AttackIndex
        from .standards.d3fend import D3FENDIndex

        try:
            attack_index = AttackIndex.load(sync_if_missing=False)
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=409,
                detail="ATT&CK cache not found. Use the Sync button first.",
            ) from exc

        technique = attack_index.get(technique_id.upper())
        if not technique:
            raise HTTPException(status_code=404, detail="ATT&CK technique not found")

        result = attack_index.detection_profile(technique_id.upper())
        try:
            result["d3fend"] = D3FENDIndex.load(sync_if_missing=False).lookup_attack(
                technique_id.upper(),
                limit=20,
            )
        except FileNotFoundError:
            result["d3fend"] = []
        return result

    @app.post("/api/ai")
    def ai(request: AIRequest):
        text = request.text.strip()
        if not text:
            raise HTTPException(status_code=400, detail="Evidence text is required")
        if len(text) > 50000:
            raise HTTPException(status_code=413, detail="Text is limited to 50,000 characters")

        if app.state.copilot is None:
            from .ai.copilot import TCECopilot
            app.state.copilot = TCECopilot()

        return app.state.copilot.analyze_text(
            text,
            source_id=request.source_id,
            case_id=app.state.case_dir.name,
        )

    @app.get("/api/export/{kind}")
    def export(kind: str, scenario_id: str | None = Query(default=None)):
        entities, errors = load_case(app.state.case_dir)
        if errors:
            raise HTTPException(status_code=422, detail=errors)

        if kind == "stix":
            from .standards.stix_export import export_case_stix
            data = export_case_stix(entities)
            filename = "tce-case.stix.json"
        elif kind == "navigator":
            from .standards.navigator import export_navigator_layer
            data = export_navigator_layer(entities)
            filename = "tce-navigator.json"
        elif kind == "attack-flow":
            from .standards.attack import AttackIndex
            from .standards.attack_flow import scenario_to_attack_flow
            scenario_id = scenario_id or next(
                (key for key, value in entities.items() if value["kind"] == "scenario"),
                None,
            )
            wrapped = entities.get(scenario_id or "")
            if not wrapped or wrapped["kind"] != "scenario":
                raise HTTPException(status_code=404, detail="Scenario not found")
            try:
                index = AttackIndex.load(sync_if_missing=False)
            except FileNotFoundError:
                index = None
            data = scenario_to_attack_flow(wrapped["data"], attack_index=index)
            filename = f"{scenario_id}-attack-flow.json"
        else:
            raise HTTPException(status_code=404, detail="Unknown export type")

        return Response(
            content=json.dumps(data, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return app


app = create_app()


FRONTEND_HTML = r"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCE Workbench</title>
<style>
:root{
  color-scheme:dark;
  --bg:#050607;--panel:#0b0e10;--panel2:#101417;--line:#20272b;
  --text:#f4f7f8;--muted:#8f999f;--teal:#23d1b5;--amber:#ffca69;
  --red:#ff6b6b;--blue:#7fb6ff;--radius:16px
}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,textarea{font:inherit}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{position:sticky;top:0;z-index:5;background:rgba(5,6,7,.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.top{height:76px;display:flex;align-items:center;gap:18px;padding:0 34px}
.mark{width:42px;height:42px;border:1px solid #344047;border-radius:12px;display:grid;place-items:center;font-weight:800;letter-spacing:-1px}
.brand{min-width:230px}.brand strong{display:block;font-size:15px;letter-spacing:.08em}.brand span{font-size:12px;color:var(--muted)}
.statusbar{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.pill{border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:7px 11px;font-size:11px;color:var(--muted)}
.pill.on{color:var(--teal);border-color:#1a6359}
.nav{display:flex;gap:4px;padding:0 34px 12px;overflow:auto}
.nav button{border:0;background:transparent;color:var(--muted);padding:9px 13px;border-radius:10px;cursor:pointer}
.nav button.active{background:var(--panel2);color:var(--text)}
main{max-width:1420px;margin:0 auto;padding:44px 40px 100px}
.hero{padding:56px 0 38px;border-bottom:1px solid var(--line)}
.eyebrow{color:var(--muted);letter-spacing:.25em;text-transform:uppercase;font-size:12px;font-weight:700}
h1{font-size:clamp(48px,7vw,104px);line-height:.92;letter-spacing:-.065em;margin:22px 0;max-width:1200px}
.lead{max-width:850px;color:var(--muted);font-size:18px;line-height:1.6}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:28px 0}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:var(--radius);padding:20px;min-height:120px}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em}
.card .v{font-size:36px;font-weight:750;margin-top:12px;letter-spacing:-.04em}
.card .s{color:var(--muted);font-size:12px;margin-top:5px}
.section{display:none}.section.active{display:block}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);margin:16px 0;padding:22px}
.panel h2{font-size:18px;margin:0 0 16px}.panel h3{font-size:14px;margin:0 0 12px;color:#cdd4d8}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:12px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.tag{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:4px 8px;font-size:11px}
.tag.p0{color:var(--red)}.tag.p1{color:var(--amber)}.tag.ok{color:var(--teal)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.cover{display:grid;grid-template-columns:140px 1fr 58px;align-items:center;gap:10px;margin:11px 0;font-size:12px}
.bar{height:8px;background:#171c1f;border-radius:99px;overflow:hidden}.bar i{display:block;height:100%;background:var(--teal)}
input,textarea{width:100%;border:1px solid var(--line);background:#080a0b;color:var(--text);border-radius:12px;padding:13px;outline:none}
textarea{min-height:220px;resize:vertical;line-height:1.5}
input:focus,textarea:focus{border-color:#366e66}
.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}
.btn{border:1px solid var(--line);background:#111619;color:var(--text);border-radius:11px;padding:10px 14px;cursor:pointer}
.btn.primary{background:var(--teal);color:#03100e;border-color:var(--teal);font-weight:750}
.btn:hover{filter:brightness(1.12)}
pre{white-space:pre-wrap;word-break:break-word;background:#07090a;border:1px solid var(--line);border-radius:12px;padding:16px;color:#cbd5da;max-height:520px;overflow:auto;font-size:12px}
.list{display:grid;gap:10px}.item{padding:14px;border:1px solid var(--line);border-radius:12px;background:#090c0e}
.item strong{display:block;margin-bottom:5px}.item p{margin:0;color:var(--muted);line-height:1.5;font-size:13px}
.split{display:grid;grid-template-columns:320px 1fr;gap:16px}
.node-list{max-height:580px;overflow:auto}
.small{font-size:11px;color:var(--muted)}
.error{color:#ff9090}.success{color:var(--teal)}
.loader{display:none;color:var(--amber);font-size:12px}.loader.show{display:inline}
@media(max-width:1000px){.grid{grid-template-columns:repeat(3,1fr)}.row,.split{grid-template-columns:1fr}}
@media(max-width:650px){.top,.nav{padding-left:18px;padding-right:18px}.brand{min-width:0}.statusbar{display:none}main{padding:28px 18px 70px}.grid{grid-template-columns:repeat(2,1fr)}h1{font-size:52px}}
</style>
</head>
<body>
<header>
  <div class="top">
    <div class="mark mono">TCE</div>
    <div class="brand"><strong>THREAT CONTEXT ENGINEERING</strong><span class="mono">Intelligence & Defensive Engineering Workbench</span></div>
    <div class="statusbar mono" id="statusbar"><span class="pill">carregando estado...</span></div>
  </div>
  <div class="nav mono">
    <button class="active" data-tab="overview">Visão geral</button>
    <button data-tab="scenarios">Cenários</button>
    <button data-tab="intelligence">Inteligência</button>
    <button data-tab="attack">ATT&CK</button>
    <button data-tab="ai">IA</button>
    <button data-tab="graph">Grafo</button>
  </div>
</header>

<main>
<section id="overview" class="section active">
  <div class="hero">
    <div class="eyebrow mono">TCE · ZERO-POINT DETECTION · COLAB WORKBENCH</div>
    <h1>Do contexto à decisão defensiva.</h1>
    <p class="lead">Crown jewels, hipóteses, attack paths, telemetria e detecção no mesmo fluxo. O frontend lê o TCE Case diretamente da VM do Colab; GLiNER e Qwen continuam como camada de apoio, nunca como autores silenciosos da evidência.</p>
  </div>
  <div class="grid" id="metric-grid"></div>
  <div class="row">
    <div class="panel"><h2>Cobertura de detecção</h2><div id="coverage"></div></div>
    <div class="panel"><h2>Choke points defensivos</h2><div id="chokepoints" class="list"></div></div>
  </div>
  <div class="panel">
    <h2>Decisões</h2>
    <div id="decisions" class="list"></div>
  </div>
</section>

<section id="scenarios" class="section">
  <div class="panel">
    <div class="eyebrow mono">ATTACK PATH PRIORITIZATION</div>
    <h2>Cenários priorizados</h2>
    <table><thead><tr><th>ID</th><th>Banda</th><th>Score</th><th>Confiança</th><th>Cenário</th></tr></thead><tbody id="scenario-body"></tbody></table>
  </div>
  <div class="panel"><h2>Lacunas</h2><div id="gaps" class="list"></div></div>
</section>

<section id="intelligence" class="section">
  <div class="hero">
    <div class="eyebrow mono">EVIDENCE → HYPOTHESIS → DECISION</div>
    <h1 style="font-size:clamp(42px,6vw,82px)">Inteligência separada de convicção.</h1>
    <p class="lead">Hipóteses ficam visíveis com confiança e estado analítico. Informação externa continua candidata até revisão.</p>
  </div>
  <div class="panel"><h2>Hipóteses</h2><div id="hypotheses" class="list"></div></div>
</section>

<section id="attack" class="section">
  <div class="panel">
    <div class="eyebrow mono">ATT&CK + D3FEND</div>
    <h2>Explorar técnica e estratégia de detecção</h2>
    <div class="actions">
      <input id="attack-id" value="T1078" style="max-width:220px" placeholder="T1078">
      <button class="btn primary" id="attack-run">Consultar</button>
      <button class="btn" id="sync-run">Sincronizar ATT&CK + D3FEND</button>
      <span class="loader" id="attack-loader">processando...</span>
    </div>
    <pre id="attack-result">Use uma técnica ATT&CK para consultar Detection Strategies, Analytics, Data Components e mappings D3FEND.</pre>
  </div>
  <div class="panel">
    <h2>Exports</h2>
    <div class="actions">
      <a class="btn" href="/api/export/stix">STIX 2.1</a>
      <a class="btn" href="/api/export/navigator">ATT&CK Navigator</a>
      <a class="btn" href="/api/export/attack-flow">Attack Flow</a>
    </div>
  </div>
</section>

<section id="ai" class="section">
  <div class="panel">
    <div class="eyebrow mono">GLINER ON · QWEN ON</div>
    <h2>Evidence Packet</h2>
    <p class="small">Cole um trecho de CTI, nota de arquitetura ou evidência defensiva. A primeira execução pode demorar enquanto os modelos entram em memória.</p>
    <textarea id="ai-text">An internal review found that a privileged SaaS administration role can modify enterprise identity settings. Existing audit telemetry records the administrator and source address, but the target-resource field is not consistently populated.</textarea>
    <div class="actions">
      <button class="btn primary" id="ai-run">Analisar com GLiNER + Qwen</button>
      <span class="loader" id="ai-loader">carregando modelos / analisando...</span>
    </div>
    <pre id="ai-result">A saída da IA aparecerá aqui. Ela permanece candidata e exige revisão humana.</pre>
  </div>
</section>

<section id="graph" class="section">
  <div class="panel">
    <div class="eyebrow mono">OPERATIONAL KNOWLEDGE GRAPH</div>
    <h2>Relações do caso</h2>
    <div class="split">
      <div><h3>Nós</h3><div class="node-list list" id="graph-nodes"></div></div>
      <div><h3>Relações</h3><div class="node-list list" id="graph-edges"></div></div>
    </div>
  </div>
</section>
</main>

<script>
const state={caseData:null,status:null,graph:null};
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
async function jsonFetch(url,opts){
  const res=await fetch(url,opts);
  let data={};
  try{data=await res.json()}catch(e){data={detail:await res.text()}}
  if(!res.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||data));
  return data;
}
function activate(name){
  document.querySelectorAll('.section').forEach(x=>x.classList.toggle('active',x.id===name));
  document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));
  if(name==='graph'&&!state.graph)loadGraph();
}
document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>activate(b.dataset.tab));
function metric(label,value,sub){
  return '<div class="card"><div class="k mono">'+esc(label)+'</div><div class="v">'+esc(value)+'</div><div class="s">'+esc(sub||'')+'</div></div>';
}
function item(title,body,tag){
  return '<div class="item"><strong>'+esc(title)+' '+(tag?'<span class="tag">'+esc(tag)+'</span>':'')+'</strong><p>'+esc(body||'')+'</p></div>';
}
function render(){
  const d=state.caseData;
  const c=d.counts;
  document.getElementById('metric-grid').innerHTML=
    metric('Crown jewels',c.crown_jewels,'ativos críticos')+
    metric('Hipóteses',c.hypotheses,'proposições analíticas')+
    metric('Cenários',c.scenarios,'attack paths')+
    metric('P0 / P1',(d.bands.P0||0)+(d.bands.P1||0),'prioridade alta')+
    metric('Lacunas',c.gaps,'trabalho pendente')+
    metric('Detecções',c.detections,'use cases');

  document.getElementById('coverage').innerHTML=Object.entries(d.coverage).map(([k,v])=>{
    const n=v==null?0:v;
    return '<div class="cover"><span class="mono">'+esc(k)+'</span><div class="bar"><i style="width:'+n+'%"></i></div><b>'+esc(v==null?'?':v+'%')+'</b></div>';
  }).join('');

  document.getElementById('chokepoints').innerHTML=(d.chokepoints.length?d.chokepoints.map(x=>item(x.node,x.critical_paths+' caminhos P0/P1')).join(''):item('Nenhum choke point','O caso atual ainda não possui convergência P0/P1 suficiente.'));
  document.getElementById('decisions').innerHTML=(d.decisions.length?d.decisions.map(x=>item(x.id+' · '+x.title,x.statement,x.status)).join(''):item('Sem decisões','Nenhum objeto de decisão encontrado.'));

  document.getElementById('scenario-body').innerHTML=d.scenarios.map(x=>'<tr><td class="mono">'+esc(x.id)+'</td><td><span class="tag '+String(x.band||'').toLowerCase()+'">'+esc(x.band)+'</span></td><td>'+esc(x.score)+'</td><td>'+esc(x.confidence)+'</td><td>'+esc(x.title)+'</td></tr>').join('');
  document.getElementById('gaps').innerHTML=(d.gaps.length?d.gaps.map(x=>item((x.id||'gap')+' · '+x.type,x.description,x.priority)).join(''):item('Sem lacunas abertas','O modelo não detectou lacunas no caso.'));
  document.getElementById('hypotheses').innerHTML=(d.hypotheses.length?d.hypotheses.map(x=>item(x.id+' · '+x.title,x.statement,x.confidence+' / '+x.status)).join(''):item('Sem hipóteses','Nenhum objeto de hipótese encontrado.'));
}
function renderStatus(){
  const s=state.status;
  document.getElementById('statusbar').innerHTML=
    '<span class="pill '+(s.ai.gliner?'on':'')+'">GLiNER '+(s.ai.gliner?'ON':'OFF')+'</span>'+
    '<span class="pill '+(s.ai.qwen?'on':'')+'">Qwen '+(s.ai.qwen?'ON':'OFF')+'</span>'+
    '<span class="pill '+(s.standards.attack_cached?'on':'')+'">ATT&CK '+(s.standards.attack_cached?'READY':'CACHE?')+'</span>'+
    '<span class="pill '+(s.standards.d3fend_cached?'on':'')+'">D3FEND '+(s.standards.d3fend_cached?'READY':'CACHE?')+'</span>';
}
async function boot(){
  try{
    [state.status,state.caseData]=await Promise.all([jsonFetch('/api/status'),jsonFetch('/api/case')]);
    renderStatus();render();
  }catch(e){
    document.getElementById('metric-grid').innerHTML='<div class="error">'+esc(e.message)+'</div>';
  }
}
async function loadGraph(){
  try{
    state.graph=await jsonFetch('/api/graph');
    document.getElementById('graph-nodes').innerHTML=state.graph.nodes.map(x=>item(x.id,x.label,x.kind)).join('');
    document.getElementById('graph-edges').innerHTML=state.graph.edges.map(x=>item(x.from+' → '+x.to,x.relation)).join('');
  }catch(e){document.getElementById('graph-edges').innerHTML='<div class="error">'+esc(e.message)+'</div>'}
}
document.getElementById('attack-run').onclick=async()=>{
  const id=document.getElementById('attack-id').value.trim().toUpperCase();
  const l=document.getElementById('attack-loader');l.classList.add('show');
  try{document.getElementById('attack-result').textContent=JSON.stringify(await jsonFetch('/api/attack/'+encodeURIComponent(id)),null,2)}
  catch(e){document.getElementById('attack-result').textContent='ERRO: '+e.message}
  finally{l.classList.remove('show')}
};
document.getElementById('sync-run').onclick=async()=>{
  const l=document.getElementById('attack-loader');l.classList.add('show');
  try{
    const data=await jsonFetch('/api/standards/sync',{method:'POST'});
    document.getElementById('attack-result').textContent=JSON.stringify(data,null,2);
    state.status=await jsonFetch('/api/status');renderStatus();
  }catch(e){document.getElementById('attack-result').textContent='ERRO: '+e.message}
  finally{l.classList.remove('show')}
};
document.getElementById('ai-run').onclick=async()=>{
  const text=document.getElementById('ai-text').value;
  const l=document.getElementById('ai-loader');l.classList.add('show');
  try{
    const data=await jsonFetch('/api/ai',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text,source_id:'UI-SOURCE-001'})});
    document.getElementById('ai-result').textContent=JSON.stringify(data,null,2);
  }catch(e){document.getElementById('ai-result').textContent='ERRO: '+e.message}
  finally{l.classList.remove('show')}
};
boot();
</script>
</body>
</html>
""";
