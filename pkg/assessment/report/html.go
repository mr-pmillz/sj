package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"slices"
	"strings"
)

type htmlReportView struct {
	Snapshot
	SuppressedDisproved            int
	SuppressedDisprovedComparisons int
}

func newHTMLReportView(snapshot Snapshot) htmlReportView {
	view := htmlReportView{
		Snapshot:                       snapshot,
		SuppressedDisproved:            snapshot.SuppressedDisprovedFindings,
		SuppressedDisprovedComparisons: snapshot.SuppressedDisprovedComparisons,
	}
	view.Findings = make([]Finding, 0, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		if strings.EqualFold(strings.TrimSpace(finding.Status), "disproved") {
			view.SuppressedDisproved++
			continue
		}
		view.Findings = append(view.Findings, finding)
	}
	slices.SortStableFunc(view.Findings, func(left, right Finding) int {
		if rank := severityRank(right.Severity) - severityRank(left.Severity); rank != 0 {
			return rank
		}
		return strings.Compare(left.ID, right.ID)
	})
	view.Comparisons = make([]Comparison, 0, len(snapshot.Comparisons))
	for _, comparison := range snapshot.Comparisons {
		if strings.EqualFold(strings.TrimSpace(comparison.Outcome), "disproved") {
			view.SuppressedDisprovedComparisons++
			continue
		}
		view.Comparisons = append(view.Comparisons, comparison)
	}
	return view
}

func renderHTML(snapshot Snapshot) ([]byte, error) {
	view := newHTMLReportView(snapshot)
	const document = `<!doctype html>
<html lang="en" data-theme="light" data-bs-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="application-name" content="sj authorized API assessment">
<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; connect-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; script-src &#39;unsafe-inline&#39;; img-src data:; base-uri &#39;none&#39;; form-action &#39;none&#39;">
<title>sj Assessment {{.Assessment.ID}}</title>
<style>
:root{color-scheme:light;--bg:#f4f7f6;--panel:#fff;--text:#13201c;--muted:#61716b;--line:#d8e2de;--head:#edf5f1;--accent:#059669;--accent-2:#0f766e;--nav:#071e18;--danger:#dc3545;--warn:#b7791f;--ok:#198754;--code:#f2f7f5;--shadow:0 14px 36px rgba(7,30,24,.08)}
[data-theme=dark]{color-scheme:dark;--bg:#07110e;--panel:#0e1c18;--text:#e5f2ed;--muted:#9bb0a8;--line:#263c35;--head:#142822;--accent:#34d399;--accent-2:#5eead4;--nav:#030b09;--danger:#ff7b8a;--warn:#f6c76d;--ok:#6ee7a8;--code:#081310;--shadow:0 18px 42px rgba(0,0,0,.28)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.container-fluid{max-width:1680px;margin:0 auto;padding:26px}.topbar{position:sticky;top:0;z-index:20;background:var(--nav);color:#e8fff7;border-bottom:1px solid rgba(110,231,183,.18);box-shadow:0 8px 24px rgba(0,0,0,.15)}.topbar-inner{max-width:1680px;margin:auto;padding:12px 26px;display:flex;gap:16px;align-items:center;justify-content:space-between}.brand{font-weight:800;letter-spacing:.01em}.brand-mark{display:inline-grid;place-items:center;width:30px;height:30px;margin-right:9px;border-radius:8px;background:linear-gradient(135deg,#10b981,#0f766e);color:#fff;font:800 15px/1 ui-monospace,monospace}.topbar .btn{background:rgba(255,255,255,.06);border-color:rgba(255,255,255,.2);color:#effff9}.nav-links{display:flex;gap:6px;flex-wrap:wrap}.nav-links a{color:#b8d8cd;text-decoration:none;padding:6px 8px;border-radius:6px}.nav-links a:hover{background:rgba(52,211,153,.12);color:#fff}.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:7px;padding:7px 11px;cursor:pointer;font:inherit}.btn:hover,.btn:focus-visible{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(16,185,129,.14)}.btn-sm{padding:4px 8px;font-size:12px}.hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:22px;align-items:end;margin:24px 0;padding:24px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(135deg,var(--panel),var(--head));box-shadow:var(--shadow)}.kicker{color:var(--accent);font-weight:800;text-transform:uppercase;font-size:11px;letter-spacing:.13em}.hero h1{font:750 clamp(22px,3vw,34px)/1.12 ui-monospace,SFMono-Regular,Menlo,monospace;margin:7px 0 11px;overflow-wrap:anywhere}.meta{color:var(--muted);overflow-wrap:anywhere}.sensitive-banner{border:1px solid color-mix(in srgb,var(--warn) 42%,var(--line));background:color-mix(in srgb,var(--warn) 10%,var(--panel));padding:10px 13px;border-radius:8px;margin:14px 0}.cards{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin:18px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:15px;box-shadow:0 6px 20px rgba(7,30,24,.04)}.stat{font-size:25px;font-weight:800;font-variant-numeric:tabular-nums}.label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.origin-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px 14px;max-height:245px;overflow:auto;padding:9px;background:var(--code);border:1px solid var(--line);border-radius:8px}.origin-list code{display:block}.section{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:17px 0;padding:17px;box-shadow:0 8px 24px rgba(7,30,24,.04)}.section h2{margin:0;font-size:18px}.table-responsive{overflow:auto;border:1px solid var(--line);border-radius:9px}.table{width:100%;border-collapse:collapse;background:var(--panel)}.table th,.table td{border-bottom:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top}.table th{position:sticky;top:0;background:var(--head);font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap;cursor:pointer;user-select:none}.table th:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}.table-striped tbody tr:nth-child(even){background:color-mix(in srgb,var(--head) 65%,transparent)}.table tbody tr:hover{background:color-mix(in srgb,var(--accent) 7%,var(--panel))}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}code{overflow-wrap:anywhere}pre{white-space:pre-wrap;word-break:break-word;margin:.4rem 0 0;background:var(--code);border:1px solid var(--line);border-radius:7px;padding:11px;max-height:360px;overflow:auto}.http-exchange{min-width:420px}.http-line{display:flex;gap:8px;align-items:center;margin-bottom:6px}.badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.03em}.sev-critical,.sev-high{background:rgba(220,53,69,.16);color:var(--danger)}.sev-medium{background:rgba(240,173,78,.18);color:var(--warn)}.sev-low{background:rgba(25,135,84,.16);color:var(--ok)}.sev-info,.sev-informational{background:rgba(100,116,139,.16);color:var(--muted)}.toolbar{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:11px}.control{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.form-control,.form-select{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:7px;padding:7px 9px;font:inherit}.form-control{min-width:230px}.pager,.pagination{display:flex;gap:6px;align-items:center;justify-content:flex-end;margin-top:11px}.page-numbers{display:flex;gap:4px}.page-current{background:var(--accent);border-color:var(--accent);color:#fff}.muted{color:var(--muted)}.notice{border-left:4px solid var(--warn);background:rgba(240,173,78,.12);padding:10px;border-radius:6px}.empty{padding:20px;text-align:center;color:var(--muted)}.evidence-hidden .raw-evidence{display:none}.raw-evidence[hidden]{display:none}@media (max-width:1050px){.hero,.grid{grid-template-columns:1fr}.cards{grid-template-columns:repeat(3,minmax(0,1fr))}.nav-links{display:none}}@media (max-width:620px){.container-fluid{padding:14px}.topbar-inner{align-items:flex-start;flex-direction:column;padding:10px 14px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.origin-list{grid-template-columns:1fr}.form-control{min-width:0;width:100%}.control{width:100%}.http-exchange{min-width:280px}}
</style>
</head>
<body class="sj-report">
<div class="topbar"><div class="topbar-inner"><div class="brand"><span class="brand-mark">sj</span>authorized API assessment</div><nav class="nav-links" aria-label="Report sections"><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#requests">Requests &amp; responses</a><a href="#coverage">Coverage</a><a href="#provenance">Provenance</a></nav><div class="control"><button class="btn evidence-toggle" id="evidence-toggle" type="button" aria-label="Toggle all evidence" aria-expanded="true">Hide Evidence</button><button class="btn" id="theme-toggle" type="button" aria-label="Toggle light and dark theme" aria-pressed="false">Dark Mode</button></div></div></div>
<main class="container-fluid">
<section class="hero" id="overview"><div><div class="kicker">SJ / authorized API assessment</div><h1>{{.Assessment.ID}}</h1><div class="meta">Status <code>{{.Assessment.Status}}</code> · Started {{.Assessment.StartedAt}} · Scope <code>{{.Scope.Digest}}</code></div></div><div class="meta">Plan integrity<br><code>{{.Plan.Digest}}</code></div></section>
<div class="sensitive-banner"><strong>Sensitive assessment evidence.</strong> Actual persisted request and response material may be present in this file. Keep it owner-only (<code>0600</code>) and share it deliberately.</div>
<section class="cards"><div class="card"><div class="stat">{{.Counts.Planned}}</div><div class="label">Planned</div></div><div class="card"><div class="stat">{{.Counts.Executed}}</div><div class="label">Executed</div></div><div class="card"><div class="stat">{{.Counts.Skipped}}</div><div class="label">Skipped</div></div><div class="card"><div class="stat">{{.Counts.Retried}}</div><div class="label">Retried</div></div><div class="card"><div class="stat">{{.Counts.Verified}}</div><div class="label">Verified</div></div><div class="card"><div class="stat">{{len .Findings}}</div><div class="label">Actionable findings</div></div></section>
<section class="grid">
<div class="section"><h2>Scope</h2><p class="muted">Policy <code>{{.Policy.Digest}}</code><br>Manifest <code>{{.Plan.ManifestDigest}}</code><br>Inventory <code>{{.Plan.InventoryDigest}}</code></p><div class="origin-list">{{range .Scope.Origins}}<code>{{.}}</code>{{else}}<span class="muted">No origins recorded.</span>{{end}}</div></div>
<div class="section">{{template "tableOpen" args "Modules and Identities" "modules-table" "modules"}}<thead><tr><th aria-sort="none">Module</th><th aria-sort="none">Version</th></tr></thead><tbody>{{range .Modules}}<tr><td>{{.Name}}</td><td>{{empty .Version "unknown"}}</td></tr>{{end}}</tbody>{{template "tableClose" args "modules-table"}}<p class="muted">{{range $i, $v := .Identities}}{{if $i}}, {{end}}{{$v.Label}}{{else}}No identities recorded.{{end}}</p></div>
</section>
<section class="section" id="coverage">{{template "tableOpen" args "Coverage" "coverage-table" "coverage"}}<thead><tr><th aria-sort="none" tabindex="0">Dimension</th><th aria-sort="none" tabindex="0">Value</th><th aria-sort="none" tabindex="0">Planned</th><th aria-sort="none" tabindex="0">Executed</th><th aria-sort="none" tabindex="0">Skipped</th><th aria-sort="none" tabindex="0">Verified</th><th aria-sort="none" tabindex="0">Inconclusive</th></tr></thead><tbody>{{range .Coverage.Module}}{{template "coverage" pair "module" .}}{{end}}{{range .Coverage.Identity}}{{template "coverage" pair "identity" .}}{{end}}{{range .Coverage.Object}}{{template "coverage" pair "object" .}}{{end}}{{range .Coverage.Risk}}{{template "coverage" pair "risk" .}}{{end}}</tbody>{{template "tableClose" args "coverage-table"}}</section>
{{if .StopReasons}}<section class="section">{{template "tableOpen" args "Stop Reasons" "stop-reasons-table" "stop-reasons"}}<thead><tr><th aria-sort="none">Source</th><th aria-sort="none">Reason</th></tr></thead><tbody>{{range .StopReasons}}<tr><td>{{.Source}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody>{{template "tableClose" args "stop-reasons-table"}}</section>{{end}}
<section class="section" id="findings">{{template "tableOpen" args "Actionable findings" "findings-table" "findings"}}<thead><tr><th aria-sort="none" tabindex="0">ID</th><th aria-sort="none" tabindex="0">Status</th><th aria-sort="none" tabindex="0">Confidence</th><th aria-sort="none" tabindex="0" data-sort-type="severity">Severity</th><th aria-sort="none" tabindex="0">Category</th><th aria-sort="none" tabindex="0">OWASP</th><th aria-sort="none" tabindex="0">CWE</th><th aria-sort="none" tabindex="0">Method</th><th aria-sort="none" tabindex="0">Origin</th><th aria-sort="none" tabindex="0">Title</th><th aria-sort="none" tabindex="0">Evidence</th></tr></thead><tbody>{{range .Findings}}<tr data-finding-id="{{.ID}}"><td><code>{{.ID}}</code></td><td>{{.Status}}</td><td>{{.Confidence}}</td><td data-sort-rank="{{severityRank .Severity}}"><span class="badge {{severity .Severity}}">{{.Severity}}</span></td><td>{{.Category}}</td><td>{{join .OWASP}}</td><td>{{join .CWE}}</td><td>{{.Method}}</td><td><code>{{.Origin}}</code></td><td>{{.Title}}</td><td>{{if .Evidence.Available}}<button class="btn btn-sm evidence-toggle" type="button" aria-controls="evidence-{{.ID}}" aria-expanded="true">Hide evidence</button><pre class="raw-evidence" id="evidence-{{.ID}}">{{.Evidence.Raw}}</pre>{{else}}No persisted evidence metadata{{end}}</td></tr>{{end}}</tbody>{{template "tableClose" args "findings-table"}}{{if .SuppressedDisproved}}<p class="muted">{{.SuppressedDisproved}} false-positive control result(s) were suppressed from Findings. Their request/response evidence remains available below.</p>{{end}}{{if not .Findings}}<p class="empty">No actionable findings. False-positive controls are intentionally excluded.</p>{{end}}</section>
<section class="section" id="requests">{{template "tableOpen" args "Requests & Responses" "attempts-table" "attempts" "attempts-data"}}<thead><tr><th aria-sort="none" tabindex="0">ID</th><th aria-sort="none" tabindex="0">#</th><th aria-sort="none" tabindex="0">Status</th><th aria-sort="none" tabindex="0">Request</th><th aria-sort="none" tabindex="0">Response</th><th aria-sort="none" tabindex="0">Metadata</th></tr></thead><tbody></tbody>{{template "tableClose" args "attempts-table"}}<script id="attempts-data" type="application/json">{{json .Attempts}}</script></section>
<section class="section" id="provenance">{{template "tableOpen" args "Comparisons" "comparisons-table" "comparisons"}}<thead><tr><th aria-sort="none" tabindex="0">ID</th><th aria-sort="none" tabindex="0">Left</th><th aria-sort="none" tabindex="0">Right</th><th aria-sort="none" tabindex="0">Oracle</th><th aria-sort="none" tabindex="0">Outcome</th><th aria-sort="none" tabindex="0">Details</th></tr></thead><tbody>{{range .Comparisons}}<tr data-comparison-id="{{.ID}}"><td><code>{{.ID}}</code></td><td><code>{{.LeftAttemptID}}</code></td><td><code>{{.RightAttemptID}}</code></td><td>{{.Oracle}}</td><td>{{.Outcome}}</td><td>{{if .Details}}<pre class="raw-evidence">{{.Details}}</pre>{{else}}No comparison details retained{{end}}</td></tr>{{end}}</tbody>{{template "tableClose" args "comparisons-table"}}{{if .SuppressedDisprovedComparisons}}<p class="muted">{{.SuppressedDisprovedComparisons}} false-positive comparison result(s) were suppressed. Underlying request/response rows remain available above.</p>{{end}}{{if not .Comparisons}}<p class="empty">No actionable comparisons.</p>{{end}}</section>
<section class="section">{{template "tableOpen" args "Evidence artifacts" "artifacts-table" "artifacts" "artifacts-data"}}<thead><tr><th aria-sort="none" tabindex="0">ID</th><th aria-sort="none" tabindex="0">Attempt</th><th aria-sort="none" tabindex="0">Kind</th><th aria-sort="none" tabindex="0">Content Type</th><th aria-sort="none" tabindex="0">Bytes</th><th aria-sort="none" tabindex="0">SHA256</th><th aria-sort="none" tabindex="0">Sensitive</th><th aria-sort="none" tabindex="0">Truncated</th><th aria-sort="none" tabindex="0">Metadata</th></tr></thead><tbody></tbody>{{template "tableClose" args "artifacts-table"}}<script id="artifacts-data" type="application/json">{{json .Artifacts}}</script></section>
{{if truncated .Truncation}}<section class="notice">Report output was bounded; canonical truncation totals are available in the JSON report.</section>{{end}}
</main>
<script>
(function(){
  const root=document.documentElement;
  function storageGet(key){try{return window.localStorage.getItem(key)}catch(_){return null}}
  function storageSet(key,value){try{window.localStorage.setItem(key,value)}catch(_){}}
  const savedTheme=storageGet('sj-report-theme');
  const prefersDark=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;
  if(savedTheme==='dark'||(!savedTheme&&prefersDark)){root.setAttribute('data-theme','dark');root.setAttribute('data-bs-theme','dark')}
  const theme=document.getElementById('theme-toggle');
  function labelTheme(){const dark=root.getAttribute('data-theme')==='dark';theme.textContent=dark?'Light mode':'Dark mode';theme.setAttribute('aria-pressed',String(dark))}
  labelTheme();
  theme.addEventListener('click',function(){const next=root.getAttribute('data-theme')==='dark'?'light':'dark';root.setAttribute('data-theme',next);root.setAttribute('data-bs-theme',next);storageSet('sj-report-theme',next);labelTheme()});

  const evidence=document.getElementById('evidence-toggle');
  if(storageGet('sj-report-evidence')==='hidden'){document.body.classList.add('evidence-hidden')}
  function labelEvidence(){const hidden=document.body.classList.contains('evidence-hidden');evidence.textContent=hidden?'Show all evidence':'Hide all evidence';evidence.setAttribute('aria-expanded',String(!hidden))}
  labelEvidence();
  evidence.addEventListener('click',function(){document.body.classList.toggle('evidence-hidden');storageSet('sj-report-evidence',document.body.classList.contains('evidence-hidden')?'hidden':'shown');labelEvidence()});
  document.querySelectorAll('button[aria-controls^="evidence-"]').forEach(function(button){
    const panel=document.getElementById(button.getAttribute('aria-controls'));
    if(!panel)return;
    button.addEventListener('click',function(){const hidden=!panel.hidden;panel.hidden=hidden;button.setAttribute('aria-expanded',String(!hidden));button.textContent=hidden?'Show evidence':'Hide evidence'});
  });

  function appendElement(parent,tag,className,text){
    const element=document.createElement(tag);
    if(className)element.className=className;
    if(text!==undefined&&text!==null)element.textContent=String(text);
    parent.appendChild(element);
    return element;
  }
  function appendEvidence(parent,label,value){
    appendElement(parent,'strong','',label);
    appendElement(parent,'pre','raw-evidence',value);
  }
  function appendHeaders(parent,headers){
    if(headers&&Object.keys(headers).length){appendEvidence(parent,'Headers',JSON.stringify(headers,null,2))}
  }
  function appendBody(parent,label,body,isBase64,truncated){
    if(body){appendEvidence(parent,label+(isBase64?' (base64)':''),body)}
    else{appendElement(parent,'div','muted','Empty '+label.toLowerCase())}
    if(truncated){appendElement(parent,'div','notice',label+' was truncated at the authorized artifact limit.')}
  }
  function appendUnavailable(parent,label){
    appendElement(parent,'div','muted','Raw '+label.toLowerCase()+' not retained by assessment policy');
  }
  function buildAttemptRow(record){
    const row=document.createElement('tr');row.setAttribute('data-attempt-id',record.id);
    appendElement(appendElement(row,'td'),'code','',record.id);
    appendElement(row,'td','',record.ordinal);
    appendElement(row,'td','',record.status);
    const request=appendElement(row,'td','http-exchange');
    const requestLine=appendElement(request,'div','http-line');
    appendElement(requestLine,'span','badge',record.method);
    appendElement(requestLine,'code','',record.origin);
    if(record.exchange_available){
      appendHeaders(request,record.request_headers);
      appendBody(request,'Request body',record.request_body,record.request_body_base64,record.request_truncated);
    }else{appendUnavailable(request,'request body')}
    const response=appendElement(row,'td','http-exchange');
    const responseLine=appendElement(response,'div','http-line');
    appendElement(responseLine,'strong','','HTTP '+String(record.http_status||0));
    if(record.exchange_available){
      appendHeaders(response,record.response_headers);
      appendBody(response,'Response body',record.response_body,record.response_body_base64,record.response_truncated);
    }else{appendUnavailable(response,'response body')}
    const metadata=appendElement(row,'td');
    if(record.message)appendElement(metadata,'div','',record.message);
    if(record.evidence)appendElement(metadata,'pre','raw-evidence',record.evidence);
    const fingerprints=appendElement(metadata,'div','muted');
    appendElement(fingerprints,'span','','Request ');
    appendElement(fingerprints,'code','',record.request_fingerprint||'');
    appendElement(fingerprints,'br');
    appendElement(fingerprints,'span','','Response ');
    appendElement(fingerprints,'code','',record.response_fingerprint||'');
    return row;
  }
  function buildArtifactRow(record){
    const row=document.createElement('tr');row.setAttribute('data-artifact-id',record.id);
    appendElement(appendElement(row,'td'),'code','',record.id);
    appendElement(appendElement(row,'td'),'code','',record.attempt_id||'');
    appendElement(row,'td','',record.kind);
    appendElement(row,'td','',record.content_type);
    appendElement(row,'td','',record.size_bytes);
    appendElement(appendElement(row,'td'),'code','',record.sha256);
    appendElement(row,'td','',record.sensitive);
    appendElement(row,'td','',record.truncated);
    const metadata=appendElement(row,'td');
    if(record.metadata)appendElement(metadata,'pre','raw-evidence',record.metadata);
    else appendElement(metadata,'span','muted','No additional artifact metadata');
    return row;
  }
  function buildDeferredRow(tableID,record){
    if(tableID==='attempts-table')return buildAttemptRow(record);
    if(tableID==='artifacts-table')return buildArtifactRow(record);
    throw new Error('Unsupported deferred table '+tableID);
  }
  function deferredSortValue(tableID,record,index){
    if(tableID==='attempts-table'){
      const values=[record.id,record.ordinal,record.status,
        [record.method,record.origin,JSON.stringify(record.request_headers||{}),record.request_body||''].join(' '),
        [record.http_status,JSON.stringify(record.response_headers||{}),record.response_body||''].join(' '),
        [record.message||'',record.evidence||'',record.request_fingerprint||'',record.response_fingerprint||''].join(' ')];
      return values[index];
    }
    const values=[record.id,record.attempt_id||'',record.kind,record.content_type,record.size_bytes,record.sha256,record.sensitive,record.truncated,record.metadata||''];
    return values[index];
  }

  document.querySelectorAll('[data-sj-table]').forEach(function(table){
    const tbody=table.tBodies[0];if(!tbody)return;
    const id=table.id;
    const sourceID=table.getAttribute('data-sj-source');
    const source=sourceID?document.getElementById(sourceID):null;
    const deferred=Boolean(source);
    let allRows=Array.from(tbody.rows);
    if(source){
      try{allRows=JSON.parse(source.textContent)}
      catch(error){allRows=[];appendElement(table.parentElement,'div','notice','Evidence data could not be decoded: '+error.message)}
    }
    const filter=document.querySelector('[data-sj-search-for="'+id+'"]');
    const size=document.querySelector('[data-sj-page-size-for="'+id+'"]');
    const label=document.querySelector('[data-sj-page-label-for="'+id+'"]');
    const pager=document.querySelector('[data-sj-pager-for="'+id+'"]');
    const pageNumbers=document.querySelector('[data-sj-pages-for="'+id+'"]');
    const headers=Array.from(table.tHead.rows[0].querySelectorAll('th'));
    let page=0,sortIndex=-1,sortDir=1;
    function comparisonValue(row,index,header){
      if(deferred)return deferredSortValue(id,row,index);
      const cell=row.cells[index];
      if(header.getAttribute('data-sort-type')==='severity'){return Number(cell.getAttribute('data-sort-rank')||0)}
      return cell.textContent.trim();
    }
    function filteredRows(){
      const q=filter.value.trim().toLowerCase();
      let rows=allRows.filter(function(row){const text=deferred?JSON.stringify(row):row.textContent;return !q||text.toLowerCase().indexOf(q)!==-1});
      if(sortIndex>=0){const header=headers[sortIndex];rows=rows.slice().sort(function(a,b){const left=comparisonValue(a,sortIndex,header);const right=comparisonValue(b,sortIndex,header);if(typeof left==='number'&&typeof right==='number'){return(left-right)*sortDir}return String(left).localeCompare(String(right),undefined,{numeric:true,sensitivity:'base'})*sortDir})}
      return rows;
    }
    function pageButton(number,current){
      const button=document.createElement('button');button.type='button';button.className='btn btn-sm'+(current?' page-current':'');button.textContent=String(number+1);button.setAttribute('data-page-number',String(number));button.setAttribute('aria-label','Page '+String(number+1));if(current)button.setAttribute('aria-current','page');return button;
    }
    function render(){
      const rows=filteredRows(),per=parseInt(size.value,10)||25,pages=Math.max(1,Math.ceil(rows.length/per));
      page=Math.max(0,Math.min(page,pages-1));tbody.textContent='';
      rows.slice(page*per,page*per+per).forEach(function(row){tbody.appendChild(deferred?buildDeferredRow(id,row):row)});
      label.textContent=(rows.length?String(page*per+1)+'–'+String(Math.min(rows.length,(page+1)*per)):'0')+' of '+rows.length;
      pageNumbers.textContent='';
      const start=Math.max(0,page-2),end=Math.min(pages,start+5);
      for(let number=start;number<end;number++){pageNumbers.appendChild(pageButton(number,number===page))}
      pager.querySelector('[data-page="prev"]').disabled=page===0;
      pager.querySelector('[data-page="next"]').disabled=page>=pages-1;
    }
    function sortBy(index){
      const header=headers[index],firstDirection=header.getAttribute('data-sort-type')==='severity'?-1:1;
      sortDir=sortIndex===index?sortDir*-1:firstDirection;sortIndex=index;page=0;
      headers.forEach(function(item,itemIndex){item.setAttribute('aria-sort',itemIndex===index?(sortDir===1?'ascending':'descending'):'none')});
      render();
    }
    headers.forEach(function(header,index){header.addEventListener('click',function(){sortBy(index)});header.addEventListener('keydown',function(event){if(event.key==='Enter'||event.key===' '){event.preventDefault();sortBy(index)}})});
    filter.addEventListener('input',function(){page=0;render()});
    size.addEventListener('change',function(){page=0;render()});
    pager.addEventListener('click',function(event){const action=event.target.getAttribute('data-page'),number=event.target.getAttribute('data-page-number');if(action==='prev')page--;if(action==='next')page++;if(number!==null)page=Number(number);render()});
    render();
  });
})();
</script>
</body>
</html>
{{define "tableOpen"}}{{$title := index . 0}}{{$id := index . 1}}{{$name := index . 2}}<div class="toolbar"><h2>{{$title}}</h2><div class="control"><label for="{{$id}}-filter">Search</label><input class="form-control" id="{{$id}}-filter" type="search" placeholder="Search {{$title}}" aria-label="Search {{$title}}" data-sj-search-for="{{$id}}"><label for="{{$id}}-page-size">Rows</label><select class="form-select" id="{{$id}}-page-size" aria-label="Rows per page for {{$title}}" data-sj-page-size-for="{{$id}}"><option selected>10</option><option>25</option><option>50</option><option>100</option></select></div></div><div class="table-responsive"><table class="table table-striped report-table" id="{{$id}}" data-sj-table="{{$name}}" data-table="{{$name}}"{{if gt (len .) 3}} data-sj-source="{{index . 3}}"{{end}}>{{end}}
{{define "tableClose"}}{{$id := index . 0}}</table></div><div class="pager" data-sj-pager-for="{{$id}}"><span class="pagination"></span><button class="btn btn-sm" data-page="prev" type="button" aria-label="Previous page">Previous</button><span class="page-numbers" data-sj-pages-for="{{$id}}"></span><span class="muted" aria-live="polite" data-sj-page-label-for="{{$id}}" id="{{$id}}-page-label"></span><button class="btn btn-sm" data-page="next" type="button" aria-label="Next page">Next</button></div>{{end}}
{{define "coverage"}}<tr><td>{{index . 0}}</td>{{$m := index . 1}}<td>{{$m.Value}}</td><td>{{$m.Planned}}</td><td>{{$m.Executed}}</td><td>{{$m.Skipped}}</td><td>{{$m.Verified}}</td><td>{{$m.Inconclusive}}</td></tr>{{end}}`
	functions := template.FuncMap{
		"args":  func(values ...string) []string { return values },
		"empty": emptyAs,
		"join":  func(values []string) string { return strings.Join(values, ", ") },
		"pair":  func(dimension string, metric CoverageMetric) []any { return []any{dimension, metric} },
		"json": func(value any) (template.JS, error) {
			encoded, err := json.Marshal(value)
			if err != nil {
				return "", err
			}
			// encoding/json escapes HTML-significant runes, including any
			// target-controlled closing script sequence. The result is safe
			// inert application/json, not executable JavaScript.
			return template.JS(encoded), nil // #nosec G203 -- produced only by encoding/json.
		},
		"severity": func(value string) string {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized == "" {
				normalized = "info"
			}
			return "sev-" + normalized
		},
		"severityRank": severityRank,
		"truncated": func(value Truncation) bool {
			return value.Modules || value.PlanNodeDigests || value.Findings || value.StopReasons || value.Coverage || value.Identities || value.Origins
		},
	}
	parsed, err := template.New("assessment").Funcs(functions).Parse(document)
	if err != nil {
		return nil, fmt.Errorf("parse assessment HTML template: %w", err)
	}
	var output bytes.Buffer
	if err := parsed.Execute(&output, view); err != nil {
		return nil, fmt.Errorf("render assessment HTML: %w", err)
	}
	return output.Bytes(), nil
}
