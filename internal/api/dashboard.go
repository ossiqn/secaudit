package api

import "net/http"

const dashboardHTML = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecAudit</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#060918;color:#c9d1d9;min-height:100vh}
.container{max-width:960px;margin:0 auto;padding:24px}
.header{text-align:center;padding:60px 0 40px}
.logo{font-size:2.8em;font-weight:800;letter-spacing:-1px;color:#fff}
.logo i{color:#3b82f6;margin-right:8px}
.logo span{background:linear-gradient(135deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.tagline{color:#6b7280;font-size:1.05em;margin-top:10px;font-weight:400}
.card{background:#0d1117;border:1px solid #1c2333;border-radius:16px;padding:32px;margin-bottom:24px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#3b82f633,transparent)}
.card-title{color:#f0f6fc;font-size:1.15em;font-weight:600;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.card-title i{color:#3b82f6;font-size:0.95em}
.search-box{display:flex;gap:12px}
.search-box input{flex:1;padding:14px 20px;border-radius:10px;border:1px solid #1c2333;background:#161b22;color:#f0f6fc;font-size:15px;transition:border-color 0.2s}
.search-box input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px #3b82f611}
.search-box input::placeholder{color:#484f58}
.btn{padding:14px 28px;border-radius:10px;border:none;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff}
.btn-primary:hover{background:linear-gradient(135deg,#60a5fa,#3b82f6);transform:translateY(-1px);box-shadow:0 4px 12px #3b82f633}
.btn-secondary{background:#161b22;color:#c9d1d9;border:1px solid #1c2333}
.btn-secondary:hover{background:#1c2333}
.btn:disabled{opacity:0.4;cursor:not-allowed;transform:none;box-shadow:none}
.score-wrap{text-align:center;padding:30px 0}
.score-ring{width:160px;height:160px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto;position:relative}
.score-ring::before{content:'';position:absolute;inset:-4px;border-radius:50%;background:conic-gradient(var(--ring-color) calc(var(--pct) * 1%),#1c2333 0);mask:radial-gradient(farthest-side,transparent calc(100% - 6px),#000 calc(100% - 5px))}
.score-inner{background:#0d1117;width:140px;height:140px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;position:relative;z-index:1}
.score-grade{font-size:3.2em;font-weight:800;line-height:1}
.score-pts{font-size:0.85em;color:#6b7280;margin-top:4px}
.color-a{--ring-color:#22c55e}.color-a .score-grade{color:#22c55e}
.color-b{--ring-color:#84cc16}.color-b .score-grade{color:#84cc16}
.color-c{--ring-color:#eab308}.color-c .score-grade{color:#eab308}
.color-d{--ring-color:#f97316}.color-d .score-grade{color:#f97316}
.color-f{--ring-color:#ef4444}.color-f .score-grade{color:#ef4444}
.section{margin:24px 0}
.section-head{display:flex;align-items:center;gap:8px;color:#8b949e;font-size:0.8em;text-transform:uppercase;letter-spacing:1.5px;font-weight:600;margin-bottom:12px}
.section-head i{font-size:0.9em;color:#3b82f6}
.row{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-radius:10px;margin-bottom:6px;background:#161b22;border:1px solid #1c2333;transition:border-color 0.2s}
.row:hover{border-color:#30363d}
.row-left{display:flex;flex-direction:column;gap:2px}
.row-name{font-weight:500;color:#f0f6fc;font-size:0.95em}
.row-detail{font-size:0.8em;color:#6b7280}
.badge{padding:4px 14px;border-radius:20px;font-size:0.78em;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
.badge-pass{background:#22c55e18;color:#22c55e;border:1px solid #22c55e33}
.badge-warn{background:#eab30818;color:#eab308;border:1px solid #eab30833}
.badge-fail{background:#ef444418;color:#ef4444;border:1px solid #ef444433}
.badge-info{background:#3b82f618;color:#3b82f6;border:1px solid #3b82f633}
.rec{display:flex;align-items:flex-start;gap:10px;padding:12px 16px;border-radius:10px;margin-bottom:6px;background:#161b22;border:1px solid #1c2333;font-size:0.9em;color:#8b949e}
.rec i{color:#f97316;margin-top:2px;flex-shrink:0}
.loading{text-align:center;padding:40px}
.loading .spinner{width:36px;height:36px;border:4px solid #1c2333;border-top:4px solid #3b82f6;border-radius:50%;animation:spin 0.7s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-text{color:#6b7280;font-size:0.95em}
.console{background:#0a0e14;border:1px solid #1c2333;border-radius:10px;padding:14px;margin-top:16px;max-height:180px;overflow-y:auto;font-family:'JetBrains Mono','Fira Code',monospace;font-size:0.78em;color:#3b82f6;line-height:1.6}
.hidden{display:none}
footer{text-align:center;color:#30363d;padding:40px 0 20px;font-size:0.8em}
footer a{color:#3b82f6;text-decoration:none}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="logo"><i class="fas fa-shield-halved"></i><span>SecAudit</span></div>
<p class="tagline">Web sitelerinin guvenlik analizini saniyeler icinde yapin</p>
</div>
<div class="card" id="phase-domain">
<div class="card-title"><i class="fas fa-globe"></i>Hedef Domain</div>
<div class="search-box">
<input type="text" id="domain" placeholder="example.com" onkeypress="if(event.key==='Enter')startScan()"/>
<button class="btn btn-primary" id="btn-scan" onclick="startScan()"><i class="fas fa-crosshairs"></i>Tara</button>
</div>
</div>
<div class="card hidden" id="phase-scan">
<div class="loading">
<div class="spinner"></div>
<div class="loading-text" id="scan-status">Tarama baslatiliyor...</div>
</div>
<div class="console" id="log"></div>
</div>
<div class="hidden" id="phase-report">
<div class="card">
<div class="card-title"><i class="fas fa-chart-line"></i>Sonuc: <span id="report-domain" style="color:#3b82f6"></span></div>
<div class="score-wrap" id="score-display"></div>
</div>
<div id="report-details"></div>
<div style="text-align:center;margin-top:24px">
<button class="btn btn-secondary" onclick="resetAll()"><i class="fas fa-rotate-right"></i>Yeni Tarama</button>
</div>
</div>
</div>
<footer>SecAudit <a href="#">GitHub</a></footer>
<script>
var currentDomain="";
var currentJobId="";
function log(msg){
var el=document.getElementById("log");
el.innerHTML+="<span style='color:#30363d'>"+new Date().toLocaleTimeString()+"</span> "+msg+"\n";
el.scrollTop=el.scrollHeight;
}
function show(id){document.getElementById(id).classList.remove("hidden")}
function hide(id){document.getElementById(id).classList.add("hidden")}
async function startScan(){
currentDomain=document.getElementById("domain").value.trim().toLowerCase();
currentDomain=currentDomain.replace(/^https?:\/\//,"").replace(/\/$/,"");
if(!currentDomain){return}
var btn=document.getElementById("btn-scan");
btn.disabled=true;
hide("phase-domain");
show("phase-scan");
log("Hedef: <span style='color:#f0f6fc'>"+currentDomain+"</span>");
log("Tarama kuyruga aliniyor...");
try{
var res=await fetch("/api/scan",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({domain:currentDomain})
});
var data=await res.json();
if(!res.ok)throw new Error(data.error);
currentJobId=data.job_id;
log("Job ID: "+currentJobId);
log("TLS, Header, DNS, Email, Dosya kontrolleri calisiyor...");
document.getElementById("scan-status").textContent="Analiz ediliyor...";
pollResult();
}catch(e){
log("<span style='color:#ef4444'>HATA: "+e.message+"</span>");
document.getElementById("scan-status").textContent="Hata olustu";
btn.disabled=false;
}
}
async function pollResult(){
try{
var res=await fetch("/api/report/"+currentJobId);
var data=await res.json();
if(data.status==="done"){
log("<span style='color:#22c55e'>Tarama tamamlandi</span>");
renderReport(data.result);
return;
}
if(data.status==="error"){
log("<span style='color:#ef4444'>Hata: "+data.error+"</span>");
document.getElementById("scan-status").textContent="Hata: "+data.error;
return;
}
setTimeout(pollResult,1500);
}catch(e){
setTimeout(pollResult,2000);
}
}
function renderReport(report){
hide("phase-scan");
show("phase-report");
document.getElementById("report-domain").textContent=currentDomain;
var score=report.score||{};
var grade=score.grade||"?";
var points=score.total_score||0;
var cc=grade[0]==="A"?"color-a":grade[0]==="B"?"color-b":grade[0]==="C"?"color-c":grade[0]==="D"?"color-d":"color-f";
document.getElementById("score-display").innerHTML="<div class='score-ring "+cc+"' style='--pct:"+points+"'><div class='score-inner'><div class='score-grade'>"+grade+"</div><div class='score-pts'>"+points+" / 100</div></div></div>";
var html="";
if(report.tls){
var t=report.tls;
html+=sec("fa-lock","TLS / SSL",[
row("TLS Baglantisi",t.connected?t.protocol:"Baglanti kurulamadi",t.connected?"pass":"fail"),
row("Sertifika Gecerliligi",t.cert_valid?(t.issuer||"Gecerli"):"Gecersiz",t.cert_valid?"pass":"fail"),
row("Sertifika Suresi",t.days_until_expiry+" gun kaldi",t.days_until_expiry>30?"pass":t.days_until_expiry>7?"warn":"fail")
]);
}
if(report.headers){
var h=report.headers;
html+=sec("fa-heading","Guvenlik Headerlari",[
row("Strict-Transport-Security",h.hsts_value||"Eksik",h.hsts_present?"pass":"fail"),
row("Content-Security-Policy",h.csp_present?"Mevcut":"Eksik",h.csp_present?"pass":"warn"),
row("X-Frame-Options",h.xframe_value||"Eksik",h.xframe_present?"pass":"warn"),
row("X-Content-Type-Options",h.xcto_value||"Eksik",h.xcto_present?"pass":"warn"),
row("Referrer-Policy",h.referrer_value||"Eksik",h.referrer_present?"pass":"info")
]);
if(h.server_header){
html+=rec("Server header bilgi sizdiriyor: "+h.server_header);
}
if(h.powered_by){
html+=rec("X-Powered-By header bilgi sizdiriyor: "+h.powered_by);
}
}
if(report.email){
var e=report.email;
html+=sec("fa-envelope-circle-check","Email Guvenligi",[
row("SPF",e.spf_record||"Bulunamadi",e.spf_found?"pass":"fail"),
row("DMARC",e.dmarc_record||"Bulunamadi",e.dmarc_found?"pass":"fail"),
row("DKIM",e.dkim_found?"Bulundu ("+e.dkim_selector+")":"Bulunamadi",e.dkim_found?"pass":"info"),
row("CAA",e.caa_found?"Mevcut":"Kayit yok",e.caa_found?"pass":"info"),
row("DNSSEC",e.dnssec_enabled?"Aktif":"Pasif",e.dnssec_enabled?"pass":"info")
]);
}
if(report.exposed){
var ex=report.exposed;
if(ex.found_files&&ex.found_files.length>0){
html+=sec("fa-folder-open","Acikta Kalan Dosyalar",ex.found_files.map(function(f){return row(f.path,"HTTP "+f.status+" - Erisime acik","fail")}));
}else{
html+=sec("fa-folder-closed","Acikta Kalan Dosyalar",[row("Hassas dosya tarandi","Acikta dosya bulunamadi","pass")]);
}
}
if(score.recommendations&&score.recommendations.length>0){
html+="<div class='card'><div class='card-title'><i class='fas fa-lightbulb' style='color:#f97316'></i>Oneriler</div>";
score.recommendations.forEach(function(r){html+=rec(r)});
html+="</div>";
}
document.getElementById("report-details").innerHTML=html;
}
function sec(icon,title,rows){
var html="<div class='card'><div class='section-head'><i class='fas "+icon+"'></i>"+title+"</div>";
rows.forEach(function(r){html+=r});
html+="</div>";
return html;
}
function row(name,detail,status){
var cls=status==="pass"?"badge-pass":status==="warn"?"badge-warn":status==="fail"?"badge-fail":"badge-info";
var label=status==="pass"?"PASS":status==="warn"?"WARN":status==="fail"?"FAIL":"INFO";
return "<div class='row'><div class='row-left'><span class='row-name'>"+name+"</span><span class='row-detail'>"+detail+"</span></div><span class='badge "+cls+"'>"+label+"</span></div>";
}
function rec(msg){
return "<div class='rec'><i class='fas fa-triangle-exclamation'></i><span>"+msg+"</span></div>";
}
function resetAll(){
currentDomain="";
currentJobId="";
document.getElementById("domain").value="";
document.getElementById("btn-scan").disabled=false;
hide("phase-scan");
hide("phase-report");
show("phase-domain");
document.getElementById("log").innerHTML="";
}
</script>
</body>
</html>`

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}