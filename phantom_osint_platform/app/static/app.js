const $ = (id) => document.getElementById(id);
const resultView = $("result-view");
const resultStatus = $("result-status");
const toast = $("toast");

function pretty(value){return JSON.stringify(value,null,2)}
function showToast(message){toast.textContent=message;toast.classList.add("show");setTimeout(()=>toast.classList.remove("show"),2400)}
function render(data){resultView.innerHTML=`<pre>${escapeHtml(pretty(data))}</pre>`}
function escapeHtml(value){return String(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")}
function setBusy(label){resultStatus.textContent=`RUNNING // ${label}`;resultStatus.className="result-status busy"}
function setReady(ok=true){resultStatus.textContent=ok?"COMPLETE // Output received":"ERROR // Safe failure response";resultStatus.className=ok?"result-status":"result-status error"}

async function apiGet(path, params){
  const qs=new URLSearchParams(params);
  const response=await fetch(`${path}?${qs.toString()}`,{headers:{"Accept":"application/json"}});
  let data;
  try{data=await response.json()}catch{data={ok:false,error:`HTTP ${response.status}`}}
  return data;
}
async function apiPost(path, body){
  const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify(body)});
  let data;
  try{data=await response.json()}catch{data={ok:false,error:`HTTP ${response.status}`}}
  return data;
}
async function run(label, fn){setBusy(label);try{const data=await fn();render(data);setReady(data?.ok!==false);if(data?.ok===false)showToast(data.error||"Operation failed");return data}catch(err){const data={ok:false,error:"Client-side request failed safely.",details:String(err)};render(data);setReady(false);showToast(data.error);return data}}

function setupTabs(){document.querySelectorAll(".tab").forEach(btn=>btn.addEventListener("click",()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));btn.classList.add("active");document.querySelectorAll(".tool-panel").forEach(x=>x.classList.add("hidden"));$("panel-"+btn.dataset.tab).classList.remove("hidden")}))}

$("ip-form").addEventListener("submit",e=>{e.preventDefault();run("IP INTELLIGENCE",()=>apiGet("/api/ip",{target:$("ip-input").value}))});
$("domain-form").addEventListener("submit",e=>{e.preventDefault();run("DOMAIN RECON",()=>apiGet("/api/domain",{domain:$("domain-input").value}))});
$("username-form").addEventListener("submit",e=>{e.preventDefault();run("USERNAME FOOTPRINT",()=>apiGet("/api/username",{username:$("username-input").value}))});
$("email-form").addEventListener("submit",e=>{e.preventDefault();run("EMAIL EXPOSURE",()=>apiGet("/api/email",{email:$("email-input").value}))});
$("url-form").addEventListener("submit",e=>{e.preventDefault();run("WEB TARGET AUDIT",()=>apiGet("/api/url",{url:$("url-input").value}))});

$("hash-btn").addEventListener("click",()=>run("HASH ANALYSIS",()=>apiPost("/api/hash",{value:$("hash-value").value,algorithm:$("hash-alg").value}).then(data=>{$("hash-output").textContent=pretty(data);return data})));
$("dork-btn").addEventListener("click",()=>run("DORK GENERATOR",()=>apiGet("/api/dorks",{target:$("dork-target").value,kind:$("dork-kind").value,keyword:$("dork-keyword").value,extension:$("dork-ext").value}).then(data=>{$("dork-output").textContent=pretty(data);return data})));
$("cidr-btn").addEventListener("click",()=>run("CIDR CALCULATOR",()=>apiGet("/api/cidr",{cidr:$("cidr-input").value}).then(data=>{$("cidr-output").textContent=pretty(data);return data})));
$("entropy-btn").addEventListener("click",()=>run("PASSWORD ENTROPY",()=>apiPost("/api/entropy",{password:$("entropy-input").value}).then(data=>{$("entropy-output").textContent=pretty(data);return data})));
$("hook-btn").addEventListener("click",()=>run("WEBHOOK PAYLOAD",()=>apiPost("/api/webhook",{url:$("hook-url").value,event:$("hook-event").value}).then(data=>{$("hook-output").textContent=pretty(data);return data})));

$("clear-btn").addEventListener("click",()=>{render({status:"ready",message:"Console cleared."});resultStatus.textContent="READY // Awaiting operation";resultStatus.className="result-status"});

setupTabs();
if(window.lucide){window.lucide.createIcons()}
