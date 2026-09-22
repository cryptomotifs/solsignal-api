"use strict";
const $ = (id) => document.getElementById(id);
const names = {"/tools/json/repair":"JSON repair","/tools/url/read":"Webpage to Markdown","/tools/pdf/markdown":"PDF text extraction","/tools/repo/preflight":"Repository preflight","/tools/defi/yields":"DeFi yield data","/tools/defi/protocols":"Protocol data","/tools/x402/ping":"Payment test ping"};
async function loadCatalog() {
  try {
    const response = await fetch("/tools/catalog", {signal: AbortSignal.timeout(15000)});
    if (!response.ok) throw new Error("catalog unavailable");
    const catalog = await response.json();
    const grid = $("tool-grid"); grid.replaceChildren();
    const tools = [...catalog.tools].sort((a,b) => Object.keys(names).indexOf(a.path)-Object.keys(names).indexOf(b.path));
    tools.forEach((tool,index) => {
      const card = document.createElement("article"); card.className = "card";
      const number = document.createElement("span"); number.className="number";number.textContent=String(index+1).padStart(2,"0");
      const title = document.createElement("h3"); title.textContent=names[tool.path] || tool.path;
      const body = document.createElement("p"); body.textContent=tool.use_case;
      const path = document.createElement("code");path.textContent=`${tool.method} ${tool.path}`;
      const bottom=document.createElement("div");bottom.className="card-bottom";
      const price=document.createElement("strong");price.textContent=`${tool.price_usdc} USDC / call`;
      const link=document.createElement("a");link.href="/docs";link.textContent="API docs ↗";link.setAttribute("aria-label",`${title.textContent} API documentation`);
      bottom.append(price,link);card.append(number,title,body,path,bottom);grid.append(card);
    });
  } catch { $("tool-grid").textContent="The catalog is temporarily unavailable. Try /tools/catalog or return in a moment."; }
}
async function loadStatus(){try{const r=await fetch("/health",{signal:AbortSignal.timeout(15000)});if(!r.ok)throw Error();const s=await r.json();$("service-status").textContent=s.x402?.ready?"API online · payment service ready":"API online · paid calls temporarily unavailable";}catch{$("service-status").textContent="Status unavailable · check /health";}}
let formatted="";
$("format-json").addEventListener("click",()=>{formatted="";$("copy-json").disabled=true;try{let raw=$("json-input").value.trim();if(raw.length>100000)throw new Error("Please use a snippet under 100,000 characters.");raw=raw.replace(/^```(?:json)?\s*\n?/i,"").replace(/\n?```$/,"");formatted=JSON.stringify(JSON.parse(raw),null,2);$("json-output").textContent=formatted;$("copy-json").disabled=false;}catch{$("json-output").textContent="This preview needs valid JSON under 100,000 characters. Use double-quoted keys and remove trailing commas. Nothing was sent to the server.";}});
async function copy(text,button){try{await navigator.clipboard.writeText(text);button.textContent="Copied";setTimeout(()=>button.textContent=button.id==="copy-json"?"Copy result":"Copy command",1800);}catch{button.textContent="Select text to copy";}}
$("copy-json").addEventListener("click",()=>copy(formatted,$("copy-json")));
const command=`curl ${location.origin}/tools/catalog`;$("example-command").textContent=command;$("copy-command").addEventListener("click",()=>copy(command,$("copy-command")));
loadCatalog();loadStatus();
