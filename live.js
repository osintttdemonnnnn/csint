(()=>{
const run=document.querySelector('#runTool'),result=document.querySelector('#result');
document.querySelector('.status').textContent='LIVE LOOKUPS + LOCAL ANALYSIS';
document.querySelector('.side-bottom').textContent='Public-source lookups. Unconnected tools are explicitly marked.';
const local=new Set(['hash','image-hash','file-type','defang','ioc-normalizer','ioc-extractor','handle']);
const supported=new Set(['domain','dns','mail-auth','reverse-dns','rdap','ip','asn','ct','subdomains','archive','github','cve',...local]);
document.querySelector('.sub').textContent='Public-source research workspace. Open a tool to see integration availability.';
function annotate(){document.querySelectorAll('[data-run]').forEach(b=>{b.textContent=supported.has(b.dataset.run)?'Open working tool ↗':'Integration required';});}
new MutationObserver(annotate).observe(document.querySelector('#toolGrid'),{childList:true});annotate();
document.addEventListener('click',e=>{const b=e.target.closest('[data-run]');if(!b)return;const id=b.dataset.run;const input=document.querySelector('#fileInput');input.value='';if(['hash','image-hash','file-type'].includes(id)){input.style.display='block';document.querySelector('#targetInput').style.display='block';}if(!supported.has(id)){result.style.display='block';result.textContent='Not connected: this tool requires a dedicated implementation or an authorized provider. It will not return simulated data.';}});
run.onclick=async()=>{
 if(!selectedTool||run.disabled)return;const tool=selectedTool;const f=document.querySelector('#fileInput');const file=f.style.display!=='none'?f.files[0]:null;const target=document.querySelector('#targetInput').value.trim();
 result.style.display='block';result.textContent='Looking up…';run.disabled=true;
 try{let payload;
 if(!supported.has(tool.id))throw Error('This tool is not connected. No lookup was performed.');
 if(local.has(tool.id)){
 let data;
 if(['hash','image-hash'].includes(tool.id)){if(!file&&!target)throw Error('Enter text or choose a file.');if(file&&file.size>25000000)throw Error('Choose a file under 25 MB.');const bytes=file?await file.arrayBuffer():new TextEncoder().encode(target);const digest=await crypto.subtle.digest('SHA-256',bytes);data={algorithm:'SHA-256',sha256:[...new Uint8Array(digest)].map(v=>v.toString(16).padStart(2,'0')).join(''),input:file?file.name:'Entered text'};
 }else if(tool.id==='file-type'){if(!file)throw Error('Choose a file.');const bytes=new Uint8Array(await file.slice(0,16).arrayBuffer());data={name:file.name,size:file.size,browserReportedType:file.type,firstBytesHex:[...bytes].map(v=>v.toString(16).padStart(2,'0')).join(' '),note:'Browser MIME and extension are not verified file-type detection.'};
 }else{if(!target)throw Error('Enter text.');if(tool.id==='defang')data={defanged:target.replace(/https/gi,'hxxps').replace(/http/gi,'hxxp').replace(/\./g,'[.]'),refanged:target.replace(/hxxps/gi,'https').replace(/hxxp/gi,'http').replace(/\[\.\]/g,'.')};else if(tool.id==='handle')data={normalized:target.replace(/^@/,'').trim(),note:'Normalization only; no account ownership verified.'};else if(tool.id==='ioc-extractor')data={urls:target.match(/https?:\/\/[^\s<>]+/g)||[],emails:target.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)||[],ipv4Candidates:target.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g)||[]};else data={indicators:[...new Set(target.split(/[\s,;]+/).filter(Boolean))],note:'Deduplicated input; indicators have not been verified.'};}
 payload={source:'Local browser analysis; files are not uploaded',data};
 }else{if(!target)throw Error('Enter a lookup target.');const r=await fetch('/api/lookup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:tool.id,target})});payload=await r.json();if(!r.ok)throw Error(payload.error||'Lookup failed.');}
 if(selectedTool!==tool)return;result.textContent='';const title=document.createElement('strong');title.textContent=tool.name+' — results';const pre=document.createElement('pre');pre.style.cssText='white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto';pre.textContent=JSON.stringify(payload,null,2);result.append(title,pre);
 runs.unshift({tool:tool.name,target:file?file.name:target,time:new Date().toLocaleString(),notes:document.querySelector('#notes').value.trim()});runs=runs.slice(0,100);try{localStorage.setItem('aegisRuns',JSON.stringify(runs));}catch{}render();
 }catch(e){if(selectedTool===tool)result.textContent=e.message;}finally{run.disabled=false;}
};
document.querySelector('#targetInput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();run.click();}});
})();
