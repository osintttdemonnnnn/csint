const dns = require('node:dns').promises;
module.exports = async (req,res) => {
 res.setHeader('Cache-Control','no-store');
 if(req.method !== 'POST') return res.status(405).json({error:'POST required'});
 try {
 const b=typeof req.body==='string'?JSON.parse(req.body):req.body;
 const {tool,target}=b||{};
 if(typeof target!=='string'||target.length>2000||!target.trim()) return res.status(400).json({error:'Enter a valid target (maximum 2000 characters).'});
 const t=target.trim();
 const domain=()=>{const h=new URL(t.includes('://')?t:'https://'+t).hostname;if(!/^(?=.{1,253}$)[a-z0-9.-]+$/i.test(h)||!h.includes('.'))throw Error('Enter a valid domain.');return h;};
 const get=async url=>{const r=await fetch(url,{signal:AbortSignal.timeout(10000),headers:{Accept:'application/json','User-Agent':'AegisCSINT'}});if(!r.ok)throw Error('Source returned HTTP '+r.status);return r.json();};
 let data,source;
 if(['dns','domain','mail-auth','reverse-dns'].includes(tool)){
 if(tool==='reverse-dns'){data=await dns.reverse(t);source='DNS PTR';}
 else{const h=domain();const types=tool==='mail-auth'?['MX','TXT']:['A','AAAA','MX','NS','TXT','CNAME'];data={domain:h,records:{}};await Promise.all(types.map(async type=>{try{data.records[type]=await dns.resolve(h,type);}catch(e){data.records[type]={status:e.code||'unavailable'};}}));source='DNS resolver';if(tool==='mail-auth'){try{data.dmarc=await dns.resolveTxt('_dmarc.'+h);}catch(e){data.dmarc={status:e.code};}data.note='DKIM requires a selector; no selector was supplied.';}}
 }else if(['rdap','ip','asn'].includes(tool)){let url;if(tool==='ip'){if(!require('node:net').isIP(t))throw Error('Enter a valid IP address.');url='https://rdap.org/ip/'+encodeURIComponent(t);}else if(tool==='asn'){if(!/^(AS)?[0-9]+$/i.test(t))throw Error('Enter an ASN such as AS15169.');url='https://rdap.org/autnum/'+t.replace(/^AS/i,'');}else url='https://rdap.org/domain/'+encodeURIComponent(domain());data=await get(url);source=url;
 }else if(['ct','subdomains'].includes(tool)){const h=domain();source='https://crt.sh/?q='+encodeURIComponent('%.'+h)+'&output=json';const rows=await get(source);data={domain:h,certificateNames:[...new Set(rows.flatMap(x=>(x.name_value||'').split('\n')))].slice(0,500),note:'Certificate names are historical observations, not proof of active hosts.'};
 }else if(tool==='archive'){const u=new URL(t.includes('://')?t:'https://'+t);if(!['https:','http:'].includes(u.protocol))throw Error('Use an HTTP or HTTPS URL.');source='https://archive.org/wayback/available?url='+encodeURIComponent(u.href);data=await get(source);
 }else if(tool==='github'){source='https://api.github.com/search/repositories?q='+encodeURIComponent(t)+'&per_page=10';const r=await get(source);data={total:r.total_count,repositories:r.items.map(x=>({name:x.full_name,url:x.html_url,description:x.description,updated:x.updated_at}))};
 }else if(tool==='cve'){if(!/^CVE-[0-9]{4}-[0-9]{4,}$/i.test(t))throw Error('Enter a valid CVE identifier.');source='https://cveawg.mitre.org/api/cve/'+encodeURIComponent(t.toUpperCase());data=await get(source);
 }else return res.status(501).json({error:'This tool is not connected yet. It needs a dedicated implementation or an authorized data provider. No lookup was performed.'});
 return res.json({source,retrievedAt:new Date().toISOString(),data});
 }catch(e){return res.status(502).json({error:e.message||'Lookup failed. Try again later.'});}
};
