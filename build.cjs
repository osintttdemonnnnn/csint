const fs=require('node:fs');
fs.mkdirSync('public',{recursive:true});
const html=fs.readFileSync('index.html.txt','utf8');
fs.writeFileSync('public/index.html',html.replace('</body>','<script src="/live.js"></script></body>'));
fs.copyFileSync('live.js','public/live.js');
