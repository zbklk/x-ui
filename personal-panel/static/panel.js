'use strict';
const $ = id => document.getElementById(id);
let csrf = '', snapshot = null, editing = null, refreshing = false;
const names = {'vless-reality':'VLESS · REALITY · Vision','vless-ws-tls':'VLESS · WS · TLS','vmess-ws-tls':'VMess · WS · TLS','trojan-tls':'Trojan · TLS','shadowsocks2022':'Shadowsocks 2022'};
const nodeForm = $('node-form');
function el(tag, attrs={}, ...children) {
  const n=document.createElement(tag);
  for (const [k,v] of Object.entries(attrs)) {
    if (k==='class') n.className=v;
    else if (k==='onclick') n.addEventListener('click',v);
    else if (k==='text') n.textContent=v;
    else if (k==='checked') n.checked=v;
    else if (k==='value') n.value=v;
    else n.setAttribute(k,v);
  }
  for (const c of children) n.append(typeof c==='string'?document.createTextNode(c):c);
  return n;
}
function toast(msg) {$('toast').textContent=msg;$('toast').hidden=false;clearTimeout(toast.timer);toast.timer=setTimeout(()=>{$('toast').hidden=true},5000);}
async function api(path,method='GET',data) {
  const res=await fetch(path,{method,headers:{...(method!=='GET'?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{})},body:method!=='GET'?JSON.stringify(data??{}):undefined,credentials:'same-origin'});
  const out=await res.json();
  if(!res.ok){if(res.status===401&&path!=='/api/login')showLogin();throw Error(out.error||'请求失败');}
  return out;
}
function showLogin() {csrf='';snapshot=null;$('workspace').hidden=true;$('login').hidden=false;}
function showWorkspace(username){$('login').hidden=true;$('workspace').hidden=false;$('username').textContent=username;}
function bytes(v){if(!v)return '0 B';const units=['B','KiB','MiB','GiB','TiB'];let i=0;while(v>=1024&&i<4){v/=1024;i++;}return `${v.toFixed(i?1:0)} ${units[i]}`;}
function date(v){return v?new Date(v*1000).toLocaleString():'不限期';}
function localInput(v){if(!v)return '';const d=new Date(v*1000);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}
function userState(c,u){if(!c.enabled)return '已禁用';if(c.expires_at&&c.expires_at<=Date.now()/1000)return '已到期';if(c.quota_bytes&&u.up+u.down>=c.quota_bytes)return '额度用尽';return '可用';}
async function refresh(){if(refreshing||!csrf)return;refreshing=true;try{snapshot=await api('/api/state');render();}finally{refreshing=false;}}
function render(){
  const {state,usage,status}=snapshot;
  $('version').textContent=`v${status.version}`;
  $('core-status').textContent=status.core_status==='active'?'运行中':status.core_status==='activating'?'启动中':'未运行';
  $('core-version').textContent=status.core;$('core-detail').textContent=status.core;
  $('node-count').textContent=`${state.nodes.length} / ${state.nodes.reduce((n,x)=>n+x.clients.length,0)}`;
  $('total-traffic').textContent=bytes(Object.values(usage).reduce((n,x)=>n+x.up+x.down,0));
  $('stats-time').textContent=status.stats.stats_success?`最近采集 ${date(Number(status.stats.stats_success))}`:'等待首次流量采集';
  if(status.stats.stats_error)$('stats-time').textContent='采集异常，请检查代理核心与维护任务';
  const c=status.certificate;$('cert-days').textContent=c.present?`${c.days_left} 天`:'未配置';
  $('cert-name').textContent=c.present?c.names.join(', '):'REALITY / SS2022 无需证书';
  $('cert-detail').textContent=c.present?`${c.names.join(', ')} · 到期 ${date(c.expires_at)}`:'尚未配置证书。';
  const site=status.site;$('site-detail').textContent=site?`${site.url} · REALITY 目标端口 ${site.port}，新建入站会自动填写。`:'尚未配置。安装时输入域名，或在 VPS 运行下方命令。';
  $('empty').hidden=state.nodes.length>0;$('nodes').replaceChildren();
  for(const n of state.nodes){
    const edit=el('button',{onclick:()=>openNode(n)},'编辑 / 用户');
    const toggle=el('button',{onclick:()=>attempt(async()=>{await api(`/api/nodes/${n.id}`,'PUT',{...n,enabled:!n.enabled});await refresh();})},n.enabled?'停用':'启用');
    const del=el('button',{class:'danger',onclick:()=>attempt(async()=>{if(confirm(`删除入站“${n.name}”及其用户？`)){await api(`/api/nodes/${n.id}`,'DELETE');await refresh();}})},'删除');
    const title=el('h3',{},n.name,el('span',{class:`badge ${n.enabled?'':'off'}`},n.enabled?'启用':'停用'));
    const header=el('div',{class:'node-head'},el('div',{class:'node-heading'},el('div',{class:'node-icon'},'↗'),el('div',{},title,el('div',{class:'node-meta'},`${names[n.protocol]} · ${n.listen}:${n.port}`))),el('div',{class:'node-actions'},edit,toggle,del));
    const clients=el('div',{class:'clients'});
    for(const c of n.clients){const u=usage[c.id]||{up:0,down:0};clients.append(el('div',{class:'client-row'},el('div',{},el('span',{},c.name,el('span',{class:`badge ${userState(c,u)==='可用'?'':'off'}`},userState(c,u))),el('small',{},`${bytes(u.up+u.down)} / ${c.quota_bytes?bytes(c.quota_bytes):'不限量'} · ${c.expires_at?`到期 ${date(c.expires_at)}`:'不限期'}`)),el('div',{class:'client-buttons'},el('button',{onclick:()=>attempt(()=>openShare(n.id,c.id))},'分享 / 二维码'),el('button',{onclick:()=>attempt(async()=>{if(confirm(`重置“${c.name}”累计流量？`)){await api(`/api/usage/${c.id}/reset`,'POST');await refresh();}})},'重置流量'))));}
    $('nodes').append(el('article',{class:'node'},header,clients));
  }
  const f=$('settings-form');
  if(!f.contains(document.activeElement))for(const [k,v] of Object.entries(state.settings)){const input=f.elements[k];if(input.type==='checkbox')input.checked=v;else input.value=v;}
  $('audit').replaceChildren(...status.audit.map(x=>el('li',{},el('span',{},x.action),el('small',{},date(x.at)))));
}
async function attempt(fn){try{await fn();}catch(e){toast(e.message);}}
$('login-form').addEventListener('submit',async e=>{e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;$('login-error').textContent='';try{const r=await api('/api/login','POST',{username:e.target.elements.username.value,password:e.target.elements.password.value});csrf=r.csrf;e.target.elements.password.value='';showWorkspace(r.username);await refresh();}catch(error){$('login-error').textContent=error.message;}finally{button.disabled=false;}});
$('logout').onclick=()=>attempt(async()=>{await api('/api/logout','POST');showLogin();});
$('refresh').onclick=()=>attempt(refresh);
for(const button of document.querySelectorAll('[data-tab]'))button.onclick=()=>{for(const b of document.querySelectorAll('[data-tab]'))b.classList.toggle('active',b===button);for(const s of document.querySelectorAll('.tab'))s.hidden=s.id!==button.dataset.tab;$('page-title').textContent=button.textContent.replace(/0[123]/,'').trim();};
for(const button of document.querySelectorAll('[data-close]'))button.onclick=()=>$(button.dataset.close).close();
function randKey(){return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));}
function randomUUID(){if(typeof crypto.randomUUID==='function')return crypto.randomUUID();const b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;const h=Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;}
function newClient(){const p=nodeForm.elements.protocol.value;return {id:randomUUID(),name:'用户 '+($('client-editor').children.length+1),secret:p==='shadowsocks2022'?randKey():p==='trojan-tls'?Array.from(crypto.getRandomValues(new Uint8Array(18)),x=>x.toString(16).padStart(2,'0')).join(''):randomUUID(),enabled:true,expires_at:0,quota_bytes:0};}
function field(label,name,value,type='text',attrs={}){const input=el('input',{'data-field':name,type,value,...attrs});return el('label',{},label,input);}
function addClient(c){
 const row=el('div',{class:'client-edit','data-id':c.id});
 const head=el('div',{class:'client-edit-head'},el('strong',{},'连接用户'),el('button',{type:'button',class:'danger',onclick:()=>row.remove()},'移除'));
 row.append(head,el('div',{class:'form-grid'},field('名称','name',c.name,'text',{required:'',maxlength:80}),field('密钥 / UUID','secret',c.secret,'text',{required:'',maxlength:128,autocomplete:'off'}),field('到期时间（本机时区）','expires_at',localInput(c.expires_at),'datetime-local'),field('流量上限 GiB（0 为不限）','quota_gb',c.quota_bytes/1073741824,'number',{min:0,max:931322574,step:'any'}),el('label',{class:'check'},el('input',{'data-field':'enabled',type:'checkbox',checked:c.enabled}),'启用用户')));
 $('client-editor').append(row);
}
function protocolFields(){const p=nodeForm.elements.protocol.value;for(const group of document.querySelectorAll('[data-protocol]')){const flags=group.dataset.protocol.split(' ');group.hidden=!flags.some(x=>x==='reality'?p==='vless-reality':x==='ws'?p.includes('ws'):x==='ss'?p==='shadowsocks2022':p!=='vless-reality'&&p!=='shadowsocks2022');}
 const site=snapshot?.status.site;
 $('protocol-note').textContent=p==='vless-reality'?(site?`已配置自有 HTTPS 小站 ${site.domain}:${site.port}。使用它时 SNI 和目标域名均填 ${site.domain}，目标端口填 ${site.port}；入站请使用其他端口。`:'REALITY 不使用面板证书。可在安装时创建自有 HTTPS 小站，或自行选择并验证可达的 TLS 1.3 目标域名。公钥需要与私钥对应。'):p==='shadowsocks2022'?'SS2022 使用服务端主密钥与用户密钥组合，不需要域名证书。':'TLS 入站需要先在“证书与维护”中签发证书；SNI 应被该证书覆盖。';
}
async function openNode(n=null){
 editing=n?n.id:null;nodeForm.reset();$('node-error').textContent='';$('node-title').textContent=n?'编辑入站与用户':'新建入站';$('client-editor').replaceChildren();
 if(n){for(const [k,v] of Object.entries(n)){const input=nodeForm.elements[k];if(input){if(input.type==='checkbox')input.checked=v;else input.value=v;}}n.clients.forEach(addClient);}else{nodeForm.elements.name.value='我的节点';nodeForm.elements.port.value=20000;nodeForm.elements.server_key.value=randKey();const site=snapshot?.status.site;if(site){nodeForm.elements.sni.value=site.domain;nodeForm.elements.dest.value=site.domain;nodeForm.elements.dest_port.value=site.port;if(!snapshot.state.settings.public_address)nodeForm.elements.address.value=site.domain;}addClient(newClient());}
 protocolFields();$('node-dialog').showModal();
 if(!n)try{const keys=await api('/api/keypair','POST');for(const [k,v] of Object.entries(keys))nodeForm.elements[k].value=v;}catch(e){$('node-error').textContent=e.message;}
}
$('new-node').onclick=()=>attempt(()=>openNode());$('empty-new').onclick=$('new-node').onclick;
nodeForm.elements.protocol.onchange=()=>{protocolFields();if(!editing){$('client-editor').replaceChildren();addClient(newClient());}};
$('add-client').onclick=()=>addClient(newClient());
$('generate-keys').onclick=()=>attempt(async()=>{if(editing&&!confirm('更换密钥后，所有已有 REALITY 分享链接需要重新导入。继续？'))return;const keys=await api('/api/keypair','POST');for(const [k,v] of Object.entries(keys))nodeForm.elements[k].value=v;});
nodeForm.addEventListener('submit',async e=>{e.preventDefault();$('node-error').textContent='';const button=e.target.querySelector('[type=submit]');button.disabled=true;try{
 const n={};for(const k of ['name','protocol','listen','address','sni','dest','private_key','public_key','short_id','path','server_key'])n[k]=nodeForm.elements[k].value.trim();for(const k of ['port','dest_port'])n[k]=Number(nodeForm.elements[k].value);n.enabled=nodeForm.elements.enabled.checked;
 n.clients=Array.from($('client-editor').children,row=>{const f=k=>row.querySelector(`[data-field="${k}"]`);return{id:row.dataset.id,name:f('name').value,secret:f('secret').value,enabled:f('enabled').checked,expires_at:f('expires_at').value?Math.floor(new Date(f('expires_at').value).getTime()/1000):0,quota_bytes:Math.round(Number(f('quota_gb').value)*1073741824)};});
 await api(editing?`/api/nodes/${editing}`:'/api/nodes',editing?'PUT':'POST',n);$('node-dialog').close();toast('配置校验通过，已提交到独立代理服务');await refresh();
 }catch(error){$('node-error').textContent=error.message;}finally{button.disabled=false;}});
$('settings-form').addEventListener('submit',e=>{e.preventDefault();attempt(async()=>{const f=e.target.elements;await api('/api/settings','POST',{public_address:f.public_address.value.trim(),ipv4_only:f.ipv4_only.checked,block_private:f.block_private.checked,loglevel:f.loglevel.value});toast('设置已保存');await refresh();});});
async function openShare(n,c){const r=await api(`/api/share/${n}/${c}`);$('share-text').value=r.link;$('share-qr').src=`/api/qr/${n}/${c}`;$('share-dialog').showModal();}
$('copy-link').onclick=()=>attempt(async()=>{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText($('share-text').value);toast('链接已复制');}else{const field=$('share-text');field.focus();field.select();field.setSelectionRange(0,field.value.length);const copied=typeof document.execCommand==='function'&&document.execCommand('copy');toast(copied?'链接已复制':'链接已选中，请按 Ctrl+C / ⌘C 或长按复制');}});
$('backup').onclick=()=>attempt(async()=>{const r=await fetch('/api/backup',{credentials:'same-origin'});if(!r.ok)throw Error('备份下载失败，请重新登录');const blob=await r.blob(),url=URL.createObjectURL(blob),a=el('a',{href:url,download:`personal-panel-${new Date().toISOString().slice(0,10)}.json`});document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('restore').onclick=()=>$('restore-file').click();
$('restore-file').onchange=()=>attempt(async()=>{const file=$('restore-file').files[0];$('restore-file').value='';if(!file)return;if(file.size>32*1024*1024)throw Error('备份不能超过 32 MiB');if(!confirm('恢复将替换本面板的入站、用户、设置和累计流量。继续？'))return;await api('/api/restore','POST',JSON.parse(await file.text()));toast('备份已恢复');await refresh();});
$('rollback').onclick=()=>attempt(async()=>{if(confirm('回退到上一次保存配置前的状态？')){await api('/api/rollback','POST');toast('已回退');await refresh();}});
$('restart-core').onclick=()=>attempt(async()=>{if(confirm('重启代理核心 会短暂中断节点连接。继续？')){await api('/api/restart-core','POST');toast('已请求重启');setTimeout(()=>attempt(refresh),2000);}});
(async()=>{try{const r=await api('/api/session');csrf=r.csrf;showWorkspace(r.username);await refresh();}catch{showLogin();}})();
setInterval(()=>{if(!document.hidden&&!$('workspace').hidden&&!$('node-dialog').open)attempt(refresh);},15000);
