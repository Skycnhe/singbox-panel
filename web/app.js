async function api(path, method, body) {
  const r = await fetch(path, {
    method: method || 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) {
    const e = new Error(j.error || ('HTTP ' + r.status));
    e.code = j.code;
    throw e;
  }
  return j.data;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = b, i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  return v.toFixed(2) + ' ' + u[i];
}

async function doLogin() {
  const u = document.getElementById('loginUser').value;
  const p = document.getElementById('loginPass').value;
  try {
    const d = await api('/api/auth/login', 'POST', { username: u, password: p });
    document.getElementById('loginView').classList.add('hidden');
    document.getElementById('appView').classList.remove('hidden');
    if (d.force_change) openChangePass(true);
    loadDashboard();
  } catch (e) {
    document.getElementById('loginErr').textContent = e.message;
  }
}
async function doLogout() {
  await api('/api/auth/logout', 'POST').catch(() => {});
  location.reload();
}

function showTab(name) {
  ['dashboard', 'inbounds', 'settings', 'logs'].forEach(t => {
    document.getElementById('tab-' + t).classList.toggle('hidden', t !== name);
    document.getElementById('nav-' + t).classList.toggle('active', t === name);
  });
  if (name === 'inbounds') loadInbounds();
  if (name === 'settings') loadSettings();
  if (name === 'logs') loadLogs();
  if (name === 'dashboard') loadDashboard();
}

async function loadDashboard() {
  try {
    const d = await api('/api/dashboard');
    const c = d.core;
    document.getElementById('dCore').textContent = c.running ? ('运行中 pid=' + c.pid + ' (' + c.version + ')') : '未运行';
    document.getElementById('coreBadge').textContent = c.running ? '核心运行中' : '核心未运行';
    document.getElementById('coreBadge').className = 'badge ' + (c.running ? 'on' : 'off');
    const s = d.system;
    document.getElementById('dSys').textContent =
      'CPU ' + s.cpu_percent.toFixed(1) + '% / 内存 ' + s.mem_percent.toFixed(1) + '% / 磁盘 ' + s.disk_percent.toFixed(1) + '%';
    document.getElementById('dLoad').textContent = s.load1.toFixed(2) + ' / ' + s.load5.toFixed(2) + ' / ' + s.load15.toFixed(2);
    document.getElementById('dTraffic').textContent = fmtBytes(d.traffic.up) + ' / ' + fmtBytes(d.traffic.down);
    document.getElementById('dSource').textContent = d.traffic.source || 'none';
    document.getElementById('dCounts').textContent = d.inbound_count + ' 启用 / 共 ' + d.inbound_total + ' 个入站，' + d.client_count + ' 个客户端';
  } catch (e) {
    if (e.code === 'password_change_required') openChangePass(true);
    else document.getElementById('dashErr').textContent = e.message;
  }
}

async function coreAction(action) {
  try {
    const d = await api('/api/core/' + action, 'POST');
    if (d && d.check_output) alert('校验通过并已应用：\n' + d.check_output);
    loadDashboard();
  } catch (e) { alert(e.message); }
}

async function loadInbounds() {
  const list = await api('/api/inbounds');
  const el = document.getElementById('inboundList');
  if (!list.length) { el.innerHTML = '<p class="note">暂无入站，点上方添加。</p>'; return; }
  el.innerHTML = list.map(inb => {
    const clients = (inb.clients || []).map(c => `
      <tr>
        <td>${esc(c.name)}</td>
        <td class="mono">${esc(c.uuid || c.password || '')}</td>
        <td>${fmtBytes(c.up)} / ${fmtBytes(c.down)}</td>
        <td><span class="badge ${c.enabled ? 'on' : 'off'}">${c.enabled ? '启用' : '停用'}</span></td>
        <td>
          <button class="small" onclick="showLink('${inb.id}','${c.id}')">链接/二维码</button>
          <button class="small secondary" onclick="openClientForm('${inb.id}','${c.id}')">编辑</button>
          <button class="small danger" onclick="delClient('${inb.id}','${c.id}')">删除</button>
        </td>
      </tr>`).join('');
    return `<div class="card inbound">
      <h3>${esc(inb.remark || inb.protocol)} <span class="badge ${inb.enabled ? 'on' : 'off'}">${inb.enabled ? '启用' : '停用'}</span></h3>
      <div class="meta">${esc(inb.protocol)} · 端口 ${inb.port} · 传输 ${esc(inb.transport)}${inb.tls_enabled ? ' · TLS/' + esc(inb.tls_type) : ''} · 流量 ${fmtBytes(inb.up)} / ${fmtBytes(inb.down)}${inb.total_limit_gb ? ' · 限额 ' + inb.total_limit_gb + ' GB' : ''}</div>
      <div class="actions">
        <button class="small" onclick="openClientForm('${inb.id}','')">+ 添加客户端</button>
        <button class="small secondary" onclick="openInboundForm('${inb.id}')">编辑入站</button>
        <button class="small danger" onclick="delInbound('${inb.id}')">删除入站</button>
      </div>
      <table><tr><th>备注</th><th>UUID / 口令</th><th>上行 / 下行</th><th>状态</th><th>操作</th></tr>${clients || '<tr><td colspan="5" class="note">暂无客户端</td></tr>'}</table>
    </div>`;
  }).join('');
  window._inbounds = list;
}

function openModal(html) {
  const w = document.getElementById('modalWrap');
  w.innerHTML = '<div class="modal-backdrop" onclick="if(event.target===this)closeModal()"><div class="modal">' + html + '</div></div>';
  w.classList.remove('hidden');
}
function closeModal() { document.getElementById('modalWrap').classList.add('hidden'); }

function inboundFormValues() {
  return {
    protocol: document.getElementById('fProtocol').value,
    remark: document.getElementById('fRemark').value,
    port: parseInt(document.getElementById('fPort').value, 10),
    enabled: document.getElementById('fEnabled').value === 'true',
    transport: document.getElementById('fTransport').value,
    ws_path: document.getElementById('fWSPath').value,
    ws_host: document.getElementById('fWSHost').value,
    grpc_service: document.getElementById('fGRPC').value,
    hu_path: document.getElementById('fHUPath').value,
    hu_host: document.getElementById('fHUHost').value,
    tls_enabled: document.getElementById('fTLSEnabled').value === 'true',
    tls_type: document.getElementById('fTLSType').value,
    cert_path: document.getElementById('fCert').value,
    key_path: document.getElementById('fKey').value,
    server_name: document.getElementById('fSNI').value,
    reality_private_key: document.getElementById('fRealityPriv').value,
    reality_public_key: document.getElementById('fRealityPub').value,
    reality_short_id: document.getElementById('fRealitySID').value,
    reality_dest: document.getElementById('fRealityDest').value,
    ss_method: document.getElementById('fSSMethod').value,
    total_limit_gb: parseFloat(document.getElementById('fLimit').value) || 0,
  };
}

function openInboundForm(id) {
  const inb = (window._inbounds || []).find(x => x.id === id) || {
    protocol: 'vless', remark: '', port: 10001, enabled: true, transport: 'tcp',
    ws_path: '/', ws_host: '', grpc_service: '', hu_path: '/', hu_host: '',
    tls_enabled: false, tls_type: 'reality', cert_path: '', key_path: '', server_name: '',
    reality_private_key: '', reality_public_key: '', reality_short_id: '', reality_dest: 'www.microsoft.com:443',
    ss_method: 'aes-128-gcm', total_limit_gb: 0,
  };
  openModal(`
    <h3>${id ? '编辑入站' : '添加入站'}</h3>
    <div class="row">
      <div><label>协议</label><select id="fProtocol">
        ${['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2'].map(p => `<option ${p === inb.protocol ? 'selected' : ''}>${p}</option>`).join('')}
      </select></div>
      <div><label>端口（禁止含 443）</label><input id="fPort" type="number" value="${inb.port}"></div>
    </div>
    <label>备注</label><input id="fRemark" value="${esc(inb.remark)}">
    <div class="row">
      <div><label>状态</label><select id="fEnabled"><option value="true" ${inb.enabled ? 'selected' : ''}>启用</option><option value="false" ${!inb.enabled ? 'selected' : ''}>停用</option></select></div>
      <div><label>传输</label><select id="fTransport">
        ${['tcp', 'ws', 'grpc', 'httpupgrade'].map(t => `<option ${t === inb.transport ? 'selected' : ''}>${t}</option>`).join('')}
      </select></div>
    </div>
    <div class="row">
      <div><label>WS 路径</label><input id="fWSPath" value="${esc(inb.ws_path)}"></div>
      <div><label>WS Host</label><input id="fWSHost" value="${esc(inb.ws_host)}"></div>
      <div><label>gRPC service</label><input id="fGRPC" value="${esc(inb.grpc_service)}"></div>
      <div><label>HTTPUpgrade 路径</label><input id="fHUPath" value="${esc(inb.hu_path)}"></div>
      <div><label>HTTPUpgrade Host</label><input id="fHUHost" value="${esc(inb.hu_host)}"></div>
      <div><label>SS 加密</label><select id="fSSMethod">
        ${['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].map(m => `<option ${m === inb.ss_method ? 'selected' : ''}>${m}</option>`).join('')}
      </select></div>
    </div>
    <div class="row">
      <div><label>启用 TLS</label><select id="fTLSEnabled"><option value="true" ${inb.tls_enabled ? 'selected' : ''}>是</option><option value="false" ${!inb.tls_enabled ? 'selected' : ''}>否</option></select></div>
      <div><label>TLS 类型</label><select id="fTLSType">
        ${['reality', 'tls', 'self'].map(t => `<option ${t === inb.tls_type ? 'selected' : ''} value="${t}">${t === 'self' ? 'self（自签，仅 hysteria2）' : t}</option>`).join('')}
      </select></div>
    </div>
    <label>SNI / ServerName</label><input id="fSNI" value="${esc(inb.server_name)}">
    <div class="row">
      <div><label>证书路径（tls）</label><input id="fCert" value="${esc(inb.cert_path)}"></div>
      <div><label>私钥路径（tls）</label><input id="fKey" value="${esc(inb.key_path)}"></div>
    </div>
    <label>Reality 私钥（空则自动生成）</label><input id="fRealityPriv" value="${esc(inb.reality_private_key)}">
    <div class="row">
      <div><label>Reality 公钥（自动生成后回填）</label><input id="fRealityPub" value="${esc(inb.reality_public_key)}"></div>
      <div><label>Reality short ID</label><input id="fRealitySID" value="${esc(inb.reality_short_id)}"></div>
    </div>
    <label>Reality 握手目标（host:port，仅作握手目标，非监听端口）</label><input id="fRealityDest" value="${esc(inb.reality_dest)}">
    <label>流量限额 GB（0 = 不限；超限自动停用）</label><input id="fLimit" type="number" step="0.1" value="${inb.total_limit_gb || 0}">
    <div style="margin-top:14px;display:flex;gap:8px">
      <button onclick="saveInbound('${id || ''}')">保存</button>
      <button class="secondary" onclick="genReality()">生成 Reality 密钥对</button>
      <button class="secondary" onclick="closeModal()">取消</button>
    </div>
    <div id="fErr" class="err"></div>
    <p class="note">注意：Shadowsocks 为入站级单口令，仅首个启用客户端的口令真正生效；hysteria2 选 self 时面板自动生成自签证书。</p>`);
}
async function genReality() {
  const d = await api('/api/utils/reality-keypair', 'POST');
  document.getElementById('fRealityPriv').value = d.private_key;
  document.getElementById('fRealityPub').value = d.public_key;
  if (!document.getElementById('fRealitySID').value) document.getElementById('fRealitySID').value = Math.random().toString(16).slice(2, 10);
}
async function saveInbound(id) {
  const v = inboundFormValues();
  try {
    if (id) await api('/api/inbounds/' + id, 'PUT', v);
    else await api('/api/inbounds', 'POST', v);
    closeModal(); loadInbounds();
  } catch (e) { document.getElementById('fErr').textContent = e.message; }
}
async function delInbound(id) {
  if (!confirm('删除该入站及其全部客户端？')) return;
  await api('/api/inbounds/' + id, 'DELETE'); loadInbounds();
}

function openClientForm(inboundId, clientId) {
  const inb = (window._inbounds || []).find(x => x.id === inboundId);
  const c = (inb.clients || []).find(x => x.id === clientId) || { name: '', uuid: '', password: '', flow: 'xtls-rprx-vision', total_limit_gb: 0, enabled: true };
  openModal(`
    <h3>${clientId ? '编辑客户端' : '添加客户端'}</h3>
    <label>备注（订阅与链接里显示的名字）</label><input id="cName" value="${esc(c.name)}">
    <label>UUID（vless/vmess，空则自动生成）</label><input id="cUUID" value="${esc(c.uuid)}">
    <label>口令（trojan/ss/hysteria2，空则自动生成）</label><input id="cPassword" value="${esc(c.password)}">
    <label>vless flow（仅 tcp+TLS 时生效）</label><input id="cFlow" value="${esc(c.flow)}">
    <label>流量限额 GB（0 = 不限）</label><input id="cLimit" type="number" step="0.1" value="${c.total_limit_gb || 0}">
    <label>状态</label><select id="cEnabled"><option value="true" ${c.enabled ? 'selected' : ''}>启用</option><option value="false" ${!c.enabled ? 'selected' : ''}>停用</option></select>
    <div style="margin-top:14px;display:flex;gap:8px">
      <button onclick="saveClient('${inboundId}','${clientId}')">保存</button>
      <button class="secondary" onclick="closeModal()">取消</button>
    </div>
    <div id="cErr" class="err"></div>`);
}
async function saveClient(inboundId, clientId) {
  const v = {
    name: document.getElementById('cName').value,
    uuid: document.getElementById('cUUID').value,
    password: document.getElementById('cPassword').value,
    flow: document.getElementById('cFlow').value,
    total_limit_gb: parseFloat(document.getElementById('cLimit').value) || 0,
    enabled: document.getElementById('cEnabled').value === 'true',
  };
  try {
    if (clientId) await api(`/api/inbounds/${inboundId}/clients/${clientId}`, 'PUT', v);
    else await api(`/api/inbounds/${inboundId}/clients`, 'POST', v);
    closeModal(); loadInbounds();
  } catch (e) { document.getElementById('cErr').textContent = e.message; }
}
async function delClient(inboundId, clientId) {
  if (!confirm('删除该客户端？')) return;
  await api(`/api/inbounds/${inboundId}/clients/${clientId}`, 'DELETE'); loadInbounds();
}
async function showLink(inboundId, clientId) {
  const d = await api(`/api/inbounds/${inboundId}/clients/${clientId}/link`);
  openModal(`
    <h3>客户端链接与订阅</h3>
    <label>客户端链接</label><textarea rows="4" readonly onclick="this.select()">${esc(d.link)}</textarea>
    <label>订阅地址（sing-box JSON 配置）</label><input value="${esc(d.sub_url)}" readonly onclick="this.select()">
    <div style="margin-top:12px"><div class="qrbox" id="qrBox"></div></div>
    <p class="note">扫码即为客户端链接；订阅地址返回 sing-box JSON 配置。</p>
    <button class="secondary" onclick="closeModal()">关闭</button>`);
  try {
    const qr = qrcode(0, 'M');
    qr.addData(d.link);
    qr.make();
    document.getElementById('qrBox').innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4 });
  } catch (e) {
    document.getElementById('qrBox').textContent = '二维码生成失败：' + e.message;
  }
}

async function loadSettings() {
  const s = await api('/api/settings');
  document.getElementById('setSubDomain').value = s.sub_domain || '';
  document.getElementById('setBinPath').value = s.singbox_path || '';
  document.getElementById('setClashPort').value = s.clash_port;
  document.getElementById('setV2RayPort').value = s.v2ray_port;
  document.getElementById('setV2Ray').value = String(s.enable_v2ray_api);
  document.getElementById('setStatsSource').value = s.stats_source;
  document.getElementById('coreInfo').textContent = '当前核心版本：' + (s.core_version || '未检测到') + ' · 实际流量口径：' + (s.stats_actual || 'none');
}
async function saveSettings() {
  try {
    await api('/api/settings', 'PUT', {
      sub_domain: document.getElementById('setSubDomain').value,
      singbox_path: document.getElementById('setBinPath').value,
      clash_port: parseInt(document.getElementById('setClashPort').value, 10),
      v2ray_port: parseInt(document.getElementById('setV2RayPort').value, 10),
      enable_v2ray_api: document.getElementById('setV2Ray').value === 'true',
      stats_source: document.getElementById('setStatsSource').value,
    });
    document.getElementById('setErr').textContent = '已保存。修改 clash/v2ray 端口后需重新应用配置。';
  } catch (e) { document.getElementById('setErr').textContent = e.message; }
}
async function downloadCore() {
  const v = document.getElementById('dlVersion').value;
  document.getElementById('setErr').textContent = '下载中…';
  try {
    const d = await api('/api/core/download', 'POST', { version: v });
    document.getElementById('setErr').textContent = '已安装：' + d.path + '（' + d.version + '），请到仪表盘应用配置。';
    loadSettings();
  } catch (e) { document.getElementById('setErr').textContent = e.message; }
}

function openChangePass(forced) {
  openModal(`
    <h3>${forced ? '首次登录：请修改密码' : '修改登录密码'}</h3>
    ${forced ? '' : '<label>旧密码</label><input id="pOld" type="password">'}
    <label>新密码（至少 6 位）</label><input id="pNew" type="password">
    <label>确认新密码</label><input id="pNew2" type="password">
    <div style="margin-top:14px"><button onclick="doChangePass(${!!forced})">确认修改</button></div>
    <div id="pErr" class="err"></div>`);
}
async function doChangePass(forced) {
  const oldEl = document.getElementById('pOld');
  const n = document.getElementById('pNew').value;
  const n2 = document.getElementById('pNew2').value;
  if (n !== n2) { document.getElementById('pErr').textContent = '两次新密码不一致'; return; }
  try {
    await api('/api/auth/change-password', 'POST', { old_password: oldEl ? oldEl.value : '', new_password: n });
    closeModal();
    if (forced) loadDashboard();
  } catch (e) { document.getElementById('pErr').textContent = e.message; }
}

async function loadLogs() {
  const d = await api('/api/core/logs?lines=300');
  document.getElementById('logBox').textContent = (d.logs || []).join('\n');
}

// 启动时若已有 session，直接进应用
(async () => {
  try {
    const me = await api('/api/auth/me');
    document.getElementById('loginView').classList.add('hidden');
    document.getElementById('appView').classList.remove('hidden');
    if (me.force_change) openChangePass(true);
    loadDashboard();
  } catch (e) { /* 未登录，停留在登录页 */ }
})();
setInterval(() => {
  if (!document.getElementById('appView').classList.contains('hidden')) loadDashboard();
}, 30000);
