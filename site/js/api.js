// Comunicação com o Worker + utilidades usadas em todas as páginas.
const API = {
  token() {
    try { return localStorage.getItem('ae_token'); } catch { return null; }
  },
  salvarToken(t) {
    try { t ? localStorage.setItem('ae_token', t) : localStorage.removeItem('ae_token'); } catch { /* navegador bloqueou */ }
  },

  async req(caminho, { metodo = 'GET', corpo, arquivo } = {}) {
    const headers = {};
    const t = API.token();
    if (t) headers.Authorization = 'Bearer ' + t;
    let body;
    if (arquivo) { headers['Content-Type'] = arquivo.type; body = arquivo; }
    else if (corpo !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(corpo); }

    let r;
    try {
      r = await fetch(window.API_URL + caminho, { method: metodo, headers, body });
    } catch {
      throw new Error('Sem conexão com o servidor. Confira a internet e o endereço em js/config.js.');
    }
    const dados = await r.json().catch(() => ({}));
    if (r.status === 401 && caminho !== '/api/login') {
      API.salvarToken(null);
      location.href = 'index.html';
      throw new Error(dados.erro || 'Sessão expirada.');
    }
    if (!r.ok) throw new Error(dados.erro || 'Erro ' + r.status);
    return dados;
  },

  arquivoUrl(key) {
    return key ? window.API_URL + '/api/arquivos/' + key.split('/').map(encodeURIComponent).join('/') : '';
  }
};

// Cria elemento com segurança (texto nunca vira HTML).
function el(tag, attrs = {}, ...filhos) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const f of filhos.flat()) if (f != null) e.append(f instanceof Node ? f : document.createTextNode(String(f)));
  return e;
}

function mostrarMsg(alvo, texto, tipo = 'erro') {
  alvo.textContent = texto;
  alvo.className = 'msg ' + tipo;
}

function limparMsg(alvo) {
  alvo.textContent = '';
  alvo.className = 'msg';
}

// Escolhe texto preto ou branco conforme a cor principal.
function aplicarCor(hex) {
  if (!/^#[0-9a-fA-F]{6}$/.test(hex || '')) return;
  const n = parseInt(hex.slice(1), 16);
  const lum = (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255;
  document.documentElement.style.setProperty('--cor', hex);
  document.documentElement.style.setProperty('--cor-texto', lum > 0.6 ? '#04121C' : '#FFFFFF');
}

function iniciais(nome) {
  return String(nome || '?').split(/\s+/).filter(Boolean).slice(0, 2).map(p => p[0].toUpperCase()).join('');
}

function logoEl(empresa) {
  const box = el('div', { class: 'marca-logo' });
  if (empresa.logo_key) box.append(el('img', { src: API.arquivoUrl(empresa.logo_key), alt: empresa.nome_fantasia }));
  else box.textContent = iniciais(empresa.nome_fantasia);
  return box;
}
