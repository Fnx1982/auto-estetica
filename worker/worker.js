// ============================================================
// Auto Estética — API (Cloudflare Worker) — etapa 1
// Vínculos (Settings > Bindings):
//   DB        -> banco D1 "auto-estetica-db"            (obrigatório)
//   ARQUIVOS  -> bucket R2 "auto-estetica-arquivos"     (para a logo)
// Variáveis (Settings > Variables and Secrets):
//   ALLOWED_ORIGIN    -> endereço do site (ex.: https://auto-estetica.pages.dev)
//   CHAVE_INSTALACAO  -> (Secret) senha usada só no primeiro acesso
// ============================================================

const MAX_TENTATIVAS = 5;      // erros de senha antes de bloquear
const BLOQUEIO_MIN = 15;       // minutos de bloqueio
const SESSAO_DIAS = 7;         // validade do login
const LOGO_MAX_BYTES = 2 * 1024 * 1024;
const PBKDF2_ITER = 100000;    // máximo aceito pelo Workers

const CAMPOS_EMPRESA = [
  'nome_fantasia', 'razao_social', 'documento', 'inscricao_municipal', 'whatsapp',
  'instagram', 'endereco', 'horario', 'chave_pix', 'rodape_orcamento', 'cor_principal'
];

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    let res;
    try {
      if (!env.DB) throw erro(500, 'Banco D1 não vinculado ao Worker (binding DB).');
      res = await rotear(req, env);
    } catch (e) {
      if (e && e.status) {
        res = json({ erro: e.message }, e.status);
      } else {
        console.error(e);
        res = json({ erro: 'Erro interno no servidor.' }, 500);
      }
    }
    for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
    return res;
  }
};

// ---------------- Rotas ----------------
async function rotear(req, env) {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, '') || '/';
  const m = req.method;

  if (p === '/api/status' && m === 'GET') return status(env);
  if (p === '/api/setup' && m === 'POST') return setup(req, env);
  if (p === '/api/login' && m === 'POST') return login(req, env);
  if (p.startsWith('/api/arquivos/') && m === 'GET') return arquivo(p, env);

  const eu = await autenticar(req, env);

  if (p === '/api/logout' && m === 'POST') return logout(eu, env);
  if (p === '/api/me' && m === 'GET') return json({ usuario: publico(eu), empresa: await lerEmpresa(env) });

  if (p === '/api/empresa' && m === 'GET') return json(await lerEmpresa(env));
  if (p === '/api/empresa' && m === 'PUT') { exigirAdmin(eu); return salvarEmpresa(req, env); }
  if (p === '/api/empresa/logo' && m === 'POST') { exigirAdmin(eu); return enviarLogo(req, env); }
  if (p === '/api/empresa/logo' && m === 'DELETE') { exigirAdmin(eu); return removerLogo(env); }

  if (p === '/api/usuarios' && m === 'GET') { exigirAdmin(eu); return listarUsuarios(env); }
  if (p === '/api/usuarios' && m === 'POST') { exigirAdmin(eu); return criarUsuario(req, env); }
  const mu = p.match(/^\/api\/usuarios\/(\d+)$/);
  if (mu && m === 'PUT') { exigirAdmin(eu); return editarUsuario(req, env, eu, Number(mu[1])); }

  throw erro(404, 'Rota não encontrada.');
}

// ---------------- Instalação / status ----------------
async function status(env) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM usuarios WHERE papel = 'admin'").first();
  const e = await lerEmpresa(env);
  return json({
    configurado: r.n > 0,
    empresa: { nome_fantasia: e.nome_fantasia, cor_principal: e.cor_principal, logo_key: e.logo_key }
  });
}

async function setup(req, env) {
  const b = await corpo(req);
  if (!env.CHAVE_INSTALACAO) throw erro(500, 'Configure o secret CHAVE_INSTALACAO no Worker antes do primeiro acesso.');
  if (!iguais(String(b.chave || ''), env.CHAVE_INSTALACAO)) throw erro(403, 'Chave de instalação incorreta.');
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM usuarios').first();
  if (r.n > 0) throw erro(409, 'O sistema já foi configurado.');

  const nome = texto(b.nome, 80, 'Nome');
  const usuario = validarUsuario(b.usuario);
  validarSenha(b.senha);
  const empresaNome = texto(b.empresa_nome, 80, 'Nome da empresa');

  await env.DB.batch([
    env.DB.prepare("UPDATE empresa SET nome_fantasia = ?, atualizado_em = datetime('now') WHERE id = 1").bind(empresaNome),
    env.DB.prepare("INSERT INTO usuarios (nome, usuario, senha_hash, papel) VALUES (?, ?, ?, 'admin')")
      .bind(nome, usuario, await gerarHash(b.senha))
  ]);
  return json({ ok: true }, 201);
}

// ---------------- Login / sessão ----------------
async function login(req, env) {
  const b = await corpo(req);
  const usuario = String(b.usuario || '').trim().toLowerCase();
  const senha = String(b.senha || '');
  if (!usuario || !senha) throw erro(400, 'Informe usuário e senha.');

  const agora = Date.now();
  const t = await env.DB.prepare('SELECT falhas, bloqueado_ate FROM tentativas_login WHERE usuario = ?').bind(usuario).first();
  if (t && t.bloqueado_ate > agora) {
    const min = Math.ceil((t.bloqueado_ate - agora) / 60000);
    throw erro(429, `Muitas tentativas. Tente novamente em ${min} minuto(s).`);
  }

  const u = await env.DB.prepare('SELECT * FROM usuarios WHERE usuario = ?').bind(usuario).first();
  // mesmo sem usuário, calcula um hash para não revelar quem existe pelo tempo de resposta
  const ok = u ? await verificarSenha(senha, u.senha_hash) : (await gerarHash(senha), false);

  if (!ok || !u.ativo) {
    const anteriores = t && t.bloqueado_ate === 0 ? t.falhas : 0;
    const falhas = anteriores + 1;
    const bloqueia = falhas >= MAX_TENTATIVAS;
    await env.DB.prepare(
      `INSERT INTO tentativas_login (usuario, falhas, bloqueado_ate) VALUES (?, ?, ?)
       ON CONFLICT(usuario) DO UPDATE SET falhas = excluded.falhas, bloqueado_ate = excluded.bloqueado_ate`
    ).bind(usuario, bloqueia ? 0 : falhas, bloqueia ? agora + BLOQUEIO_MIN * 60000 : 0).run();
    if (bloqueia) throw erro(429, `Muitas tentativas. Login bloqueado por ${BLOQUEIO_MIN} minutos.`);
    if (ok && !u.ativo) throw erro(403, 'Usuário desativado. Fale com o administrador.');
    throw erro(401, `Usuário ou senha inválidos. Restam ${MAX_TENTATIVAS - falhas} tentativa(s).`);
  }

  const token = tokenAleatorio();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM tentativas_login WHERE usuario = ?').bind(usuario),
    env.DB.prepare('DELETE FROM sessoes WHERE expira_em < ?').bind(agora),
    env.DB.prepare('INSERT INTO sessoes (token_hash, usuario_id, expira_em) VALUES (?, ?, ?)')
      .bind(await sha256hex(token), u.id, agora + SESSAO_DIAS * 86400000)
  ]);
  return json({ token, usuario: publico(u) });
}

async function logout(eu, env) {
  await env.DB.prepare('DELETE FROM sessoes WHERE token_hash = ?').bind(eu.token_hash).run();
  return json({ ok: true });
}

async function autenticar(req, env) {
  const h = req.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!token) throw erro(401, 'Faça login para continuar.');
  const th = await sha256hex(token);
  const s = await env.DB.prepare(
    `SELECT u.id, u.nome, u.usuario, u.papel, u.ativo, s.expira_em
     FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id WHERE s.token_hash = ?`
  ).bind(th).first();
  if (!s || s.expira_em < Date.now() || !s.ativo) throw erro(401, 'Sessão expirada. Faça login novamente.');
  return { ...s, token_hash: th };
}

function exigirAdmin(eu) {
  if (eu.papel !== 'admin') throw erro(403, 'Apenas o administrador pode fazer isso.');
}

// ---------------- Empresa ----------------
async function lerEmpresa(env) {
  return await env.DB.prepare('SELECT * FROM empresa WHERE id = 1').first();
}

async function salvarEmpresa(req, env) {
  const b = await corpo(req);
  const sets = [], vals = [];
  for (const c of CAMPOS_EMPRESA) {
    if (!(c in b)) continue;
    let v = b[c] == null ? '' : String(b[c]).trim();
    if (v.length > 300) throw erro(400, `Campo ${c} muito longo.`);
    if (c === 'nome_fantasia' && !v) throw erro(400, 'Nome fantasia é obrigatório.');
    if (c === 'cor_principal' && !/^#[0-9a-fA-F]{6}$/.test(v)) throw erro(400, 'Cor inválida (use #RRGGBB).');
    sets.push(`${c} = ?`);
    vals.push(v || null);
  }
  if (!sets.length) throw erro(400, 'Nada para salvar.');
  await env.DB.prepare(`UPDATE empresa SET ${sets.join(', ')}, atualizado_em = datetime('now') WHERE id = 1`).bind(...vals).run();
  return json(await lerEmpresa(env));
}

async function enviarLogo(req, env) {
  if (!env.ARQUIVOS) throw erro(500, 'Bucket R2 não vinculado ao Worker (binding ARQUIVOS).');
  const tipos = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' };
  const tipo = (req.headers.get('Content-Type') || '').split(';')[0].trim();
  if (!tipos[tipo]) throw erro(400, 'Envie a logo em PNG, JPG ou WEBP.');
  const dados = await req.arrayBuffer();
  if (!dados.byteLength) throw erro(400, 'Arquivo vazio.');
  if (dados.byteLength > LOGO_MAX_BYTES) throw erro(400, 'Logo maior que 2 MB.');

  const atual = await lerEmpresa(env);
  const key = `empresa/logo-${Date.now()}.${tipos[tipo]}`;
  await env.ARQUIVOS.put(key, dados, { httpMetadata: { contentType: tipo } });
  await env.DB.prepare("UPDATE empresa SET logo_key = ?, atualizado_em = datetime('now') WHERE id = 1").bind(key).run();
  if (atual.logo_key) await env.ARQUIVOS.delete(atual.logo_key);
  return json(await lerEmpresa(env));
}

async function removerLogo(env) {
  const atual = await lerEmpresa(env);
  if (atual.logo_key && env.ARQUIVOS) await env.ARQUIVOS.delete(atual.logo_key);
  await env.DB.prepare("UPDATE empresa SET logo_key = NULL, atualizado_em = datetime('now') WHERE id = 1").run();
  return json(await lerEmpresa(env));
}

async function arquivo(p, env) {
  if (!env.ARQUIVOS) throw erro(404, 'Arquivo não encontrado.');
  const key = decodeURIComponent(p.slice('/api/arquivos/'.length));
  // por enquanto só a pasta da empresa (logo) é pública
  if (!key.startsWith('empresa/') || key.includes('..')) throw erro(404, 'Arquivo não encontrado.');
  const obj = await env.ARQUIVOS.get(key);
  if (!obj) throw erro(404, 'Arquivo não encontrado.');
  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
      'Cache-Control': 'public, max-age=86400',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

// ---------------- Usuários ----------------
async function listarUsuarios(env) {
  const r = await env.DB.prepare('SELECT id, nome, usuario, papel, ativo, criado_em FROM usuarios ORDER BY ativo DESC, nome').all();
  return json(r.results);
}

async function criarUsuario(req, env) {
  const b = await corpo(req);
  const nome = texto(b.nome, 80, 'Nome');
  const usuario = validarUsuario(b.usuario);
  validarSenha(b.senha);
  const papel = b.papel === 'admin' ? 'admin' : 'colaborador';
  try {
    await env.DB.prepare('INSERT INTO usuarios (nome, usuario, senha_hash, papel) VALUES (?, ?, ?, ?)')
      .bind(nome, usuario, await gerarHash(b.senha), papel).run();
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) throw erro(409, 'Já existe alguém com esse usuário.');
    throw e;
  }
  return listarUsuarios(env);
}

async function editarUsuario(req, env, eu, id) {
  const b = await corpo(req);
  const alvo = await env.DB.prepare('SELECT * FROM usuarios WHERE id = ?').bind(id).first();
  if (!alvo) throw erro(404, 'Usuário não encontrado.');
  const proprio = alvo.id === eu.id;

  const sets = [], vals = [];
  let derrubarSessoes = false;
  if ('nome' in b) { sets.push('nome = ?'); vals.push(texto(b.nome, 80, 'Nome')); }
  if ('papel' in b) {
    const papel = b.papel === 'admin' ? 'admin' : 'colaborador';
    if (proprio && papel !== 'admin') throw erro(400, 'Você não pode tirar o seu próprio acesso de administrador.');
    sets.push('papel = ?'); vals.push(papel);
  }
  if ('ativo' in b) {
    const ativo = b.ativo ? 1 : 0;
    if (proprio && !ativo) throw erro(400, 'Você não pode desativar o seu próprio usuário.');
    sets.push('ativo = ?'); vals.push(ativo);
    if (!ativo) derrubarSessoes = true;
  }
  if (b.senha) {
    validarSenha(b.senha);
    sets.push('senha_hash = ?'); vals.push(await gerarHash(b.senha));
    derrubarSessoes = !proprio;
  }
  if (!sets.length) throw erro(400, 'Nada para salvar.');

  const ops = [env.DB.prepare(`UPDATE usuarios SET ${sets.join(', ')} WHERE id = ?`).bind(...vals, id)];
  if (derrubarSessoes) ops.push(env.DB.prepare('DELETE FROM sessoes WHERE usuario_id = ?').bind(id));
  if (b.senha) ops.push(env.DB.prepare('DELETE FROM tentativas_login WHERE usuario = ?').bind(alvo.usuario));
  await env.DB.batch(ops);
  return listarUsuarios(env);
}

// ---------------- Senhas e tokens ----------------
async function gerarHash(senha) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(senha, salt, PBKDF2_ITER);
  return `pbkdf2$${PBKDF2_ITER}$${b64(salt)}$${b64(bits)}`;
}

async function verificarSenha(senha, guardado) {
  const [alg, iter, saltB64, hashB64] = String(guardado).split('$');
  if (alg !== 'pbkdf2') return false;
  const bits = await pbkdf2(senha, deB64(saltB64), Number(iter));
  return iguais(b64(bits), hashB64);
}

async function pbkdf2(senha, salt, iter) {
  const chave = await crypto.subtle.importKey('raw', new TextEncoder().encode(senha), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, chave, 256));
}

function tokenAleatorio() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map(x => x.toString(16).padStart(2, '0')).join('');
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join('');
}

function iguais(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

const b64 = (u8) => btoa(String.fromCharCode(...u8));
const deB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// ---------------- Utilitários ----------------
function validarUsuario(v) {
  const u = String(v || '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,30}$/.test(u)) throw erro(400, 'Usuário deve ter 3 a 30 caracteres: letras, números, ponto, hífen ou _.');
  return u;
}

function validarSenha(v) {
  if (typeof v !== 'string' || v.length < 8) throw erro(400, 'A senha precisa ter pelo menos 8 caracteres.');
  if (v.length > 128) throw erro(400, 'Senha longa demais.');
}

function texto(v, max, nome) {
  const s = String(v ?? '').trim();
  if (!s) throw erro(400, `${nome} é obrigatório.`);
  if (s.length > max) throw erro(400, `${nome} muito longo.`);
  return s;
}

function publico(u) {
  return { id: u.id, nome: u.nome, usuario: u.usuario, papel: u.papel };
}

async function corpo(req) {
  try { return await req.json(); } catch { throw erro(400, 'Dados inválidos.'); }
}

function erro(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function json(dados, status = 200) {
  return new Response(JSON.stringify(dados), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function corsHeaders(req, env) {
  const origem = req.headers.get('Origin') || '';
  const permitidas = String(env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  // aceita também os endereços de pré-visualização do Pages (xxxx.auto-estetica.pages.dev)
  const ok = !permitidas.length || permitidas.some(p => origem === p || (p.endsWith('.pages.dev') && origem.endsWith('.' + p.replace(/^https?:\/\//, ''))));
  return {
    'Access-Control-Allow-Origin': ok ? (origem || '*') : permitidas[0],
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
