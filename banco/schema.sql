-- Auto Estética — banco D1 (etapa 1: empresa, usuários, sessões e bloqueio de login)
-- Rodar no painel do Cloudflare: D1 > auto-estetica-db > Console > colar tudo > Execute.
-- Pode rodar de novo sem perder dados (IF NOT EXISTS / OR IGNORE).

CREATE TABLE IF NOT EXISTS empresa (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  nome_fantasia TEXT NOT NULL DEFAULT 'Minha Estética Automotiva',
  razao_social TEXT,
  documento TEXT,
  inscricao_municipal TEXT,
  whatsapp TEXT,
  instagram TEXT,
  endereco TEXT,
  horario TEXT,
  chave_pix TEXT,
  rodape_orcamento TEXT,
  cor_principal TEXT NOT NULL DEFAULT '#0EA5E9',
  logo_key TEXT,
  atualizado_em TEXT
);

INSERT OR IGNORE INTO empresa (id) VALUES (1);

CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  usuario TEXT NOT NULL UNIQUE COLLATE NOCASE,
  senha_hash TEXT NOT NULL,
  papel TEXT NOT NULL CHECK (papel IN ('admin', 'colaborador')),
  ativo INTEGER NOT NULL DEFAULT 1,
  criado_em TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessoes (
  token_hash TEXT PRIMARY KEY,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
  expira_em INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessoes_usuario ON sessoes(usuario_id);

CREATE TABLE IF NOT EXISTS tentativas_login (
  usuario TEXT PRIMARY KEY COLLATE NOCASE,
  falhas INTEGER NOT NULL DEFAULT 0,
  bloqueado_ate INTEGER NOT NULL DEFAULT 0
);
