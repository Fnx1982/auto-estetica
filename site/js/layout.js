// Monta o menu lateral e confere o login. Cada página chama: const { usuario, empresa } = await montarLayout('empresa', { somenteAdmin: true });

const ITENS_MENU = [
  { id: 'painel', nome: 'Painel', href: 'painel.html' },
  { id: 'entrada', nome: 'Entrada de veículo', breve: true },
  { id: 'clientes', nome: 'Clientes e veículos', breve: true },
  { id: 'patio', nome: 'Agenda / pátio', breve: true },
  { id: 'orcamentos', nome: 'Orçamentos', breve: true },
  { id: 'servicos', nome: 'Serviços e preços', breve: true },
  { id: 'estoque', nome: 'Estoque', breve: true },
  { id: 'financeiro', nome: 'Financeiro / caixa', breve: true, admin: true },
  { id: 'usuarios', nome: 'Colaboradores', href: 'usuarios.html', admin: true },
  { id: 'empresa', nome: 'Empresa', href: 'empresa.html', admin: true }
];

async function montarLayout(paginaAtiva, { somenteAdmin = false } = {}) {
  if (!API.token()) { location.href = 'index.html'; return new Promise(() => {}); }

  const { usuario, empresa } = await API.req('/api/me');
  const admin = usuario.papel === 'admin';
  if (somenteAdmin && !admin) { location.href = 'painel.html'; return new Promise(() => {}); }

  aplicarCor(empresa.cor_principal);
  document.title = document.title + ' · ' + empresa.nome_fantasia;

  const nav = el('nav', {}, ITENS_MENU.filter(i => admin || !i.admin).map(i =>
    i.breve
      ? el('span', { title: 'Disponível nas próximas etapas' }, i.nome, el('small', {}, 'em breve'))
      : el('a', { href: i.href, class: i.id === paginaAtiva ? 'ativo' : null }, i.nome)
  ));

  const menu = el('aside', { class: 'menu', id: 'menu' },
    el('div', { class: 'marca' }, logoEl(empresa),
      el('div', {}, el('div', { class: 'marca-nome', id: 'marca-nome' }, empresa.nome_fantasia), el('div', { class: 'marca-sub' }, 'Estética Automotiva'))),
    nav,
    el('div', { class: 'menu-rodape' },
      el('div', {}, 'Logado como ', el('b', {}, usuario.nome), admin ? ' (admin)' : ''),
      el('button', { type: 'button', onclick: sair }, 'Sair'))
  );

  const topo = el('div', { class: 'topo-mobile' },
    el('b', {}, empresa.nome_fantasia),
    el('button', { type: 'button', onclick: () => menu.classList.toggle('aberto') }, 'Menu'));

  const app = document.querySelector('.app');
  app.prepend(menu);
  app.prepend(topo);
  document.body.style.visibility = 'visible';
  return { usuario, empresa };
}

async function sair() {
  try { await API.req('/api/logout', { metodo: 'POST' }); } catch { /* sai mesmo assim */ }
  API.salvarToken(null);
  location.href = 'index.html';
}
