'use strict';
// 结果页构建：把核验内核的结构化结果渲染为静态 HTML（Node 与浏览器共用）。
// Node 端由 HTTP 服务在服务端渲染后返回；页面构建逻辑可在无 DOM 的测试中直接断言。

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const KIND_LABEL = {
  leaf: '叶节点',
  extension: '扩展节点',
  branch: '分支节点',
  'branch-value': '分支节点（值槽）',
};

const REF_LABEL = {
  'root-commitment': '根承诺（32 字节根哈希）',
  'hash-32': '32 字节散列引用',
  'embedded-node': '内嵌节点（父节点 RLP 内联）',
};

function statusBanner(result) {
  if (result.status === 'authorized') {
    return `<div class="banner banner-ok" role="status">
      <span class="banner-title">已授权</span>
      <span class="banner-sub">证明有效，叶值为 <code>0x${esc(result.value)}</code>（启用承诺 <code>01</code>）</span>
    </div>`;
  }
  if (result.status === 'unauthorized') {
    return `<div class="banner banner-no" role="status">
      <span class="banner-title">未授权</span>
      <span class="banner-sub">路径完整抵达叶节点，但叶值为 <code>0x${esc(result.value)}</code>，并非启用承诺 <code>01</code>。路径证据保留如下。</span>
    </div>`;
  }
  return `<div class="banner banner-bad" role="alert">
    <span class="banner-title">证明无效</span>
    <span class="banner-sub">首个失败层：<strong>第 ${esc(result.firstFailedLayer)} 层</strong>（${esc(result.code)}）——${esc(result.reason)}</span>
  </div>`;
}

function layerRows(layer) {
  const rows = [];
  rows.push(['层号', `第 ${layer.layer} 层`]);
  rows.push(['节点类型', KIND_LABEL[layer.kind] || layer.kind]);
  rows.push(['引用方式', REF_LABEL[layer.reference] || layer.reference]);
  if (layer.embeddedInLayer) rows.push(['内嵌于', `第 ${layer.embeddedInLayer} 层节点的 RLP 负载`]);
  rows.push(['节点摘要（Keccak-256）', `<code class="hash">0x${esc(layer.nodeHash)}</code>`]);
  rows.push(['RLP 长度', `${layer.rlpSize} 字节${layer.rlpSize < 32 ? '（< 32，可内嵌）' : '（≥ 32，须散列引用）'}`]);
  if (layer.hpPrefix !== undefined) rows.push(['十六进制前缀', `<code>0x${esc(layer.hpPrefix)}</code>`]);
  if (layer.slot !== undefined) {
    rows.push(['分支槽', layer.slot === 16 ? '16（值槽）' : `0x${layer.slot.toString(16)}`]);
  }
  if (layer.consumedNibbles !== undefined && layer.consumedNibbles !== '') {
    rows.push(['本层消费半字节', `<code>${esc(layer.consumedNibbles)}</code>`]);
  }
  if (layer.cumulativePath !== undefined) {
    rows.push(['累计已消费路径', `<code>${esc(layer.cumulativePath) || '（空）'}</code>`]);
  }
  if (layer.childReference) {
    const refDesc = REF_LABEL[layer.childReference] || layer.childReference;
    rows.push(['子节点引用方式', layer.childHash ? `${refDesc} <code class="hash">0x${esc(layer.childHash)}</code>` : refDesc]);
  }
  if (layer.value !== undefined) rows.push(['叶/槽值', `<code>0x${esc(layer.value)}</code>`]);
  return rows;
}

function renderLayer(layer, failedLayer) {
  const isFailed = failedLayer === layer.layer;
  const tds = layerRows(layer)
    .map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${v}</td></tr>`)
    .join('\n');
  return `<section class="layer${isFailed ? ' layer-failed' : ''}" aria-label="第 ${layer.layer} 层">
  <h3>第 ${layer.layer} 层 · ${esc(KIND_LABEL[layer.kind] || layer.kind)}${isFailed ? ' · 首个失败层' : ''}</h3>
  <table><tbody>${tds}</tbody></table>
</section>`;
}

// 双时点对照用：把每一层包成可单独展开的 <details>，默认只展开最后一层
// （失败侧则展开首个失败层），其余层审查员可逐层展开回放。
function renderLayerDetails(layer, { failedLayer, openLayer } = {}) {
  const isFailed = failedLayer === layer.layer;
  const tds = layerRows(layer)
    .map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${v}</td></tr>`)
    .join('\n');
  const open = openLayer === layer.layer ? ' open' : '';
  return `<details class="layer layer-details${isFailed ? ' layer-failed' : ''}"${open} aria-label="第 ${layer.layer} 层">
  <summary>第 ${layer.layer} 层 · ${esc(KIND_LABEL[layer.kind] || layer.kind)}${isFailed ? ' · 首个失败层' : ''} · <code class="hash">0x${esc(layer.nodeHash.slice(0, 16))}…</code></summary>
  <table><tbody>${tds}</tbody></table>
</details>`;
}

function renderFailureMarker(result) {
  if (result.status !== 'invalid') return '';
  return `<section class="layer layer-failed" aria-label="首个失败层">
  <h3>第 ${esc(result.firstFailedLayer)} 层 · 核验中止</h3>
  <p class="reason"><strong>${esc(result.code)}</strong>：${esc(result.reason)}</p>
  <p class="note">旧成功结论已清除；以上各层为中止前已核验保留的路径证据。</p>
</section>`;
}

function buildResultPage(result, input) {
  const meta = input || {};
  const layersHtml = result.layers.map((l) => renderLayer(l, result.firstFailedLayer)).join('\n');
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>离线指令授权快照复核结果</title>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
  <h1>离线指令授权快照复核</h1>
  ${statusBanner(result)}
  <section class="meta" aria-label="核验输入">
    <h2>核验输入</h2>
    <dl>
      <dt>32 字节根哈希</dt><dd><code class="hash">0x${esc(meta.rootHash || '')}</code></dd>
      <dt>十六进制指令标识</dt><dd><code>0x${esc(meta.keyHex || '')}</code></dd>
      <dt>证明 RLP 节点数</dt><dd>${esc(meta.nodeCount ?? result.layers.length)}（根到叶顺序）</dd>
      <dt>完整已消费半字节路径</dt><dd><code>${esc(result.consumedPath || '（无）')}</code></dd>
    </dl>
  </section>
  <h2>逐层节点回放</h2>
  ${layersHtml || '<p class="note">无已核验层。</p>'}
  ${renderFailureMarker(result)}
  <p class="back"><a href="/">返回导入页</a></p>
</main>
</body>
</html>`;
}

// ========== 双时点对照 ==========

const SIDE_LABEL = { earlier: '较早快照', later: '较晚快照' };

const TRANSITION_TEXT = {
  'still-authorized': { title: '持续授权', cls: 'banner-ok', desc: '较早与较晚两张快照的证明均完整有效，叶值均为启用承诺 <code>01</code>，授权状态未发生变化。' },
  revoked: { title: '已撤销', cls: 'banner-revoked', desc: '较早快照叶值为启用承诺 <code>01</code>，较晚快照叶值已非 <code>01</code>；两侧证明均完整有效，授权已被撤销。' },
  enabled: { title: '已启用', cls: 'banner-ok', desc: '较早快照叶值非启用承诺 <code>01</code>，较晚快照叶值为 <code>01</code>；两侧证明均完整有效，授权已启用。' },
  'still-unauthorized': { title: '持续未授权', cls: 'banner-no', desc: '较早与较晚两张快照的证明均完整有效，叶值均非启用承诺 <code>01</code>，授权状态未发生变化。' },
};

function compareBanner(result) {
  if (result.status === 'comparable') {
    const t = TRANSITION_TEXT[result.transition];
    return `<div class="banner ${t.cls}" role="status">
      <span class="banner-title">${t.title}</span>
      <span class="banner-sub">${t.desc}</span>
    </div>`;
  }
  const items = result.failures
    .map((f) => `<li><strong>${esc(SIDE_LABEL[f.side])}</strong>：首个失败层<strong>第 ${esc(f.firstFailedLayer)} 层</strong>（${esc(f.code)}）——${esc(f.reason)}</li>`)
    .join('\n      ');
  return `<div class="banner banner-bad" role="alert">
    <span class="banner-title">对照无效</span>
    <span class="banner-sub">两侧证明未经各自独立核验通过，<strong>不归纳任何授权状态变化</strong>，也不得以另一侧的成功结果推断本侧状态。失败侧如下：</span>
    <ul class="failure-list">
      ${items}
    </ul>
  </div>`;
}

function sideStatusPill(v) {
  if (v.status === 'authorized') {
    return `<span class="pill pill-ok">已授权</span> 叶值 <code>0x${esc(v.value)}</code>（启用承诺 <code>01</code>）`;
  }
  if (v.status === 'unauthorized') {
    return `<span class="pill pill-no">未授权</span> 叶值 <code>0x${esc(v.value)}</code>（非启用承诺 <code>01</code>）`;
  }
  return `<span class="pill pill-bad">证明无效</span> 首个失败层<strong>第 ${esc(v.firstFailedLayer)} 层</strong>（${esc(v.code)}）`;
}

function renderSidePanel(side, rec) {
  const v = rec.verification;
  const failed = v.status === 'invalid';
  // 有效侧默认展开末层；失败侧展开首个失败层（若该层有已核验证据），
  // 纯输入层失败（第 0 层）时展开已保留的最后一层。
  const openLayer = failed
    ? (v.layers.some((l) => l.layer === v.firstFailedLayer)
        ? v.firstFailedLayer
        : (v.layers.length ? v.layers[v.layers.length - 1].layer : null))
    : (v.layers.length ? v.layers[v.layers.length - 1].layer : null);
  const layersHtml = v.layers
    .map((l) => renderLayerDetails(l, { failedLayer: v.firstFailedLayer, openLayer }))
    .join('\n  ');
  const failureMarker = failed
    ? `<details class="layer layer-failed layer-details" open aria-label="首个失败层">
  <summary>第 ${esc(v.firstFailedLayer)} 层 · 核验中止 · ${esc(v.code)}</summary>
  <p class="reason"><strong>${esc(v.code)}</strong>：${esc(v.reason)}</p>
  <p class="note">该侧核验在此中止；仅保留中止前已独立核验的路径层，另一侧的成功结果不能替代或推断本层。</p>
</details>`
    : '';
  return `<section class="side-panel side-${side}${failed ? ' side-invalid' : ''}" aria-label="${esc(SIDE_LABEL[side])}">
  <h2>${esc(SIDE_LABEL[side])}</h2>
  <dl class="side-meta">
    <dt>根摘要（32 字节根哈希）</dt><dd><code class="hash">0x${esc(rec.input.rootHash || '（未提供）')}</code></dd>
    <dt>叶值与授权状态</dt><dd>${sideStatusPill(v)}</dd>
    <dt>完整已消费半字节路径</dt><dd><code>${esc(v.consumedPath || '（无）')}</code></dd>
    <dt>证明 RLP 节点数</dt><dd>${esc(rec.input.nodeCount ?? v.layers.length)}（根到叶顺序）</dd>
  </dl>
  <h3>逐层路径证据（可展开）</h3>
  <div class="layer-list">
  ${layersHtml || '<p class="note">该侧无已核验层。</p>'}
  ${failureMarker}
  </div>
</section>`;
}

function buildComparePage(result) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>离线指令授权双时点对照结果</title>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
  <h1>离线指令授权双时点对照</h1>
  <p class="note">同一十六进制指令 <code>0x${esc(result.keyHex)}</code> 在较早与较晚两张离线快照中的独立核验结果。</p>
  ${compareBanner(result)}
  <div class="side-grid">
    ${renderSidePanel('earlier', result.earlier)}
    ${renderSidePanel('later', result.later)}
  </div>
  <p class="back"><a href="/">返回导入页</a></p>
</main>
</body>
</html>`;
}

const STYLES = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; font-family: system-ui, "PingFang SC", "Microsoft YaHei", sans-serif; line-height:1.6; }
.page { max-width: 920px; margin: 0 auto; padding: 24px 18px 64px; }
h1 { font-size: 1.5rem; } h2 { margin-top: 28px; font-size: 1.15rem; }
.banner { border-radius: 10px; padding: 16px 18px; margin: 18px 0; display:flex; flex-direction:column; gap:4px; border:2px solid; }
.banner-title { font-size: 1.25rem; font-weight: 700; }
.banner-ok { border-color:#1a7f37; background:rgba(34,139,64,.12); }
.banner-no { border-color:#9a6700; background:rgba(190,145,0,.12); }
.banner-bad { border-color:#cf222e; background:rgba(207,34,46,.10); }
.banner-revoked { border-color:#bf5700; background:rgba(214,107,0,.12); }
.failure-list { margin:6px 0 0; padding-left: 20px; }
.failure-list li { margin: 3px 0; }
.side-grid { display:grid; grid-template-columns: 1fr 1fr; gap:18px; align-items:start; }
@media (max-width: 860px) { .side-grid { grid-template-columns: 1fr; } }
.side-panel { border:2px solid rgba(128,128,128,.45); border-radius:12px; padding:10px 16px 16px; }
.side-earlier { border-color:#0969da; }
.side-later { border-color:#8250df; }
.side-invalid { border-color:#cf222e; background:rgba(207,34,46,.04); }
.side-panel h2 { margin-top:10px; font-size:1.05rem; display:flex; align-items:center; gap:8px; }
.side-earlier h2::before { content:'◀'; color:#0969da; font-size:.9rem; font-weight:700; }
.side-later h2::after { content:'▶'; color:#8250df; font-size:.9rem; font-weight:700; }
.side-meta { display:grid; grid-template-columns: 9.5em 1fr; gap:4px 12px; margin: 6px 0 4px; }
.side-meta dt { font-weight:600; } .side-meta dd { margin:0; word-break:break-all; }
.pill { display:inline-block; border-radius:999px; padding:1px 10px; font-size:.82rem; font-weight:700; border:1.5px solid; }
.pill-ok { border-color:#1a7f37; color:#1a7f37; }
.pill-no { border-color:#9a6700; color:#9a6700; }
.pill-bad { border-color:#cf222e; color:#cf222e; }
.layer-details summary { cursor:pointer; font-weight:600; padding:4px 0; list-style: revert; }
.layer-details[open] summary { margin-bottom:6px; border-bottom:1px dashed rgba(128,128,128,.35); }
.layer-list .layer { margin:10px 0; }
.layer { border:1px solid rgba(128,128,128,.4); border-radius:10px; padding:12px 16px; margin:14px 0; }
.layer-failed { border-color:#cf222e; border-width:2px; background:rgba(207,34,46,.06); }
.layer h3 { margin: 4px 0 8px; font-size: 1rem; }
table { border-collapse: collapse; width:100%; }
th,td { text-align:left; vertical-align:top; padding:5px 10px 5px 0; border-bottom:1px dashed rgba(128,128,128,.35); font-weight:400; }
th { width: 13em; color: rgba(128,128,128,1); white-space:nowrap; }
code { word-break: break-all; }
.hash { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:.85rem; }
.meta dl { display:grid; grid-template-columns: 12em 1fr; gap:4px 16px; }
.meta dt { font-weight:600; } .meta dd { margin:0; word-break:break-all; }
.reason { color:#cf222e; font-weight:600; }
.note { color: rgba(128,128,128,1); font-size:.92rem; }
form textarea, form input { width:100%; font-family: ui-monospace, Menlo, Consolas, monospace; font-size:.85rem; }
form textarea { min-height: 120px; }
label { font-weight:600; display:block; margin:12px 0 4px; }
button { margin-top:16px; padding:8px 18px; font-size:1rem; border-radius:8px; cursor:pointer; }
button.secondary { margin-left:10px; padding:8px 12px; font-size:.88rem; opacity:.9; }
.error-line { color:#cf222e; font-weight:600; white-space:pre-wrap; }
.form-sep { margin: 36px 0 8px; border:0; border-top:2px solid rgba(128,128,128,.35); }
.compare-grid { display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-top:8px; }
@media (max-width: 860px) { .compare-grid { grid-template-columns: 1fr; } }
.compare-side { border:2px solid; border-radius:12px; padding:6px 16px 14px; margin:0; min-width:0; }
.compare-side legend { font-weight:700; padding:0 6px; }
.compare-earlier { border-color:#0969da; }
.compare-earlier legend { color:#0969da; }
.compare-later { border-color:#8250df; }
.compare-later legend { color:#8250df; }
`;

function buildIndexPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>离线指令授权快照复核</title>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
  <h1>离线指令授权快照复核</h1>
  <p>地面审查员导入离线授权快照：提交 <strong>32 字节根哈希</strong>、<strong>十六进制指令标识</strong> 与<strong>按根到叶排序的 RLP 节点</strong>。系统核验该指令是否被承诺为启用（叶值 <code>01</code>）。</p>
  <form id="verify-form" method="post" action="/api/verify">
    <label for="rootHash">32 字节根哈希（hex，可带 0x）</label>
    <input id="rootHash" name="rootHash" required placeholder="0x..." autocomplete="off">
    <label for="keyHex">十六进制指令标识（hex，可带 0x）</label>
    <input id="keyHex" name="keyHex" required placeholder="a1b2c3..." autocomplete="off">
    <label for="proofNodes">RLP 节点（每行一个 hex；或填写由节点 hex 组成的 JSON 数组）</label>
    <textarea id="proofNodes" name="proofNodes" required placeholder="0xf8...&#10;0xe3..."></textarea>
    <p id="form-error" class="error-line" role="alert"></p>
    <button type="submit">核验授权</button>
    <button type="button" id="load-ok" class="secondary">载入示例：已授权（叶值 01）</button>
    <button type="button" id="load-no" class="secondary">载入示例：未授权（叶值 00）</button>
  </form>

  <hr class="form-sep">
  <h2>双时点快照对照</h2>
  <p>为<strong>同一条十六进制指令</strong>分别录入<strong>较早</strong>与<strong>较晚</strong>两张快照的根哈希与根到叶 RLP 节点，一次提交比对。两侧证明各自独立核验：仅当两侧都完整有效时，才归纳“持续授权 / 已撤销 / 已启用 / 持续未授权”；任一侧失败，结论仅显示该侧首个失败层，不推断状态变化。</p>
  <form id="compare-form">
    <label for="c-keyHex">十六进制指令标识（两侧共用，hex，可带 0x）</label>
    <input id="c-keyHex" name="keyHex" required placeholder="a1b2c3..." autocomplete="off">
    <div class="compare-grid">
      <fieldset class="compare-side compare-earlier">
        <legend>较早快照</legend>
        <label for="c-earlier-root">32 字节根哈希（hex，可带 0x）</label>
        <input id="c-earlier-root" required placeholder="0x..." autocomplete="off">
        <label for="c-earlier-nodes">根到叶 RLP 节点（每行一个 hex，或 JSON 数组）</label>
        <textarea id="c-earlier-nodes" required placeholder="0xf8...&#10;0xe3..."></textarea>
      </fieldset>
      <fieldset class="compare-side compare-later">
        <legend>较晚快照</legend>
        <label for="c-later-root">32 字节根哈希（hex，可带 0x）</label>
        <input id="c-later-root" required placeholder="0x..." autocomplete="off">
        <label for="c-later-nodes">根到叶 RLP 节点（每行一个 hex，或 JSON 数组）</label>
        <textarea id="c-later-nodes" required placeholder="0xf8...&#10;0xe3..."></textarea>
      </fieldset>
    </div>
    <p id="compare-error" class="error-line" role="alert"></p>
    <button type="submit">提交双时点对照</button>
    <button type="button" id="load-compare-revoke" class="secondary">载入对照示例：启用 → 撤销</button>
  </form>
</main>
<script>
${CLIENT_SCRIPT}
</script>
</body>
</html>`;
}

const CLIENT_SCRIPT = `
const form = document.getElementById('verify-form');
const fill = (c) => {
  document.getElementById('rootHash').value = c.rootHash;
  document.getElementById('keyHex').value = c.keyHex;
  document.getElementById('proofNodes').value = c.proofNodes.join('\\n');
};
for (const [id, kind] of [['load-ok','authorized'], ['load-no','unauthorized']]) {
  document.getElementById(id).addEventListener('click', async () => {
    const errEl = document.getElementById('form-error');
    errEl.textContent = '';
    try {
      const res = await fetch('/api/sample');
      const data = await res.json();
      fill(data.cases[kind]);
    } catch (e) {
      errEl.textContent = '示例载入失败：' + e.message;
    }
  });
}
form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errEl = document.getElementById('form-error');
  errEl.textContent = '';
  const payload = {
    rootHash: document.getElementById('rootHash').value.trim(),
    keyHex: document.getElementById('keyHex').value.trim(),
    proofNodes: document.getElementById('proofNodes').value
  };
  try {
    const res = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = (data && data.error) ? data.error : ('请求失败：HTTP ' + res.status);
      return;
    }
    document.open();
    document.write(data.page);
    document.close();
  } catch (e) {
    errEl.textContent = '请求失败：' + e.message;
  }
});

// ---- 双时点对照 ----
const cForm = document.getElementById('compare-form');
const fillCompare = (c) => {
  document.getElementById('c-keyHex').value = c.keyHex;
  document.getElementById('c-earlier-root').value = c.earlier.rootHash;
  document.getElementById('c-earlier-nodes').value = c.earlier.proofNodes.join('\\n');
  document.getElementById('c-later-root').value = c.later.rootHash;
  document.getElementById('c-later-nodes').value = c.later.proofNodes.join('\\n');
};
document.getElementById('load-compare-revoke').addEventListener('click', async () => {
  const errEl = document.getElementById('compare-error');
  errEl.textContent = '';
  try {
    const res = await fetch('/api/sample');
    const data = await res.json();
    if (!data.compare || !data.compare.revoked) throw new Error('示例数据缺少对照用例');
    fillCompare(data.compare.revoked);
  } catch (e) {
    errEl.textContent = '对照示例载入失败：' + e.message;
  }
});
cForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errEl = document.getElementById('compare-error');
  errEl.textContent = '';
  const payload = {
    keyHex: document.getElementById('c-keyHex').value.trim(),
    earlier: {
      rootHash: document.getElementById('c-earlier-root').value.trim(),
      proofNodes: document.getElementById('c-earlier-nodes').value
    },
    later: {
      rootHash: document.getElementById('c-later-root').value.trim(),
      proofNodes: document.getElementById('c-later-nodes').value
    }
  };
  try {
    const res = await fetch('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = (data && data.error) ? data.error : ('请求失败：HTTP ' + res.status);
      return;
    }
    document.open();
    document.write(data.page);
    document.close();
  } catch (e) {
    errEl.textContent = '请求失败：' + e.message;
  }
});
`;

module.exports = { buildResultPage, buildIndexPage, buildComparePage, esc };
