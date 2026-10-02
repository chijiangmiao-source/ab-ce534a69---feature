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

function renderLayer(layer, failedLayer) {
  const isFailed = failedLayer === layer.layer;
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

  const tds = rows
    .map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${v}</td></tr>`)
    .join('\n');
  return `<section class="layer${isFailed ? ' layer-failed' : ''}" aria-label="第 ${layer.layer} 层">
  <h3>第 ${layer.layer} 层 · ${esc(KIND_LABEL[layer.kind] || layer.kind)}${isFailed ? ' · 首个失败层' : ''}</h3>
  <table><tbody>${tds}</tbody></table>
</section>`;
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

// ---------------- 双时点对照结果页 ----------------

const CONCLUSION_VIEW = {
  enabled: { cls: 'banner-ok', title: '已启用' },
  revoked: { cls: 'banner-revoked', title: '已撤销' },
  'still-authorized': { cls: 'banner-ok', title: '持续授权' },
  'still-unauthorized': { cls: 'banner-no', title: '持续未授权' },
};

function compareBanner(cmp) {
  if (cmp.status === 'compared') {
    const view = CONCLUSION_VIEW[cmp.conclusion];
    const ev = cmp.earlier.result.value;
    const lv = cmp.later.result.value;
    const desc = {
      enabled: `两侧证明均完整有效：较早快照叶值 0x${esc(ev)}（未授权），较晚快照叶值 0x${esc(lv)}（启用承诺 01）——该指令在较晚时点已启用。`,
      revoked: `两侧证明均完整有效：较早快照叶值 0x${esc(ev)}（启用承诺 01），较晚快照叶值 0x${esc(lv)}（未授权）——该指令的授权在较晚时点已撤销。`,
      'still-authorized': `两侧证明均完整有效：两个时点叶值均为 0x${esc(lv)}（启用承诺 01）——授权持续有效，未发生变化。`,
      'still-unauthorized': `两侧证明均完整有效：较早叶值 0x${esc(ev)}、较晚叶值 0x${esc(lv)}，均非启用承诺 01——该指令持续未授权。`,
    }[cmp.conclusion];
    return `<div class="banner ${view.cls}" role="status">
      <span class="banner-title">${view.title}</span>
      <span class="banner-sub">${desc}</span>
    </div>`;
  }
  return `<div class="banner banner-bad" role="alert">
    <span class="banner-title">对照无效</span>
    <span class="banner-sub">${esc(cmp.reason || '')}</span>
    <span class="banner-sub">任一侧出现引用不符、非规范 RLP、路径残缺或输入标识不一致时，不得据另一侧的成功结果推断状态变化；此前的变更结论已清除。</span>
  </div>`;
}

function sideBadge(side) {
  if (side.inputError) return '<span class="badge badge-bad">输入无效</span>';
  if (!side.result) return '<span class="badge badge-bad">未核验</span>';
  if (side.result.status === 'authorized') return '<span class="badge badge-ok">已授权</span>';
  if (side.result.status === 'unauthorized') return '<span class="badge badge-no">未授权</span>';
  return '<span class="badge badge-bad">证明无效</span>';
}

function renderCompareSide(side) {
  const rows = [];
  rows.push(['32 字节根哈希', side.rootHash ? `<code class="hash">0x${esc(side.rootHash)}</code>` : '（缺失）']);
  rows.push(['十六进制指令标识', side.keyHex ? `<code>0x${esc(side.keyHex)}</code>` : '（缺失）']);
  rows.push(['证明 RLP 节点数', `${esc(side.nodeCount)}（根到叶顺序）`]);
  rows.push(['授权状态', sideBadge(side)]);
  if (side.result && side.result.value !== null && side.result.value !== undefined) {
    rows.push(['叶值', `<code>0x${esc(side.result.value)}</code>`]);
  }
  if (side.result) {
    rows.push(['已消费半字节路径', `<code>${esc(side.result.consumedPath || '（无）')}</code>`]);
  }
  if (side.inputError) {
    rows.push(['首个失败层', '第 0 层（输入校验阶段）']);
    rows.push(['失败原因', `<span class="reason">${esc(side.inputError)}</span>`]);
  } else if (side.result && side.result.status === 'invalid') {
    rows.push(['首个失败层', `第 ${esc(side.result.firstFailedLayer)} 层（${esc(side.result.code)}）`]);
    rows.push(['失败原因', `<span class="reason">${esc(side.result.reason)}</span>`]);
  }
  const dl = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('\n      ');

  let evidence;
  if (side.result && side.result.layers.length > 0) {
    const layersHtml = side.result.layers.map((l) => renderLayer(l, side.result.firstFailedLayer)).join('\n');
    evidence = `<details class="layers"><summary>逐层路径证据（共 ${side.result.layers.length} 层，点击展开）</summary>
${layersHtml}
</details>`;
  } else {
    evidence = '<p class="note">无已核验层。</p>';
  }
  const failMarker = side.result && side.result.status === 'invalid' ? renderFailureMarker(side.result) : '';

  return `<section class="side side-${esc(side.key)}" aria-label="${esc(side.label)}">
    <h2>${esc(side.label)}</h2>
    <dl class="side-meta">
      ${dl}
    </dl>
    ${evidence}
    ${failMarker}
  </section>`;
}

function buildComparePage(cmp) {
  const keyCell = cmp.keyHex
    ? `<code>0x${esc(cmp.keyHex)}</code>`
    : '（两侧输入标识不一致，见各自面板）';
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>离线指令授权快照双时点对照结果</title>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
  <h1>离线指令授权快照双时点对照</h1>
  ${compareBanner(cmp)}
  <section class="meta" aria-label="对照输入">
    <h2>对照输入</h2>
    <dl>
      <dt>十六进制指令标识</dt><dd>${keyCell}</dd>
      <dt>较早快照根哈希</dt><dd>${cmp.earlier.rootHash ? `<code class="hash">0x${esc(cmp.earlier.rootHash)}</code>` : '（缺失）'}</dd>
      <dt>较晚快照根哈希</dt><dd>${cmp.later.rootHash ? `<code class="hash">0x${esc(cmp.later.rootHash)}</code>` : '（缺失）'}</dd>
    </dl>
  </section>
  <div class="compare-grid">
    ${renderCompareSide(cmp.earlier)}
    ${renderCompareSide(cmp.later)}
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
.banner-revoked { border-color:#cf222e; background:rgba(207,34,46,.10); }
.compare-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:18px; margin:18px 0; }
.side { border:1px solid rgba(128,128,128,.4); border-radius:10px; padding:12px 16px; }
.side h2 { margin-top:4px; }
.side-earlier { border-top:4px solid #0969da; }
.side-later { border-top:4px solid #6f42c1; }
.side-meta { display:grid; grid-template-columns: 10em 1fr; gap:4px 12px; margin:8px 0; }
.side-meta dt { font-weight:600; } .side-meta dd { margin:0; word-break:break-all; }
.badge { display:inline-block; padding:1px 10px; border-radius:999px; font-weight:700; border:1.5px solid; }
.badge-ok { color:#1a7f37; border-color:#1a7f37; }
.badge-no { color:#9a6700; border-color:#9a6700; }
.badge-bad { color:#cf222e; border-color:#cf222e; }
details.layers { margin-top:10px; }
details.layers > summary { cursor:pointer; font-weight:600; }
fieldset { border:1px solid rgba(128,128,128,.4); border-radius:10px; margin:14px 0; padding:6px 14px 14px; }
legend { font-weight:700; padding:0 6px; }
form textarea, form input { width:100%; font-family: ui-monospace, Menlo, Consolas, monospace; font-size:.85rem; }
form textarea { min-height: 120px; }
label { font-weight:600; display:block; margin:12px 0 4px; }
button { margin-top:16px; padding:8px 18px; font-size:1rem; border-radius:8px; cursor:pointer; }
button.secondary { margin-left:10px; padding:8px 12px; font-size:.88rem; opacity:.9; }
.error-line { color:#cf222e; font-weight:600; white-space:pre-wrap; }
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
  <h2>双时点对照</h2>
  <p>为<strong>同一十六进制指令</strong>分别录入<strong>较早</strong>与<strong>较晚</strong>快照的根哈希及根到叶 RLP 节点，一次提交比对。系统独立核验两侧证明，仅在两侧都完整有效时归纳“持续授权 / 已撤销 / 已启用 / 持续未授权”；任一侧无效时仅显示该侧首个失败层，不据另一侧推断状态变化。</p>
  <form id="compare-form" method="post" action="/api/compare">
    <fieldset>
      <legend>较早快照（时点一）</legend>
      <label for="cmp-key-earlier">十六进制指令标识（hex，可带 0x）</label>
      <input id="cmp-key-earlier" name="cmpKeyEarlier" required placeholder="a1b2c3..." autocomplete="off">
      <label for="cmp-root-earlier">32 字节根哈希（hex，可带 0x）</label>
      <input id="cmp-root-earlier" name="cmpRootEarlier" required placeholder="0x..." autocomplete="off">
      <label for="cmp-nodes-earlier">RLP 节点（每行一个 hex；或 JSON 数组）</label>
      <textarea id="cmp-nodes-earlier" name="cmpNodesEarlier" required placeholder="0xf8...&#10;0xe3..."></textarea>
    </fieldset>
    <fieldset>
      <legend>较晚快照（时点二）</legend>
      <label for="cmp-key-later">十六进制指令标识（须与较早快照一致）</label>
      <input id="cmp-key-later" name="cmpKeyLater" required placeholder="a1b2c3..." autocomplete="off">
      <label for="cmp-root-later">32 字节根哈希（hex，可带 0x）</label>
      <input id="cmp-root-later" name="cmpRootLater" required placeholder="0x..." autocomplete="off">
      <label for="cmp-nodes-later">RLP 节点（每行一个 hex；或 JSON 数组）</label>
      <textarea id="cmp-nodes-later" name="cmpNodesLater" required placeholder="0xf8...&#10;0xe3..."></textarea>
    </fieldset>
    <p id="compare-error" class="error-line" role="alert"></p>
    <button type="submit">提交双时点对照</button>
    <button type="button" id="load-compare" class="secondary">载入对照示例：已启用 → 已撤销</button>
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

// ---- 双时点对照表单 ----
const cmpForm = document.getElementById('compare-form');
const cmpErr = document.getElementById('compare-error');
const cmpSide = (prefix) => ({
  keyHex: document.getElementById('cmp-key-' + prefix).value.trim(),
  rootHash: document.getElementById('cmp-root-' + prefix).value.trim(),
  proofNodes: document.getElementById('cmp-nodes-' + prefix).value
});
document.getElementById('load-compare').addEventListener('click', async () => {
  cmpErr.textContent = '';
  try {
    const res = await fetch('/api/sample/compare');
    const data = await res.json();
    for (const prefix of ['earlier', 'later']) {
      document.getElementById('cmp-key-' + prefix).value = data[prefix].keyHex;
      document.getElementById('cmp-root-' + prefix).value = data[prefix].rootHash;
      document.getElementById('cmp-nodes-' + prefix).value = data[prefix].proofNodes.join('\\n');
    }
  } catch (e) {
    cmpErr.textContent = '对照示例载入失败：' + e.message;
  }
});
cmpForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  cmpErr.textContent = '';
  const payload = { earlier: cmpSide('earlier'), later: cmpSide('later') };
  try {
    const res = await fetch('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      cmpErr.textContent = (data && data.error) ? data.error : ('请求失败：HTTP ' + res.status);
      return;
    }
    document.open();
    document.write(data.page);
    document.close();
  } catch (e) {
    cmpErr.textContent = '请求失败：' + e.message;
  }
});
`;

module.exports = { buildResultPage, buildIndexPage, buildComparePage, esc };
