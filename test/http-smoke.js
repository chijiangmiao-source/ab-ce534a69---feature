'use strict';
// 对运行中的 web 服务执行端到端 HTTP 冒烟：
//   健康端点 / 静态入口页 / 示例快照 / 有效授权 / 篡改子节点引用 / 非规范 RLP
// 用法：BASE_URL=http://web:8080 node test/http-smoke.js
// 任一检查失败即以非零退出码结束。
const BASE = process.env.BASE_URL || 'http://127.0.0.1:8080';

let failures = 0;
function check(name, cond, detail) {
  if (cond) {
    console.log(`  ok - ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL - ${name}${detail ? '：' + detail : ''}`);
  }
}

async function postJson(path, body) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex'));
}

// 手工构造含非规范内嵌叶（c4 20 8101）的根分支 RLP。
function nonCanonicalNode() {
  const parts = [];
  for (let i = 0; i < 17; i++) parts.push(Buffer.from(i === 2 ? 'c4208101' : '80', 'hex'));
  const payload = Buffer.concat(parts);
  let prefix;
  if (payload.length < 56) prefix = Buffer.from([0xc0 + payload.length]);
  else {
    const lenBytes = [];
    let x = payload.length;
    while (x > 0) { lenBytes.push(x & 0xff); x = Math.floor(x / 256); }
    lenBytes.reverse();
    prefix = Buffer.from([0xf7 + lenBytes.length, ...lenBytes]);
  }
  return Buffer.concat([prefix, payload]);
}

function keccak256Local(bytes) {
  // 复用项目内实现，避免在冒烟脚本里依赖外部库。
  return require('../src/keccak').keccak256(bytes);
}
const { toHex } = require('../src/hexutil');

async function main() {
  console.log(`HTTP 冒烟目标：${BASE}`);

  const health = await fetch(BASE + '/healthz');
  check('GET /healthz 返回 200', health.status === 200);
  const healthBody = await health.json();
  check('健康体 status=ok', healthBody.status === 'ok', JSON.stringify(healthBody));

  const home = await fetch(BASE + '/');
  check('GET / 返回 200 HTML', home.status === 200 && /text\/html/.test(home.headers.get('content-type') || ''));
  const homeHtml = await home.text();
  check('入口页含三要素表单与静态入口标题',
    homeHtml.includes('name="rootHash"') && homeHtml.includes('name="keyHex"') &&
    homeHtml.includes('name="proofNodes"') && homeHtml.includes('离线指令授权快照复核'));

  const sampleRes = await fetch(BASE + '/api/sample');
  check('GET /api/sample 返回 200', sampleRes.status === 200);
  const sample = await sampleRes.json();
  check('示例含 32 字节根哈希', /^[0-9a-f]{64}$/.test(sample.rootHash));
  check('示例含已授权/未授权两套用例', !!sample.cases.authorized && !!sample.cases.unauthorized);

  // 场景一：有效授权
  const ok = await postJson('/api/verify', sample.cases.authorized);
  check('有效授权：HTTP 200', ok.status === 200);
  check('有效授权：status=authorized 且叶值 01',
    ok.json.result && ok.json.result.status === 'authorized' && ok.json.result.value === '01',
    JSON.stringify(ok.json.result && ok.json.result.status));
  check('结果页显示“已授权”并逐层回放',
    typeof ok.json.page === 'string' && ok.json.page.includes('已授权') &&
    ok.json.page.includes('累计已消费路径') && ok.json.page.includes('节点摘要'));

  // 场景二：篡改子节点引用（翻转第 2 个证明节点末尾一字节）
  const tampered = JSON.parse(JSON.stringify(sample.cases.authorized));
  const nodes = tampered.proofNodes.map(hexToBytes);
  nodes[1][nodes[1].length - 1] ^= 0x01;
  tampered.proofNodes = nodes.map((b) => toHex(b));
  const bad = await postJson('/api/verify', tampered);
  check('篡改引用：status=invalid / REF_MISMATCH / 第 2 层',
    bad.json.result && bad.json.result.status === 'invalid' &&
    bad.json.result.code === 'REF_MISMATCH' && bad.json.result.firstFailedLayer === 2,
    JSON.stringify(bad.json.result && bad.json.result.code));
  check('篡改页标明首个失败层且无“已授权”横幅',
    bad.json.page.includes('证明无效') && bad.json.page.includes('第 2 层') &&
    !bad.json.page.includes('banner-title">已授权'));

  // 场景三：非规范 RLP
  const ncNode = nonCanonicalNode();
  const nc = await postJson('/api/verify', {
    rootHash: toHex(keccak256Local(ncNode)),
    keyHex: '02',
    proofNodes: toHex(ncNode),
  });
  check('非规范 RLP：status=invalid / RLP_NONCANONICAL / 第 1 层',
    nc.json.result && nc.json.result.status === 'invalid' &&
    nc.json.result.code === 'RLP_NONCANONICAL' && nc.json.result.firstFailedLayer === 1,
    JSON.stringify(nc.json.result && nc.json.result.code));
  check('非规范页不含旧成功结论', nc.json.page.includes('证明无效') && !nc.json.page.includes('banner-title">已授权'));

  // 未授权：完整抵达叶但值 00
  const no = await postJson('/api/verify', sample.cases.unauthorized);
  check('未授权：status=unauthorized 且保留路径证据',
    no.json.result && no.json.result.status === 'unauthorized' &&
    no.json.result.value === '00' && no.json.result.layers.length > 0);
  check('未授权页明确显示“未授权”', no.json.page.includes('未授权'));

  // ===== 双时点对照 =====
  check('示例含双时点对照（启用→撤销）',
    sample.compare && sample.compare.revoked && sample.compare.revoked.earlier &&
    sample.compare.revoked.later && /^[0-9a-f]+$/.test(sample.compare.revoked.keyHex));
  const cmp = sample.compare.revoked;

  // 入口页应同时保留单快照表单并提供对照表单
  check('入口页含双时点对照表单与示例按钮',
    homeHtml.includes('id="compare-form"') && homeHtml.includes('id="c-earlier-root"') &&
    homeHtml.includes('id="c-later-root"') && homeHtml.includes('id="load-compare-revoke"') &&
    homeHtml.includes('id="verify-form"') && homeHtml.includes('id="load-ok"'));

  const cmpOk = await postJson('/api/compare', {
    keyHex: cmp.keyHex, earlier: cmp.earlier, later: cmp.later,
  });
  check('有效对照：HTTP 200 且 status=comparable / transition=revoked',
    cmpOk.status === 200 && cmpOk.json.result &&
    cmpOk.json.result.status === 'comparable' && cmpOk.json.result.transition === 'revoked',
    JSON.stringify(cmpOk.json.result && cmpOk.json.result.transition));
  check('有效对照：两侧叶值 01→00 且根摘要各自不同',
    cmpOk.json.result &&
    cmpOk.json.result.earlier.verification.value === '01' &&
    cmpOk.json.result.later.verification.value === '00' &&
    cmpOk.json.result.earlier.input.rootHash !== cmpOk.json.result.later.input.rootHash);
  check('有效对照页：已撤销横幅 + 左右面板 + 两条可展开逐层证据',
    cmpOk.json.page.includes('已撤销') && cmpOk.json.page.includes('side-earlier') &&
    cmpOk.json.page.includes('side-later') && cmpOk.json.page.includes(cmp.earlier.rootHash) &&
    cmpOk.json.page.includes(cmp.later.rootHash) &&
    (cmpOk.json.page.match(/<details /g) || []).length >= 6);

  // 较晚侧篡改扩展节点末字节：RLP 仍可解码，但子散列引用不符 -> REF_MISMATCH 第 2 层
  const tamperedLater = JSON.parse(JSON.stringify(cmp.later));
  tamperedLater.proofNodes = tamperedLater.proofNodes.map(hexToBytes).map((b, i) => {
    if (i === 1) b[b.length - 1] ^= 0x01;
    return toHex(b);
  });
  const cmpBad = await postJson('/api/compare', {
    keyHex: cmp.keyHex, earlier: cmp.earlier, later: tamperedLater,
  });
  check('篡改对照：status=invalid / 不归纳变化（transition=null）',
    cmpBad.json.result && cmpBad.json.result.status === 'invalid' &&
    cmpBad.json.result.transition === null &&
    cmpBad.json.result.failures && cmpBad.json.result.failures.length === 1 &&
    cmpBad.json.result.failures[0].side === 'later' &&
    cmpBad.json.result.failures[0].code === 'REF_MISMATCH' &&
    cmpBad.json.result.failures[0].firstFailedLayer === 2,
    JSON.stringify(cmpBad.json.result && cmpBad.json.result.failures));
  check('篡改对照页：显示对照无效与失败层，不残留已撤销等变更结论',
    cmpBad.json.page.includes('对照无效') && cmpBad.json.page.includes('第 2 层') &&
    !cmpBad.json.page.includes('banner-title">已撤销') &&
    !cmpBad.json.page.includes('持续授权') &&
    // 较早侧独立成功结果仍保留展示
    cmpBad.json.page.includes('side-earlier') && cmpBad.json.page.includes(cmp.earlier.rootHash));

  // 输入标识不一致
  const cmpKeyMismatch = await postJson('/api/compare', {
    keyHex: cmp.keyHex, earlier: cmp.earlier, later: { ...cmp.later, keyHex: 'deadbeef' },
  });
  check('标识不一致：KEY_MISMATCH 第 0 层失败',
    cmpKeyMismatch.json.result && cmpKeyMismatch.json.result.status === 'invalid' &&
    cmpKeyMismatch.json.result.failures[0].code === 'KEY_MISMATCH' &&
    cmpKeyMismatch.json.result.failures[0].firstFailedLayer === 0);

  // 缺少一侧 -> 400
  const cmpMissing = await postJson('/api/compare', { keyHex: cmp.keyHex, earlier: cmp.earlier });
  check('缺少较晚侧：HTTP 400', cmpMissing.status === 400 && /较早|较晚/.test(cmpMissing.json.error || ''));

  console.log(`\nHTTP 冒烟：${failures === 0 ? '全部通过 ✅' : failures + ' 项失败'}`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error('HTTP 冒烟运行器异常（目标可能未就绪）：', e.message);
  process.exit(2);
});
