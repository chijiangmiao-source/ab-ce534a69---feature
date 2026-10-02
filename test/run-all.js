'use strict';
// 验收测试总入口：按「有效授权 → 篡改子节点引用 → 非规范 RLP」三大场景，
// 穿插运行 证明内核校验 / 结果页构建检查 / API 与 HTTP（含健康端点）冒烟。
const { createHarness, assert } = require('./harness');
const { buildSnapshots } = require('./fixtures');
const { verifyProof } = require('../src/verifier');
const { handleVerify, parseProofNodes } = require('../src/verify-api');
const { buildResultPage, buildIndexPage } = require('../src/page');
const { createServer } = require('../src/server');
const { keccak256 } = require('../src/keccak');
const rlp = require('../src/rlp');
const hp = require('../src/hexpath');
const { toHex, fromHex, bytesToNibbles, equalBytes } = require('../src/hexutil');

const B = (hex) => fromHex(hex);
const U = (...xs) => Uint8Array.of(...xs);

// 手工 RLP 列表封装（用于构造含非规范内嵌项的测试字节）。
function concatRaw(parts) {
  return Buffer.concat(parts.map((p) => Buffer.from(p)));
}
function rlpLenPrefix(payloadLen, base) {
  if (payloadLen < 56) return Uint8Array.of(base + payloadLen);
  const bytes = [];
  let x = payloadLen;
  while (x > 0) {
    bytes.push(x & 0xff);
    x = Math.floor(x / 256);
  }
  bytes.reverse();
  return Uint8Array.of(base + 55 + bytes.length, ...bytes);
}

async function main() {
  const h = createHarness();
  const { test, suite, assert: a } = h;

  const snap = buildSnapshots();
  const keyAuth = snap.keys.authorized;
  const keyNo = snap.keys.unauthorized;
  const proofAuth = snap.proofFor(keyAuth);
  const proofNo = snap.proofFor(keyNo);

  // ---------- 原语向量 ----------
  await suite('原语：Keccak-256 / RLP / HP').run(async () => {
    test('Keccak-256 空串与 "abc" 标准向量', () => {
      a.equal(toHex(keccak256(U())), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
      a.equal(toHex(keccak256(Buffer.from('abc'))), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
    });

    test('RLP 标准编码向量', () => {
      a.equal(toHex(rlp.encode(B('646f67'))), '83646f67');
      a.equal(toHex(rlp.encode(U())), '80');
      a.equal(toHex(rlp.encode([])), 'c0');
      a.equal(toHex(rlp.encode(U(0))), '00');
    });

    test('RLP 拒绝非规范/截断/前导零/尾部多余字节', () => {
      // 截断/结构错误：宽容与严格两种解码都必须拒绝
      const broken = [
        ['8261', '短串截断'],
        ['c1', '列表截断'],
        ['f838' + 'c0'.repeat(0x37), '长列表截断（声明 56 字节负载，实给 55）'],
        ['8000', '完整项后多余字节'],
      ];
      for (const [hex, label] of broken) {
        a.throws(() => rlp.decode(B(hex)), undefined, label);
        a.throws(() => rlp.decodeCanonical(B(hex)), undefined, label + '（严格）');
      }
      // 纯非规范形式：宽容解码接受、严格解码拒绝
      const noncanon = [
        ['8100', '单字节 0x00 的长形式'],
        ['817f', '单字节 0x7f 的长形式'],
        ['b800', '空串误用长形式'],
        ['b837' + '61'.repeat(0x37), '55 字节误用长形式'],
        ['b90038' + '61'.repeat(0x38), '长度前导零'],
      ];
      for (const [hex, label] of noncanon) {
        a.doesNotThrow(() => rlp.decode(B(hex)), label + ' 可被宽容解码');
        a.throws(() => rlp.decodeCanonical(B(hex)), undefined, label);
      }
      // 非规范形式重编码后字节必然不同
      const nc = rlp.decode(B('8100'));
      a.notEqual(toHex(rlp.encode(nc)), '8100');
    });

    test('HP 编解码往返与非法前缀拒绝', () => {
      for (const [nibs, term] of [[[1, 2, 3], true], [[0xa, 0xb], false], [[0xf], true], [[], true]]) {
        const d = hp.decode(hp.encode(nibs, term));
        a.deepEqual(d.nibbles, nibs);
        a.equal(d.terminator, term);
      }
      a.throws(() => hp.decode(B('40')), /高两位/, '高两位置位');
      a.throws(() => hp.decode(B('0fab')), /填充半字节/, '偶数路径低半字节非零');
      a.throws(() => hp.decode(U()), /为空/, '空前缀');
    });
  });

  // 预先启动一台临时 HTTP 服务，供三大场景穿插冒烟（单次初始化，避免并发竞态）。
  let server;
  let baseUrl;
  let starting;
  const http = async (path, opts) => {
    if (!starting) {
      starting = (async () => {
        server = createServer();
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        baseUrl = `http://127.0.0.1:${server.address().port}`;
      })();
    }
    await starting;
    return fetch(baseUrl + path, opts);
  };

  const postVerify = async (rootHash, keyHex, nodesText) =>
    http('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rootHash, keyHex, proofNodes: nodesText }),
    });

  // ========== 场景一：有效授权（叶值 01）==========
  await suite('场景一：有效授权（证明内核 → 页面 → API → HTTP 穿插）').run(async () => {
    test('证明内核：长键证明状态为 authorized，逐层消费完整路径', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), proofAuth);
      a.equal(res.status, 'authorized');
      a.equal(res.authorized, true);
      a.equal(res.value, '01');
      a.equal(res.firstFailedLayer, null);
      a.equal(res.consumedPath, keyAuth);
      a.ok(res.layers.length >= 3, '应回放多层（含扩展/分支/叶）');
      const leaf = res.layers[res.layers.length - 1];
      a.equal(leaf.kind, 'leaf');
      a.equal(leaf.value, '01');
      // 每层必须给出节点摘要与引用方式
      for (const layer of res.layers) {
        a.match(layer.nodeHash, /^[0-9a-f]{64}$/);
        a.ok(['root-commitment', 'hash-32', 'embedded-node'].includes(layer.reference));
      }
      // 至少出现一次内嵌节点引用与一次 32 字节散列引用
      a.ok(res.layers.some((l) => l.childReference === 'embedded-node' || l.reference === 'embedded-node'));
      a.ok(res.layers.some((l) => l.childReference === 'hash-32' || l.reference === 'root-commitment'));
    });

    test('证明内核：短键 + 内嵌叶同样授权', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(snap.keys.otherAuthorized)), snap.proofFor(snap.keys.otherAuthorized));
      a.equal(res.status, 'authorized');
      a.equal(res.consumedPath, 'a2');
    });

    test('页面构建：结果页显示“已授权”并逐层列出摘要/路径/引用方式', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), proofAuth);
      const page = buildResultPage(res, { rootHash: snap.rootHashHex, keyHex: keyAuth, nodeCount: proofAuth.length });
      a.match(page, /<title>离线指令授权快照复核结果<\/title>/);
      a.match(page, /已授权/);
      a.match(page, /叶值为 <code>0x01<\/code>/);
      a.match(page, new RegExp(snap.rootHashHex));
      a.match(page, new RegExp(keyAuth));
      a.match(page, /内嵌节点/);
      a.match(page, /32 字节散列引用|根承诺/);
      a.match(page, /累计已消费路径/);
      a.equal(page.includes('证明无效'), false);
    });

    test('API：合法 JSON 入参返回 200 与 result+page', () => {
      const out = handleVerify({
        rootHash: snap.rootHashHex,
        keyHex: keyAuth,
        proofNodes: proofAuth.map((p) => toHex(p)).join('\n'),
      });
      a.equal(out.httpStatus, 200);
      a.equal(out.result.status, 'authorized');
      a.match(out.page, /已授权/);
    });

    test('API：JSON 数组形式的节点列表同样接受', () => {
      const out = handleVerify({
        rootHash: snap.rootHashHex,
        keyHex: snap.keys.otherAuthorized,
        proofNodes: snap.proofFor(snap.keys.otherAuthorized).map((p) => '0x' + toHex(p)),
      });
      a.equal(out.result.status, 'authorized');
    });

    test('API：指令标识支持 0x 前缀，非十六进制字符被 400 拒绝', () => {
      const out = handleVerify({
        rootHash: '0x' + snap.rootHashHex,
        keyHex: '0x' + snap.keys.otherAuthorized,
        proofNodes: snap.proofFor(snap.keys.otherAuthorized).map((p) => toHex(p)),
      });
      a.equal(out.result.status, 'authorized');
      const bad = handleVerify({ rootHash: snap.rootHashHex, keyHex: 'a2g', proofNodes: '80' });
      a.equal(bad.httpStatus, 400);
      a.match(bad.error, /十六进制/);
    });

    test('HTTP 冒烟：健康端点 200 ok', async () => {
      const res = await http('/healthz');
      a.equal(res.status, 200);
      a.deepEqual(await res.json(), { status: 'ok', service: 'offline-instruction-auth-review' });
    });

    test('HTTP 冒烟：静态入口页可访问且含表单', async () => {
      const res = await http('/');
      a.equal(res.status, 200);
      a.match(res.headers.get('content-type'), /text\/html/);
      const html = await res.text();
      a.match(html, /<title>离线指令授权快照复核<\/title>/);
      a.match(html, /name="rootHash"/);
      a.match(html, /name="keyHex"/);
      a.match(html, /name="proofNodes"/);
    });

    test('HTTP 冒烟：POST 有效授权证明返回已授权页面', async () => {
      const res = await postVerify(snap.rootHashHex, keyAuth, proofAuth.map((p) => toHex(p)).join('\n'));
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'authorized');
      a.match(data.page, /已授权/);
    });
  });

  // ========== 场景二：篡改子节点引用 ==========
  await suite('场景二：篡改子节点引用（REF_MISMATCH，内核 → 页面 → API → HTTP 穿插）').run(async () => {
    // 翻转第 2 个证明节点（扩展节点）散列负载中的一个字节，保持 RLP 仍可解码。
    const tampered = proofAuth.map((p) => Uint8Array.from(p));
    tampered[1][tampered[1].length - 1] ^= 0x01;

    test('证明内核：首个失败层为第 2 层且无成功结论', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), tampered);
      a.equal(res.status, 'invalid');
      a.equal(res.code, 'REF_MISMATCH');
      a.equal(res.firstFailedLayer, 2);
      a.equal(res.value, null);
      a.match(res.reason, /父子引用不符/);
      // 第 1 层路径证据保留
      a.equal(res.layers.length, 1);
      a.equal(res.layers[0].kind, 'branch');
      a.equal(res.layers[0].cumulativePath, '0');
    });

    test('页面构建：无效页标明首个失败层并保留既有路径证据', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), tampered);
      const page = buildResultPage(res, { rootHash: snap.rootHashHex, keyHex: keyAuth, nodeCount: tampered.length });
      a.match(page, /证明无效/);
      a.match(page, /首个失败层：<strong>第 2 层<\/strong>/);
      a.match(page, /父子引用不符/);
      a.match(page, /旧成功结论已清除/);
      a.equal(page.includes('已授权</span>'), false);
      a.match(page, /第 1 层/);
    });

    test('API：篡改引用产生 invalid 结果（HTTP 200 语义化结果）', () => {
      const out = handleVerify({
        rootHash: snap.rootHashHex,
        keyHex: keyAuth,
        proofNodes: tampered.map((p) => toHex(p)).join('\n'),
      });
      a.equal(out.httpStatus, 200);
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'REF_MISMATCH');
      a.equal(out.result.firstFailedLayer, 2);
    });

    test('HTTP 冒烟：POST 篡改证明返回 invalid 页面', async () => {
      const res = await postVerify(snap.rootHashHex, keyAuth, tampered.map((p) => toHex(p)).join('\n'));
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'invalid');
      a.equal(data.result.code, 'REF_MISMATCH');
      a.match(data.page, /证明无效/);
    });

    test('证明内核：根哈希本身不符 -> ROOT_MISMATCH 第 1 层', () => {
      const wrong = Uint8Array.from(snap.rootHash);
      wrong[31] ^= 0xff;
      const res = verifyProof(wrong, bytesToNibbles(fromHex(keyAuth)), proofAuth);
      a.equal(res.code, 'ROOT_MISMATCH');
      a.equal(res.firstFailedLayer, 1);
      a.equal(res.layers.length, 0);
    });

    test('证明内核：缺失后续证明节点 -> PATH_INCOMPLETE', () => {
      const truncated = proofAuth.slice(0, 2); // 扩展节点的散列子节点无对应证明
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), truncated);
      a.equal(res.code, 'PATH_INCOMPLETE');
      a.equal(res.firstFailedLayer, 3);
      a.match(res.reason, /路径残缺/);
    });

    test('证明内核：叶后多余节点 -> TAIL_DUPLICATE 重复尾节点', () => {
      const proof = snap.proofFor(snap.keys.otherAuthorized);
      const withTail = proof.concat([Uint8Array.from(proof[proof.length - 1])]);
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(snap.keys.otherAuthorized)), withTail);
      a.equal(res.code, 'TAIL_DUPLICATE');
      a.match(res.reason, /重复尾节点/);
    });
  });

  // ========== 场景三：非规范 RLP ==========
  await suite('场景三：非规范/截断 RLP（内核 → 页面 → API → HTTP 穿插）').run(async () => {
    // 手工拼接一个“根分支 + 槽2 内嵌叶”的原始 RLP，其中叶值 0x01 被非规范地编码为 81 01。
    // 合法内嵌叶应为 c3 20 01（3 字节）；这里改写为 c4 20 8101（4 字节，单字节误用长形式）。
    // 整个节点：分支 17 项，槽 0、1 为空(80 80)，槽 2 = c4208101，其后槽 3..16 共 14 个空项。
    const makeNoncanonRoot = () => {
      const slots = [];
      for (let i = 0; i < 17; i++) slots.push(B(i === 2 ? 'c4208101' : '80'));
      const payload = concatRaw(slots);
      return Buffer.concat([Buffer.from(rlpLenPrefix(payload.length, 0xc0)), payload]);
    };

    test('证明内核：嵌套的非规范单字节编码被拒绝（RLP_NONCANONICAL）', () => {
      const bad = makeNoncanonRoot();
      const res = verifyProof(keccak256(bad), bytesToNibbles(fromHex(snap.keys.otherAuthorized)), [bad]);
      a.equal(res.status, 'invalid');
      a.equal(res.code, 'RLP_NONCANONICAL');
      a.equal(res.firstFailedLayer, 1);
      a.match(res.reason, /非规范/);
    });

    test('页面构建：非规范 RLP 页标明失败层且不含旧成功结论', () => {
      const bad = makeNoncanonRoot();
      const res = verifyProof(keccak256(bad), bytesToNibbles(fromHex(snap.keys.otherAuthorized)), [bad]);
      const page = buildResultPage(res, { rootHash: toHex(keccak256(bad)), keyHex: snap.keys.otherAuthorized, nodeCount: 1 });
      a.match(page, /证明无效/);
      a.match(page, /RLP_NONCANONICAL/);
      a.match(page, /第 1 层/);
      a.equal(page.includes('已授权</span>'), false);
    });

    test('API：非规范 RLP 返回 invalid 与可读原因', () => {
      const bad = makeNoncanonRoot();
      const out = handleVerify({
        rootHash: toHex(keccak256(bad)),
        keyHex: snap.keys.otherAuthorized,
        proofNodes: toHex(bad),
      });
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'RLP_NONCANONICAL');
    });

    test('HTTP 冒烟：POST 非规范 RLP 返回 invalid 页面', async () => {
      const bad = makeNoncanonRoot();
      const res = await postVerify(toHex(keccak256(bad)), snap.keys.otherAuthorized, toHex(bad));
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'invalid');
      a.equal(data.result.code, 'RLP_NONCANONICAL');
      a.match(data.page, /RLP_NONCANONICAL/);
    });

    test('证明内核：截断的节点字节被拒绝（RLP_INVALID）', () => {
      const cut = proofAuth[0].subarray(0, proofAuth[0].length - 3);
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), [cut]);
      a.equal(res.code, 'RLP_INVALID');
      a.equal(res.firstFailedLayer, 1);
    });

    test('证明内核：非规范长度前缀（前导零）被拒绝', () => {
      const bad = B('b90038' + '61'.repeat(0x38)); // 56 字节串却带 00 前导
      const res = verifyProof(keccak256(bad), [1, 2], [bad]);
      a.equal(res.code, 'RLP_NONCANONICAL');
    });

    test('证明内核：证明为空被拒绝', () => {
      const res = verifyProof(snap.rootHash, [1], []);
      a.equal(res.code, 'EMPTY_PROOF');
    });
  });

  // ========== 场景四：双时点对照 ==========
  await suite('场景四：双时点对照（启用→撤销 / 一侧篡改 / 标识不一致）').run(async () => {
    const { handleCompare } = require('../src/compare-api');
    const { buildCompareSnapshots } = require('../src/sample-snapshot');
    const { buildComparePage } = require('../src/page');

    const cmpSnap = buildCompareSnapshots();
    const sidePayload = (s) => ({
      rootHash: s.rootHashHex,
      keyHex: cmpSnap.keyHex,
      proofNodes: s.proof.map((p) => toHex(p)),
    });
    const validBody = () => ({ earlier: sidePayload(cmpSnap.earlier), later: sidePayload(cmpSnap.later) });
    const tamperSide = (side) => {
      const nodes = side.proofNodes.map((h) => Uint8Array.from(fromHex(h)));
      nodes[1][nodes[1].length - 1] ^= 0x01; // 翻转第 2 个证明节点末字节，保持 RLP 可解码
      side.proofNodes = nodes.map((n) => toHex(n));
      return side;
    };
    // 与场景三相同的非规范内嵌叶（c4 20 8101）根分支，键 02 可达。
    const noncanonNode = () => {
      const slots = [];
      for (let i = 0; i < 17; i++) slots.push(B(i === 2 ? 'c4208101' : '80'));
      const payload = concatRaw(slots);
      return Buffer.concat([Buffer.from(rlpLenPrefix(payload.length, 0xc0)), payload]);
    };
    // 把规范列表节点改写为“前导零长度前缀”的非规范长形式（负载不变），
    // 用于在不改动指令标识的前提下让较早侧触发 RLP_NONCANONICAL。
    const noncanonRewrap = (nodeBytes) => {
      const b = nodeBytes;
      let headerLen;
      let payloadLen;
      if (b[0] <= 0xf7) {
        headerLen = 1;
        payloadLen = b[0] - 0xc0;
      } else {
        const ll = b[0] - 0xf7;
        headerLen = 1 + ll;
        payloadLen = 0;
        for (let i = 0; i < ll; i++) payloadLen = payloadLen * 256 + b[1 + i];
      }
      const payload = b.subarray(headerLen, headerLen + payloadLen);
      const lenBytes = [];
      let x = payloadLen;
      while (x > 0) {
        lenBytes.push(x & 0xff);
        x = Math.floor(x / 256);
      }
      lenBytes.reverse();
      return concatRaw([Uint8Array.of(0xf7 + lenBytes.length + 1, 0x00, ...lenBytes), payload]);
    };

    test('对照API：有效启用→撤销 -> compared/revoked，两侧证据独立完整', () => {
      const out = handleCompare(validBody());
      a.equal(out.httpStatus, 200);
      a.equal(out.result.status, 'compared');
      a.equal(out.result.conclusion, 'revoked');
      a.equal(out.result.conclusionLabel, '已撤销');
      a.equal(out.result.keyHex, cmpSnap.keyHex);
      a.equal(out.result.earlier.result.status, 'authorized');
      a.equal(out.result.earlier.result.value, '01');
      a.equal(out.result.later.result.status, 'unauthorized');
      a.equal(out.result.later.result.value, '00');
      a.ok(out.result.earlier.result.layers.length >= 3, '较早侧应回放多层');
      a.ok(out.result.later.result.layers.length >= 3, '较晚侧应回放多层');
      a.notEqual(out.result.earlier.rootHash, out.result.later.rootHash);
    });

    test('对照页面：双栏区分两侧根摘要/叶值/授权状态，两条可展开路径证据', () => {
      const out = handleCompare(validBody());
      const page = out.page;
      a.match(page, /<title>离线指令授权快照双时点对照结果<\/title>/);
      a.match(page, /banner-title">已撤销/);
      a.match(page, /较早快照/);
      a.match(page, /较晚快照/);
      a.match(page, new RegExp(cmpSnap.earlier.rootHashHex));
      a.match(page, new RegExp(cmpSnap.later.rootHashHex));
      a.match(page, /badge-ok">已授权/);
      a.match(page, /badge-no">未授权/);
      a.match(page, /0x01/);
      a.match(page, /0x00/);
      a.equal((page.match(/<details class="layers">/g) || []).length, 2, '应有两条可展开路径证据');
      a.match(page, /逐层路径证据（共 \d+ 层，点击展开）/);
    });

    test('对照API：归纳 持续授权 / 已启用 / 持续未授权', () => {
      const still = handleCompare({ earlier: sidePayload(cmpSnap.earlier), later: sidePayload(cmpSnap.earlier) });
      a.equal(still.result.status, 'compared');
      a.equal(still.result.conclusion, 'still-authorized');
      a.match(still.page, /持续授权/);

      const enabled = handleCompare({ earlier: sidePayload(cmpSnap.later), later: sidePayload(cmpSnap.earlier) });
      a.equal(enabled.result.conclusion, 'enabled');
      a.equal(enabled.result.conclusionLabel, '已启用');
      a.match(enabled.page, /banner-title">已启用/);

      const stillNo = handleCompare({ earlier: sidePayload(cmpSnap.later), later: sidePayload(cmpSnap.later) });
      a.equal(stillNo.result.conclusion, 'still-unauthorized');
      a.match(stillNo.page, /持续未授权/);
    });

    test('对照API：较晚侧篡改节点 -> invalid，定位该侧首个失败层，不残留变更结论', () => {
      const body = validBody();
      body.later = tamperSide(body.later);
      const out = handleCompare(body);
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.conclusion, null);
      a.equal(out.result.conclusionLabel, null);
      a.equal(out.result.code, 'SIDE_INVALID');
      a.match(out.result.reason, /较晚快照首个失败层：第 2 层（REF_MISMATCH）/);
      // 较早侧证据保留，但不得据此归纳状态变化
      a.equal(out.result.earlier.result.status, 'authorized');
      const page = out.page;
      a.match(page, /对照无效/);
      a.match(page, /不得据另一侧/);
      a.match(page, /第 2 层/);
      a.equal(page.includes('banner-title">已撤销'), false);
      a.equal(page.includes('banner-title">已启用'), false);
      a.equal(page.includes('banner-title">持续授权'), false);
      // 两侧面板仍各自呈现（较早侧保留已核验证据）
      a.match(page, /较早快照/);
      a.match(page, /badge-ok">已授权/);
      a.match(page, /badge-bad">证明无效/);
    });

    test('对照API：较早侧非规范 RLP -> invalid，首败层定位到较早侧第 1 层', () => {
      const body = validBody();
      const nodes = body.earlier.proofNodes.map((h) => fromHex(h));
      nodes[0] = noncanonRewrap(nodes[0]); // 同一指令标识下，根节点非规范重封装
      body.earlier.proofNodes = nodes.map((n) => toHex(n));
      const out = handleCompare(body);
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'SIDE_INVALID');
      a.match(out.result.reason, /较早快照首个失败层：第 1 层（RLP_NONCANONICAL）/);
      a.equal(out.result.later.result.status, 'unauthorized');
      a.match(out.page, /对照无效/);
    });

    test('对照API：非规范内嵌叶节点同样被较早侧拒绝', () => {
      const bad = noncanonNode();
      const body = validBody();
      body.earlier = { rootHash: toHex(keccak256(bad)), keyHex: cmpSnap.keyHex, proofNodes: toHex(bad) };
      const out = handleCompare(body);
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'SIDE_INVALID');
      a.match(out.result.reason, /较早快照首个失败层：第 1 层（RLP_NONCANONICAL）/);
    });

    test('对照API：输入标识不一致 -> KEY_MISMATCH，不进入证明核验', () => {
      const body = validBody();
      body.later.keyHex = 'a2';
      const out = handleCompare(body);
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'KEY_MISMATCH');
      a.match(out.result.reason, /输入标识不一致/);
      a.equal(out.result.earlier.result, null);
      a.equal(out.result.later.result, null);
      a.match(out.page, /对照无效/);
      a.match(out.page, /输入标识不一致/);
      a.match(out.page, /第 0 层/);
    });

    test('对照API：一侧输入无效（根哈希长度错误）-> INPUT_INVALID 第 0 层', () => {
      const body = validBody();
      body.earlier.rootHash = '0102';
      const out = handleCompare(body);
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'INPUT_INVALID');
      a.match(out.result.reason, /较早快照输入无效/);
      a.match(out.page, /第 0 层（输入校验阶段）/);
    });

    test('对照API：缺少 earlier/later 或非对象 -> 400', () => {
      a.equal(handleCompare({}).httpStatus, 400);
      a.equal(handleCompare({ earlier: {} }).httpStatus, 400);
      a.equal(handleCompare('x').httpStatus, 400);
      a.equal(handleCompare(null).httpStatus, 400);
    });

    test('对照页面构建：buildComparePage 可直接渲染且转义输入', () => {
      const out = handleCompare(validBody());
      const page = buildComparePage(out.result);
      a.match(page, /双时点对照/);
      const bad = handleCompare({ earlier: { rootHash: '<script>', keyHex: 'a2', proofNodes: '80' }, later: sidePayload(cmpSnap.later) });
      a.equal(bad.result.status, 'invalid');
      a.equal(bad.page.includes('<script>'), false);
    });

    test('HTTP 冒烟：GET /api/sample/compare 返回双时点示例', async () => {
      const res = await http('/api/sample/compare');
      a.equal(res.status, 200);
      const data = await res.json();
      a.ok(data.earlier && data.later);
      a.equal(data.earlier.keyHex, data.later.keyHex);
      a.equal(data.keyHex, data.earlier.keyHex);
      a.notEqual(data.earlier.rootHash, data.later.rootHash);
      a.ok(data.earlier.proofNodes.length > 0 && data.later.proofNodes.length > 0);
    });

    test('HTTP 冒烟：POST /api/compare 有效启用→撤销对照返回完整变更证据', async () => {
      const res = await http('/api/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBody()),
      });
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'compared');
      a.equal(data.result.conclusion, 'revoked');
      a.match(data.page, /已撤销/);
      a.equal((data.page.match(/<details class="layers">/g) || []).length, 2);
    });

    test('HTTP 冒烟：POST /api/compare 一侧篡改只显示无效对照', async () => {
      const body = validBody();
      body.earlier = tamperSide(body.earlier);
      const res = await http('/api/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'invalid');
      a.match(data.result.reason, /较早快照首个失败层：第 2 层/);
      a.match(data.page, /对照无效/);
      a.equal(data.page.includes('banner-title">已撤销'), false);
    });

    test('入口页：保留原单快照表单并新增双时点对照表单', () => {
      const html = buildIndexPage();
      a.match(html, /id="verify-form"/);
      a.match(html, /id="load-ok"/);
      a.match(html, /id="load-no"/);
      a.match(html, /id="compare-form"/);
      a.match(html, /id="cmp-root-earlier"/);
      a.match(html, /id="cmp-root-later"/);
      a.match(html, /id="cmp-key-earlier"/);
      a.match(html, /id="cmp-key-later"/);
      a.match(html, /id="load-compare"/);
      a.match(html, /\/api\/compare/);
    });

    test('入口页：内联客户端脚本语法有效（模板转义回归）', () => {
      const script = buildIndexPage().match(/<script>([\s\S]*?)<\/script>/)[1];
      a.doesNotThrow(() => new Function(script));
    });
  });

  // ========== 未授权与其余路径/HP/引用失败 ==========
  await suite('未授权（叶值非 01）与其余失败类别').run(async () => {
    test('证明内核：完整抵达叶但值 0x00 -> unauthorized 且保留路径证据', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyNo)), proofNo);
      a.equal(res.status, 'unauthorized');
      a.equal(res.authorized, false);
      a.equal(res.value, '00');
      a.equal(res.consumedPath, keyNo);
      a.equal(res.firstFailedLayer, null);
      a.equal(res.layers[res.layers.length - 1].kind, 'leaf');
    });

    test('页面构建：未授权页明确显示“未授权”并保留路径证据', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyNo)), proofNo);
      const page = buildResultPage(res, { rootHash: snap.rootHashHex, keyHex: keyNo, nodeCount: proofNo.length });
      a.match(page, /未授权/);
      a.match(page, /0x00/);
      a.match(page, new RegExp(keyNo));
      a.equal(page.includes('证明无效'), false);
    });

    test('证明内核：叶值多字节（0100）不构成启用承诺', () => {
      const raw = [hp.encode([1, 2, 3], true), B('0100')];
      const node = rlp.encode(raw);
      const res = verifyProof(keccak256(node), [1, 2, 3], [node]);
      a.equal(res.status, 'unauthorized');
      a.equal(res.value, '0100');
    });

    test('证明内核：分支值槽终结且值 01 -> authorized', () => {
      const { Trie } = require('../src/trie');
      const t = new Trie();
      t.put(bytesToNibbles(B('ab')), U(0x01));
      t.put(bytesToNibbles(B('abcdef')), U(0x01));
      t.commit();
      const proof = t.proveKey(bytesToNibbles(B('ab')));
      const res = verifyProof(t.rootHash, bytesToNibbles(B('ab')), proof);
      a.equal(res.status, 'authorized');
      a.ok(res.layers.some((l) => l.kind === 'branch-value'));
    });

    test('证明内核：查询键偏离到空槽 -> PATH_INCOMPLETE', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex('a3')), snap.proofFor(snap.keys.otherAuthorized));
      a.equal(res.code, 'PATH_INCOMPLETE');
      // 第 1 层为根分支（消费 a），第 2 层为其内嵌分支，在槽 3 处断链。
      a.equal(res.firstFailedLayer, 2);
    });

    test('证明内核：叶路径与剩余半字节不符 -> PATH_MISMATCH', () => {
      // 用 a2 的单节点证明去查 a9：根分支槽 9 为空 -> 先命中 PATH_INCOMPLETE（合理）。
      // 手工构造单叶证明验证 PATH_MISMATCH：
      const node = rlp.encode([hp.encode([1, 2, 3], true), U(0x01)]);
      const res = verifyProof(keccak256(node), [1, 2, 9], [node]);
      a.equal(res.code, 'PATH_MISMATCH');
    });

    test('证明内核：HP 前缀高两位置位 -> HP_INVALID', () => {
      const node = rlp.encode([B('40ab'), keccak256(U(1))]);
      const res = verifyProof(keccak256(node), [0xa, 0xb], [node]);
      a.equal(res.code, 'HP_INVALID');
      a.match(res.reason, /十六进制前缀错误/);
    });

    test('证明内核：分支槽出现非空非 32 字节串 -> BAD_REF', () => {
      const branch = new Array(17).fill(U());
      branch[1] = B('0a0b'); // 10 字节非法引用
      const node = rlp.encode(branch);
      const res = verifyProof(keccak256(node), [1], [node]);
      a.equal(res.code, 'BAD_REF');
      a.equal(res.firstFailedLayer, 1);
    });

    test('证明内核：内嵌节点 ≥32 字节必须散列引用 -> BAD_REF', () => {
      const bigChild = [hp.encode([0, 1], true), B('aa'.repeat(40))]; // 编码 ≥32
      a.ok(rlp.encode(bigChild).length >= 32);
      const ext = [hp.encode([5], false), bigChild];
      const node = rlp.encode(ext);
      const res = verifyProof(keccak256(node), [5, 0, 1], [node]);
      a.equal(res.code, 'BAD_REF');
      a.match(res.reason, /32 字节散列引用/);
    });

    test('证明内核：32 字节根哈希以外的输入被拒绝', () => {
      a.equal(verifyProof(U(1, 2, 3), [1], proofAuth).code, 'BAD_ROOT');
      a.equal(verifyProof(snap.rootHash, [1, 99], proofAuth).code, 'BAD_KEY');
    });
  });

  // ========== API 输入校验与 HTTP 杂项 ==========
  await suite('API 输入校验与 HTTP 杂项').run(async () => {
    test('API：根哈希长度错误返回 400', () => {
      const out = handleVerify({ rootHash: '0102', keyHex: keyAuth, proofNodes: toHex(proofAuth[0]) });
      a.equal(out.httpStatus, 400);
      a.match(out.error, /32 字节/);
    });

    test('API：非法十六进制返回 400', () => {
      const out = handleVerify({ rootHash: 'zz' + snap.rootHashHex.slice(2), keyHex: keyAuth, proofNodes: 'a0' });
      a.equal(out.httpStatus, 400);
    });

    test('API：空节点列表返回 400', () => {
      const out = handleVerify({ rootHash: snap.rootHashHex, keyHex: keyAuth, proofNodes: '  \n ' });
      a.equal(out.httpStatus, 400);
    });

    test('API：多行与逗号分隔解析一致', () => {
      const nodes = proofAuth.map((p) => toHex(p));
      const a1 = parseProofNodes(nodes.join('\n'));
      const a2 = parseProofNodes(nodes.join(','));
      const a3 = parseProofNodes(nodes.map((x) => '0x' + x));
      a.equal(a1.length, nodes.length);
      a.ok(a1.every((n, i) => equalBytes(n, a2[i]) && equalBytes(n, a3[i])));
    });

    test('页面：HTML 转义防止注入', () => {
      const res = verifyProof(U(1), [1], []); // BAD_ROOT 前的简单 invalid
      const page = buildResultPage(res, { rootHash: '<script>x</script>', keyHex: '"><b>', nodeCount: 0 });
      a.equal(page.includes('<script>x</script>'), false);
      a.ok(page.includes('&lt;script&gt;'));
    });

    test('入口页包含提交说明与启用承诺 01', () => {
      a.match(buildIndexPage(), /32 字节根哈希/);
      a.match(buildIndexPage(), /十六进制指令标识/);
      a.match(buildIndexPage(), /按根到叶排序的 RLP 节点/);
      a.match(buildIndexPage(), /01/);
    });

    test('HTTP 冒烟：/health 别名同样可用', async () => {
      const res = await http('/health');
      a.equal(res.status, 200);
      a.equal((await res.json()).status, 'ok');
    });

    test('HTTP 冒烟：未知路径 404 JSON', async () => {
      const res = await http('/nope');
      a.equal(res.status, 404);
      a.equal((await res.json()).error, '未找到该路径');
    });

    test('HTTP 冒烟：坏 JSON 请求体 400', async () => {
      const res = await http('/api/verify', { method: 'POST', body: '{not-json' });
      a.equal(res.status, 400);
      a.match((await res.json()).error, /JSON/);
    });
  });

  if (server) await new Promise((resolve) => server.close(resolve));

  const { passed, failed } = h.summary();
  console.log(`\n========================================`);
  console.log(`测试结果：${passed} 通过，${failed} 失败`);
  if (failed > 0) {
    process.exitCode = 1;
  } else {
    console.log('验收测试全部通过 ✅');
  }
}

main().catch((e) => {
  console.error('测试运行器异常：', e);
  process.exit(1);
});
