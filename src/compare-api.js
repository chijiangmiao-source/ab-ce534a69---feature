'use strict';
// /api/compare 的纯逻辑层：双时点对照。
//
// 为同一条十六进制指令分别提交「较早」与「较晚」两张快照的根哈希与根到叶
// RLP 节点；两侧证明必须各自独立核验。仅当两侧都完整有效时，才根据各自叶值
// 归纳授权状态变化（持续授权 / 已撤销 / 已启用 / 持续未授权）。
// 任一侧出现引用不符、非规范 RLP、路径残缺或输入标识不一致，即判对照无效，
// 并指明该侧首个失败层——绝不以另一侧的成功结果推断状态变化。
const { verifyProof } = require('./verifier');
const { toHex, fromHex, keyHexToNibbles } = require('./hexutil');
const { parseProofNodes } = require('./verify-api');
const { buildComparePage } = require('./page');

function normalizeKey(hex) {
  return String(hex).replace(/^0[xX]/, '').toLowerCase();
}

// 仅供失败面板展示：尽量规范化为小写无 0x 的 hex；非法时返回空串。
function safeRootHex(text) {
  if (typeof text !== 'string') return '';
  try {
    return toHex(fromHex(text.trim()));
  } catch {
    return '';
  }
}

// 组装一侧的输入解析与独立核验。任何解析/核验失败都落为该侧的 invalid 记录，
// 不影响另一侧的独立核验（两侧始终都会被执行）。
function verifySide(side, sharedKeyHex, keyNibbles) {
  const input = { rootHash: '', keyHex: sharedKeyHex, nodeCount: 0 };

  if (!side || typeof side !== 'object') {
    return {
      input,
      verification: {
        status: 'invalid',
        authorized: false,
        value: null,
        code: 'BAD_INPUT',
        reason: '该侧快照输入缺失或不是 JSON 对象',
        firstFailedLayer: 0,
        layers: [],
        consumedPath: '',
      },
    };
  }

  // 该侧可携带自己的指令标识；缺省采用两侧共用标识，若提供则必须逐字符一致，
  // 否则属于“输入标识不一致”，在该侧第 0 层（输入层）即失败。
  if (side.keyHex !== undefined && side.keyHex !== null && side.keyHex !== '') {
    if (typeof side.keyHex !== 'string') {
      return {
        input,
        verification: {
          status: 'invalid',
          authorized: false,
          value: null,
          code: 'BAD_INPUT',
          reason: '该侧十六进制指令标识必须是字符串',
          firstFailedLayer: 0,
          layers: [],
          consumedPath: '',
        },
      };
    }
    const sideKey = normalizeKey(side.keyHex.trim());
    if (sideKey !== normalizeKey(sharedKeyHex)) {
      return {
        input: { rootHash: safeRootHex(side.rootHash), keyHex: sideKey, nodeCount: 0 },
        verification: {
          status: 'invalid',
          authorized: false,
          value: null,
          code: 'KEY_MISMATCH',
          reason: `输入标识不一致：该侧指令标识 0x${sideKey} 与对照共用标识 0x${normalizeKey(sharedKeyHex)} 不是同一条十六进制指令`,
          firstFailedLayer: 0,
          layers: [],
          consumedPath: '',
        },
      };
    }
  }

  let rootHash;
  let proofNodes;
  try {
    if (typeof side.rootHash !== 'string') throw new Error('缺少 32 字节根哈希（rootHash）');
    rootHash = fromHex(side.rootHash.trim());
    input.rootHash = toHex(rootHash);
    proofNodes = parseProofNodes(side.proofNodes);
    input.nodeCount = proofNodes.length;
  } catch (e) {
    return {
      input,
      verification: {
        status: 'invalid',
        authorized: false,
        value: null,
        code: 'BAD_INPUT',
        reason: `该侧输入解析失败：${e.message}`,
        firstFailedLayer: 0,
        layers: [],
        consumedPath: '',
      },
    };
  }

  // 长度不为 32 字节等承诺层错误由核验内核按 BAD_ROOT 在第 0 层报告。
  const verification = verifyProof(rootHash, keyNibbles, proofNodes);
  return { input, verification };
}

function handleCompare(body) {
  if (!body || typeof body !== 'object') {
    return { httpStatus: 400, error: '请求体必须为 JSON 对象' };
  }

  let keyHex;
  let keyNibbles;
  try {
    if (typeof body.keyHex !== 'string') throw new Error('缺少两侧共用的十六进制指令标识（keyHex）');
    keyHex = body.keyHex.trim();
    keyNibbles = keyHexToNibbles(keyHex);
  } catch (e) {
    return { httpStatus: 400, error: e.message };
  }

  if (!body.earlier || !body.later) {
    return { httpStatus: 400, error: '必须同时提供较早（earlier）与较晚（later）两侧快照的根哈希与 RLP 节点' };
  }

  const normKey = normalizeKey(keyHex);

  // 两侧独立核验：即使较早侧已经失败，较晚侧仍照常核验并保留其证据。
  const earlier = verifySide(body.earlier, normKey, keyNibbles);
  const later = verifySide(body.later, normKey, keyNibbles);

  const failures = [];
  for (const [side, rec] of [['earlier', earlier], ['later', later]]) {
    const v = rec.verification;
    if (v.status === 'invalid') {
      failures.push({
        side,
        code: v.code,
        reason: v.reason,
        firstFailedLayer: v.firstFailedLayer,
      });
    }
  }

  let status;
  let transition = null;
  if (failures.length > 0) {
    // 对照无效：不归纳、不暗示任何授权状态变化。
    status = 'invalid';
  } else {
    status = 'comparable';
    const was = earlier.verification.authorized;
    const now = later.verification.authorized;
    if (was && now) transition = 'still-authorized';
    else if (was && !now) transition = 'revoked';
    else if (!was && now) transition = 'enabled';
    else transition = 'still-unauthorized';
  }

  const result = {
    status,
    transition,
    keyHex: normKey,
    earlier,
    later,
    failures,
  };
  const page = buildComparePage(result);
  return { httpStatus: 200, result, page };
}

module.exports = { handleCompare };
