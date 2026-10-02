'use strict';
// /api/compare 的纯逻辑层：双时点（较早/较晚）对照核验。
//
// 规则：
//   1. 两侧证明完全独立核验（各自根哈希 + 各自根到叶 RLP 节点）；
//   2. 仅当两侧都完整有效时，才根据各自叶值归纳：
//        较早=01 且 较晚=01 -> 持续授权（still-authorized）
//        较早=01 且 较晚≠01 -> 已撤销（revoked）
//        较早≠01 且 较晚=01 -> 已启用（enabled）
//        较早≠01 且 较晚≠01 -> 持续未授权（still-unauthorized）
//   3. 任一侧出现引用不符、非规范 RLP、路径残缺或输入标识不一致时，
//      对照结论为 invalid，并标明该侧首个失败层；
//      不得以另一侧的成功结果推断状态变化。
const { verifyProof } = require('./verifier');
const { fromHex, toHex, keyHexToNibbles } = require('./hexutil');
const { parseProofNodes } = require('./verify-api');
const { buildComparePage } = require('./page');

const SIDE_LABEL = { earlier: '较早快照', later: '较晚快照' };

const CONCLUSION_LABEL = {
  enabled: '已启用',
  revoked: '已撤销',
  'still-authorized': '持续授权',
  'still-unauthorized': '持续未授权',
};

function normalizeKeyHex(keyHex) {
  return keyHex.replace(/^0[xX]/, '').toLowerCase();
}

// 解析一侧输入；失败时不抛出，记录 inputError（首个失败层视为第 0 层：输入校验阶段）。
function parseSide(raw, sideKey) {
  const label = SIDE_LABEL[sideKey];
  const side = {
    key: sideKey,
    label,
    rootHash: null,
    keyHex: null,
    nodeCount: 0,
    inputError: null,
    result: null,
    rootBytes: null,
    keyNibbles: null,
    proofNodes: null,
  };
  if (!raw || typeof raw !== 'object') {
    side.inputError = `${label}输入无效：缺少输入对象（需要 rootHash / keyHex / proofNodes）`;
    return side;
  }
  try {
    if (typeof raw.rootHash !== 'string') throw new Error('缺少 32 字节根哈希（rootHash）');
    const rootBytes = fromHex(raw.rootHash.trim());
    if (rootBytes.length !== 32) throw new Error(`根哈希长度为 ${rootBytes.length} 字节，必须为 32 字节`);
    side.rootBytes = rootBytes;
    side.rootHash = toHex(rootBytes);

    if (typeof raw.keyHex !== 'string') throw new Error('缺少十六进制指令标识（keyHex）');
    side.keyNibbles = keyHexToNibbles(raw.keyHex.trim());
    side.keyHex = normalizeKeyHex(raw.keyHex.trim());

    side.proofNodes = parseProofNodes(raw.proofNodes);
    side.nodeCount = side.proofNodes.length;
  } catch (e) {
    side.inputError = `${label}输入无效：${e.message}`;
  }
  return side;
}

function publicSide(side) {
  return {
    key: side.key,
    label: side.label,
    rootHash: side.rootHash,
    keyHex: side.keyHex,
    nodeCount: side.nodeCount,
    inputError: side.inputError,
    result: side.result,
  };
}

function handleCompare(body) {
  if (!body || typeof body !== 'object') {
    return { httpStatus: 400, error: '请求体必须为 JSON 对象' };
  }
  if (!('earlier' in body) || !('later' in body)) {
    return { httpStatus: 400, error: '请求体必须包含 earlier 与 later 两个快照输入' };
  }

  const earlier = parseSide(body.earlier, 'earlier');
  const later = parseSide(body.later, 'later');

  let status = 'invalid';
  let conclusion = null;
  let code = null;
  let reason = null;
  let keyHex = null;

  const inputBad = [earlier, later].filter((s) => s.inputError);
  if (inputBad.length > 0) {
    // 输入级错误：首个失败层记为第 0 层（输入校验阶段），不进入证明核验。
    code = 'INPUT_INVALID';
    reason = `${inputBad.map((s) => s.inputError).join('；')}。首个失败层：第 0 层（输入校验阶段）`;
  } else if (earlier.keyHex !== later.keyHex) {
    // 输入标识不一致：双时点对照必须针对同一十六进制指令。
    code = 'KEY_MISMATCH';
    reason =
      `输入标识不一致：较早快照指令标识 0x${earlier.keyHex} 与较晚快照指令标识 0x${later.keyHex} 不同，` +
      `双时点对照必须针对同一十六进制指令。首个失败层：第 0 层（输入校验阶段）`;
  } else {
    keyHex = earlier.keyHex;
    // 两侧独立核验，互不借用对方结论。
    earlier.result = verifyProof(earlier.rootBytes, earlier.keyNibbles, earlier.proofNodes);
    later.result = verifyProof(later.rootBytes, later.keyNibbles, later.proofNodes);

    const failed = [];
    for (const side of [earlier, later]) {
      if (side.result.status === 'invalid') {
        failed.push(
          `${side.label}首个失败层：第 ${side.result.firstFailedLayer} 层（${side.result.code}）——${side.result.reason}`
        );
      }
    }
    if (failed.length > 0) {
      code = 'SIDE_INVALID';
      reason = failed.join('；');
    } else {
      status = 'compared';
      const e = earlier.result.authorized;
      const l = later.result.authorized;
      conclusion = e && l ? 'still-authorized' : e ? 'revoked' : l ? 'enabled' : 'still-unauthorized';
    }
  }

  const result = {
    status,
    conclusion,
    conclusionLabel: conclusion ? CONCLUSION_LABEL[conclusion] : null,
    keyHex,
    code,
    reason,
    earlier: publicSide(earlier),
    later: publicSide(later),
  };
  const page = buildComparePage(result);
  return { httpStatus: 200, result, page };
}

module.exports = { handleCompare, CONCLUSION_LABEL };
