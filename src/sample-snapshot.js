'use strict';
// 内置离线示例快照：构造一棵覆盖 扩展/分支/叶、内嵌节点与 32 字节散列引用的 MPT。
// 供入口页“一键载入示例”与验收冒烟使用；真实使用时审查员导入自己的离线快照。
const { Trie } = require('./trie');
const { toHex, bytesToNibbles } = require('./hexutil');

function buildSnapshots() {
  const trie = new Trie();
  const put = (keyHex, ...value) => trie.put(bytesToNibbles(Buffer.from(keyHex, 'hex')), Uint8Array.of(...value));

  // 深前缀族：迫使上层出现扩展节点与散列引用
  put('0123456789abcdef0123', 0x01); // 有效授权目标
  put('0123456789abcdef0124', 0x00); // 同构兄弟键：叶值 00 -> 未授权
  put('0123456789abcdef0abc', 0x01);
  put('0123456789abdddddddd', 0x02);
  // 另一前缀族
  put('fedcba9876543210abcd', 0x01);
  put('fedcba9876543210abce', 0x01);
  // 短键：迫使分支槽下出现 < 32 字节的内嵌叶节点
  put('a1', 0x00);
  put('a2', 0x01);

  const rootHash = trie.commit();

  const proofFor = (keyHex) => trie.proveKey(bytesToNibbles(Buffer.from(keyHex, 'hex')));

  return {
    trie,
    rootHash,
    rootHashHex: toHex(rootHash),
    keys: {
      authorized: '0123456789abcdef0123',
      unauthorized: '0123456789abcdef0124',
      otherAuthorized: 'a2',
      shortUnauthorized: 'a1',
    },
    proofFor,
  };
}

// 双时点对照示例：同一指令在较早快照中为启用（01）、在较晚快照中被撤销（00）。
// 两棵树的背景键集合一致（MPT 规范结构与插入顺序无关），仅目标键叶值不同，
// 因此两个根哈希不同、两侧证明各自独立有效。
function buildCompareSnapshots() {
  const keyHex = '0123456789abcdef0123';
  const keyNibbles = bytesToNibbles(Buffer.from(keyHex, 'hex'));

  const build = (targetValue) => {
    const trie = new Trie();
    const put = (k, ...value) => trie.put(bytesToNibbles(Buffer.from(k, 'hex')), Uint8Array.of(...value));
    put('0123456789abcdef0124', 0x00);
    put('0123456789abcdef0abc', 0x01);
    put('0123456789abdddddddd', 0x02);
    put('fedcba9876543210abcd', 0x01);
    put('fedcba9876543210abce', 0x01);
    put('a1', 0x00);
    put('a2', 0x01);
    put(keyHex, targetValue); // 目标指令：较早 01（已启用），较晚 00（已撤销）
    const rootHash = trie.commit();
    return { rootHash, rootHashHex: toHex(rootHash), proof: trie.proveKey(keyNibbles) };
  };

  return {
    keyHex,
    earlier: build(0x01),
    later: build(0x00),
  };
}

module.exports = { buildSnapshots, buildCompareSnapshots };
