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

// 双时点对照示例：同一条十六进制指令存在于两张不同根的快照中，
// 较早快照承诺启用（01），较晚快照承诺撤销（00）。
// 两张树结构同构但目标叶值不同，因此根哈希不同、根到叶路径一致。
function buildCompareSnapshots() {
  const targetKey = '0a1b2c3d4e5f0011';
  const targetNibbles = bytesToNibbles(Buffer.from(targetKey, 'hex'));
  // 同一深前缀族下的兄弟键：把共享分支撑到 ≥32 字节，
  // 使扩展节点以 32 字节散列引用该分支（与单快照示例的引用形态保持丰富一致）。
  const siblingKeys = ['0a1b2c3d4e5f0012', '0a1b2c3d4e5f0013', '0a1b2c3d4e5f001a'];
  const otherKey = '99887766aabbccdd';

  const build = (targetValue) => {
    const trie = new Trie();
    trie.put(targetNibbles, Uint8Array.of(targetValue));
    siblingKeys.forEach((k, i) => {
      // 长叶值确保共享分支的 RLP 体量达到 32 字节而必须散列引用。
      trie.put(bytesToNibbles(Buffer.from(k, 'hex')), new Uint8Array(24).fill(i + 2));
    });
    trie.put(bytesToNibbles(Buffer.from(otherKey, 'hex')), Uint8Array.of(0x01));
    const rootHash = trie.commit();
    return { trie, rootHash, rootHashHex: toHex(rootHash) };
  };

  const earlierSnap = build(0x01);
  const laterSnap = build(0x00);

  const side = (snap) => ({
    rootHash: snap.rootHashHex,
    proofNodes: snap.trie.proveKey(targetNibbles).map((p) => toHex(p)),
  });

  return {
    keyHex: targetKey,
    earlier: side(earlierSnap),
    later: side(laterSnap),
  };
}

module.exports = { buildSnapshots, buildCompareSnapshots };
