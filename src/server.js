'use strict';
// 零依赖 HTTP 服务：
//   GET  /                    静态导入入口页（单快照复核 + 双时点对照）
//   GET  /healthz             健康检查 -> 200 {"status":"ok"}
//   POST /api/verify          单快照证明核验（JSON 入参，返回 {result, page}）
//   POST /api/compare         双时点对照核验（JSON 入参，返回 {result, page}）
//   GET  /api/sample          单快照示例
//   GET  /api/sample/compare  双时点对照示例（已启用 → 已撤销）
// 宿主端口可经环境变量 PORT / HOST 配置。
const http = require('node:http');
const { handleVerify } = require('./verify-api');
const { handleCompare } = require('./compare-api');
const { buildIndexPage } = require('./page');
const { buildSnapshots, buildCompareSnapshots } = require('./sample-snapshot');
const { toHex } = require('./hexutil');

function samplePayload() {
  const snap = buildSnapshots();
  const make = (key) => ({
    rootHash: snap.rootHashHex,
    keyHex: key,
    proofNodes: snap.proofFor(key).map((p) => toHex(p)),
  });
  return {
    rootHash: snap.rootHashHex,
    cases: {
      authorized: make(snap.keys.authorized),
      unauthorized: make(snap.keys.unauthorized),
    },
  };
}

function sampleComparePayload() {
  const cmp = buildCompareSnapshots();
  const side = (s) => ({
    rootHash: s.rootHashHex,
    keyHex: cmp.keyHex,
    proofNodes: s.proof.map((p) => toHex(p)),
  });
  return {
    keyHex: cmp.keyHex,
    earlier: side(cmp.earlier),
    later: side(cmp.later),
  };
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function sendHtml(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
  });
  res.end(html);
}

// 读取并解析 JSON 请求体（2 MiB 上限），然后交给 handler。
function readJsonBody(req, res, handler) {
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > 2 * 1024 * 1024) {
      sendJson(res, 413, { error: '请求体超过 2 MiB 限制' });
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => {
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    } catch (e) {
      return sendJson(res, 400, { error: `JSON 请求体解析失败：${e.message}` });
    }
    handler(body);
  });
}

function createServer() {
  const indexHtml = buildIndexPage();

  return http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      return sendHtml(res, 200, indexHtml);
    }

    if (req.method === 'GET' && (url.pathname === '/healthz' || url.pathname === '/health')) {
      return sendJson(res, 200, { status: 'ok', service: 'offline-instruction-auth-review' });
    }

    if (req.method === 'GET' && url.pathname === '/api/sample') {
      return sendJson(res, 200, samplePayload());
    }

    if (req.method === 'GET' && url.pathname === '/api/sample/compare') {
      return sendJson(res, 200, sampleComparePayload());
    }

    if (req.method === 'POST' && url.pathname === '/api/verify') {
      return readJsonBody(req, res, (body) => {
        const out = handleVerify(body);
        if (out.error) return sendJson(res, out.httpStatus, { error: out.error });
        sendJson(res, 200, { result: out.result, page: out.page });
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/compare') {
      return readJsonBody(req, res, (body) => {
        const out = handleCompare(body);
        if (out.error) return sendJson(res, out.httpStatus, { error: out.error });
        sendJson(res, 200, { result: out.result, page: out.page });
      });
    }

    sendJson(res, 404, { error: '未找到该路径' });
  });
}

if (require.main === module) {
  const host = process.env.HOST || '0.0.0.0';
  const port = Number.parseInt(process.env.PORT || '8080', 10);
  createServer().listen(port, host, () => {
    console.log(`offline-instruction-auth-review listening on http://${host}:${port}`);
  });
}

module.exports = { createServer };
