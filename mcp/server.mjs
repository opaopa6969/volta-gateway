#!/usr/bin/env node
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const NS = 'vgw';
const VERSION = '0.1.0';

function log(...a) {
  process.stderr.write(`[${NS}] ` + a.map((x) => typeof x === 'string' ? x : JSON.stringify(x)).join(' ') + '\n');
}

const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'http://192.168.1.8:7072';
const GATEWAY_URL = process.env.GATEWAY_URL || 'http://127.0.0.1:80';
const VGW_AUTH_TOKEN = process.env.VGW_AUTH_TOKEN || '';
const VOLTA_ADMIN_TOKEN = process.env.VOLTA_ADMIN_TOKEN || '';
const TRAEFIK_TO_VOLTA_BIN = process.env.TRAEFIK_TO_VOLTA_BIN || '';

async function fetchJson(url, opts = {}) {
  const headers = { ...opts.headers };
  if (headers.authorization === undefined && opts.bearer) {
    headers.authorization = `Bearer ${opts.bearer}`;
  }
  const res = await fetch(url, { ...opts, headers });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text }; }
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} ${res.statusText}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

async function fetchText(url, opts = {}) {
  const headers = { ...opts.headers };
  if (headers.authorization === undefined && opts.bearer) {
    headers.authorization = `Bearer ${opts.bearer}`;
  }
  const res = await fetch(url, { ...opts, headers });
  const text = await res.text();
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} ${res.statusText}`);
    err.status = res.status;
    err.body = text;
    throw err;
  }
  return text;
}

function authHeaders() {
  return VGW_AUTH_TOKEN ? { Authorization: `Bearer ${VGW_AUTH_TOKEN}` } : {};
}

function gwHeaders() {
  return VOLTA_ADMIN_TOKEN ? { Authorization: `Bearer ${VOLTA_ADMIN_TOKEN}` } : {};
}

function buildQuery(params) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v));
  }
  const qs = sp.toString();
  return qs ? `?${qs}` : '';
}

function textResult(text) {
  return { content: [{ type: 'text', text: typeof text === 'string' ? text : JSON.stringify(text, null, 2) }] };
}

function jsonResult(obj) {
  return textResult(JSON.stringify(obj, null, 2));
}

function errorResult(err) {
  return {
    isError: true,
    content: [{ type: 'text', text: `error: ${err.message}${err.status ? ` (HTTP ${err.status})` : ''}${err.body ? `\n${typeof err.body === 'string' ? err.body : JSON.stringify(err.body)}` : ''}` }],
  };
}

export function createServer() {
  const server = new McpServer({ name: `${NS}-mcp`, version: VERSION });

  server.tool(
    'audit_search',
    '監査ログを検索する（auth-server admin API・読み取り専用・ADMIN 権限必要）',
    {
      q: z.string().optional().describe('検索クエリ'),
      userId: z.string().optional().describe('ユーザーIDで絞り込み'),
      event: z.string().optional().describe('イベント種別で絞り込み'),
      from: z.string().optional().describe('開始日時（ISO 8601）'),
      to: z.string().optional().describe('終了日時（ISO 8601）'),
      page: z.number().int().min(1).optional().default(1).describe('ページ番号'),
      size: z.number().int().min(1).max(100).optional().default(20).describe('ページサイズ'),
    },
    { readOnlyHint: true, openWorldHint: false },
    async (args) => {
      try {
        const qs = buildQuery({ q: args.q, user_id: args.userId, event: args.event, from: args.from, to: args.to, page: args.page, size: args.size });
        const data = await fetchJson(`${AUTH_SERVER_URL}/api/v1/admin/audit${qs}`, { bearer: VGW_AUTH_TOKEN });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'user_search',
    'ユーザーを検索する（auth-server admin API・読み取り専用・ADMIN 権限必要）',
    {
      q: z.string().optional().describe('検索クエリ（email/name）'),
      status: z.string().optional().describe('ステータスで絞り込み'),
      page: z.number().int().min(1).optional().default(1),
      size: z.number().int().min(1).max(100).optional().default(20),
    },
    { readOnlyHint: true, openWorldHint: false },
    async (args) => {
      try {
        const qs = buildQuery({ q: args.q, status: args.status, page: args.page, size: args.size });
        const data = await fetchJson(`${AUTH_SERVER_URL}/api/v1/admin/users${qs}`, { bearer: VGW_AUTH_TOKEN });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'tenant_list',
    'テナント一覧を取得する（auth-server admin API・読み取り専用・ADMIN 権限必要）',
    {
      q: z.string().optional().describe('検索クエリ'),
      page: z.number().int().min(1).optional().default(1),
      size: z.number().int().min(1).max(100).optional().default(20),
    },
    { readOnlyHint: true, openWorldHint: false },
    async (args) => {
      try {
        const qs = buildQuery({ q: args.q, page: args.page, size: args.size });
        const data = await fetchJson(`${AUTH_SERVER_URL}/api/v1/admin/tenants${qs}`, { bearer: VGW_AUTH_TOKEN });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'metrics',
    'gateway の Prometheus メトリクスを取得する（読み取り専用）',
    {},
    { readOnlyHint: true, openWorldHint: false },
    async () => {
      try {
        const text = await fetchText(`${GATEWAY_URL}/metrics`);
        return textResult(text);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'routes_list',
    'gateway のルート一覧を取得する（読み取り専用・loopback からアクセス）',
    {},
    { readOnlyHint: true, openWorldHint: false },
    async () => {
      try {
        const data = await fetchJson(`${GATEWAY_URL}/admin/routes`, { bearer: VOLTA_ADMIN_TOKEN });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'backends_health',
    'gateway のバックエンド健全性を取得する（circuit breaker 状態含む・読み取り専用）',
    {},
    { readOnlyHint: true, openWorldHint: false },
    async () => {
      try {
        const data = await fetchJson(`${GATEWAY_URL}/admin/backends`, { bearer: VOLTA_ADMIN_TOKEN });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'stats',
    'gateway のリクエスト統計を取得する（読み取り専用）',
    {},
    { readOnlyHint: true, openWorldHint: false },
    async () => {
      try {
        const data = await fetchJson(`${GATEWAY_URL}/admin/stats`, { bearer: VOLTA_ADMIN_TOKEN });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'traefik_convert',
    'Traefik 設定を volta-gateway YAML に変換する（traefik-to-volta CLI・読み取り専用）',
    {
      format: z.enum(['docker-compose', 'traefik-yaml']).describe('入力形式'),
      input: z.string().min(1).describe('入力ファイルの内容（Traefik 設定）'),
    },
    { readOnlyHint: true, openWorldHint: false },
    async (args) => {
      try {
        if (!TRAEFIK_TO_VOLTA_BIN) {
          return textResult('error: TRAEFIK_TO_VOLTA_BIN 環境変数が設定されていません。traefik-to-volta バイナリのパスを指定してください。');
        }
        const tmpFile = `/tmp/vgw-traefik-${process.pid}-${Date.now()}.yml`;
        const { writeFileSync, unlinkSync } = await import('node:fs');
        writeFileSync(tmpFile, args.input);
        try {
          const result = await new Promise((resolve, reject) => {
            execFile(TRAEFIK_TO_VOLTA_BIN, ['--from', args.format, '--input', tmpFile], (err, stdout, stderr) => {
              if (err) reject(err);
              else resolve({ stdout, stderr });
            });
          });
          return textResult(result.stdout);
        } finally {
          try { unlinkSync(tmpFile); } catch {}
        }
      } catch (e) { return errorResult(e); }
    }
  );

  server.resource(
    'spec',
    `${NS}://spec`,
    { mimeType: 'application/json', description: 'vgw の能力仕様（機械可読）' },
    async () => {
      const toolDefs = server._registeredTools || {};
      const tools = Object.entries(toolDefs).map(([name, def]) => ({
        kind: 'tool',
        name,
        summary: def.description || '',
        input: def.inputSchema ? '<see tools/list>' : '<none>',
        output: '<JSON>',
        side_effect: 'read',
        long_running: false,
        dry_run: false,
        min_role: name.startsWith('session') || name.startsWith('device') || name.startsWith('policy') || name.startsWith('data_export') || name.startsWith('audit') || name.startsWith('user') || name.startsWith('tenant') ? 'ADMIN' : 'OPERATOR',
      }));
      const spec = {
        namespace: NS,
        name: 'vgw-mcp',
        version: VERSION,
        summary: 'volta-gateway / auth-server 運用 MCP（監査ログ・ユーザー/テナント検索・gateway メトリクス・Traefik 変換）',
        capabilities: tools,
        compositions: [
          { title: 'インシデント対応', flow: ['vgw__audit_search', 'vgw__session_revoke(未実装)'], note: '監査ログから異常を検出しセッションを無効化' },
          { title: 'Traefik 移行', flow: ['vgw__traefik_convert', 'volta__gateway_routes_diff', 'volta__gateway_routes_apply'], note: 'Traefik 設定を変換して gateway に適用' },
        ],
        depends_on: [
          { namespace: 'volta', capability: 'volta__gateway_routes_apply' },
          { namespace: 'volta', capability: 'volta__gateway_reload' },
        ],
        health: '/healthz',
        docs: [`${NS}://guide`, 'volta://docs/GUIDE-add-backend'],
      };
      return { contents: [{ uri: `${NS}://spec`, mimeType: 'application/json', text: JSON.stringify(spec, null, 2) }] };
    }
  );

  server.resource(
    'guide',
    `${NS}://guide`,
    { mimeType: 'text/markdown', description: 'vgw の使い方ガイド' },
    async () => {
      const guide = [
        '# vgw MCP — 使い方ガイド',
        '',
        '## 概要',
        `namespace: \`${NS}\` / version: ${VERSION}`,
        'volta-gateway と auth-server の運用能力を MCP で提供する。',
        '',
        '## tools',
        '',
        '### auth-server 系（ADMIN 権限必要）',
        '- `audit_search` — 監査ログ検索。`q`, `userId`, `event`, `from`, `to` で絞り込み。',
        '- `user_search` — ユーザー検索。`q`, `status` で絞り込み。',
        '- `tenant_list` — テナント一覧。',
        '',
        '### gateway 系（OPERATOR 権限）',
        '- `metrics` — Prometheus メトリクス（text 形式）。',
        '- `routes_list` — ルート一覧。',
        '- `backends_health` — バックエンド健全性（circuit breaker 状態含む）。',
        '- `stats` — リクエスト統計。',
        '',
        '### CLI 系',
        '- `traefik_convert` — Traefik 設定を volta-gateway YAML に変換。`TRAEFIK_TO_VOLTA_BIN` 環境変数必須。',
        '',
        '## 環境変数',
        '- `VGW_AUTH_TOKEN` — auth-server admin API の Bearer token（JWT, ADMIN/OWNER）',
        '- `VOLTA_ADMIN_TOKEN` — gateway admin API の Bearer token',
        '- `AUTH_SERVER_URL` — auth-server URL（デフォルト: http://192.168.1.8:7072）',
        '- `GATEWAY_URL` — gateway URL（デフォルト: http://127.0.0.1:80）',
        '- `TRAEFIK_TO_VOLTA_BIN` — traefik-to-volta バイナリパス',
        '',
        '## 未実装（issue-hub #258 で協調中）',
        '- `session_list`, `session_revoke` — auth-server の Bearer 対応待ち',
        '- `policy_evaluate`, `data_export_*` — 同上',
        '- `device_list`, `device_delete` — 同上',
        '',
        '## 組み合わせ例',
        '1. `vgw__audit_search` → LLM で異常抽出 → `vgw__session_revoke`（インシデント対応）',
        '2. `vgw__traefik_convert` → `volta__gateway_routes_diff` → `volta__gateway_routes_apply`（Traefik 移行）',
      ].join('\n');
      return { contents: [{ uri: `${NS}://guide`, mimeType: 'text/markdown', text: guide }] };
    }
  );

  server.resource(
    'flows',
    `${NS}://flows`,
    { mimeType: 'application/json', description: '認証フロー定義一覧（tramli FlowDefinition）' },
    async () => {
      const flows = [
        { name: 'login', description: '標準ログイン（email + password）', steps: ['credentials', 'session', 'cookie'] },
        { name: 'mfa', description: '多要素認証', steps: ['credentials', 'mfa_challenge', 'mfa_verify', 'session'] },
        { name: 'oidc', description: 'OIDC（Google等）', steps: ['oidc_redirect', 'oidc_callback', 'session'] },
        { name: 'passkey', description: 'Passkey/WebAuthn ログイン', steps: ['passkey_challenge', 'passkey_verify', 'session'] },
        { name: 'magic_link', description: 'マジックリンク', steps: ['request', 'email', 'click', 'session'] },
      ];
      return { contents: [{ uri: `${NS}://flows`, mimeType: 'application/json', text: JSON.stringify(flows, null, 2) }] };
    }
  );

  server.resource(
    'parity',
    `${NS}://parity`,
    { mimeType: 'application/json', description: 'Rust(auth-server) ↔ Java(volta-auth-proxy) ルートパリティ表' },
    async () => {
      const parity = {
        note: 'auth-server は Java volta-auth-proxy の 1:1 置換。約 96 ルート。',
        rust_server: { host: '192.168.1.8', port: 7072, status: 'active' },
        java_proxy: { host: '192.168.1.8', port: 7070, status: 'retired' },
        routes: [
          { method: 'POST', path: '/auth/login', parity: 'match' },
          { method: 'POST', path: '/auth/logout', parity: 'match' },
          { method: 'GET', path: '/auth/verify', parity: 'match' },
          { method: 'POST', path: '/auth/refresh', parity: 'match' },
          { method: 'POST', path: '/auth/register', parity: 'match' },
          { method: 'GET', path: '/api/v1/admin/audit', parity: 'match' },
          { method: 'GET', path: '/api/v1/admin/users', parity: 'match' },
          { method: 'GET', path: '/api/v1/admin/tenants', parity: 'match' },
          { method: 'GET', path: '/api/v1/admin/sessions', parity: 'match' },
          { method: 'POST', path: '/api/v1/tenants/{id}/policies/evaluate', parity: 'match' },
        ],
      };
      return { contents: [{ uri: `${NS}://parity`, mimeType: 'application/json', text: JSON.stringify(parity, null, 2) }] };
    }
  );

  server.resource(
    'skill-gateway-ops',
    'skill://gateway-ops',
    { mimeType: 'text/markdown', description: 'skill: gateway リバースプロキシ運用手順' },
    async () => ({
      contents: [{ uri: 'skill://gateway-ops', mimeType: 'text/markdown', text: [
        '---',
        'name: gateway-ops',
        'description: gateway リバースプロキシの運用手順（drain, reload, routes 確認）',
        'volta:',
        '  version: 2',
        '  namespace: vgw',
        '  locality: service',
        '  applies_when: gateway の運用操作が必要なとき',
        '  requires:',
        '    tools: [vgw__routes_list, vgw__backends_health]',
        '  min_role: OPERATOR',
        '  tags: [gateway, ops, drain, reload]',
        '---',
        '# gateway 運用手順',
        '',
        '## ルート確認',
        '`vgw__routes_list` で現在のルート一覧を取得。',
        '',
        '## バックエンド健全性',
        '`vgw__backends_health` で circuit breaker 状態を確認。',
        '',
        '## reload（volta namespace）',
        '`volta__gateway_reload` で設定を再読み込み。',
        '',
        '## drain（volta namespace）',
        '`volta__gateway_reload` で drain を開始。healthz が 503 になるまで待つ。',
        '',
        '## routes 適用（volta namespace）',
        '`volta__gateway_routes_diff` で差分確認 → `volta__gateway_routes_apply` で適用。',
      ].join('\n') }],
    })
  );

  server.resource(
    'skill-add-route',
    'skill://add-route',
    { mimeType: 'text/markdown', description: 'skill: auth-server にルートを追加する手順' },
    async () => ({
      contents: [{ uri: 'skill://add-route', mimeType: 'text/markdown', text: [
        '---',
        'name: add-route',
        'description: auth-server に新規エンドポイントを追加する手順',
        'volta:',
        '  version: 2',
        '  namespace: vgw',
        '  locality: repo',
        '  applies_when: auth-server に新規エンドポイントを追加するとき',
        '  requires: []',
        '  min_role: ADMIN',
        '  tags: [auth-server, route, development]',
        '---',
        '# auth-server ルート追加手順',
        '',
        '1. `auth-server/src/handlers/` にハンドラ関数を追加',
        '2. `auth-server/src/app.rs` の `build_router()` にルートを登録',
        '3. admin 系なら `require_admin` または `require_admin_with_headers` を使用',
        '4. `cargo test -p volta-auth-server` でテスト',
        '5. MCP wrapper に tool を追加する場合は `mcp/server.mjs` に登録',
        '6. `vgw://spec` resource が自動的に更新される',
      ].join('\n') }],
    })
  );

  server.resource(
    'skill-traefik-migration',
    'skill://traefik-migration',
    { mimeType: 'text/markdown', description: 'skill: Traefik から volta-gateway への移行手順' },
    async () => ({
      contents: [{ uri: 'skill://traefik-migration', mimeType: 'text/markdown', text: [
        '---',
        'name: traefik-migration',
        'description: Traefik 設定を volta-gateway に移行する手順',
        'volta:',
        '  version: 2',
        '  namespace: vgw',
        '  locality: global',
        '  applies_when: Traefik 設定を volta-gateway に移行するとき',
        '  requires:',
        '    tools: [vgw__traefik_convert, volta__gateway_routes_diff, volta__gateway_routes_apply]',
        '  min_role: OPERATOR',
        '  tags: [traefik, migration, gateway]',
        '---',
        '# Traefik → volta-gateway 移行手順',
        '',
        '## 1. 変換',
        '`vgw__traefik_convert` に Traefik 設定（docker-compose 形式または traefik-yaml 形式）を渡す。',
        'volta-gateway 用 YAML が返る。',
        '',
        '## 2. 差分確認',
        '`volta__gateway_routes_diff` で現在の routes との差分を確認。',
        '',
        '## 3. 適用',
        '`volta__gateway_routes_apply` で差分を適用。',
        '',
        '## 注意',
        '- traefik-to-volta は `server.port: 8080` と `auth.volta_url: http://localhost:7070` を固定出力する',
        '- 実際のポートや auth-server URL は手動で修正する必要がある',
        '- CORS や strip_prefix 等の middleware は可能な限り変換するが、全ての Traefik middleware に対応しているわけではない',
      ].join('\n') }],
    })
  );

  return server;
}

async function serveHttp(port) {
  const transports = new Map();
  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    try {
      if (url.pathname === '/healthz') {
        res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'identity' });
        return res.end(JSON.stringify({ ok: true, name: `${NS}-mcp`, version: VERSION }));
      }
      if (url.pathname !== '/mcp') {
        res.writeHead(404, { 'content-type': 'application/json', 'content-encoding': 'identity' });
        return res.end(JSON.stringify({ error: 'not found' }));
      }

      const clientIp = req.socket.remoteAddress || '';
      const allowed = ['127.0.0.1', '::1', '::ffff:127.0.0.1', '192.168.1.50', '192.168.1.8'];
      if (!allowed.includes(clientIp)) {
        res.writeHead(403, { 'content-type': 'application/json', 'content-encoding': 'identity' });
        return res.end(JSON.stringify({ error: 'forbidden' }));
      }

      const sid = req.headers['mcp-session-id'];
      if (sid && transports.has(sid)) {
        return await transports.get(sid).handleRequest(req, res);
      }
      if (req.method === 'POST' && !sid) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          onsessioninitialized: (id) => { transports.set(id, transport); log('session open', { sid: id }); },
          onsessionclosed: (id) => { transports.delete(id); log('session closed', { sid: id }); },
        });
        const server = createServer();
        transport.onclose = () => {
          if (transport.sessionId) transports.delete(transport.sessionId);
          server.close().catch(() => {});
        };
        await server.connect(transport);
        return await transport.handleRequest(req, res);
      }
      res.writeHead(sid ? 404 : 400, { 'content-type': 'application/json', 'content-encoding': 'identity' });
      return res.end(JSON.stringify({ error: sid ? 'unknown session' : 'missing mcp-session-id' }));
    } catch (e) {
      log('request failed', { path: url.pathname, error: String(e?.stack || e) });
      if (!res.headersSent) { res.writeHead(500); res.end(JSON.stringify({ error: 'internal error' })); }
      else res.end();
    }
  });
  httpServer.listen(port, '0.0.0.0', () => log('http listening', { url: `http://0.0.0.0:${port}/mcp` }));
}

const port = Number(process.env.PORT || 9214);
serveHttp(port).catch((e) => { log('http failed', { error: String(e?.stack || e) }); process.exit(1); });
