#!/usr/bin/env node
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const NS = 'gw';
const VERSION = '0.1.0';

function log(...a) {
  process.stderr.write(`[${NS}] ` + a.map((x) => typeof x === 'string' ? x : JSON.stringify(x)).join(' ') + '\n');
}

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://127.0.0.1:80';
const VOLTA_ADMIN_TOKEN = process.env.VOLTA_ADMIN_TOKEN || '';
const GATEWAY_BIN = process.env.GATEWAY_BIN || '';
const TRAEFIK_TO_VOLTA_BIN = process.env.TRAEFIK_TO_VOLTA_BIN || '';

function gwHeaders() {
  return VOLTA_ADMIN_TOKEN ? { Authorization: `Bearer ${VOLTA_ADMIN_TOKEN}` } : {};
}

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

  // ── 読取系 tools ──────────────────────────────────────────────

  server.tool(
    'list_routes',
    'gateway のルーティング表を一覧する（読取専用）',
    {},
    async () => {
      try {
        const data = await fetchJson(`${GATEWAY_URL}/admin/routes`, { headers: gwHeaders() });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'list_backends',
    'gateway のバックエンド健全性とサーキットブレーカー状態を一覧する（読取専用）',
    {},
    async () => {
      try {
        const data = await fetchJson(`${GATEWAY_URL}/admin/backends`, { headers: gwHeaders() });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'stats',
    'gateway のリクエスト統計（2xx/4xx/5xx・WebSocket・キャッシュ・ミラー）を取得する（読取専用）',
    {},
    async () => {
      try {
        const data = await fetchJson(`${GATEWAY_URL}/admin/stats`, { headers: gwHeaders() });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'get_config',
    'gateway の有効設定（base YAML ⊕ overlay）を取得する（読取専用）',
    {},
    async () => {
      try {
        const data = await fetchJson(`${GATEWAY_URL}/admin/config`, { headers: gwHeaders() });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'metrics',
    'gateway の Prometheus メトリクスを取得する（読取専用・text 形式）',
    {},
    async () => {
      try {
        const text = await fetchText(`${GATEWAY_URL}/metrics`);
        return textResult(text);
      } catch (e) { return errorResult(e); }
    }
  );

  // ── 書込系 tools（dry-run 既定・confirm 必須）──────────────────

  server.tool(
    'patch_config',
    'gateway 設定に JSON Merge Patch を適用し永続化・ホット適用する（破壊的・confirm=false で dry-run）',
    {
      patch: z.record(z.any()).describe('JSON Merge Patch オブジェクト'),
      confirm: z.boolean().optional().default(false).describe('false（既定）= dry-run（差分プレビュー）、true = 実行'),
    },
    async (args) => {
      try {
        if (!args.confirm) {
          return jsonResult({
            status: 'dry-run',
            message: 'confirm=true で実際に適用します',
            patch: args.patch,
          });
        }
        const data = await fetchJson(`${GATEWAY_URL}/admin/config`, {
          method: 'PATCH',
          headers: { ...gwHeaders(), 'content-type': 'application/json' },
          body: JSON.stringify(args.patch),
        });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'clear_overlay',
    'gateway 設定オーバーレイを破棄しベース YAML に戻す（破壊的・confirm=false で dry-run）',
    {
      confirm: z.boolean().optional().default(false).describe('false（既定）= dry-run、true = 実行'),
    },
    async (args) => {
      try {
        if (!args.confirm) {
          return jsonResult({
            status: 'dry-run',
            message: 'confirm=true で overlay を破棄しベース YAML に戻します',
          });
        }
        const data = await fetchJson(`${GATEWAY_URL}/admin/config/overlay`, {
          method: 'DELETE',
          headers: gwHeaders(),
        });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'reload',
    'gateway 設定を再読み込みしホットスワップする（破壊的・confirm=false で dry-run）',
    {
      confirm: z.boolean().optional().default(false).describe('false（既定）= dry-run、true = 実行'),
    },
    async (args) => {
      try {
        if (!args.confirm) {
          return jsonResult({
            status: 'dry-run',
            message: 'confirm=true で設定を再読み込みします',
          });
        }
        const data = await fetchJson(`${GATEWAY_URL}/admin/reload`, {
          method: 'POST',
          headers: gwHeaders(),
        });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'drain',
    'gateway のグレースフルシャットダウン（drain）を開始する（破壊的・トラフィック停止・confirm=false で dry-run）',
    {
      confirm: z.boolean().optional().default(false).describe('false（既定）= dry-run、true = 実行（トラフィック停止）'),
    },
    async (args) => {
      try {
        if (!args.confirm) {
          return jsonResult({
            status: 'dry-run',
            message: 'confirm=true で drain を開始します。gateway が 503 を返しトラフィックが停止します。',
            warning: 'これはプロセスのシャットダウンを伴います。本番環境では注意して使用してください。',
          });
        }
        const data = await fetchJson(`${GATEWAY_URL}/admin/drain`, {
          method: 'POST',
          headers: gwHeaders(),
        });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'reset_circuit',
    '指定バックエンドのサーキットブレーカーをリセットする（破壊的・confirm=false で dry-run）',
    {
      backend_url: z.string().min(1).describe('リセット対象のバックエンド URL（例: http://192.168.1.50:3000）'),
      confirm: z.boolean().optional().default(false).describe('false（既定）= dry-run（現在の状態を返す）、true = 実行'),
    },
    async (args) => {
      try {
        const backends = await fetchJson(`${GATEWAY_URL}/admin/backends`, { headers: gwHeaders() });
        const target = backends.find((b) => b.url === args.backend_url);
        if (!target) {
          return jsonResult({ status: 'error', message: `backend not found: ${args.backend_url}`, available: backends.map((b) => b.url) });
        }
        if (!args.confirm) {
          return jsonResult({
            status: 'dry-run',
            message: 'confirm=true でサーキットブレーカーをリセットします',
            backend: target,
          });
        }
        const encoded = encodeURIComponent(args.backend_url);
        const data = await fetchJson(`${GATEWAY_URL}/admin/backends/${encoded}/reset`, {
          method: 'POST',
          headers: gwHeaders(),
        });
        return jsonResult(data);
      } catch (e) { return errorResult(e); }
    }
  );

  // ── 純粋計算 tools ────────────────────────────────────────────

  server.tool(
    'validate_config',
    'gateway 設定ファイルを静的検証する（純粋計算・副作用なし・CI/CD 向け）',
    {
      config_path: z.string().min(1).describe('検証する設定ファイルのパス'),
    },
    async (args) => {
      try {
        if (!GATEWAY_BIN) {
          return textResult('error: GATEWAY_BIN 環境変数が設定されていません。volta-gateway バイナリのパスを指定してください。');
        }
        if (!existsSync(args.config_path)) {
          return jsonResult({ valid: false, errors: [`file not found: ${args.config_path}`] });
        }
        const result = await new Promise((resolve, reject) => {
          execFile(GATEWAY_BIN, ['--validate', args.config_path], (err, stdout, stderr) => {
            if (err && err.code === 1) {
              resolve({ valid: false, errors: stderr.split('\n').filter(Boolean) });
            } else if (err) {
              reject(err);
            } else {
              resolve({ valid: true, errors: [] });
            }
          });
        });
        return jsonResult(result);
      } catch (e) { return errorResult(e); }
    }
  );

  server.tool(
    'convert_traefik',
    'Traefik 設定を volta-gateway YAML に変換する（純粋計算・副作用なし）',
    {
      format: z.enum(['docker-compose', 'traefik-yaml']).describe('入力形式'),
      input: z.string().min(1).describe('入力ファイルの内容（Traefik 設定）'),
    },
    async (args) => {
      try {
        if (!TRAEFIK_TO_VOLTA_BIN) {
          return textResult('error: TRAEFIK_TO_VOLTA_BIN 環境変数が設定されていません。traefik-to-volta バイナリのパスを指定してください。');
        }
        const tmpFile = `/tmp/gw-traefik-${process.pid}-${Date.now()}.yml`;
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

  // ── resources ────────────────────────────────────────────────

  server.resource(
    'spec',
    `${NS}://spec`,
    { mimeType: 'application/json', description: 'gw の能力仕様（機械可読）' },
    async () => {
      const toolDefs = server._registeredTools || {};
      const writeTools = ['patch_config', 'clear_overlay', 'reload', 'drain', 'reset_circuit'];
      const tools = Object.entries(toolDefs).map(([name, def]) => ({
        kind: 'tool',
        name,
        summary: def.description || '',
        input: def.inputSchema ? '<see tools/list>' : '<none>',
        output: '<JSON>',
        side_effect: writeTools.includes(name) ? 'write' : 'none',
        long_running: false,
        dry_run: writeTools.includes(name),
        min_role: writeTools.includes(name) ? 'OPERATOR' : 'MEMBER',
      }));
      const spec = {
        namespace: NS,
        name: 'gw-mcp',
        version: VERSION,
        summary: 'volta-gateway admin API MCP wrapper（ルート一覧・バックエンド健全性・設定取得/変更・リロード・drain・CB リセット・設定検証・Traefik 変換）',
        capabilities: tools,
        compositions: [
          { title: 'サービス追加', flow: ['gw__list_routes', 'gw__list_backends', 'volta__svc_restart'], note: 'ルート一覧→死活確認→不調サービス再起動' },
          { title: '設定変更', flow: ['gw__get_config', 'gw__patch_config', 'gw__list_backends'], note: '設定取得→dry-run patch→適用→健全性確認' },
          { title: 'インシデント対応', flow: ['gw__stats', 'gw__list_backends', 'gw__reset_circuit', 'volta__svc_logs'], note: '5xx スパイク検知→CB オープン特定→リセット→ログ確認' },
          { title: 'Traefik 移行', flow: ['gw__convert_traefik', 'gw__validate_config', 'gw__patch_config', 'gw__reload'], note: 'Traefik 変換→検証→適用→リロード' },
        ],
        depends_on: [
          { namespace: 'volta', capability: 'volta__gateway_routes_apply' },
          { namespace: 'volta', capability: 'volta__svc_restart' },
          { namespace: 'volta', capability: 'volta__svc_logs' },
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
    { mimeType: 'text/markdown', description: 'gw の使い方ガイド' },
    async () => {
      const guide = [
        '# gw MCP — 使い方ガイド',
        '',
        '## 概要',
        `namespace: \`${NS}\` / version: ${VERSION}`,
        'volta-gateway の admin API を直接ラップする MCP。読取系と書込系の両方を提供する。',
        '',
        '## vgw との使い分け',
        '- `gw`（本サーバ）: gateway 全 admin API（読取+書込）+ validate_config + traefik 変換',
        '- `vgw`（既存）: auth-server admin API（監査ログ・ユーザー/テナント）+ gateway 読取系',
        '- 書込系操作が必要なら `gw`。auth-server 管理が必要なら `vgw`。',
        '',
        '## tools',
        '',
        '### 読取系（MEMBER 権限）',
        '- `list_routes` — ルーティング表',
        '- `list_backends` — バックエンド健全性（CB 状態含む）',
        '- `stats` — リクエスト統計',
        '- `get_config` — 有効設定（base ⊕ overlay）',
        '- `metrics` — Prometheus メトリクス',
        '',
        '### 書込系（OPERATOR 権限・dry-run 既定）',
        '- `patch_config` — JSON Merge Patch 適用。`confirm=false`（既定）で dry-run。',
        '- `clear_overlay` — overlay 破棄。`confirm=false` で dry-run。',
        '- `reload` — 設定再読込。`confirm=false` で dry-run。',
        '- `drain` — グレースフルシャットダウン。`confirm=false` で dry-run。**本番では注意**。',
        '- `reset_circuit` — CB リセット。`backend_url` 必須。`confirm=false` で dry-run。',
        '',
        '### 純粋計算（MEMBER 権限）',
        '- `validate_config` — 設定ファイル静的検証。`GATEWAY_BIN` 環境変数必須。',
        '- `convert_traefik` — Traefik → gateway YAML 変換。`TRAEFIK_TO_VOLTA_BIN` 環境変数必須。',
        '',
        '## 環境変数',
        '- `GATEWAY_URL` — gateway URL（デフォルト: http://127.0.0.1:80）',
        '- `VOLTA_ADMIN_TOKEN` — gateway admin API の Bearer token',
        '- `GATEWAY_BIN` — volta-gateway バイナリパス（validate_config 用）',
        '- `TRAEFIK_TO_VOLTA_BIN` — traefik-to-volta バイナリパス',
        '',
        '## volta-platform との使い分け',
        '- `volta__gateway_routes_apply` を正とする（services.json が single source of truth）',
        '- `gw__patch_config` は overlay 編集用（一時的なルート変更・canary テスト）',
        '- `gw__clear_overlay` で overlay を破棄すると services.json 由来のルートに戻る',
        '',
        '## 組み合わせ例',
        '1. `gw__stats` → `gw__list_backends` → `gw__reset_circuit(confirm=true)` → `volta__svc_logs`（インシデント対応）',
        '2. `gw__get_config` → `gw__patch_config(confirm=false)` → `gw__patch_config(confirm=true)` → `gw__list_backends`（設定変更）',
        '3. `gw__convert_traefik` → `gw__validate_config` → `gw__patch_config(confirm=true)` → `gw__reload(confirm=true)`（Traefik 移行）',
      ].join('\n');
      return { contents: [{ uri: `${NS}://guide`, mimeType: 'text/markdown', text: guide }] };
    }
  );

  server.resource(
    'config-schema',
    `${NS}://config-schema`,
    { mimeType: 'application/json', description: 'gateway 設定スキーマと全ルートオプションの参照' },
    async () => {
      const schema = {
        server: {
          port: 'u16 (default 8080)',
          reuse_port: 'bool (SO_REUSEPORT for zero-downtime deploy)',
          tls: { enabled: 'bool', cert: 'path', key: 'path', acme: { domain: 'string', email: 'string' } },
        },
        auth: {
          volta_url: 'string (auth-server URL)',
          timeout_ms: 'u32 (default 500, fail-closed)',
          bypass_paths: 'string[] (skip auth)',
          auth_bypass_paths: 'string[] (skip auth, legacy)',
        },
        admin: {
          token: 'string (Bearer token for /admin/*, env VOLTA_ADMIN_TOKEN overrides)',
        },
        routing: [{
          host: 'string (wildcard *.example.com supported)',
          backend: 'string (single backend)',
          backends: 'string[] (round-robin LB)',
          app_id: 'string',
          public: 'bool (skip auth)',
          cors_origins: 'string[]',
          strip_prefix: 'string',
          add_prefix: 'string',
          timeout_secs: 'u32 (per-route timeout)',
          geo_allowlist: 'string[] (ISO country codes)',
          geo_denylist: 'string[]',
          mirror: { backend: 'string', sample_rate: 'f32' },
          cache: { enabled: 'bool', ttl_secs: 'u32', max_size: 'u32' },
          headers: { add: 'object', remove: 'string[]' },
          ip_allowlist: 'string[]',
          ip_denylist: 'string[]',
        }],
        l4_proxy: [{ listen: 'string', backend: 'string', protocol: 'tcp|udp' }],
      };
      return { contents: [{ uri: `${NS}://config-schema`, mimeType: 'application/json', text: JSON.stringify(schema, null, 2) }] };
    }
  );

  server.resource(
    'auth-routes',
    `${NS}://auth-routes`,
    { mimeType: 'application/json', description: '126 ルート認証 API のエンドポイント一覧' },
    async () => {
      const routes = {
        note: 'auth-server (Rust) は Java volta-auth-proxy の 1:1 置換。約 126 ルート。',
        categories: [
          { name: 'auth', routes: ['POST /auth/login', 'POST /auth/logout', 'GET /auth/verify', 'POST /auth/refresh', 'POST /auth/register'] },
          { name: 'oidc', routes: ['GET /oidc/{provider}/start', 'GET /oidc/{provider}/callback'] },
          { name: 'saml', routes: ['GET /saml/metadata', 'POST /saml/acs', 'GET /saml/login', 'GET /saml/logout'] },
          { name: 'mfa', routes: ['POST /mfa/setup', 'POST /mfa/verify', 'POST /mfa/disable'] },
          { name: 'passkey', routes: ['POST /passkey/register/begin', 'POST /passkey/register/finish', 'POST /passkey/auth/begin', 'POST /passkey/auth/finish'] },
          { name: 'magic_link', routes: ['POST /magic-link/request', 'GET /magic-link/verify'] },
          { name: 'scim', routes: ['GET /scim/v2/Users', 'POST /scim/v2/Users', 'GET /scim/v2/Groups'] },
          { name: 'admin', routes: ['GET /api/v1/admin/audit', 'GET /api/v1/admin/users', 'GET /api/v1/admin/tenants', 'GET /api/v1/admin/sessions'] },
          { name: 'billing', routes: ['GET /api/v1/billing/subscriptions', 'POST /api/v1/billing/subscriptions'] },
          { name: 'policy', routes: ['POST /api/v1/tenants/{id}/policies/evaluate'] },
          { name: 'gdpr', routes: ['POST /api/v1/gdpr/export', 'POST /api/v1/gdpr/delete'] },
          { name: 'webhook', routes: ['POST /api/v1/webhooks', 'GET /api/v1/webhooks'] },
          { name: 'jwks', routes: ['GET /.well-known/jwks.json'] },
          { name: 'viz', routes: ['GET /viz/flows'] },
        ],
        parity_doc: 'docs/parity.md',
        rust_server: { host: '192.168.1.8', port: 7072, status: 'active' },
        java_proxy: { host: '192.168.1.8', port: 7070, status: 'retired' },
      };
      return { contents: [{ uri: `${NS}://auth-routes`, mimeType: 'application/json', text: JSON.stringify(routes, null, 2) }] };
    }
  );

  // ── skill resources ──────────────────────────────────────────

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
        '  namespace: gw',
        '  locality: service',
        '  applies_when: gateway の運用操作が必要なとき',
        '  requires:',
        '    tools: [gw__list_routes, gw__list_backends, gw__reload]',
        '  min_role: OPERATOR',
        '  tags: [gateway, ops, drain, reload]',
        '---',
        '# gateway 運用手順',
        '',
        '## ルート確認',
        '`gw__list_routes` で現在のルート一覧を取得。',
        '',
        '## バックエンド健全性',
        '`gw__list_backends` で circuit breaker 状態を確認。',
        '',
        '## reload',
        '`gw__reload(confirm=false)` で dry-run → `gw__reload(confirm=true)` で実行。',
        '',
        '## drain',
        '`gw__drain(confirm=false)` で dry-run → `gw__drain(confirm=true)` で実行。',
        'healthz が 503 になるので、上流 LB/CF が新規トラフィックを止めるのを待つ。',
        '',
        '## 設定変更',
        '`gw__get_config` → `gw__patch_config(confirm=false)` で dry-run → `gw__patch_config(confirm=true)` で適用。',
      ].join('\n') }],
    })
  );

  server.resource(
    'skill-migrate-from-traefik',
    'skill://migrate-from-traefik',
    { mimeType: 'text/markdown', description: 'skill: Traefik から volta-gateway への移行手順' },
    async () => ({
      contents: [{ uri: 'skill://migrate-from-traefik', mimeType: 'text/markdown', text: [
        '---',
        'name: migrate-from-traefik',
        'description: Traefik 設定を volta-gateway に移行する手順',
        'volta:',
        '  version: 2',
        '  namespace: gw',
        '  locality: global',
        '  applies_when: Traefik 設定を volta-gateway に移行するとき',
        '  requires:',
        '    tools: [gw__convert_traefik, gw__validate_config, gw__patch_config, gw__reload]',
        '  min_role: OPERATOR',
        '  tags: [traefik, migration, gateway]',
        '---',
        '# Traefik → volta-gateway 移行手順',
        '',
        '## 1. 変換',
        '`gw__convert_traefik` に Traefik 設定（docker-compose 形式または traefik-yaml 形式）を渡す。',
        'volta-gateway 用 YAML が返る。',
        '',
        '## 2. 検証',
        '`gw__validate_config` で変換後の YAML を静的検証。',
        '',
        '## 3. 適用',
        '`gw__patch_config(confirm=false)` で dry-run → `gw__patch_config(confirm=true)` で適用。',
        '',
        '## 4. リロード',
        '`gw__reload(confirm=false)` で dry-run → `gw__reload(confirm=true)` でホットリロード。',
        '',
        '## 注意',
        '- traefik-to-volta は server.port:8080 と auth.volta_url:http://localhost:7070 を固定出力する',
        '- 実際のポートや auth-server URL は手動で修正する必要がある',
        '- 全ての Traefik middleware に対応しているわけではない',
      ].join('\n') }],
    })
  );

  server.resource(
    'skill-deploy-volta-gateway',
    'skill://deploy-volta-gateway',
    { mimeType: 'text/markdown', description: 'skill: gateway + auth-server のデプロイ手順' },
    async () => ({
      contents: [{ uri: 'skill://deploy-volta-gateway', mimeType: 'text/markdown', text: [
        '---',
        'name: deploy-volta-gateway',
        'description: gateway + auth-server のデプロイ・更新手順',
        'volta:',
        '  version: 2',
        '  namespace: gw',
        '  locality: service',
        '  applies_when: gateway をデプロイ・更新するとき',
        '  requires:',
        '    tools: [gw__reload, gw__list_routes, gw__list_backends]',
        '  min_role: OPERATOR',
        '  tags: [deploy, gateway, auth-server]',
        '---',
        '# gateway + auth-server デプロイ手順',
        '',
        '## 1. ビルド',
        '`cargo build --workspace --release`',
        '',
        '## 2. 設定検証',
        '`gw__validate_config` で設定ファイルを検証。',
        '',
        '## 3. デプロイ',
        'Docker: `docker compose up -d` または `docker stop volta-gateway && docker run ...`',
        '',
        '## 4. 確認',
        '- `gw__list_routes` でルート一覧',
        '- `gw__list_backends` でバックエンド健全性',
        '- `gw__stats` でリクエスト統計',
        '',
        '## 5. ホットリロード（設定変更のみ）',
        '`gw__reload(confirm=true)` で設定を再読み込み。',
        '',
        '## 6. グレースフルシャットダウン（プロセス更新）',
        '1. `gw__drain(confirm=true)` で drain 開始',
        '2. healthz が 503 になるのを確認',
        '3. 新プロセスを起動（reuse_port で無瞬断）',
        '4. 旧プロセスの in-flight が終わったら終了',
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

const port = Number(process.env.PORT || 9217);
serveHttp(port).catch((e) => { log('http failed', { error: String(e?.stack || e) }); process.exit(1); });
