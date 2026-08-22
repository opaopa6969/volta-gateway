import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const PORT = 19214;
const BASE = `http://127.0.0.1:${PORT}`;

let serverProcess;

function startServer() {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, PORT: String(PORT) };
    serverProcess = execFile('node', ['server.mjs'], { env, cwd: new URL('.', import.meta.url).pathname + '../' }, (err) => {
      if (err && err.code !== null && !err.killed) reject(err);
    });
    let resolved = false;
    serverProcess.stderr.on('data', (d) => {
      if (!resolved && d.includes('http listening')) { resolved = true; resolve(); }
    });
    setTimeout(() => { if (!resolved) { resolved = true; resolve(); } }, 3000);
  });
}

describe('vgw-mcp e2e', () => {
  before(async () => {
    await startServer();
    await new Promise((r) => setTimeout(r, 500));
  });

  after(async () => {
    if (serverProcess) { serverProcess.kill('SIGTERM'); }
  });

  test('GET /healthz returns 200', async () => {
    const res = await fetch(`${BASE}/healthz`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.name, 'vgw-mcp');
    assert.ok(body.version);
  });

  test('GET /unknown returns 404', async () => {
    const res = await fetch(`${BASE}/unknown`);
    assert.equal(res.status, 404);
  });

  test('MCP tools/list returns expected tools', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.listTools();
    const names = result.tools.map((t) => t.name);
    assert.ok(names.includes('audit_search'), `missing audit_search in ${names.join(',')}`);
    assert.ok(names.includes('user_search'));
    assert.ok(names.includes('tenant_list'));
    assert.ok(names.includes('metrics'));
    assert.ok(names.includes('routes_list'));
    assert.ok(names.includes('backends_health'));
    assert.ok(names.includes('stats'));
    assert.ok(names.includes('traefik_convert'));
    await client.close();
  });

  test('traefik_convert returns error without binary', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client2', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'traefik_convert',
      arguments: { format: 'docker-compose', input: 'version: "3"\nservices: {}' },
    });
    const text = result.content[0]?.text || '';
    assert.ok(text.includes('TRAEFIK_TO_VOLTA_BIN'), `expected env error, got: ${text}`);
    await client.close();
  });

  test('vgw://spec resource is valid JSON', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client3', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'vgw://spec' });
    const text = result.contents[0]?.text;
    const spec = JSON.parse(text);
    assert.equal(spec.namespace, 'vgw');
    assert.ok(Array.isArray(spec.capabilities));
    assert.ok(spec.capabilities.length > 0);
    assert.ok(Array.isArray(spec.compositions));
    assert.ok(Array.isArray(spec.depends_on));
    await client.close();
  });

  test('vgw://guide resource is markdown', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client4', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'vgw://guide' });
    const text = result.contents[0]?.text;
    assert.ok(text.includes('# vgw MCP'), `expected guide title, got: ${text?.slice(0, 50)}`);
    await client.close();
  });

  test('skill://gateway-ops resource exists', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client5', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'skill://gateway-ops' });
    const text = result.contents[0]?.text;
    assert.ok(text.includes('name: gateway-ops'));
    assert.ok(text.includes('namespace: vgw'));
    await client.close();
  });
});
