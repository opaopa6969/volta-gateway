import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const PORT = 19217;
const BASE = `http://127.0.0.1:${PORT}`;

let serverProcess;

function startServer() {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, PORT: String(PORT), GATEWAY_URL: 'http://127.0.0.1:9999' };
    serverProcess = execFile('node', ['server.mjs'], { env, cwd: process.cwd() }, (err) => {
      if (err && err.code !== null && !err.killed) reject(err);
    });
    let resolved = false;
    serverProcess.stderr.on('data', (d) => {
      if (!resolved && d.includes('http listening')) { resolved = true; resolve(); }
    });
    setTimeout(() => { if (!resolved) { resolved = true; resolve(); } }, 3000);
  });
}

describe('gw-mcp e2e', () => {
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
    assert.equal(body.name, 'gw-mcp');
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
    const expected = [
      'list_routes', 'list_backends', 'stats', 'get_config', 'metrics',
      'patch_config', 'clear_overlay', 'reload', 'drain', 'reset_circuit',
      'validate_config', 'convert_traefik',
    ];
    for (const name of expected) {
      assert.ok(names.includes(name), `missing ${name} in ${names.join(',')}`);
    }
    await client.close();
  });

  test('list_routes returns error (gateway not running on test port)', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client2', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({ name: 'list_routes', arguments: {} });
    const text = result.content[0]?.text || '';
    assert.ok(text.includes('error'), `expected error, got: ${text}`);
    await client.close();
  });

  test('patch_config with confirm=false returns dry-run', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client3', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'patch_config',
      arguments: { patch: { server: { port: 9999 } }, confirm: false },
    });
    const text = result.content[0]?.text || '';
    const data = JSON.parse(text);
    assert.equal(data.status, 'dry-run');
    await client.close();
  });

  test('clear_overlay with confirm=false returns dry-run', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client4', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'clear_overlay',
      arguments: { confirm: false },
    });
    const text = result.content[0]?.text || '';
    const data = JSON.parse(text);
    assert.equal(data.status, 'dry-run');
    await client.close();
  });

  test('reload with confirm=false returns dry-run', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client5', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'reload',
      arguments: { confirm: false },
    });
    const text = result.content[0]?.text || '';
    const data = JSON.parse(text);
    assert.equal(data.status, 'dry-run');
    await client.close();
  });

  test('drain with confirm=false returns dry-run', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client6', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'drain',
      arguments: { confirm: false },
    });
    const text = result.content[0]?.text || '';
    const data = JSON.parse(text);
    assert.equal(data.status, 'dry-run');
    await client.close();
  });

  test('reset_circuit with confirm=false returns dry-run or error', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client7', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'reset_circuit',
      arguments: { backend_url: 'http://192.168.1.50:3000', confirm: false },
    });
    const text = result.content[0]?.text || '';
    assert.ok(text.includes('error') || text.includes('dry-run'), `expected error or dry-run, got: ${text}`);
    await client.close();
  });

  test('convert_traefik returns error without binary', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client8', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'convert_traefik',
      arguments: { format: 'docker-compose', input: 'version: "3"\nservices: {}' },
    });
    const text = result.content[0]?.text || '';
    assert.ok(text.includes('TRAEFIK_TO_VOLTA_BIN'), `expected env error, got: ${text}`);
    await client.close();
  });

  test('validate_config returns error without binary', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client9', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({
      name: 'validate_config',
      arguments: { config_path: '/dev/null' },
    });
    const text = result.content[0]?.text || '';
    assert.ok(text.includes('GATEWAY_BIN'), `expected env error, got: ${text}`);
    await client.close();
  });

  test('gw://spec resource is valid JSON', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client10', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'gw://spec' });
    const text = result.contents[0]?.text;
    const spec = JSON.parse(text);
    assert.equal(spec.namespace, 'gw');
    assert.ok(Array.isArray(spec.capabilities));
    assert.ok(spec.capabilities.length > 0);
    assert.ok(Array.isArray(spec.compositions));
    assert.ok(Array.isArray(spec.depends_on));
    await client.close();
  });

  test('gw://guide resource is markdown', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client11', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'gw://guide' });
    const text = result.contents[0]?.text;
    assert.ok(text.includes('# gw MCP'), `expected guide title, got: ${text?.slice(0, 50)}`);
    await client.close();
  });

  test('gw://config-schema resource is valid JSON', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client12', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'gw://config-schema' });
    const text = result.contents[0]?.text;
    const schema = JSON.parse(text);
    assert.ok(schema.server);
    assert.ok(schema.routing);
    await client.close();
  });

  test('gw://auth-routes resource is valid JSON', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client13', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'gw://auth-routes' });
    const text = result.contents[0]?.text;
    const routes = JSON.parse(text);
    assert.ok(Array.isArray(routes.categories));
    assert.ok(routes.categories.length > 0);
    await client.close();
  });

  test('skill://gateway-ops resource exists', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`));
    const client = new Client({ name: 'test-client14', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.readResource({ uri: 'skill://gateway-ops' });
    const text = result.contents[0]?.text;
    assert.ok(text.includes('name: gateway-ops'));
    assert.ok(text.includes('namespace: gw'));
    await client.close();
  });
});
