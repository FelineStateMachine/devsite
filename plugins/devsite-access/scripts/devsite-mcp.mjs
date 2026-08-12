#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import readline from 'node:readline';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositorySkillPath = resolve(root, '../../skills/devsite-cli/SKILL.md');
const skillPath = existsSync(repositorySkillPath)
  ? repositorySkillPath
  : resolve(root, 'skills/devsite-cli/SKILL.md');
const binary = process.env.DEVSITE_BIN || 'devsite';
const protocolVersion = '2026-07-28';
const pluginManifest = JSON.parse(
  readFileSync(resolve(root, '.codex-plugin/plugin.json'), 'utf8'),
);
const serverInfo = { name: 'devsite', version: pluginManifest.version };
const serverMeta = { 'io.modelcontextprotocol/serverInfo': serverInfo };
const inFlight = new Map();
const cancelled = new Set();

const tools = [
  {
    name: 'devsite_cli',
    description: 'Run one finite devsite CLI command in JSON mode. Resident connect/daemon commands are refused; supervise those directly in the harness.',
    inputSchema: {
      type: 'object',
      properties: {
        args: { type: 'array', items: { type: 'string' }, description: 'Arguments after devsite, without --json.' },
      },
      required: ['args'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
  {
    name: 'devsite_access_request',
    description: 'Create a signed, short-lived service request and a separate private requester endpoint key. Share only the request file.',
    inputSchema: {
      type: 'object',
      properties: {
        service: { type: 'string' },
        request_path: { type: 'string' },
        key_path: { type: 'string' },
        ttl: { type: 'integer', minimum: 1, maximum: 600, default: 300 },
      },
      required: ['service', 'request_path', 'key_path'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: 'devsite_access_resolve',
    description: 'Resolve a service keyword against services this scoped broker credential may delegate.',
    inputSchema: {
      type: 'object',
      properties: { keyword: { type: 'string' } },
      required: ['keyword'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'devsite_access_grant',
    description: 'Plan or issue a short-lived endpoint-bound service grant. Set plan=true unless the exact grant is already authorized.',
    inputSchema: {
      type: 'object',
      properties: {
        request_path: { type: 'string' },
        resource_id: { type: 'string' },
        ttl: { type: 'integer', minimum: 1, maximum: 900, default: 900 },
        plan: { type: 'boolean', default: true },
        approved_plan: { type: 'string', description: 'Server-signed dsp_ token returned by the exact reviewed plan; required when plan=false.' },
      },
      required: ['request_path'],
      additionalProperties: false,
    },
    annotations: { destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
];

function commandWords(args) {
  const words = [];
  for (let index = 0; index < args.length; index += 1) {
    const word = args[index];
    if (word === '--json') continue;
    if (word === '--server') {
      index += 1;
      continue;
    }
    if (word.startsWith('--server=')) continue;
    words.push(word);
  }
  return words;
}

async function runDevsite(args, requestId) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    throw new Error('args must be an array of strings');
  }
  const words = args.filter((arg) => arg !== '--json');
  const command = commandWords(words);
  if (
    command[0] === 'connect'
    || (command[0] === 'daemon' && command[1] === 'run')
    || (command[0] === 'access' && command[1] === 'connect')
  ) {
    throw new Error('resident commands must be launched under the harness process supervisor');
  }
  if (command[0] === 'access' && command[1] === 'grant') {
    throw new Error('use devsite_access_grant so planning and approved-plan enforcement cannot be bypassed');
  }
  const result = await new Promise((resolveResult, rejectResult) => {
    const child = spawn(binary, ['--json', ...words], {
      env: process.env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const limit = 4 * 1024 * 1024;
    const timeout = setTimeout(() => child.kill(), 30000);
    inFlight.set(requestId, child);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (stdout.length > limit) child.kill();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
      if (stderr.length > limit) child.kill();
    });
    child.on('error', rejectResult);
    child.on('close', (status, signal) => {
      clearTimeout(timeout);
      inFlight.delete(requestId);
      if (cancelled.has(requestId)) {
        rejectResult(new Error('request cancelled'));
      } else if (signal) {
        rejectResult(new Error(`devsite terminated by ${signal}`));
      } else {
        resolveResult({ stdout, stderr, status });
      }
    });
  });
  const stdout = result.stdout.trim();
  if (!stdout) throw new Error(result.stderr.trim() || `devsite exited ${result.status}`);
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error(`devsite returned non-JSON output: ${stdout.slice(0, 500)}`);
  }
  return parsed;
}

async function callTool(name, input = {}, requestId) {
  switch (name) {
    case 'devsite_cli':
      return runDevsite(input.args, requestId);
    case 'devsite_access_request':
      return runDevsite([
        'access', 'request', input.service,
        '--request', input.request_path,
        '--key', input.key_path,
        '--ttl', String(input.ttl ?? 300),
      ], requestId);
    case 'devsite_access_resolve':
      return runDevsite(['access', 'resolve', input.keyword], requestId);
    case 'devsite_access_grant': {
      const args = [
        'access', 'grant', '--request', input.request_path,
        '--ttl', String(input.ttl ?? 900),
      ];
      if (input.resource_id) args.push('--resource', input.resource_id);
      if (input.plan !== false) {
        args.push('--plan');
      } else if (input.approved_plan) {
        args.push('--approved-plan', input.approved_plan);
      } else {
        throw new Error('approved_plan is required when plan=false');
      }
      return runDevsite(args, requestId);
    }
    default:
      throw new Error(`unknown tool ${name}`);
  }
}

function result(id, value) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result: value })}\n`);
}

function rpcError(id, code, message, data) {
  process.stdout.write(`${JSON.stringify({
    jsonrpc: '2.0',
    ...(typeof id === 'string' || typeof id === 'number' ? { id } : {}),
    error: { code, message, ...(data === undefined ? {} : { data }) },
  })}\n`);
}

function requestProtocol(message) {
  return message.params?._meta?.['io.modelcontextprotocol/protocolVersion'];
}

function validateModernRequest(message) {
  const requested = requestProtocol(message);
  if (typeof requested !== 'string') {
    rpcError(message.id, -32602, 'Missing per-request protocol version');
    return false;
  }
  if (requested !== protocolVersion) {
    rpcError(message.id, -32022, 'Unsupported protocol version', {
      supported: [protocolVersion],
      requested: requested ?? null,
    });
    return false;
  }
  const capabilities = message.params?._meta?.['io.modelcontextprotocol/clientCapabilities'];
  if (!capabilities || typeof capabilities !== 'object' || Array.isArray(capabilities)) {
    rpcError(message.id, -32602, 'Missing per-request client capabilities');
    return false;
  }
  return true;
}

function complete(value) {
  return { resultType: 'complete', _meta: serverMeta, ...value };
}

async function handle(message) {
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    rpcError(undefined, -32600, 'Invalid Request');
    return;
  }
  const { id, method, params = {} } = message;
  if (id === undefined) {
    if (method === 'notifications/cancelled') {
      const requestId = params.requestId;
      const child = inFlight.get(requestId);
      if (child) {
        cancelled.add(requestId);
        child.kill();
      }
    }
    return;
  }
  if (
    message.jsonrpc !== '2.0'
    || (typeof id !== 'string' && typeof id !== 'number')
    || typeof method !== 'string'
    || !params
    || typeof params !== 'object'
    || Array.isArray(params)
  ) {
    rpcError(id, -32600, 'Invalid Request');
    return;
  }
  if (!validateModernRequest(message)) return;
  try {
    switch (method) {
      case 'server/discover':
        result(id, complete({
          supportedVersions: [protocolVersion],
          capabilities: { tools: {}, resources: {} },
          serverInfo,
          instructions: 'Use the bundled devsite skill. Plan grant issuance before applying it, and never share requester endpoint keys.',
          ttlMs: 300000,
          cacheScope: 'public',
        }));
        break;
      case 'tools/list':
        result(id, complete({ tools, ttlMs: 300000, cacheScope: 'public' }));
        break;
      case 'tools/call': {
        if (!tools.some((tool) => tool.name === params.name)) {
          rpcError(id, -32602, `Unknown tool: ${params.name}`);
          break;
        }
        try {
          const value = await callTool(params.name, params.arguments, id);
          if (cancelled.delete(id)) break;
          result(id, complete({
            content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
            structuredContent: value,
            isError: value?.ok === false,
          }));
        } catch (err) {
          if (cancelled.delete(id)) break;
          result(id, complete({
            content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
            isError: true,
          }));
        }
        break;
      }
      case 'resources/list':
        result(id, complete({ resources: [
          { uri: 'devsite://skill', name: 'devsite CLI skill', mimeType: 'text/markdown' },
          { uri: 'devsite://help', name: 'installed devsite CLI help', mimeType: 'application/json' },
        ], ttlMs: 300000, cacheScope: 'public' }));
        break;
      case 'resources/read':
        if (params.uri === 'devsite://skill') {
          result(id, complete({
            contents: [{ uri: params.uri, mimeType: 'text/markdown', text: readFileSync(skillPath, 'utf8') }],
            ttlMs: 300000,
            cacheScope: 'public',
          }));
        } else if (params.uri === 'devsite://help') {
          result(id, complete({
            contents: [{ uri: params.uri, mimeType: 'application/json', text: JSON.stringify(await runDevsite(['--help'], id), null, 2) }],
            ttlMs: 60000,
            cacheScope: 'private',
          }));
        } else {
          rpcError(id, -32602, `Unknown resource: ${params.uri}`);
        }
        break;
      default:
        rpcError(id, -32601, `Method not found: ${method}`);
    }
  } catch (err) {
    rpcError(id, -32603, err instanceof Error ? err.message : String(err));
  }
}

const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) continue;
  try {
    void handle(JSON.parse(line));
  } catch (err) {
    rpcError(undefined, -32700, err instanceof Error ? err.message : String(err));
  }
}
