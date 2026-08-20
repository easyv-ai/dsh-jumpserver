import assert from 'node:assert/strict'
import test from 'node:test'
import { createHmac } from 'node:crypto'
import { apply, Config, internals, SETTINGS_NAMESPACE } from '../index.js'

function execution() {
  return { signal: new AbortController().signal }
}

function createContext({ baseUrl = 'https://jumpserver.example.com', ak = 'test-ak', sk = 'test-sk' } = {}) {
  const tools = []
  const sections = []
  const ctx = {
    credentials: {
      async resolve(ref) {
        if (ref === 'JUMPSERVER_ACCESS_KEY_ID') return ak ? { value: ak } : undefined
        if (ref === 'JUMPSERVER_ACCESS_KEY_SECRET') return sk ? { value: sk } : undefined
        return undefined
      },
    },
    // 无 settings 服务时注入回调不会执行（与真实 cordis 行为一致）。
    inject() {},
    systemPrompt: {
      section(section) { sections.push(section) },
    },
    tools: {
      register(tool) { tools.push(tool); return () => {} },
    },
  }
  apply(ctx, { baseUrl })
  return { sections, tools }
}

function toolByName(tools, name) {
  const tool = tools.find((candidate) => candidate.name === name)
  assert.ok(tool, `missing tool ${name}`)
  return tool
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

test('normalizeBaseUrl allows HTTP out of the box and can enforce HTTPS only', () => {
  assert.equal(internals.normalizeBaseUrl('https://jumpserver.example.com/'), 'https://jumpserver.example.com')
  assert.equal(internals.normalizeBaseUrl('http://127.0.0.1:8080/'), 'http://127.0.0.1:8080')
  assert.equal(internals.normalizeBaseUrl('http://jumpserver.internal/'), 'http://jumpserver.internal')
  assert.equal(internals.normalizeBaseUrl('http://jumpserver.internal/', true), 'http://jumpserver.internal')
  assert.throws(() => internals.normalizeBaseUrl('http://jumpserver.internal/', false), /Plain HTTP is disabled/)
  assert.throws(() => internals.normalizeBaseUrl('https://user:pass@jumpserver.example.com'), /embedded credentials/)
  assert.throws(() => internals.normalizeBaseUrl('https://jumpserver.example.com?target=x'), /query string or fragment/)
  assert.throws(() => internals.normalizeBaseUrl(''), /not configured/)
})

test('readLimitedText rejects oversized responses', async () => {
  await assert.rejects(
    internals.readLimitedText(new Response('123456'), 4),
    /exceeds the 4-byte limit/,
  )
})

test('safeApiErrorDetail exposes only bounded status/detail/message fields', () => {
  const detail = internals.safeApiErrorDetail(JSON.stringify({
    detail: 'invalid signature',
    code: 'auth_failed',
    secret: 'must-not-leak',
  }))
  assert.equal(detail, 'invalid signature: auth_failed')
})

test('clampInt clamps to bounds and falls back on invalid input', () => {
  assert.equal(internals.clampInt('50', 20, 1, 100), 50)
  assert.equal(internals.clampInt('500', 20, 1, 100), 100)
  assert.equal(internals.clampInt('-5', 20, 0, 100), 0)
  assert.equal(internals.clampInt('not-a-number', 20, 1, 100), 20)
  assert.equal(internals.clampInt(undefined, 20, 1, 100), 20)
})

test('buildSignatureHeader produces a draft-cavage hmac-sha256 signature over (request-target) accept date', () => {
  const headers = { accept: 'application/json', date: 'Wed, 20 Aug 2026 09:00:00 GMT' }
  const header = internals.buildSignatureHeader({
    keyId: 'AK123',
    secret: 'SK456',
    method: 'GET',
    path: '/api/v1/assets/assets/?limit=20&offset=0',
    headers,
  })
  const expectedSigningString = [
    '(request-target): get /api/v1/assets/assets/?limit=20&offset=0',
    'accept: application/json',
    'date: Wed, 20 Aug 2026 09:00:00 GMT',
  ].join('\n')
  const expectedSignature = createHmac('sha256', 'SK456').update(expectedSigningString, 'utf8').digest('base64')
  assert.equal(
    header,
    `Signature keyId="AK123",algorithm="hmac-sha256",headers="(request-target) accept date",signature="${expectedSignature}"`,
  )
})

test('gmtNow returns an RFC 1123 / GMT formatted date string', () => {
  assert.match(internals.gmtNow(), /^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/)
})

test('apply registers all read-only tools and a system prompt section', () => {
  const { sections, tools } = createContext()
  assert.deepEqual(tools.map((tool) => tool.name), [
    'jumpserver_list_assets',
    'jumpserver_get_asset',
    'jumpserver_list_users',
    'jumpserver_get_user',
    'jumpserver_list_accounts',
    'jumpserver_get_account',
    'jumpserver_list_permissions',
    'jumpserver_list_sessions',
  ])
  assert.equal(sections.length, 1)
  assert.equal(sections[0].name, 'tool:jumpserver')
})

test('jumpserver_list_assets sends a signed GET request and formats results', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init })
    return jsonResponse({
      count: 1,
      next: null,
      previous: null,
      results: [
        { id: 'uuid-1', name: 'web-01', address: '10.0.0.1', platform: 'Linux', category: { value: 'host', label: '主机' }, type: { value: 'linux', label: 'Linux' }, is_active: true },
      ],
    })
  }
  try {
    const { tools } = createContext()
    const list = toolByName(tools, 'jumpserver_list_assets')
    const output = await list.execute({ search: 'web' }, execution())
    assert.match(output, /count=1/)
    assert.match(output, /name="web-01"/)
    assert.match(output, /address="10\.0\.0\.1"/)
    assert.equal(calls.length, 1)
    const requestUrl = new URL(calls[0].url)
    assert.equal(requestUrl.origin, 'https://jumpserver.example.com')
    assert.equal(requestUrl.pathname, '/api/v1/assets/assets/')
    assert.equal(requestUrl.searchParams.get('search'), 'web')
    assert.equal(requestUrl.searchParams.get('limit'), '20')
    assert.equal(requestUrl.searchParams.get('offset'), '0')
    assert.equal(calls[0].init.redirect, 'error')
    assert.match(calls[0].init.headers.Authorization, /^Signature keyId="test-ak",algorithm="hmac-sha256",headers="\(request-target\) accept date",signature="[^"]+"$/)
    assert.ok(calls[0].init.headers.Date)
    assert.equal(calls[0].init.headers.Accept, 'application/json')
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_list_assets clamps limit/offset and omits empty search', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(String(url))
    return jsonResponse({ count: 0, results: [] })
  }
  try {
    const { tools } = createContext()
    const list = toolByName(tools, 'jumpserver_list_assets')
    const output = await list.execute({ limit: 1000, offset: -5 }, execution())
    assert.equal(output, '(no results found)')
    const requestUrl = new URL(calls[0])
    assert.equal(requestUrl.searchParams.get('limit'), '100')
    assert.equal(requestUrl.searchParams.get('offset'), '0')
    assert.equal(requestUrl.searchParams.has('search'), false)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_list_assets surfaces bounded API error details on non-2xx responses', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => jsonResponse({ detail: 'Invalid signature.' }, 401)
  try {
    const { tools } = createContext()
    const list = toolByName(tools, 'jumpserver_list_assets')
    await assert.rejects(list.execute({}, execution()), /401.*Invalid signature/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_list_assets fails clearly when AccessKey credentials are missing', async () => {
  const { tools } = createContext({ ak: '', sk: '' })
  const list = toolByName(tools, 'jumpserver_list_assets')
  await assert.rejects(list.execute({}, execution()), /JUMPSERVER_ACCESS_KEY_ID.*not configured/)
})

test('requireId accepts JumpServer UUIDs and rejects anything else (path injection guard)', () => {
  assert.equal(internals.requireId('123e4567-e89b-12d3-a456-426614174000', 'id'), '123e4567-e89b-12d3-a456-426614174000')
  assert.throws(() => internals.requireId('../assets/other-id', 'id'), /must be a valid JumpServer UUID/)
  assert.throws(() => internals.requireId('not-a-uuid', 'id'), /must be a valid JumpServer UUID/)
  assert.throws(() => internals.requireId('', 'id'), /must be a valid JumpServer UUID/)
})

test('jumpserver_get_asset fetches a single asset by id and rejects malformed ids', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(String(url))
    return jsonResponse({
      id: '123e4567-e89b-12d3-a456-426614174000',
      name: 'web-01',
      address: '10.0.0.1',
      platform: 'Linux',
      category: { label: '主机' },
      type: { label: 'Linux' },
      domain: null,
      protocols: [{ name: 'ssh', port: 22 }],
      is_active: true,
      comment: '',
    })
  }
  try {
    const { tools } = createContext()
    const get = toolByName(tools, 'jumpserver_get_asset')
    const output = await get.execute({ id: '123e4567-e89b-12d3-a456-426614174000' }, execution())
    assert.match(output, /name="web-01"/)
    assert.match(output, /protocols="ssh:22"/)
    const requestUrl = new URL(calls[0])
    assert.equal(requestUrl.pathname, '/api/v1/assets/assets/123e4567-e89b-12d3-a456-426614174000/')
    await assert.rejects(get.execute({ id: '../etc/passwd' }, execution()), /valid JumpServer UUID/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_list_users never surfaces password, public_key, or MFA secret fields', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => jsonResponse({
    count: 1,
    results: [{
      id: 'u1', username: 'alice', name: 'Alice', email: 'alice@example.com',
      is_active: true, is_superuser: false, source: 'local',
      password: 'must-not-leak', public_key: 'ssh-rsa MUST-NOT-LEAK',
    }],
  })
  try {
    const { tools } = createContext()
    const output = await toolByName(tools, 'jumpserver_list_users').execute({}, execution())
    assert.match(output, /username="alice"/)
    assert.doesNotMatch(output, /must-not-leak/)
    assert.doesNotMatch(output, /password/)
    assert.doesNotMatch(output, /public_key/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_get_user never surfaces password, public_key, or MFA secret fields', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => jsonResponse({
    id: 'u1', username: 'alice', name: 'Alice', email: 'alice@example.com',
    phone: '', source: 'local', is_active: true, is_superuser: false, is_org_admin: false,
    mfa_enabled: false, is_valid: true, is_expired: false, last_login: null, comment: '',
    password: 'must-not-leak', public_key: 'ssh-rsa MUST-NOT-LEAK',
  })
  try {
    const { tools } = createContext()
    const output = await toolByName(tools, 'jumpserver_get_user').execute({ id: '123e4567-e89b-12d3-a456-426614174000' }, execution())
    assert.match(output, /username="alice"/)
    assert.doesNotMatch(output, /must-not-leak/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_list_accounts never surfaces secret or passphrase fields, and validates asset filter', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(String(url))
    return jsonResponse({
      count: 1,
      results: [{
        id: 'a1', name: 'root account', username: 'root', asset: 'asset-1',
        secret_type: 'password', privileged: true, is_active: true, source: 'local',
        secret: 'must-not-leak', passphrase: 'must-not-leak-either',
      }],
    })
  }
  try {
    const { tools } = createContext()
    const list = toolByName(tools, 'jumpserver_list_accounts')
    const output = await list.execute({ asset: '123e4567-e89b-12d3-a456-426614174000' }, execution())
    assert.match(output, /username="root"/)
    assert.doesNotMatch(output, /must-not-leak/)
    assert.doesNotMatch(output, /secret=/)
    assert.doesNotMatch(output, /passphrase/)
    const requestUrl = new URL(calls[0])
    assert.equal(requestUrl.searchParams.get('asset'), '123e4567-e89b-12d3-a456-426614174000')
    await assert.rejects(list.execute({ asset: 'not-a-uuid' }, execution()), /valid JumpServer UUID/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_get_account never surfaces the secret or passphrase field', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => jsonResponse({
    id: 'a1', name: 'root account', username: 'root', asset: 'asset-1',
    secret_type: 'password', privileged: true, is_active: true, source: 'local',
    connectivity: 'ok', comment: '',
    secret: 'must-not-leak', passphrase: 'must-not-leak-either',
  })
  try {
    const { tools } = createContext()
    const output = await toolByName(tools, 'jumpserver_get_account').execute({ id: '123e4567-e89b-12d3-a456-426614174000' }, execution())
    assert.match(output, /username="root"/)
    assert.doesNotMatch(output, /must-not-leak/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_list_permissions validates userId/assetId filters and formats rows', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(String(url))
    return jsonResponse({ count: 1, results: [{ id: 'p1', name: 'dev-access', is_active: true, is_valid: true, is_expired: false }] })
  }
  try {
    const { tools } = createContext()
    const list = toolByName(tools, 'jumpserver_list_permissions')
    const output = await list.execute({ userId: '123e4567-e89b-12d3-a456-426614174000' }, execution())
    assert.match(output, /name="dev-access"/)
    const requestUrl = new URL(calls[0])
    assert.equal(requestUrl.searchParams.get('user_id'), '123e4567-e89b-12d3-a456-426614174000')
    await assert.rejects(list.execute({ assetId: 'bad' }, execution()), /valid JumpServer UUID/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('jumpserver_list_sessions filters by user/asset/isFinished and formats rows', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(String(url))
    return jsonResponse({ count: 1, results: [{ id: 's1', user: 'alice', asset: 'web-01', account: 'root', protocol: 'ssh', is_success: true, is_finished: true }] })
  }
  try {
    const { tools } = createContext()
    const list = toolByName(tools, 'jumpserver_list_sessions')
    const output = await list.execute({ user: 'alice', isFinished: true }, execution())
    assert.match(output, /user="alice"/)
    const requestUrl = new URL(calls[0])
    assert.equal(requestUrl.searchParams.get('user'), 'alice')
    assert.equal(requestUrl.searchParams.get('is_finished'), 'true')
  } finally {
    globalThis.fetch = originalFetch
  }
})

function createSettingsContext(userSection = {}) {
  const tools = []
  let section = { ...userSection }
  const registrations = []
  const ctx = {
    credentials: {
      async resolve(ref) {
        if (ref === 'JUMPSERVER_ACCESS_KEY_ID') return { value: 'test-ak' }
        if (ref === 'JUMPSERVER_ACCESS_KEY_SECRET') return { value: 'test-sk' }
        return undefined
      },
    },
    inject(services, callback) {
      if (!services.includes('settings')) return
      callback({
        ...ctx,
        effect(setup) { setup() },
        settings: {
          register(ns, schema, options = {}) {
            const scope = {
              get: () => schema({ ...options.base, ...section }),
              async update(patch) { section = { ...section, ...patch } },
            }
            options.validate?.(scope.get())
            registrations.push({ ns, options, scope })
            return scope
          },
        },
      })
    },
    systemPrompt: { section() {} },
    tools: {
      register(tool) { tools.push(tool); return () => {} },
    },
  }
  apply(ctx, {})
  return { registrations, tools }
}

test('apply registers a jumpserver settings namespace and resolves baseUrl through it', async () => {
  const { registrations, tools } = createSettingsContext({ baseUrl: 'https://jumpserver.internal' })
  assert.equal(registrations.length, 1)
  const [{ ns, options, scope }] = registrations
  assert.equal(ns, SETTINGS_NAMESPACE)
  assert.equal(typeof options.validate, 'function')
  assert.throws(() => options.validate({ ...scope.get(), akRef: 'bad ref' }), /Invalid AccessKeyID credential reference/)

  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(String(url))
    return jsonResponse({ count: 0, results: [] })
  }
  try {
    await toolByName(tools, 'jumpserver_list_assets').execute({}, execution())
  } finally {
    globalThis.fetch = originalFetch
  }
  assert.equal(new URL(calls[0]).origin, 'https://jumpserver.internal')
})

test('Config schema exposes documented defaults', () => {
  const config = Config({})
  assert.equal(config.baseUrl, '')
  assert.equal(config.akRef, 'JUMPSERVER_ACCESS_KEY_ID')
  assert.equal(config.skRef, 'JUMPSERVER_ACCESS_KEY_SECRET')
  assert.equal(config.allowInsecureHttp, true)
})
