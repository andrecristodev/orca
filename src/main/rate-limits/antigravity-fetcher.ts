import { net } from 'electron'
import type { ProviderRateLimits, RateLimitBucket } from '../../shared/rate-limit-types'
import {
  readGeminiCredentials,
  tryRefreshTokenFromBundle,
  type GeminiCredentials
} from './gemini-oauth-sources'
import { readAntigravityKeyringCredentials } from './antigravity-keyring'
import {
  buildRateLimitBucket,
  deduplicateBuckets,
  deriveSessionSummary
} from './gemini-bucket-formatting'

// Why: Antigravity (Google's agentic coding tool, CLI `agy`) authenticates the
// same Google account the Gemini CLI uses and shares the `~/.gemini` config
// directory. Its subscription usage is served by Google's Code Assist backend
// on the same host as Gemini's, but under the ANTIGRAVITY ideType, which
// returns Antigravity's own per-model quota rather than the Gemini CLI quota.
// Phase 1 is single-account and READ-ONLY. It sources the Google OAuth token
// from, in order: (1) `~/.gemini/oauth_creds.json` (written by a Gemini CLI
// login), then (2) the OS credential store where the `agy` CLI keeps its token
// (Windows Credential Manager entry `gemini:antigravity`, macOS/Linux keyring).
// It never rewrites either source, so it can't race the Gemini provider or the
// `agy` CLI that own them.
const API_TIMEOUT_MS = 10_000
const BASE_URL = 'https://cloudcode-pa.googleapis.com'
const LOAD_CODE_ASSIST_URL = `${BASE_URL}/v1internal:loadCodeAssist`
const FETCH_AVAILABLE_MODELS_URL = `${BASE_URL}/v1internal:fetchAvailableModels`
const RETRIEVE_QUOTA_URL = `${BASE_URL}/v1internal:retrieveUserQuota`

// Why: mirrors CodexBar's AntigravityRemoteUsageFetcher metadata so the backend
// returns Antigravity quota buckets, not the Gemini CLI's.
const ANTIGRAVITY_METADATA = {
  ideType: 'ANTIGRAVITY',
  platform: 'PLATFORM_UNSPECIFIED',
  pluginType: 'GEMINI'
} as const

type ModelQuota = { remainingFraction: number; resetTime: string; modelId: string }

function unavailable(error: string): ProviderRateLimits {
  return {
    provider: 'antigravity',
    session: null,
    weekly: null,
    updatedAt: Date.now(),
    error,
    status: 'unavailable'
  }
}

function failed(error: string): ProviderRateLimits {
  return {
    provider: 'antigravity',
    session: null,
    weekly: null,
    updatedAt: Date.now(),
    error,
    status: 'error'
  }
}

async function postJson(url: string, accessToken: string, body: unknown): Promise<Response> {
  return net.fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
      // Why: the Antigravity backend keys quota off the calling client's
      // User-Agent; CodexBar sends "antigravity" and so do we.
      'User-Agent': 'antigravity'
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(API_TIMEOUT_MS)
  })
}

// Why: `cloudaicompanionProject` comes back either as a bare string or as a
// `{ value: string }` reference depending on the account's onboarding state.
function extractProjectId(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim()
  }
  if (value && typeof value === 'object' && 'value' in value) {
    const inner = (value as { value?: unknown }).value
    return typeof inner === 'string' ? inner.trim() : ''
  }
  return ''
}

async function loadProjectId(accessToken: string): Promise<string> {
  const res = await postJson(LOAD_CODE_ASSIST_URL, accessToken, { metadata: ANTIGRAVITY_METADATA })
  if (!res.ok) {
    throw new Error(`loadCodeAssist failed (HTTP ${res.status})`)
  }
  const data = (await res.json()) as { cloudaicompanionProject?: unknown }
  return extractProjectId(data.cloudaicompanionProject)
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

// Primary source: fetchAvailableModels returns a `{ models: { <id>: { quotaInfo } } }`
// map, which is Antigravity's live per-model quota view.
function parseModelQuotas(data: unknown): ModelQuota[] {
  if (!data || typeof data !== 'object' || !('models' in data)) {
    return []
  }
  const models = (data as { models?: Record<string, unknown> }).models
  if (!models || typeof models !== 'object') {
    return []
  }
  const quotas: ModelQuota[] = []
  for (const [modelId, model] of Object.entries(models)) {
    if (!model || typeof model !== 'object' || !('quotaInfo' in model)) {
      continue
    }
    const quotaInfo = (model as { quotaInfo?: unknown }).quotaInfo
    if (!quotaInfo || typeof quotaInfo !== 'object') {
      continue
    }
    const { remainingFraction, resetTime } = quotaInfo as {
      remainingFraction?: unknown
      resetTime?: unknown
    }
    if (isFiniteNumber(remainingFraction) && typeof resetTime === 'string') {
      quotas.push({ remainingFraction, resetTime, modelId })
    }
  }
  return quotas
}

// Fallback source: retrieveUserQuota returns a `{ buckets: [...] }` array.
function parseQuotaBuckets(data: unknown): ModelQuota[] {
  let rawBuckets: unknown[] = []
  if (data && typeof data === 'object' && 'buckets' in data && Array.isArray(data.buckets)) {
    rawBuckets = data.buckets
  }
  const quotas: ModelQuota[] = []
  for (const bucket of rawBuckets) {
    if (!bucket || typeof bucket !== 'object') {
      continue
    }
    const { remainingFraction, resetTime, modelId } = bucket as {
      remainingFraction?: unknown
      resetTime?: unknown
      modelId?: unknown
    }
    if (isFiniteNumber(remainingFraction) && typeof resetTime === 'string') {
      quotas.push({
        remainingFraction,
        resetTime,
        modelId: typeof modelId === 'string' ? modelId : 'unknown'
      })
    }
  }
  return quotas
}

async function fetchModelQuotas(accessToken: string, projectId: string): Promise<ModelQuota[]> {
  const body = projectId ? { project: projectId } : {}
  const modelsRes = await postJson(FETCH_AVAILABLE_MODELS_URL, accessToken, body)
  if (modelsRes.status === 401) {
    throw new UnauthorizedError()
  }
  if (modelsRes.ok) {
    const quotas = parseModelQuotas(await modelsRes.json())
    if (quotas.length > 0) {
      return quotas
    }
  }
  // Fall back to retrieveUserQuota when fetchAvailableModels is empty or errors.
  const quotaRes = await postJson(RETRIEVE_QUOTA_URL, accessToken, body)
  if (quotaRes.status === 401) {
    throw new UnauthorizedError()
  }
  if (!quotaRes.ok) {
    throw new Error(`Quota fetch failed (HTTP ${quotaRes.status})`)
  }
  return parseQuotaBuckets(await quotaRes.json())
}

class UnauthorizedError extends Error {
  constructor() {
    super('Antigravity request unauthorized (HTTP 401)')
    this.name = 'UnauthorizedError'
  }
}

function toRateLimits(quotas: ModelQuota[]): ProviderRateLimits {
  const buckets: RateLimitBucket[] = deduplicateBuckets(
    quotas.map((q) => ({ ...buildRateLimitBucket(q), modelId: q.modelId }))
  )
  if (buckets.length === 0) {
    return failed('Antigravity quota response did not include any model buckets')
  }
  return {
    provider: 'antigravity',
    session: deriveSessionSummary(buckets),
    weekly: null,
    buckets,
    updatedAt: Date.now(),
    error: null,
    status: 'ok'
  }
}

async function resolveAccessToken(creds: GeminiCredentials): Promise<string | null> {
  if (creds.expiry_date >= Date.now() && creds.access_token) {
    return creds.access_token
  }
  // Why: read-only refresh — reuse the Gemini CLI's OAuth client (same Google
  // account, same `~/.gemini` creds) to mint a fresh access token in memory.
  // We deliberately do NOT persist it: the Gemini provider owns that file, and
  // Google refresh tokens are reusable, so an in-memory token is sufficient.
  const refreshed = await tryRefreshTokenFromBundle(creds.refresh_token, true)
  return refreshed?.accessToken ?? null
}

/**
 * Read-only, single-account Antigravity subscription usage.
 *
 * Reads the Google OAuth token at `~/.gemini/oauth_creds.json` (written by a
 * Gemini/Google login on this host — the `agy` CLI keeps its own token in the
 * OS keyring, with no readable file), resolves the Code Assist project under
 * the ANTIGRAVITY ideType, and reports Antigravity's per-model quota. Never
 * writes the credentials file.
 */
export async function fetchAntigravityRateLimits(): Promise<ProviderRateLimits> {
  let creds: GeminiCredentials | null
  try {
    // File first (Gemini CLI login), then the OS keyring where `agy` stores its
    // token — most Antigravity users only have the latter.
    creds = (await readGeminiCredentials()) ?? readAntigravityKeyringCredentials()
  } catch (err) {
    return failed(err instanceof Error ? err.message : 'Unable to read Antigravity credentials')
  }
  if (!creds) {
    return unavailable(
      'Not signed in to Antigravity (no ~/.gemini credentials or agy keyring token)'
    )
  }

  try {
    const accessToken = await resolveAccessToken(creds)
    if (!accessToken) {
      return failed('Antigravity token expired — sign in again to refresh')
    }
    const projectId = await loadProjectId(accessToken).catch(() => '')
    try {
      return toRateLimits(await fetchModelQuotas(accessToken, projectId))
    } catch (err) {
      if (!(err instanceof UnauthorizedError)) {
        throw err
      }
      // One refresh + retry on 401, mirroring the Gemini fetcher.
      const refreshed = await tryRefreshTokenFromBundle(creds.refresh_token, true)
      if (!refreshed?.accessToken) {
        return failed('Antigravity request unauthorized and token refresh failed')
      }
      const retryProjectId = await loadProjectId(refreshed.accessToken).catch(() => projectId)
      return toRateLimits(await fetchModelQuotas(refreshed.accessToken, retryProjectId))
    }
  } catch (err) {
    return failed(err instanceof Error ? err.message : 'Antigravity usage request failed')
  }
}
