import { execFileSync } from 'node:child_process'
import type { GeminiCredentials } from './gemini-oauth-sources'

// Why: the `agy` (Antigravity) CLI stores its Google OAuth token in the OS
// credential store, not in a file like the Gemini CLI's oauth_creds.json. On
// Windows the entry is a Generic credential named `gemini:antigravity`; macOS
// and Linux use the platform keyring with the same identifiers. This module
// reads that entry read-only and normalizes it to the same shape the file path
// returns, so the Antigravity usage fetcher works for real `agy` users who
// never run the Gemini CLI. We never write or refresh the keyring entry — the
// `agy` CLI owns its lifecycle.
const KEYRING_SERVICE = 'gemini'
const KEYRING_ACCOUNT = 'antigravity'
const WINDOWS_TARGET = `${KEYRING_SERVICE}:${KEYRING_ACCOUNT}`
const CMD_TIMEOUT_MS = 10_000

type KeyringToken = {
  access_token?: unknown
  refresh_token?: unknown
  expiry?: unknown
  expiry_date?: unknown
}

type KeyringBlob = KeyringToken & { token?: KeyringToken }

/**
 * Normalize an expiry value to a Unix-ms timestamp. Accepts an ISO-8601 string
 * (agy's format), epoch seconds, or epoch milliseconds; returns null when the
 * value is missing or unparseable.
 */
function toMillis(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Heuristic: seconds vs milliseconds (agy stores ISO strings, but be safe).
    return value > 10_000_000_000 ? value : value * 1000
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = new Date(value).getTime()
    return Number.isNaN(parsed) ? null : parsed
  }
  return null
}

/**
 * Parse a raw keyring blob into the `GeminiCredentials` shape. Tolerates both
 * agy's nested `{ token: { … } }` layout and a flat token object; returns null
 * when the blob is not JSON or lacks a usable access token / expiry.
 */
function normalize(raw: string): GeminiCredentials | null {
  let parsed: KeyringBlob
  try {
    parsed = JSON.parse(raw) as KeyringBlob
  } catch {
    return null
  }
  // agy nests the OAuth token under `token`; tolerate a flat shape too.
  const token: KeyringToken = parsed.token ?? parsed
  const accessToken = typeof token.access_token === 'string' ? token.access_token : null
  const refreshToken = typeof token.refresh_token === 'string' ? token.refresh_token : ''
  const expiryDate = toMillis(token.expiry ?? token.expiry_date)
  if (!accessToken || expiryDate === null) {
    return null
  }
  return { access_token: accessToken, refresh_token: refreshToken, expiry_date: expiryDate }
}

/**
 * Read the `gemini:antigravity` Generic credential from the Windows Credential
 * Manager and return its raw JSON blob (or null when absent). The CredRead
 * P/Invoke script is passed via -EncodedCommand (UTF-16LE base64) so the
 * embedded C# and quotes survive shell parsing intact — mirroring the
 * established `execFileSync('powershell', …)` pattern in browser-cookie-import.
 */
function readWindowsCredential(): string | null {
  const script = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class OrcaAntigravityCred {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool CredRead(string target, int type, int flags, out IntPtr credential);
  [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr cred);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public long LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
  }
  public static byte[] Read(string target) {
    IntPtr p;
    if (!CredRead(target, 1, 0, out p)) return null;
    var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
    var b = new byte[c.CredentialBlobSize];
    Marshal.Copy(c.CredentialBlob, b, 0, c.CredentialBlobSize);
    CredFree(p);
    return b;
  }
}
'@
$bytes = [OrcaAntigravityCred]::Read('${WINDOWS_TARGET}')
if ($null -eq $bytes) { exit 1 }
$text = [System.Text.Encoding]::UTF8.GetString($bytes)
if ($text -notmatch '[{]') { $text = [System.Text.Encoding]::Unicode.GetString($bytes) }
Write-Output $text
`
  const encoded = Buffer.from(script, 'utf16le').toString('base64')
  const out = execFileSync(
    'powershell',
    ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
    { encoding: 'utf-8', timeout: CMD_TIMEOUT_MS }
  )
  return out.trim() || null
}

/**
 * Read the agy token from the macOS Keychain (best-effort). Assumes a generic
 * password stored under the same `gemini` / `antigravity` identifiers; returns
 * its raw blob or null.
 */
function readMacCredential(): string | null {
  const out = execFileSync(
    'security',
    ['find-generic-password', '-s', KEYRING_SERVICE, '-a', KEYRING_ACCOUNT, '-w'],
    { encoding: 'utf-8', timeout: CMD_TIMEOUT_MS }
  )
  return out.trim() || null
}

/**
 * Read the agy token from the Linux libsecret keyring (best-effort) via
 * `secret-tool`, matching the same service/account attributes; returns its raw
 * blob or null.
 */
function readLinuxCredential(): string | null {
  const out = execFileSync(
    'secret-tool',
    ['lookup', 'service', KEYRING_SERVICE, 'account', KEYRING_ACCOUNT],
    { encoding: 'utf-8', timeout: CMD_TIMEOUT_MS }
  )
  return out.trim() || null
}

/**
 * Read the Antigravity (`agy`) OAuth token from the OS credential store.
 * Returns null when the entry is absent, unreadable, or malformed — callers
 * fall back to the `~/.gemini/oauth_creds.json` file path. Read-only.
 */
export function readAntigravityKeyringCredentials(): GeminiCredentials | null {
  try {
    let raw: string | null
    if (process.platform === 'win32') {
      raw = readWindowsCredential()
    } else if (process.platform === 'darwin') {
      raw = readMacCredential()
    } else if (process.platform === 'linux') {
      raw = readLinuxCredential()
    } else {
      return null
    }
    return raw ? normalize(raw) : null
  } catch {
    // Missing entry (CredRead miss / non-zero exit) or no keyring tool present.
    return null
  }
}
