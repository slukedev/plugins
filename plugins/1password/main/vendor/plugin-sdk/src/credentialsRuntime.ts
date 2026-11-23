import { PluginError, errorMessage, type Transport } from "./rpc";
import { PLUGIN_PROTOCOL } from "./protocol";
import { disposable, type CancelSignal } from "./types";
import {
  CREDENTIALS_PROTOCOL,
  CREDENTIALS_SDK_VERSION,
  CREDENTIAL_CALL_KIND,
  CREDENTIAL_HANDLERS,
  CREDENTIAL_LIMITS,
  type Cli,
  type CredentialContext,
  type CredentialErrorCode,
  type CredentialHandler,
  type CredentialHandlerName,
  type CredentialProvider,
  type FailureState,
  type ItemPage,
  type JsonRecord,
  type ListRequest,
  type ListedItem,
  type ProblemCode,
  type RunHints,
  type RunningVerb,
  type SecretHandle,
  type SessionStore,
  type SignInNeed,
  type SignInOutcome,
  type SignInRunState,
  type StreamLine,
  type TotpSecret,
  type ValueStore,
  type VerbOptions,
  type VerbParams,
  type VerbResult,
  type WireCredentialError,
} from "./credentials";

type ErrorOptions = { problem?: ProblemCode; detail?: string; state?: FailureState; field?: string };

export class CredentialError extends PluginError {
  readonly code: CredentialErrorCode;
  readonly problem: ProblemCode | undefined;
  readonly detail: string | undefined;
  readonly state: FailureState | undefined;
  readonly field: string | undefined;

  private constructor(code: CredentialErrorCode, options: ErrorOptions = {}) {
    super(code, options.detail ?? options.problem ?? code);
    this.name = "CredentialError";
    this.code = code;
    this.problem = options.problem;
    this.detail = options.detail;
    this.state = options.state;
    this.field = options.field;
  }

  static locked(): CredentialError {
    return new CredentialError("locked");
  }

  static signedOut(): CredentialError {
    return new CredentialError("signedOut");
  }

  static notFound(): CredentialError {
    return new CredentialError("notFound");
  }

  static unsupported(): CredentialError {
    return new CredentialError("unsupported");
  }

  static failed(problem: ProblemCode, options: { detail?: string; state?: FailureState; field?: string } = {}): CredentialError {
    return new CredentialError("failed", { ...options, problem });
  }

  static is(error: unknown, code?: CredentialErrorCode): error is CredentialError {
    return error instanceof CredentialError && (code === undefined || error.code === code);
  }

  toWire(): WireCredentialError {
    return withoutUndefined({ code: this.code, problem: this.problem, detail: this.detail, state: this.state, field: this.field }) as WireCredentialError;
  }
}

function withoutUndefined<T extends Record<string, unknown>>(record: T): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) if (value !== undefined) out[key] = value;
  return out as Partial<T>;
}

export const SignIn = {
  done(options: { session?: SecretHandle } = {}): SignInOutcome {
    return options.session ? { ok: true, session: options.session } : { ok: true };
  },
  needs(need: SignInNeed, options: { problem?: ProblemCode; detail?: string; state?: FailureState } = {}): SignInOutcome {
    return { ok: false, need, ...withoutUndefined(options) };
  },
  failed(problem: ProblemCode, options: { detail?: string; state?: FailureState; field?: string } = {}): SignInOutcome {
    return { ok: false, problem, ...withoutUndefined(options) };
  },
  cancelled(state?: FailureState): SignInOutcome {
    return state ? { ok: false, problem: "cancelled", state } : { ok: false, problem: "cancelled" };
  },
};

const SECRET_HANDLE = /^h[1-9][0-9]{0,15}$/;

export function isSecretHandle(value: unknown): value is SecretHandle {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  const handle = (value as { $secret?: unknown }).$secret;
  return keys.length === 1 && typeof handle === "string" && SECRET_HANDLE.test(handle);
}

const UNREACHABLE_HINTS: readonly string[] = [
  "getaddrinfo",
  "enotfound",
  "econnrefused",
  "econnreset",
  "etimedout",
  "ehostunreach",
  "enetunreach",
  "fetch failed",
  "network error",
  "unable to connect",
  "could not resolve host",
  "no such host",
  "certificate",
];

const OUTDATED_HINTS: readonly string[] = ["unknown option", "unknown command", "unrecognized option", "unexpected argument", "please update"];

const ESCAPE_CODES = /\x1B\[[0-9;?]*[A-Za-z]/g;
const LOG_PREFIX = /^\[[A-Za-z]+\]\s+\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+/;

function mentions(result: Pick<VerbResult, "stderr">, needles: readonly string[]): boolean {
  const haystack = result.stderr.toLowerCase();
  return needles.some((needle) => haystack.includes(needle.toLowerCase()));
}

function problemOf(result: VerbResult, offline: boolean): ProblemCode {
  if (result.cancelled) return "cancelled";
  if (!result.launched) return "notLaunched";
  if (result.timedOut) return "timedOut";
  if (result.overflowed) return "overflowed";
  if (mentions(result, UNREACHABLE_HINTS)) return offline ? "offline" : "unreachable";
  if (mentions(result, OUTDATED_HINTS)) return "outdated";
  return "failed";
}

function firstLineOf(text: string): string | null {
  for (const raw of text.replace(ESCAPE_CODES, "").split(/\r?\n/)) {
    let line = raw.trim().replace(LOG_PREFIX, "");
    if (line.toLowerCase().startsWith("error:")) line = line.slice("error:".length).trim();
    if (line) return line;
  }
  return null;
}

export const verbs = {
  mentions,
  problem: problemOf,
  check(result: VerbResult, hints: RunHints, offline: boolean): void {
    if (result.succeeded) return;
    if (!result.cancelled && !result.timedOut && result.launched) {
      if (hints.locked && mentions(result, hints.locked)) throw CredentialError.locked();
      if (hints.signedOut && mentions(result, hints.signedOut)) throw CredentialError.signedOut();
      if (hints.notFound && mentions(result, hints.notFound)) throw CredentialError.notFound();
    }
    const problem = problemOf(result, offline);
    const detail = problem === "failed" ? firstLineOf(result.stderr) : null;
    throw CredentialError.failed(problem, detail ? { detail } : {});
  },
  firstLine(result: VerbResult): string | null {
    return firstLineOf(result.lines.join("\n"));
  },
  unreachableHints: UNREACHABLE_HINTS,
  outdatedHints: OUTDATED_HINTS,
};

const isRecord = (value: unknown): value is JsonRecord => typeof value === "object" && value !== null && !Array.isArray(value);

function jsonString(value: unknown): string | undefined {
  if (typeof value === "string") return value === "" ? undefined : value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function jsonList(value: unknown): JsonRecord[] {
  if (!Array.isArray(value)) throw CredentialError.failed("unreadable");
  return value.filter(isRecord);
}

export const json = {
  record(value: unknown): JsonRecord {
    if (!isRecord(value)) throw CredentialError.failed("unreadable");
    return value;
  },
  list: jsonList,
  listAt(value: unknown, key: string): JsonRecord[] {
    return jsonList(json.record(value)[key]);
  },
  dict(value: unknown): JsonRecord | undefined {
    return isRecord(value) ? value : undefined;
  },
  dicts(value: unknown): JsonRecord[] {
    return Array.isArray(value) ? value.filter(isRecord) : [];
  },
  string: jsonString,
  strings(value: unknown): string[] {
    return Array.isArray(value) ? value.flatMap((entry) => jsonString(entry) ?? []) : [];
  },
  int(value: unknown): number | undefined {
    if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
    if (typeof value === "string" && /^[+-]?\d{1,15}$/.test(value)) return Number.parseInt(value, 10);
    return undefined;
  },
  bool(value: unknown): boolean | undefined {
    if (typeof value === "boolean") return value;
    if (typeof value === "number" && Number.isFinite(value)) return value !== 0;
    return undefined;
  },
  milliseconds(value: unknown): number | undefined {
    if (typeof value === "number") {
      if (!Number.isFinite(value) || value <= 0) return undefined;
      return value > 100_000_000_000 ? value : value * 1000;
    }
    if (typeof value !== "string" || value === "") return undefined;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? Math.round(parsed) : undefined;
  },
};

const URL_SHAPE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)/;

function authorityHost(url: string): { scheme: string; host: string; userinfo: boolean } | undefined {
  const match = URL_SHAPE.exec(url.trim());
  if (!match) return undefined;
  const scheme = match[1]!.toLowerCase();
  let authority = match[2]!;
  const at = authority.lastIndexOf("@");
  const userinfo = at >= 0;
  if (userinfo) authority = authority.slice(at + 1);
  let host: string;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) return undefined;
    host = authority.slice(0, end + 1);
  } else {
    const colon = authority.indexOf(":");
    host = colon >= 0 ? authority.slice(0, colon) : authority;
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (!host || /[\s\\%]/.test(host)) return undefined;
  return { scheme, host, userinfo };
}

export const origins = {
  host(url: string): string | undefined {
    return authorityHost(url)?.host;
  },
  isLocalHost(host: string): boolean {
    const plain = host.toLowerCase();
    return plain === "localhost" || plain.endsWith(".localhost") || plain === "::1" || plain === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(plain);
  },
  isWebOrigin(url: string): boolean {
    const parsed = authorityHost(url);
    return !!parsed && (parsed.scheme === "http" || parsed.scheme === "https") && !parsed.userinfo;
  },
  hostIn(url: string, allowed: readonly string[]): boolean {
    const host = authorityHost(url)?.host;
    if (!host) return false;
    return allowed.some((entry) => {
      const plain = entry.toLowerCase();
      return host === plain || host.endsWith(`.${plain}`);
    });
  },
};

export function utf8Bytes(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i++;
      }
    }
    if (code < 0x80) out.push(code);
    else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 63));
    else if (code < 0x10000) out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    else out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
  }
  return Uint8Array.from(out);
}

export function utf8Length(text: string): number {
  let length = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) length += 1;
    else if (code < 0x800) length += 2;
    else if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      length += 4;
      i++;
    } else length += 3;
  }
  return length;
}

function isqrt(n: bigint): bigint {
  if (n < 2n) return n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}

function icbrt(n: bigint): bigint {
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(n.toString(2).length / 3));
  for (;;) {
    const y = (2n * x + n / (x * x)) / 3n;
    if (y >= x) break;
    x = y;
  }
  while ((x + 1n) ** 3n <= n) x += 1n;
  while (x ** 3n > n) x -= 1n;
  return x;
}

function firstPrimes(count: number): bigint[] {
  const primes: bigint[] = [];
  for (let candidate = 2; primes.length < count; candidate++) {
    if (primes.every((p) => candidate % Number(p) !== 0)) primes.push(BigInt(candidate));
  }
  return primes;
}

const MASK64 = (1n << 64n) - 1n;

let roundConstants: { k512: bigint[]; h512: bigint[]; k256: Uint32Array; h256: Uint32Array } | null = null;

function constants() {
  if (roundConstants) return roundConstants;
  const primes = firstPrimes(80);
  const k512 = primes.map((p) => icbrt(p << 192n) & MASK64);
  const h512 = primes.slice(0, 8).map((p) => isqrt(p << 128n) & MASK64);
  const k256 = Uint32Array.from(k512.slice(0, 64).map((k) => Number(k >> 32n)));
  const h256 = Uint32Array.from(h512.map((h) => Number(h >> 32n)));
  roundConstants = { k512, h512, k256, h256 };
  return roundConstants;
}

function padded(bytes: Uint8Array, block: number, lengthBytes: number): Uint8Array {
  const total = Math.ceil((bytes.length + 1 + lengthBytes) / block) * block;
  const out = new Uint8Array(total);
  out.set(bytes);
  out[bytes.length] = 0x80;
  let bits = BigInt(bytes.length) * 8n;
  for (let i = total - 1; i >= total - lengthBytes && bits > 0n; i--) {
    out[i] = Number(bits & 0xffn);
    bits >>= 8n;
  }
  return out;
}

const rotl = (x: number, n: number) => ((x << n) | (x >>> (32 - n))) >>> 0;
const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;

function sha1(bytes: Uint8Array): Uint8Array {
  const m = padded(bytes, 64, 8);
  const h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  const w = new Uint32Array(80);
  for (let offset = 0; offset < m.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = ((m[offset + 4 * i]! << 24) | (m[offset + 4 * i + 1]! << 16) | (m[offset + 4 * i + 2]! << 8) | m[offset + 4 * i + 3]!) >>> 0;
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3]! ^ w[i - 8]! ^ w[i - 14]! ^ w[i - 16]!, 1);
    let [a, b, c, d, e] = h as [number, number, number, number, number];
    for (let i = 0; i < 80; i++) {
      const [f, k] = i < 20 ? [(b & c) | (~b & d), 0x5a827999] : i < 40 ? [b ^ c ^ d, 0x6ed9eba1] : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6];
      const t = (rotl(a, 5) + (f >>> 0) + e + k + w[i]!) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = t;
    }
    h[0] = (h[0]! + a) >>> 0;
    h[1] = (h[1]! + b) >>> 0;
    h[2] = (h[2]! + c) >>> 0;
    h[3] = (h[3]! + d) >>> 0;
    h[4] = (h[4]! + e) >>> 0;
  }
  return wordsToBytes(h);
}

function wordsToBytes(words: ArrayLike<number>): Uint8Array {
  const out = new Uint8Array(words.length * 4);
  for (let i = 0; i < words.length; i++) {
    const word = words[i]!;
    out[4 * i] = word >>> 24;
    out[4 * i + 1] = (word >>> 16) & 0xff;
    out[4 * i + 2] = (word >>> 8) & 0xff;
    out[4 * i + 3] = word & 0xff;
  }
  return out;
}

function sha256(bytes: Uint8Array): Uint8Array {
  const { k256, h256 } = constants();
  const m = padded(bytes, 64, 8);
  const h = Uint32Array.from(h256);
  const w = new Uint32Array(64);
  for (let offset = 0; offset < m.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = ((m[offset + 4 * i]! << 24) | (m[offset + 4 * i + 1]! << 16) | (m[offset + 4 * i + 2]! << 8) | m[offset + 4 * i + 3]!) >>> 0;
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15]!, 7) ^ rotr(w[i - 15]!, 18) ^ (w[i - 15]! >>> 3);
      const s1 = rotr(w[i - 2]!, 17) ^ rotr(w[i - 2]!, 19) ^ (w[i - 2]! >>> 10);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = Array.from(h) as [number, number, number, number, number, number, number, number];
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + ch + k256[i]! + w[i]!) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    const next = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) h[i] = (h[i]! + next[i]!) >>> 0;
  }
  return wordsToBytes(h);
}

const rotr64 = (x: bigint, n: bigint) => ((x >> n) | (x << (64n - n))) & MASK64;

function sha512(bytes: Uint8Array): Uint8Array {
  const { k512, h512 } = constants();
  const m = padded(bytes, 128, 16);
  const h = [...h512];
  const w: bigint[] = new Array(80).fill(0n);
  for (let offset = 0; offset < m.length; offset += 128) {
    for (let i = 0; i < 16; i++) {
      let word = 0n;
      for (let j = 0; j < 8; j++) word = (word << 8n) | BigInt(m[offset + 8 * i + j]!);
      w[i] = word;
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(w[i - 15]!, 1n) ^ rotr64(w[i - 15]!, 8n) ^ (w[i - 15]! >> 7n);
      const s1 = rotr64(w[i - 2]!, 19n) ^ rotr64(w[i - 2]!, 61n) ^ (w[i - 2]! >> 6n);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) & MASK64;
    }
    let [a, b, c, d, e, f, g, hh] = h as [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
    for (let i = 0; i < 80; i++) {
      const s1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const ch = (e & f) ^ (~e & MASK64 & g);
      const t1 = (hh + s1 + ch + k512[i]! + w[i]!) & MASK64;
      const s0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) & MASK64;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & MASK64;
    }
    const next = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) h[i] = (h[i]! + next[i]!) & MASK64;
  }
  const out = new Uint8Array(64);
  h.forEach((word, i) => {
    for (let j = 0; j < 8; j++) out[8 * i + j] = Number((word >> BigInt(56 - 8 * j)) & 0xffn);
  });
  return out;
}

const HASHES = {
  SHA1: { digest: sha1, block: 64 },
  SHA256: { digest: sha256, block: 64 },
  SHA512: { digest: sha512, block: 128 },
} as const;

export function hmac(algorithm: TotpSecret["algorithm"], key: Uint8Array, message: Uint8Array): Uint8Array {
  const { digest, block } = HASHES[algorithm];
  const shortKey = key.length > block ? digest(key) : key;
  const inner = new Uint8Array(block + message.length);
  const outer = new Uint8Array(block + (algorithm === "SHA512" ? 64 : algorithm === "SHA256" ? 32 : 20));
  for (let i = 0; i < block; i++) {
    const byte = shortKey[i] ?? 0;
    inner[i] = byte ^ 0x36;
    outer[i] = byte ^ 0x5c;
  }
  inner.set(message, block);
  outer.set(digest(inner), block);
  return digest(outer);
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LONGEST_TOTP_TEXT = 2048;

function base32(text: string): Uint8Array | null {
  const cleaned = text.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  if (!cleaned || cleaned.length > LONGEST_TOTP_TEXT) return null;
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const character of cleaned) {
    const index = BASE32.indexOf(character);
    if (index < 0) return null;
    buffer = ((buffer << 5) | index) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return bytes.length ? Uint8Array.from(bytes) : null;
}

function decodeComponent(text: string): string | null {
  try {
    return decodeURIComponent(text);
  } catch {
    return null;
  }
}

function algorithmNamed(name: string): TotpSecret["algorithm"] | null {
  let plain = name.toLowerCase().replace(/[-_\s]/g, "");
  if (plain.startsWith("hmac")) plain = plain.slice(4);
  return plain === "sha1" ? "SHA1" : plain === "sha256" ? "SHA256" : plain === "sha512" ? "SHA512" : null;
}

function parseTotp(text: string): TotpSecret | null {
  const trimmed = text.trim();
  if (!trimmed || trimmed.length > LONGEST_TOTP_TEXT) return null;
  if (!trimmed.toLowerCase().startsWith("otpauth://")) {
    if (trimmed.includes("://")) return null;
    const secret = base32(trimmed);
    return secret ? { secret, period: 30, digits: 6, algorithm: "SHA1" } : null;
  }
  const rest = trimmed.slice("otpauth://".length);
  const slash = rest.search(/[/?#]/);
  const kind = (slash >= 0 ? rest.slice(0, slash) : rest).toLowerCase();
  if (kind !== "totp") return null;
  const queryStart = rest.indexOf("?");
  const queryText = queryStart >= 0 ? rest.slice(queryStart + 1).split("#")[0]! : "";
  const query = new Map<string, string>();
  for (const pair of queryText.split("&")) {
    if (!pair) continue;
    const equals = pair.indexOf("=");
    const name = decodeComponent(equals >= 0 ? pair.slice(0, equals) : pair);
    const value = decodeComponent(equals >= 0 ? pair.slice(equals + 1) : "");
    if (name === null || value === null) return null;
    const key = name.toLowerCase();
    if (!query.has(key)) query.set(key, value.trim());
  }
  const secretText = query.get("secret");
  const secret = secretText ? base32(secretText) : null;
  if (!secret) return null;
  if ((query.get("encoder") ?? "").toLowerCase() === "steam") return null;
  if (query.get("digits") === "5" && (query.get("issuer") ?? "").toLowerCase() === "steam") return null;
  const digitsText = query.get("digits") ?? "";
  const periodText = query.get("period") ?? "";
  const digits = digitsText ? Number(digitsText) : 6;
  const period = periodText ? Number(periodText) : 30;
  if (!/^\d*$/.test(digitsText) || !/^\d*$/.test(periodText)) return null;
  const algorithmText = query.get("algorithm") ?? "";
  const algorithm = algorithmText ? algorithmNamed(algorithmText) : "SHA1";
  if (!algorithm || digits < 6 || digits > 8 || period < 5 || period > 300) return null;
  return { secret, period, digits, algorithm };
}

function totpCode(secret: TotpSecret, atMs: number): string {
  const seconds = atMs / 1000;
  const counter = seconds > 0 && Number.isFinite(seconds) ? Math.floor(seconds / secret.period) : 0;
  const message = new Uint8Array(8);
  let rest = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    message[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  const mac = hmac(secret.algorithm, secret.secret, message);
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(binary % 10 ** secret.digits).padStart(secret.digits, "0");
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export const totp = {
  parse: parseTotp,
  period(uri: string): number | undefined {
    if (!uri.includes("://")) return undefined;
    return parseTotp(uri)?.period;
  },
  code: totpCode,
  same(a: string, b: string): boolean {
    const left = parseTotp(a);
    const right = parseTotp(b);
    return !!left && !!right && left.period === right.period && left.digits === right.digits && left.algorithm === right.algorithm && sameBytes(left.secret, right.secret);
  },
};

const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export const base64url = {
  encode(bytes: Uint8Array): string {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const chunk = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
      const length = Math.min(3, bytes.length - i);
      for (let j = 0; j <= length; j++) out += BASE64URL[(chunk >> (18 - 6 * j)) & 63];
    }
    return out;
  },
  decode(text: string, longest?: number): Uint8Array | null {
    const plain = text.replace(/=+$/, "");
    if (!/^[A-Za-z0-9_-]*$/.test(plain) || plain.length % 4 === 1) return null;
    const bytes: number[] = [];
    let buffer = 0;
    let bits = 0;
    for (const character of plain) {
      buffer = ((buffer << 6) | BASE64URL.indexOf(character)) & 0xffffff;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((buffer >> bits) & 0xff);
      }
    }
    if (longest !== undefined && bytes.length > longest) return null;
    return Uint8Array.from(bytes);
  },
};

export const uuids = {
  bytes(uuid: string): Uint8Array | null {
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(uuid)) return null;
    const hex = uuid.replace(/-/g, "");
    return Uint8Array.from({ length: 16 }, (_, i) => Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16));
  },
  string(bytes: Uint8Array): string | null {
    if (bytes.length !== 16) return null;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  },
};

export function credentialHandlersOf(provider: CredentialProvider): CredentialHandlerName[] {
  return CREDENTIAL_HANDLERS.filter((name) => typeof handlerOf(provider, name) === "function");
}

function handlerOf(provider: CredentialProvider, name: CredentialHandlerName): CredentialHandler<any, unknown> | undefined {
  if (name === "passkeys.list") return provider.passkeys?.list;
  if (name === "passkeys.get") return provider.passkeys?.get;
  if (name === "passkeys.save") return provider.passkeys?.save;
  return provider[name] as CredentialHandler<any, unknown> | undefined;
}

const METHODS = {
  hello: "hello",
  ready: "ready",
  result: "result",
  verb: "credentials.verb",
  verbCancel: "credentials.verb.cancel",
  signInCancel: "credentials.signIn.cancel",
  takeStored: "credentials.session.takeStored",
  dropStored: "credentials.session.dropStored",
  valuesSet: "credentials.values.set",
  ownerConfirm: "credentials.owner.confirm",
} as const;

type Signal = CancelSignal & { cancel(): void };

function createSignal(): Signal {
  const listeners = new Set<() => void>();
  let cancelled = false;
  return {
    get cancelled() {
      return cancelled;
    },
    onCancel(listener) {
      if (cancelled) listener();
      else listeners.add(listener);
      return disposable(() => listeners.delete(listener));
    },
    cancel() {
      if (cancelled) return;
      cancelled = true;
      for (const listener of listeners) listener();
      listeners.clear();
    },
  };
}

type VerbListener = { onItem?: VerbOptions["onItem"]; onLine?: VerbOptions["onLine"]; parts: string[] };

type HeldListing = { pages: ListedItem[][]; touched: number };

export type CredentialRuntimeOptions = { now?: () => number; onError?: (error: unknown) => void };

export type CredentialRuntime = { readonly ready: Promise<void>; stop(): void };

const PAGE_ENVELOPE_BYTES = 512;

export function pageItems(items: readonly ListedItem[]): ListedItem[][] {
  const pages: ListedItem[][] = [];
  let page: ListedItem[] = [];
  let bytes = PAGE_ENVELOPE_BYTES;
  for (const item of items) {
    const size = utf8Length(JSON.stringify(item)) + 1;
    if (page.length && bytes + size > CREDENTIAL_LIMITS.pageBytes) {
      pages.push(page);
      page = [];
      bytes = PAGE_ENVELOPE_BYTES;
    }
    page.push(item);
    bytes += size;
  }
  if (page.length || !pages.length) pages.push(page);
  return pages;
}

function wireError(error: unknown): WireCredentialError {
  if (CredentialError.is(error)) return error.toWire();
  const detail = errorMessage(error).slice(0, CREDENTIAL_LIMITS.detailLength);
  return detail ? { code: "failed", problem: "failed", detail } : { code: "failed", problem: "failed" };
}

function signInRunOf(value: unknown): SignInRunState {
  const record = isRecord(value) ? value : {};
  const state = record.state === "running" || record.state === "succeeded" || record.state === "failed" ? record.state : "none";
  const hints = Array.isArray(record.hints) ? record.hints.filter((hint): hint is string => typeof hint === "string") : [];
  return {
    state,
    hints,
    ...(typeof record.detail === "string" ? { detail: record.detail } : {}),
    ...(typeof record.timedOut === "boolean" ? { timedOut: record.timedOut } : {}),
  };
}

function textValues(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isRecord(value)) return out;
  for (const [key, entry] of Object.entries(value)) if (typeof entry === "string") out[key] = entry;
  return out;
}

function verbResultOf(verb: string, reply: unknown, parts: readonly string[]): VerbResult {
  const record = isRecord(reply) ? reply : {};
  const flag = (key: string) => record[key] === true;
  let parsed: unknown = record.json ?? null;
  if (parts.length) {
    try {
      parsed = JSON.parse(parts.join(""));
    } catch {
      parsed = null;
    }
  }
  return {
    verb,
    status: typeof record.status === "number" ? record.status : -1,
    launched: flag("launched"),
    timedOut: flag("timedOut"),
    cancelled: flag("cancelled"),
    overflowed: flag("overflowed"),
    succeeded: flag("succeeded"),
    stderr: typeof record.stderr === "string" ? record.stderr : "",
    hints: Array.isArray(record.hints) ? record.hints.filter((hint): hint is string => typeof hint === "string") : [],
    json: parsed,
    lines: Array.isArray(record.lines) ? record.lines.filter((line): line is string => typeof line === "string") : [],
    items: typeof record.items === "number" ? record.items : 0,
    droppedLines: typeof record.droppedLines === "number" ? record.droppedLines : 0,
    unlocked: flag("unlocked"),
  };
}

export function runCredentialProvider(transport: Transport, provider: CredentialProvider, options: CredentialRuntimeOptions = {}): CredentialRuntime {
  const now = options.now ?? (() => Date.now());
  const report = (error: unknown) => {
    if (options.onError) options.onError(error);
    else (globalThis as { console?: { error?: (...a: unknown[]) => void } }).console?.error?.("[ardia credentials]", error);
  };
  const handlers = credentialHandlersOf(provider);
  const waiting = new Map<number, { resolve: (value: unknown) => void; reject: (error: unknown) => void }>();
  const verbListeners = new Map<number, VerbListener>();
  const calls = new Map<string, Signal>();
  const held = new Map<string, HeldListing>();
  let nextRequest = 0;
  let nextSnapshot = 0;
  let stopped = false;

  const send = (message: Record<string, unknown>) => transport.send(JSON.stringify(message));

  function request<T>(method: string, params: Record<string, unknown>, listener?: VerbListener): { id: number; reply: Promise<T> } {
    const id = ++nextRequest;
    if (stopped) return { id, reply: Promise.reject(new PluginError("stopped", "The plugin stopped.")) };
    const reply = new Promise<T>((resolve, reject) => {
      waiting.set(id, { resolve: resolve as (value: unknown) => void, reject });
      if (listener) verbListeners.set(id, listener);
      try {
        send({ id, method, params });
      } catch (error) {
        waiting.delete(id);
        verbListeners.delete(id);
        reject(new PluginError("unencodable", `The ${method} request couldn't be encoded: ${errorMessage(error)}`));
      }
    });
    return { id, reply };
  }

  function takeReply(message: Record<string, unknown>): boolean {
    if (typeof message.method === "string" || !("id" in message)) return false;
    if (!("result" in message) && !("error" in message)) return false;
    const id = message.id;
    const waiter = typeof id === "number" ? waiting.get(id) : undefined;
    if (!waiter) return true;
    waiting.delete(id as number);
    const error = message.error;
    if (error !== undefined && error !== null) {
      const code = isRecord(error) && typeof error.code === "string" ? error.code : "failed";
      const text = isRecord(error) && typeof error.message === "string" ? error.message : typeof error === "string" ? error : "The host refused the request.";
      verbListeners.delete(id as number);
      waiter.reject(code === "stale" ? CredentialError.locked() : new PluginError(code, text));
    } else waiter.resolve(message.result);
    return true;
  }

  function deliverVerbNotice(message: Record<string, unknown>) {
    const listener = typeof message.verbOf === "number" ? verbListeners.get(message.verbOf) : undefined;
    if (!listener) return;
    try {
      if ("item" in message) listener.onItem?.(message.item, typeof message.index === "number" ? message.index : 0);
      else if (isRecord(message.line)) {
        const line = message.line;
        if ((line.stream === "stdout" || line.stream === "stderr") && typeof line.text === "string") listener.onLine?.({ stream: line.stream, text: line.text } as StreamLine);
      } else if (typeof message.part === "string") listener.parts.push(message.part);
    } catch (error) {
      report(error);
    }
  }

  function contextFor(callId: string, name: CredentialHandlerName, message: Record<string, unknown>, signal: Signal): CredentialContext {
    const raw = isRecord(message.context) ? message.context : {};
    const sessionRaw = raw.session;
    const current: { key: SecretHandle | null } | null = isRecord(sessionRaw) ? { key: isSecretHandle(sessionRaw.key) ? sessionRaw.key : null } : null;
    const cliRaw = isRecord(raw.cli) ? raw.cli : {};
    let signInRun = signInRunOf(raw.signInRun);
    let hasStored = raw.hasStored === true;
    const stores = { scratch: textValues(raw.scratch), preferences: textValues(raw.preferences) };
    const valueStore = (store: "scratch" | "preferences"): ValueStore => ({
      get: (key) => stores[store][key],
      async set(key, value) {
        await request(METHODS.valuesSet, { call: callId, store, key, value }).reply;
        if (value === null) delete stores[store][key];
        else stores[store][key] = value;
      },
    });
    const cli: Cli = {
      name: typeof cliRaw.name === "string" ? cliRaw.name : "",
      version: typeof cliRaw.version === "string" ? cliRaw.version : null,
      get signInRun() {
        return signInRun;
      },
      verb(id: string, params: VerbParams = {}, verbOptions: VerbOptions = {}): RunningVerb {
        const cleaned: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(params)) if (value !== undefined) cleaned[key] = value;
        const listener: VerbListener = { onItem: verbOptions.onItem, onLine: verbOptions.onLine, parts: [] };
        const body: Record<string, unknown> = { call: callId, verb: id, params: cleaned };
        if (verbOptions.timeoutMs !== undefined) body.timeoutMs = verbOptions.timeoutMs;
        const { id: requestId, reply } = request<unknown>(METHODS.verb, body, listener);
        const result = reply
          .then((answer) => {
            if (isRecord(answer) && "signInRun" in answer) signInRun = signInRunOf(answer.signInRun);
            return verbResultOf(id, answer, listener.parts);
          })
          .finally(() => verbListeners.delete(requestId));
        return {
          id: requestId,
          then: (resolve, reject) => result.then(resolve, reject),
          cancel() {
            void request(METHODS.verbCancel, { call: callId, verbOf: requestId }).reply.catch(report);
          },
        };
      },
      async cancelSigningIn() {
        await request(METHODS.signInCancel, { call: callId }).reply;
      },
    };
    const session: SessionStore = {
      current,
      get hasStored() {
        return hasStored;
      },
      async takeStored(reason) {
        const answer = await request<{ handle?: unknown }>(METHODS.takeStored, { call: callId, reason }).reply;
        return isSecretHandle(answer?.handle) ? answer.handle : null;
      },
      async dropStored() {
        await request(METHODS.dropStored, { call: callId }).reply;
        hasStored = false;
      },
    };
    return {
      callId,
      kind: CREDENTIAL_CALL_KIND,
      name,
      context: raw,
      caller: message.caller ?? null,
      deadline: typeof message.deadline === "number" ? message.deadline : undefined,
      signal,
      epoch: typeof raw.epoch === "string" ? raw.epoch : "",
      provider: typeof raw.provider === "string" ? raw.provider : "",
      touchID: raw.touchID === true,
      offline: raw.offline === true,
      cli,
      session,
      scratch: valueStore("scratch"),
      preferences: valueStore("preferences"),
      owner: {
        async confirm(reason) {
          const answer = await request<{ confirmed?: unknown }>(METHODS.ownerConfirm, { call: callId, reason }).reply;
          return answer?.confirmed === true;
        },
      },
    };
  }

  function dropExpiredListings() {
    const oldest = now() - CREDENTIAL_LIMITS.heldSnapshotMs;
    for (const [snapshot, listing] of held) if (listing.touched < oldest) held.delete(snapshot);
  }

  async function listPage(handler: CredentialHandler<ListRequest, unknown>, input: ListRequest, ctx: CredentialContext): Promise<unknown> {
    dropExpiredListings();
    const asked = isRecord(input) ? input : { snapshot: null, cursor: null };
    if (typeof asked.snapshot === "string" && typeof asked.cursor === "string") {
      const listing = held.get(asked.snapshot);
      const index = /^[1-9][0-9]{0,8}$/.test(asked.cursor) ? Number(asked.cursor) : -1;
      if (listing && index > 0 && index < listing.pages.length) {
        listing.touched = now();
        const page: ItemPage = { snapshot: asked.snapshot, items: listing.pages[index]! };
        if (index + 1 < listing.pages.length) page.cursor = String(index + 1);
        else held.delete(asked.snapshot);
        return page;
      }
    }
    const result = await handler({ snapshot: null, cursor: null }, ctx);
    if (!Array.isArray(result)) return result;
    const pages = pageItems(result as ListedItem[]);
    const snapshot = `s${++nextSnapshot}${Math.floor(now() % 1_000_000).toString(36)}`;
    const first: ItemPage = { snapshot, items: pages[0]! };
    if (pages.length > 1) {
      held.set(snapshot, { pages, touched: now() });
      first.cursor = "1";
    }
    return first;
  }

  async function answerCall(message: Record<string, unknown>, signal: Signal) {
    const callId = message.call as string;
    const name = message.name as CredentialHandlerName;
    let body: Record<string, unknown>;
    try {
      if (message.kind !== CREDENTIAL_CALL_KIND || !CREDENTIAL_HANDLERS.includes(name)) throw CredentialError.unsupported();
      const handler = handlerOf(provider, name);
      if (!handler) throw CredentialError.unsupported();
      const ctx = contextFor(callId, name, message, signal);
      const input = message.input ?? {};
      const result = name === "list" ? await listPage(handler as CredentialHandler<ListRequest, unknown>, input as ListRequest, ctx) : await handler(input, ctx);
      body = { call: callId, result: result === undefined ? null : result };
    } catch (error) {
      body = { call: callId, error: wireError(error) };
    } finally {
      if (calls.get(callId) === signal) calls.delete(callId);
    }
    if (signal.cancelled || stopped) return;
    try {
      await request(METHODS.result, body).reply;
    } catch (error) {
      if (error instanceof PluginError && error.code === "unencodable") {
        await request(METHODS.result, { call: callId, error: { code: "failed", problem: "failed", detail: "The plugin's result couldn't be sent." } }).reply.catch(report);
      } else report(error);
    }
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    for (const signal of calls.values()) signal.cancel();
    calls.clear();
    const closed = new PluginError("stopped", "The plugin stopped.");
    for (const waiter of waiting.values()) waiter.reject(closed);
    waiting.clear();
    verbListeners.clear();
    held.clear();
  }

  let activated: Promise<void> = Promise.resolve();

  function handleLine(line: string) {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (!isRecord(message)) return;
    if (takeReply(message) || stopped) return;
    if ("verbOf" in message) return deliverVerbNotice(message);
    if (typeof message.call === "string") {
      if (message.cancel === true) return calls.get(message.call)?.cancel();
      const signal = createSignal();
      calls.set(message.call, signal);
      const record = message;
      activated.then(
        () => void answerCall(record, signal),
        () => void answerCall(record, signal),
      );
      return;
    }
    if (message.event === "plugin.stopping") stop();
  }

  transport.onLine((line) => {
    try {
      handleLine(line);
    } catch (error) {
      report(error);
    }
  });

  activated = request(METHODS.hello, { protocol: PLUGIN_PROTOCOL, sdk: CREDENTIALS_SDK_VERSION, credentials: CREDENTIALS_PROTOCOL }).reply.then(
    () => undefined,
    (error) => report(error),
  );
  const ready = activated
    .then(() =>
      stopped
        ? undefined
        : request(METHODS.ready, { commands: [], tools: [], views: [], omnibox: false, decide: [], events: [], credentialProvider: { handlers } }).reply,
    )
    .then(() => undefined);
  ready.catch(report);
  return { ready, stop };
}

function bridge(): Transport {
  const found = (globalThis as { __ardiaBridge?: Transport }).__ardiaBridge;
  if (!found || typeof found.send !== "function" || typeof found.onLine !== "function") {
    throw new Error("There's no __ardiaBridge; plugins built with @ardia/plugin-sdk run inside Ardia's plugin host.");
  }
  return found;
}

let defined = false;

export function defineCredentialProvider(provider: CredentialProvider): Promise<void> {
  if (defined) return Promise.reject(new Error("This plugin already defined its credential provider."));
  defined = true;
  return runCredentialProvider(bridge(), provider).ready;
}
