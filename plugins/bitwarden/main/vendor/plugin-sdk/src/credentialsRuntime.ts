import type * as Contract from "./credentials";
import {
  CREDENTIAL_HANDLERS,
  CREDENTIAL_LIMITS,
  CREDENTIALS_PROTOCOL,
  CREDENTIALS_SDK_VERSION,
  type CredentialContext,
  type CredentialErrorCode,
  type CredentialHandlerName,
  type CredentialProvider,
  type FailureState,
  type ItemPage,
  type ListRequest,
  type ListedItem,
  type ProblemCode,
  type RunHints,
  type RunningVerb,
  type SecretHandle,
  type SignInNeed,
  type SignInOutcome,
  type SignInRunState,
  type StreamLine,
  type TotpSecret,
  type VerbOptions,
  type VerbParams,
  type VerbResult,
  type WireCredentialError,
} from "./credentials";
import { PLUGIN_PROTOCOL } from "./protocol";
import { PluginError, errorMessage, type Transport } from "./rpc";
import { disposable, type CancelSignal } from "./types";

type ErrorOptions = { problem?: ProblemCode; detail?: string; state?: FailureState; field?: string };

function cleanDetail(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  const line = text
    .split(/\r?\n/)
    .map((part) => part.trim())
    .find((part) => part.length > 0);
  if (!line) return undefined;
  return line.length > CREDENTIAL_LIMITS.detailLength ? line.slice(0, CREDENTIAL_LIMITS.detailLength) : line;
}

export class CredentialError extends PluginError {
  declare readonly code: CredentialErrorCode;
  readonly problem: ProblemCode | undefined;
  readonly detail: string | undefined;
  readonly state: FailureState | undefined;
  readonly field: string | undefined;

  private constructor(code: CredentialErrorCode, options: ErrorOptions = {}) {
    super(code, cleanDetail(options.detail) ?? options.problem ?? code);
    this.name = "CredentialError";
    this.problem = options.problem;
    this.detail = cleanDetail(options.detail);
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
    const wire: WireCredentialError = { code: this.code };
    if (this.problem !== undefined) wire.problem = this.problem;
    if (this.detail !== undefined) wire.detail = this.detail;
    if (this.state !== undefined) wire.state = this.state;
    if (this.field !== undefined) wire.field = this.field;
    return wire;
  }
}

type Assignable<T extends U, U> = T;
export type CredentialErrorMatchesContract = Assignable<CredentialError, Contract.CredentialError>;

type OutcomeOptions = { problem?: ProblemCode; detail?: string; state?: FailureState };

function outcomeExtras(options: { problem?: ProblemCode; detail?: string; state?: FailureState; field?: string }) {
  const extras: { problem?: ProblemCode; detail?: string; state?: FailureState; field?: string } = {};
  if (options.problem !== undefined) extras.problem = options.problem;
  const detail = cleanDetail(options.detail);
  if (detail !== undefined) extras.detail = detail;
  if (options.state !== undefined) extras.state = options.state;
  if (options.field !== undefined) extras.field = options.field;
  return extras;
}

export const SignIn = {
  done(options: { session?: SecretHandle } = {}): SignInOutcome {
    return options.session ? { ok: true, session: options.session } : { ok: true };
  },
  needs(need: SignInNeed, options: OutcomeOptions = {}): SignInOutcome {
    return { ok: false, need, ...outcomeExtras(options) };
  },
  failed(problem: ProblemCode, options: { detail?: string; state?: FailureState; field?: string } = {}): SignInOutcome {
    return { ok: false, ...outcomeExtras(options), problem };
  },
  cancelled(state?: FailureState): SignInOutcome {
    return { ok: false, problem: "cancelled", ...(state ? { state } : {}) };
  },
} satisfies typeof Contract.SignIn;

export const isSecretHandle: typeof Contract.isSecretHandle = (value: unknown): value is SecretHandle =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length === 1 &&
  typeof (value as { $secret?: unknown }).$secret === "string";

export const credentialHandlersOf: typeof Contract.credentialHandlersOf = (provider: CredentialProvider): CredentialHandlerName[] =>
  CREDENTIAL_HANDLERS.filter((name) => handlerOf(provider, name) !== undefined);

function handlerOf(provider: CredentialProvider, name: CredentialHandlerName): ((input: never, ctx: CredentialContext) => unknown) | undefined {
  switch (name) {
    case "passkeys.list":
      return provider.passkeys?.list as never;
    case "passkeys.get":
      return provider.passkeys?.get as never;
    case "passkeys.save":
      return provider.passkeys?.save as never;
    default: {
      const handler = provider[name];
      return typeof handler === "function" ? (handler as never) : undefined;
    }
  }
}

const UNREACHABLE_HINTS = [
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
const OUTDATED_HINTS = ["unknown option", "unknown command", "unrecognized option", "unexpected argument", "please update"];

function mentions(result: Pick<VerbResult, "stderr">, needles: readonly string[]): boolean {
  const haystack = result.stderr.toLowerCase();
  return needles.some((needle) => needle.length > 0 && haystack.includes(needle.toLowerCase()));
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

function firstLineOf(result: VerbResult): string | null {
  const line = result.stderr
    .split(/\r?\n/)
    .map((part) => part.trim())
    .find((part) => part.length > 0);
  if (!line) return null;
  const plain = /^error:/i.test(line) ? line.slice("error:".length).trim() : line;
  return plain.length > 0 ? plain : null;
}

export const verbs = {
  mentions,
  problem: problemOf,
  check(result: VerbResult, hints: RunHints, offline: boolean): void {
    if (result.succeeded) return;
    if (hints.locked && mentions(result, hints.locked)) throw CredentialError.locked();
    if (hints.signedOut && mentions(result, hints.signedOut)) throw CredentialError.signedOut();
    if (hints.notFound && mentions(result, hints.notFound)) throw CredentialError.notFound();
    const problem = problemOf(result, offline);
    const line = firstLineOf(result);
    throw CredentialError.failed(problem, problem === "failed" && line ? { detail: line } : {});
  },
  firstLine: firstLineOf,
  unreachableHints: UNREACHABLE_HINTS,
  outdatedHints: OUTDATED_HINTS,
} satisfies typeof Contract.verbs;

type JsonRecord = Record<string, unknown>;

const isRecord = (value: unknown): value is JsonRecord => typeof value === "object" && value !== null && !Array.isArray(value);

function jsonString(value: unknown): string | undefined {
  if (typeof value === "string") return value.length > 0 ? value : undefined;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function jsonInt(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value === "string" && /^[+-]?\d{1,15}$/.test(value)) return Number.parseInt(value, 10);
  return undefined;
}

function jsonMilliseconds(value: unknown): number | undefined {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value <= 0) return undefined;
    return value > 100_000_000_000 ? value : value * 1000;
  }
  if (typeof value !== "string" || value.length === 0) return undefined;
  const civil = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(value) && !/(Z|[+-]\d{2}:?\d{2})$/i.test(value);
  const parsed = Date.parse(civil ? `${value.slice(0, 10)}T${value.slice(11, 19)}Z` : value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

const unreadable = () => CredentialError.failed("unreadable");

const dicts = (value: unknown): JsonRecord[] => (Array.isArray(value) ? value.filter(isRecord) : []);

export const json = {
  record(value: unknown): JsonRecord {
    if (!isRecord(value)) throw unreadable();
    return value;
  },
  list(value: unknown): JsonRecord[] {
    if (!Array.isArray(value)) throw unreadable();
    return value.filter(isRecord);
  },
  listAt(value: unknown, key: string): JsonRecord[] {
    if (!isRecord(value) || !Array.isArray(value[key])) throw unreadable();
    return (value[key] as unknown[]).filter(isRecord);
  },
  dict: (value: unknown): JsonRecord | undefined => (isRecord(value) ? value : undefined),
  dicts,
  string: jsonString,
  strings: (value: unknown): string[] => (Array.isArray(value) ? value.flatMap((entry) => jsonString(entry) ?? []) : []),
  int: jsonInt,
  bool(value: unknown): boolean | undefined {
    if (typeof value === "boolean") return value;
    if (typeof value === "number" && Number.isFinite(value)) return value !== 0;
    return undefined;
  },
  milliseconds: jsonMilliseconds,
} satisfies typeof Contract.json;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

function hostOf(url: string): string | undefined {
  const trimmed = url.trim();
  if (!trimmed || /\s/.test(trimmed)) return undefined;
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(trimmed);
  const rest = scheme ? trimmed.slice(scheme[0].length) : trimmed;
  const authority = rest.split(/[/?#]/, 1)[0] ?? "";
  const hostPort = authority.includes("@") ? authority.slice(authority.lastIndexOf("@") + 1) : authority;
  let host: string;
  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    if (end < 0) return undefined;
    host = hostPort.slice(1, end);
  } else {
    host = hostPort.split(":", 1)[0] ?? "";
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (!host || !/^[a-z0-9.\-:_%]+$/.test(host)) return undefined;
  return host;
}

export const origins = {
  host: hostOf,
  isLocalHost: (host: string) => LOCAL_HOSTS.has(host.trim().toLowerCase()),
  isWebOrigin(url: string): boolean {
    const lowered = url.trim().toLowerCase();
    return (lowered.startsWith("https://") || lowered.startsWith("http://")) && hostOf(url) !== undefined;
  },
  hostIn(url: string, allowed: readonly string[]): boolean {
    const host = hostOf(url);
    if (!host) return false;
    return allowed.some((entry) => {
      const wanted = entry.toLowerCase();
      return host === wanted || host.endsWith(`.${wanted}`);
    });
  },
} satisfies typeof Contract.origins;

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export const base64url = {
  encode(bytes: Uint8Array): string {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i] ?? 0;
      const b = bytes[i + 1] ?? 0;
      const c = bytes[i + 2] ?? 0;
      const triple = (a << 16) | (b << 8) | c;
      out += BASE64_ALPHABET[(triple >> 18) & 63];
      out += BASE64_ALPHABET[(triple >> 12) & 63];
      if (i + 1 < bytes.length) out += BASE64_ALPHABET[(triple >> 6) & 63];
      if (i + 2 < bytes.length) out += BASE64_ALPHABET[triple & 63];
    }
    return out;
  },
  decode(text: string, longest = 1 << 16): Uint8Array | null {
    if (text.length > longest * 2 || text.length % 4 === 1) return null;
    const out: number[] = [];
    let buffer = 0;
    let bits = 0;
    for (const character of text) {
      const index = BASE64_ALPHABET.indexOf(character);
      if (index < 0) return null;
      buffer = ((buffer << 6) | index) & 0xffffff;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out.push((buffer >> bits) & 0xff);
      }
    }
    if (out.length > longest) return null;
    return Uint8Array.from(out);
  },
} satisfies typeof Contract.base64url;

const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const uuids = {
  bytes(uuid: string): Uint8Array | null {
    if (!UUID_PATTERN.test(uuid)) return null;
    const hex = uuid.replace(/-/g, "");
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  },
  string(bytes: Uint8Array): string | null {
    if (bytes.length !== 16) return null;
    const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  },
} satisfies typeof Contract.uuids;

type Steam = TotpSecret & { readonly encoding?: "steam" };

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";
const TOTP_LONGEST_TEXT = 2048;

function base32(text: string): Uint8Array | null {
  const cleaned = text
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/=+$/, "");
  if (!cleaned || cleaned.length > TOTP_LONGEST_TEXT) return null;
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const character of cleaned) {
    const index = BASE32_ALPHABET.indexOf(character);
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

function queryOf(uri: string): Map<string, string> {
  const query = new Map<string, string>();
  const start = uri.indexOf("?");
  if (start < 0) return query;
  const text = uri.slice(start + 1).split("#", 1)[0] ?? "";
  for (const pair of text.split("&")) {
    if (!pair) continue;
    const equals = pair.indexOf("=");
    const rawName = equals < 0 ? pair : pair.slice(0, equals);
    const rawValue = equals < 0 ? "" : pair.slice(equals + 1);
    let name: string;
    let value: string;
    try {
      name = decodeURIComponent(rawName.replace(/\+/g, " ")).toLowerCase();
      value = decodeURIComponent(rawValue.replace(/\+/g, " ")).trim();
    } catch {
      continue;
    }
    if (!query.has(name)) query.set(name, value);
  }
  return query;
}

function algorithmNamed(name: string): TotpSecret["algorithm"] | null {
  let plain = name.toLowerCase().replace(/[-_\s]/g, "");
  if (plain.startsWith("hmac")) plain = plain.slice(4);
  if (plain === "sha1") return "SHA1";
  if (plain === "sha256") return "SHA256";
  if (plain === "sha512") return "SHA512";
  return null;
}

function parseTotp(text: string): TotpSecret | null {
  const trimmed = text.trim();
  if (!trimmed || trimmed.length > TOTP_LONGEST_TEXT) return null;
  const lowered = trimmed.toLowerCase();
  if (lowered.startsWith("steam://")) {
    const secret = base32(trimmed.slice("steam://".length));
    return secret ? ({ secret, period: 30, digits: 5, algorithm: "SHA1", encoding: "steam" } as Steam) : null;
  }
  if (lowered.startsWith("otpauth://")) {
    const afterScheme = trimmed.slice("otpauth://".length);
    const kind = (afterScheme.split(/[/?#]/, 1)[0] ?? "").toLowerCase();
    if (kind !== "totp") return null;
    const query = queryOf(trimmed);
    const secretText = query.get("secret");
    const secret = secretText ? base32(secretText) : null;
    if (!secret) return null;
    const digitsText = query.get("digits");
    const steam = query.get("encoder")?.toLowerCase() === "steam" || (digitsText === "5" && query.get("issuer")?.toLowerCase() === "steam");
    let digits = steam ? 5 : 6;
    if (digitsText) {
      if (!/^\d{1,3}$/.test(digitsText)) return null;
      digits = Number(digitsText);
    }
    let period = 30;
    const periodText = query.get("period");
    if (periodText) {
      if (!/^\d{1,4}$/.test(periodText)) return null;
      period = Number(periodText);
    }
    let algorithm: TotpSecret["algorithm"] = "SHA1";
    const algorithmText = query.get("algorithm");
    if (algorithmText) {
      const named = algorithmNamed(algorithmText);
      if (!named) return null;
      algorithm = named;
    }
    if (period < 5 || period > 300) return null;
    if (steam) return digits === 5 ? ({ secret, period, digits, algorithm, encoding: "steam" } as Steam) : null;
    if (digits < 6 || digits > 8) return null;
    return { secret, period, digits, algorithm };
  }
  if (trimmed.includes("://")) return null;
  const secret = base32(trimmed);
  return secret ? { secret, period: 30, digits: 6, algorithm: "SHA1" } : null;
}

const rotl = (value: number, bits: number) => ((value << bits) | (value >>> (32 - bits))) >>> 0;
const rotr = (value: number, bits: number) => ((value >>> bits) | (value << (32 - bits))) >>> 0;

function padded(message: Uint8Array, blockBytes: number, lengthBytes: number): Uint8Array {
  const total = Math.ceil((message.length + 1 + lengthBytes) / blockBytes) * blockBytes;
  const out = new Uint8Array(total);
  out.set(message);
  out[message.length] = 0x80;
  const bits = message.length * 8;
  for (let i = 0; i < 8; i++) out[total - 1 - i] = Math.floor(bits / 2 ** (8 * i)) & 0xff;
  return out;
}

function sha1(message: Uint8Array): Uint8Array {
  const data = padded(message, 64, 8);
  const h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  const w = new Array<number>(80);
  for (let block = 0; block < data.length; block += 64) {
    for (let i = 0; i < 16; i++) w[i] = ((data[block + i * 4]! << 24) | (data[block + i * 4 + 1]! << 16) | (data[block + i * 4 + 2]! << 8) | data[block + i * 4 + 3]!) >>> 0;
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3]! ^ w[i - 8]! ^ w[i - 14]! ^ w[i - 16]!, 1);
    let [a, b, c, d, e] = h as [number, number, number, number, number];
    for (let i = 0; i < 80; i++) {
      const [f, k] = i < 20 ? [(b & c) | (~b & d), 0x5a827999] : i < 40 ? [b ^ c ^ d, 0x6ed9eba1] : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6];
      const next = (rotl(a, 5) + (f >>> 0) + e + k + w[i]!) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = next;
    }
    h[0] = (h[0]! + a) >>> 0;
    h[1] = (h[1]! + b) >>> 0;
    h[2] = (h[2]! + c) >>> 0;
    h[3] = (h[3]! + d) >>> 0;
    h[4] = (h[4]! + e) >>> 0;
  }
  return wordsToBytes(h);
}

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256(message: Uint8Array): Uint8Array {
  const data = padded(message, 64, 8);
  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const w = new Array<number>(64);
  for (let block = 0; block < data.length; block += 64) {
    for (let i = 0; i < 16; i++) w[i] = ((data[block + i * 4]! << 24) | (data[block + i * 4 + 1]! << 16) | (data[block + i * 4 + 2]! << 8) | data[block + i * 4 + 3]!) >>> 0;
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15]!, 7) ^ rotr(w[i - 15]!, 18) ^ (w[i - 15]! >>> 3);
      const s1 = rotr(w[i - 2]!, 17) ^ rotr(w[i - 2]!, 19) ^ (w[i - 2]! >>> 10);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h as [number, number, number, number, number, number, number, number];
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const choice = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + choice + SHA256_K[i]! + w[i]!) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + majority) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    const added = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) h[i] = (h[i]! + added[i]!) >>> 0;
  }
  return wordsToBytes(h);
}

const SHA512_K = [
  "428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc", "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
  "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2", "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
  "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65", "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
  "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4", "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
  "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df", "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
  "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30", "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
  "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8", "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
  "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec", "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
  "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178", "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
  "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c", "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817",
].map((hex) => BigInt(`0x${hex}`));
const MASK64 = (1n << 64n) - 1n;
const rotr64 = (value: bigint, bits: bigint) => ((value >> bits) | (value << (64n - bits))) & MASK64;

function sha512(message: Uint8Array): Uint8Array {
  const data = padded(message, 128, 16);
  const h = ["6a09e667f3bcc908", "bb67ae8584caa73b", "3c6ef372fe94f82b", "a54ff53a5f1d36f1", "510e527fade682d1", "9b05688c2b3e6c1f", "1f83d9abfb41bd6b", "5be0cd19137e2179"].map((hex) =>
    BigInt(`0x${hex}`),
  );
  const w = new Array<bigint>(80);
  for (let block = 0; block < data.length; block += 128) {
    for (let i = 0; i < 16; i++) {
      let word = 0n;
      for (let j = 0; j < 8; j++) word = (word << 8n) | BigInt(data[block + i * 8 + j]!);
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
      const choice = (e & f) ^ (~e & MASK64 & g);
      const t1 = (hh + s1 + choice + SHA512_K[i]! + w[i]!) & MASK64;
      const s0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + majority) & MASK64;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & MASK64;
    }
    const added = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) h[i] = (h[i]! + added[i]!) & MASK64;
  }
  const out = new Uint8Array(64);
  h.forEach((word, i) => {
    for (let j = 0; j < 8; j++) out[i * 8 + j] = Number((word >> BigInt(56 - j * 8)) & 0xffn);
  });
  return out;
}

function wordsToBytes(words: readonly number[]): Uint8Array {
  const out = new Uint8Array(words.length * 4);
  words.forEach((word, i) => {
    out[i * 4] = (word >>> 24) & 0xff;
    out[i * 4 + 1] = (word >>> 16) & 0xff;
    out[i * 4 + 2] = (word >>> 8) & 0xff;
    out[i * 4 + 3] = word & 0xff;
  });
  return out;
}

const HASHES = { SHA1: { hash: sha1, block: 64 }, SHA256: { hash: sha256, block: 64 }, SHA512: { hash: sha512, block: 128 } } as const;

function hmac(algorithm: TotpSecret["algorithm"], key: Uint8Array, message: Uint8Array): Uint8Array {
  const { hash, block } = HASHES[algorithm];
  let keyBlock = key.length > block ? hash(key) : key;
  const padded = new Uint8Array(block);
  padded.set(keyBlock);
  keyBlock = padded;
  const inner = new Uint8Array(block + message.length);
  const outer = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    inner[i] = keyBlock[i]! ^ 0x36;
    outer[i] = keyBlock[i]! ^ 0x5c;
  }
  inner.set(message, block);
  const innerHash = hash(inner);
  const joined = new Uint8Array(block + innerHash.length);
  joined.set(outer);
  joined.set(innerHash, block);
  return hash(joined);
}

function totpCode(secret: TotpSecret, atMs: number): string {
  const seconds = atMs / 1000;
  const counter = Number.isFinite(seconds) && seconds > 0 ? Math.floor(seconds / secret.period) : 0;
  const message = new Uint8Array(8);
  let rest = counter;
  for (let i = 7; i >= 0; i--) {
    message[i] = rest % 256;
    rest = Math.floor(rest / 256);
  }
  const mac = hmac(secret.algorithm, secret.secret, message);
  const offset = mac[mac.length - 1]! & 0x0f;
  let binary = (((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!) >>> 0;
  if ((secret as Steam).encoding === "steam") {
    let letters = "";
    for (let i = 0; i < 5; i++) {
      letters += STEAM_ALPHABET[binary % STEAM_ALPHABET.length];
      binary = Math.floor(binary / STEAM_ALPHABET.length);
    }
    return letters;
  }
  const value = String(binary % 10 ** secret.digits);
  return value.padStart(secret.digits, "0");
}

const SAME_CHECK_TIMES_MS = [59_000, 1_111_111_109_000, 2_000_000_000_000];

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
    if (!left || !right) return a.trim() === b.trim();
    if (left.period !== right.period || left.digits !== right.digits) return false;
    return SAME_CHECK_TIMES_MS.every((at) => totpCode(left, at) === totpCode(right, at));
  },
} satisfies typeof Contract.totp;

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
      for (const listener of [...listeners]) listener();
      listeners.clear();
    },
  };
}

type Waiter = {
  resolve(value: unknown): void;
  reject(error: unknown): void;
  onItem?: VerbOptions["onItem"];
  onLine?: VerbOptions["onLine"];
  parts: string[];
  itemError?: unknown;
};

type HeldListing = { pages: ListedItem[][]; at: number };

export type CredentialRuntimeOptions = { onError?: (error: unknown) => void; now?: () => number };

export type CredentialRuntime = {
  define(provider: CredentialProvider): Promise<void>;
  callCount(): number;
  dispose(): void;
};

function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

const PAGE_OVERHEAD_BYTES = 512;

export function pagesOf(items: readonly ListedItem[], pageBytes: number = CREDENTIAL_LIMITS.pageBytes): ListedItem[][] {
  const pages: ListedItem[][] = [];
  let current: ListedItem[] = [];
  let size = PAGE_OVERHEAD_BYTES;
  for (const item of items) {
    const bytes = utf8Length(JSON.stringify(item)) + 1;
    if (current.length > 0 && size + bytes > pageBytes) {
      pages.push(current);
      current = [];
      size = PAGE_OVERHEAD_BYTES;
    }
    current.push(item);
    size += bytes;
  }
  pages.push(current);
  return pages;
}

function wireOf(error: unknown): WireCredentialError {
  if (CredentialError.is(error)) return error.toWire();
  const detail = cleanDetail(errorMessage(error));
  return detail ? { code: "failed", problem: "failed", detail } : { code: "failed", problem: "failed" };
}

function verbResultOf(raw: unknown, parts: readonly string[]): VerbResult {
  const record = isRecord(raw) ? raw : {};
  const bool = (key: string) => record[key] === true;
  const number = (key: string) => (typeof record[key] === "number" ? (record[key] as number) : 0);
  let value: unknown = record.json ?? null;
  if (parts.length > 0) {
    try {
      value = JSON.parse(parts.join(""));
    } catch {
      value = null;
    }
  }
  return {
    verb: typeof record.verb === "string" ? record.verb : "",
    status: typeof record.status === "number" ? record.status : -1,
    launched: bool("launched"),
    timedOut: bool("timedOut"),
    cancelled: bool("cancelled"),
    overflowed: bool("overflowed"),
    succeeded: bool("succeeded"),
    stderr: typeof record.stderr === "string" ? record.stderr : "",
    hints: Array.isArray(record.hints) ? record.hints.filter((hint): hint is string => typeof hint === "string") : [],
    json: value,
    lines: Array.isArray(record.lines) ? record.lines.filter((line): line is string => typeof line === "string") : [],
    items: number("items"),
    droppedLines: number("droppedLines"),
    unlocked: bool("unlocked"),
  };
}

function signInRunOf(value: unknown): SignInRunState | null {
  if (!isRecord(value)) return null;
  const state = value.state;
  if (state !== "none" && state !== "running" && state !== "succeeded" && state !== "failed") return null;
  const run: SignInRunState = { state, hints: Array.isArray(value.hints) ? value.hints.filter((hint): hint is string => typeof hint === "string") : [] };
  if (typeof value.detail === "string") run.detail = value.detail;
  if (typeof value.timedOut === "boolean") run.timedOut = value.timedOut;
  return run;
}

function valuesOf(value: unknown): Map<string, string> {
  const values = new Map<string, string>();
  if (!isRecord(value)) return values;
  for (const [key, entry] of Object.entries(value)) if (typeof entry === "string") values.set(key, entry);
  return values;
}

export function createCredentialRuntime(transport: Transport, options: CredentialRuntimeOptions = {}): CredentialRuntime {
  const waiting = new Map<number, Waiter>();
  const calls = new Map<string, Signal>();
  const held = new Map<string, HeldListing>();
  const now = options.now ?? (() => Date.now());
  let nextId = 0;
  let snapshots = 0;
  let provider: CredentialProvider | null = null;
  let activation: Promise<boolean> = Promise.resolve(false);
  let stopped = false;
  let queue: Promise<void> = Promise.resolve();

  const report = (error: unknown) => {
    if (options.onError) options.onError(error);
    else (globalThis as { console?: { error?: (...args: unknown[]) => void } }).console?.error?.("[ardia credentials]", error);
  };

  const send = (message: Record<string, unknown>) => transport.send(JSON.stringify(message));

  function request(method: string, params: Record<string, unknown>, hooks: Pick<Waiter, "onItem" | "onLine"> = {}): { id: number; promise: Promise<unknown>; parts: string[] } {
    const id = ++nextId;
    const parts: string[] = [];
    if (stopped) return { id, parts, promise: Promise.reject(new PluginError("stopped", "The plugin stopped.")) };
    let line: string;
    try {
      line = JSON.stringify({ id, method, params });
    } catch (error) {
      return { id, parts, promise: Promise.reject(new PluginError("unencodable", `The ${method} request couldn't be encoded: ${errorMessage(error)}`)) };
    }
    const promise = new Promise<unknown>((resolve, reject) => {
      waiting.set(id, { resolve, reject, parts, ...hooks });
      try {
        transport.send(line);
      } catch (error) {
        waiting.delete(id);
        reject(error);
      }
    });
    return { id, promise, parts };
  }

  function takeReply(record: Record<string, unknown>): boolean {
    if (typeof record.method === "string" || typeof record.id !== "number") return false;
    if (!("result" in record) && !("error" in record)) return false;
    const waiter = waiting.get(record.id);
    if (!waiter) return true;
    waiting.delete(record.id);
    const error = record.error;
    if (error !== undefined && error !== null) {
      const code = isRecord(error) && typeof error.code === "string" ? error.code : "failed";
      const message = isRecord(error) && typeof error.message === "string" ? error.message : typeof error === "string" ? error : "The host refused the request.";
      waiter.reject(new PluginError(code, message));
    } else if (waiter.itemError !== undefined) {
      waiter.reject(waiter.itemError);
    } else {
      waiter.resolve(record.result);
    }
    return true;
  }

  function takeNotification(record: Record<string, unknown>): boolean {
    if (typeof record.verbOf !== "number") return false;
    const waiter = waiting.get(record.verbOf);
    if (!waiter) return true;
    try {
      if ("item" in record) waiter.onItem?.(record.item, typeof record.index === "number" ? record.index : 0);
      else if (isRecord(record.line)) {
        const line = record.line;
        const stream = line.stream === "stderr" ? "stderr" : "stdout";
        waiter.onLine?.({ stream, text: typeof line.text === "string" ? line.text : "" } satisfies StreamLine);
      } else if (typeof record.part === "string") waiter.parts.push(record.part);
    } catch (error) {
      waiter.itemError ??= error;
    }
    return true;
  }

  function contextFor(message: Record<string, unknown>, callId: string, name: CredentialHandlerName, signal: Signal): CredentialContext {
    const raw = isRecord(message.context) ? message.context : {};
    const rawCli = isRecord(raw.cli) ? raw.cli : {};
    let signInRun = signInRunOf(raw.signInRun) ?? { state: "none", hints: [] };
    const scratch = valuesOf(raw.scratch);
    const preferences = valuesOf(raw.preferences);
    const rawSession = raw.session;
    const current = isRecord(rawSession) ? { key: isSecretHandle(rawSession.key) ? rawSession.key : null } : null;
    const ended = () => signal.cancelled || stopped;
    const closedError = () => new PluginError("closed", `The call ${callId} has ended.`);

    const ask = async (method: string, params: Record<string, unknown>) => {
      if (ended()) throw closedError();
      return request(method, { call: callId, ...params }).promise;
    };

    const valueStore = (store: "scratch" | "preferences", values: Map<string, string>) => ({
      get: (key: string) => values.get(key),
      async set(key: string, value: string | null) {
        await ask("credentials.values.set", { store, key, value });
        if (value === null) values.delete(key);
        else values.set(key, value);
      },
    });

    const verb = (id: string, params: VerbParams = {}, verbOptions: VerbOptions = {}): RunningVerb => {
      const cleaned: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(params)) if (value !== undefined) cleaned[key] = value;
      const body: Record<string, unknown> = { call: callId, verb: id, params: cleaned };
      if (verbOptions.timeoutMs !== undefined) body.timeoutMs = verbOptions.timeoutMs;
      if (ended()) {
        const refused = Promise.reject(closedError());
        return { id: 0, cancel() {}, then: (onDone, onFail) => refused.then(onDone, onFail) };
      }
      const started = request("credentials.verb", body, { onItem: verbOptions.onItem, onLine: verbOptions.onLine });
      const finished = started.promise.then((raw) => {
        const run = signInRunOf(isRecord(raw) ? raw.signInRun : undefined);
        if (run) signInRun = run;
        return verbResultOf(raw, started.parts);
      });
      return {
        id: started.id,
        cancel() {
          if (stopped) return;
          void request("credentials.verb.cancel", { call: callId, verbOf: started.id }).promise.catch(() => undefined);
        },
        then: (onDone, onFail) => finished.then(onDone, onFail),
      };
    };

    return {
      callId,
      kind: "credentials",
      name,
      context: raw,
      caller: message.caller ?? null,
      deadline: typeof message.deadline === "number" ? message.deadline : undefined,
      signal,
      epoch: typeof raw.epoch === "string" ? raw.epoch : "",
      provider: typeof raw.provider === "string" ? raw.provider : "",
      touchID: raw.touchID === true,
      offline: raw.offline === true,
      cli: {
        name: typeof rawCli.name === "string" ? rawCli.name : "",
        version: typeof rawCli.version === "string" ? rawCli.version : null,
        get signInRun() {
          return signInRun;
        },
        verb,
        async cancelSigningIn() {
          await ask("credentials.signIn.cancel", {});
        },
      },
      session: {
        current,
        hasStored: raw.hasStored === true,
        async takeStored(reason: string) {
          const answer = await ask("credentials.session.takeStored", { reason });
          const handle = isRecord(answer) ? answer.handle : null;
          return isSecretHandle(handle) ? handle : null;
        },
        async dropStored() {
          await ask("credentials.session.dropStored", {});
        },
      },
      scratch: valueStore("scratch", scratch),
      preferences: valueStore("preferences", preferences),
      owner: {
        async confirm(reason: string) {
          const answer = await ask("credentials.owner.confirm", { reason });
          return isRecord(answer) && answer.confirmed === true;
        },
      },
    };
  }

  function mintSnapshot(): string {
    snapshots += 1;
    return `s${snapshots.toString(36)}${now().toString(36)}`;
  }

  function forgetOldListings() {
    const oldest = now() - CREDENTIAL_LIMITS.heldSnapshotMs;
    for (const [snapshot, listing] of held) if (listing.at < oldest) held.delete(snapshot);
  }

  function pageFrom(snapshot: string, pages: ListedItem[][], index: number): ItemPage {
    const page: ItemPage = { snapshot, items: pages[index] ?? [] };
    if (index + 1 < pages.length) page.cursor = String(index + 1);
    else held.delete(snapshot);
    return page;
  }

  async function list(request: ListRequest, ctx: CredentialContext, handler: CredentialProvider["list"]): Promise<ItemPage> {
    forgetOldListings();
    const kept = request.snapshot ? held.get(request.snapshot) : undefined;
    const index = request.cursor !== null && /^[0-9]{1,6}$/.test(request.cursor) ? Number(request.cursor) : -1;
    if (kept && request.snapshot && index > 0 && index < kept.pages.length) {
      kept.at = now();
      return pageFrom(request.snapshot, kept.pages, index);
    }
    const listed = await handler({ snapshot: null, cursor: null }, ctx);
    if (!Array.isArray(listed)) return listed as ItemPage;
    const pages = pagesOf(listed as ListedItem[]);
    const snapshot = mintSnapshot();
    if (pages.length > 1) held.set(snapshot, { pages, at: now() });
    return pageFrom(snapshot, pages, 0);
  }

  async function dispatch(name: CredentialHandlerName, input: unknown, ctx: CredentialContext): Promise<unknown> {
    const current = provider;
    if (!current) throw CredentialError.unsupported();
    if (name === "list") return list((isRecord(input) ? input : { snapshot: null, cursor: null }) as ListRequest, ctx, current.list);
    const handler = handlerOf(current, name);
    if (!handler) throw CredentialError.unsupported();
    return handler((input ?? {}) as never, ctx);
  }

  async function sendResult(body: Record<string, unknown>) {
    try {
      await request("result", body).promise;
    } catch (error) {
      if (error instanceof PluginError && error.code === "unencodable") {
        await request("result", { call: body.call, error: { code: "failed", problem: "failed", detail: "The plugin's result couldn't be sent." } }).promise.catch(report);
      } else if (!stopped) report(error);
    }
  }

  async function answer(message: Record<string, unknown>, signal: Signal) {
    const callId = message.call as string;
    try {
      if (signal.cancelled) return;
      const name = message.name;
      if (message.kind !== "credentials" || typeof name !== "string" || !(CREDENTIAL_HANDLERS as readonly string[]).includes(name)) {
        await sendResult({ call: callId, error: CredentialError.unsupported().toWire() });
        return;
      }
      const ctx = contextFor(message, callId, name as CredentialHandlerName, signal);
      let body: Record<string, unknown>;
      try {
        const result = await dispatch(name as CredentialHandlerName, message.input, ctx);
        body = { call: callId, result: result === undefined ? null : result };
      } catch (error) {
        body = { call: callId, error: wireOf(error) };
      }
      if (signal.cancelled || stopped) return;
      await sendResult(body);
    } finally {
      if (calls.get(callId) === signal) calls.delete(callId);
      signal.cancel();
    }
  }

  function handleLine(line: string) {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      return report(new Error(`The host sent a line that isn't JSON: ${line.slice(0, 120)}`));
    }
    if (!isRecord(message)) return;
    if (takeNotification(message) || takeReply(message) || stopped) return;
    if (typeof message.call === "string") {
      const callId = message.call;
      if (message.cancel === true) return calls.get(callId)?.cancel();
      if (calls.has(callId)) return;
      const signal = createSignal();
      calls.set(callId, signal);
      queue = queue
        .then(() => activation)
        .then((ready) => {
          if (!ready) {
            calls.delete(callId);
            return;
          }
          void answer(message as Record<string, unknown>, signal).catch(report);
        })
        .catch(report);
      return;
    }
    if (message.event === "plugin.stopping") dispose();
  }

  function dispose() {
    if (stopped) return;
    stopped = true;
    for (const signal of [...calls.values()]) signal.cancel();
    calls.clear();
    held.clear();
    const waiters = [...waiting.values()];
    waiting.clear();
    for (const waiter of waiters) waiter.reject(new PluginError("stopped", "The plugin stopped."));
  }

  transport.onLine((line) => {
    try {
      handleLine(line);
    } catch (error) {
      report(error);
    }
  });

  function define(definition: CredentialProvider): Promise<void> {
    if (provider) return Promise.reject(new Error("This plugin already defined its credential provider."));
    provider = definition;
    const handlers = credentialHandlersOf(definition);
    activation = (async () => {
      try {
        const raw = await request("hello", { protocol: PLUGIN_PROTOCOL, sdk: CREDENTIALS_SDK_VERSION, credentials: CREDENTIALS_PROTOCOL }).promise;
        const credentials = isRecord(raw) && isRecord(raw.credentials) ? raw.credentials : null;
        const supported = credentials && Array.isArray(credentials.supported) ? credentials.supported : [];
        if (!supported.includes(CREDENTIALS_PROTOCOL)) throw new PluginError("refused", `Ardia doesn't speak credentials protocol ${CREDENTIALS_PROTOCOL}.`);
        if (stopped) return false;
        await request("ready", { commands: [], tools: [], views: [], omnibox: false, decide: [], events: [], credentialProvider: { handlers } }).promise;
        return !stopped;
      } catch (error) {
        report(error);
        return false;
      }
    })();
    return activation.then(() => undefined);
  }

  return { define, callCount: () => calls.size, dispose };
}

function bridge(): Transport {
  const found = (globalThis as { __ardiaBridge?: Transport }).__ardiaBridge;
  if (!found || typeof found.send !== "function" || typeof found.onLine !== "function") {
    throw new Error("There's no __ardiaBridge; plugins built with @ardia/plugin-sdk run inside Ardia's plugin host.");
  }
  return found;
}

export const defineCredentialProvider: typeof Contract.defineCredentialProvider = (provider: CredentialProvider) => createCredentialRuntime(bridge()).define(provider);
