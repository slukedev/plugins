import { mock } from "node:test";
import { createHmac } from "node:crypto";
import { PluginError } from "../../vendor/plugin-sdk/src/rpc.ts";
import type * as Contract from "../../vendor/plugin-sdk/src/credentials.ts";
import {
  CREDENTIAL_DEADLINES_MS,
  CREDENTIAL_HANDLERS,
  CREDENTIAL_LIMITS,
  CAPABILITY_HANDLERS,
  CREDENTIALS_PROTOCOL,
  CREDENTIALS_PROTOCOLS_SUPPORTED,
  DENIED_COMMANDS,
  DENIED_ENV_PATTERNS,
  GLOBAL_FLAGS,
  REQUIRED_CREDENTIAL_HANDLERS,
  VERB_TIMEOUTS_MS,
  type CredentialContext,
  type CredentialErrorCode,
  type CredentialHandlerName,
  type CredentialHarness,
  type CredentialProvider,
  type FailureState,
  type FakeCli,
  type FakeLaunch,
  type FakeReply,
  type HarnessAnswer,
  type HarnessContext,
  type ItemPage,
  type JsonRecord,
  type ListedItem,
  type ProblemCode,
  type RunHints,
  type RunningVerb,
  type SecretHandle,
  type SignInNeed,
  type SignInOutcome,
  type SignInRunState,
  type StreamLine,
  type VerbOptions,
  type VerbParams,
  type VerbResult,
  type WireCredentialError,
} from "../../vendor/plugin-sdk/src/credentials.ts";

export * from "../../vendor/plugin-sdk/src/credentials.ts";
export { PluginError };

export class CredentialError extends PluginError {
  readonly code: CredentialErrorCode;
  readonly problem: ProblemCode | undefined;
  readonly detail: string | undefined;
  readonly state: FailureState | undefined;
  readonly field: string | undefined;

  private constructor(code: CredentialErrorCode, options: { problem?: ProblemCode; detail?: string; state?: FailureState; field?: string } = {}) {
    super(code, options.problem ?? code);
    this.code = code;
    this.problem = options.problem;
    this.detail = options.detail;
    this.state = options.state;
    this.field = options.field;
  }

  static locked() {
    return new CredentialError("locked");
  }
  static signedOut() {
    return new CredentialError("signedOut");
  }
  static notFound() {
    return new CredentialError("notFound");
  }
  static unsupported() {
    return new CredentialError("unsupported");
  }
  static failed(problem: ProblemCode, options: { detail?: string; state?: FailureState; field?: string } = {}) {
    return new CredentialError("failed", { problem, ...options });
  }
  static is(error: unknown, code?: CredentialErrorCode): error is CredentialError {
    return error instanceof CredentialError && (code === undefined || error.code === code);
  }
  toWire(): WireCredentialError {
    return {
      code: this.code,
      ...(this.problem ? { problem: this.problem } : {}),
      ...(this.detail ? { detail: this.detail } : {}),
      ...(this.state ? { state: this.state } : {}),
      ...(this.field ? { field: this.field } : {}),
    };
  }
}

export const SignIn: typeof Contract.SignIn = {
  done: (options) => ({ ok: true, ...(options?.session ? { session: options.session } : {}) }),
  needs: (need: SignInNeed, options) => ({ ok: false, need, ...options }),
  failed: (problem, options) => ({ ok: false, problem, ...options }),
  cancelled: (state) => ({ ok: false, problem: "cancelled", ...(state ? { state } : {}) }),
};

export const isSecretHandle: typeof Contract.isSecretHandle = (value): value is SecretHandle =>
  typeof value === "object" && value !== null && typeof (value as { $secret?: unknown }).$secret === "string" && Object.keys(value).length === 1;

const isRecord = (value: unknown): value is JsonRecord => typeof value === "object" && value !== null && !Array.isArray(value);

export const json: typeof Contract.json = {
  record(value) {
    if (!isRecord(value)) throw CredentialError.failed("unreadable");
    return value;
  },
  list(value) {
    if (!Array.isArray(value)) throw CredentialError.failed("unreadable");
    return value.filter(isRecord);
  },
  listAt(value, key) {
    const found = json.record(value)[key];
    if (!Array.isArray(found)) throw CredentialError.failed("unreadable");
    return found.filter(isRecord);
  },
  dict: (value) => (isRecord(value) ? value : undefined),
  dicts: (value) => (Array.isArray(value) ? value.filter(isRecord) : []),
  string(value) {
    if (typeof value === "string") return value === "" ? undefined : value;
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    return undefined;
  },
  strings: (value) => (Array.isArray(value) ? value.flatMap((entry) => json.string(entry) ?? []) : []),
  int(value) {
    if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
    if (typeof value === "string" && /^-?\d+$/.test(value)) return Number(value);
    return undefined;
  },
  bool: (value) => (typeof value === "boolean" ? value : undefined),
  milliseconds(value) {
    if (typeof value === "number") {
      if (!Number.isFinite(value) || value <= 0) return undefined;
      return value > 100_000_000_000 ? value : value * 1000;
    }
    if (typeof value !== "string" || !value) return undefined;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  },
};

const LOCAL_HOSTS = ["localhost", "127.0.0.1", "::1", "[::1]"];

function parsedUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

export const origins: typeof Contract.origins = {
  host: (url) => parsedUrl(url)?.hostname.toLowerCase() || undefined,
  isLocalHost: (host) => LOCAL_HOSTS.includes(host.toLowerCase()),
  isWebOrigin(url) {
    const parsed = parsedUrl(url);
    return !!parsed && (parsed.protocol === "https:" || parsed.protocol === "http:") && !!parsed.hostname;
  },
  hostIn(url, allowed) {
    const parsed = parsedUrl(url);
    if (!parsed || parsed.protocol !== "https:" || parsed.username || parsed.password) return false;
    const host = parsed.hostname.toLowerCase();
    return allowed.some((entry) => host === entry || host.endsWith(`.${entry}`));
  },
};

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32(text: string): Uint8Array | null {
  const clean = text.replace(/[\s=-]/g, "").toUpperCase();
  if (!clean) return null;
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const character of clean) {
    const index = BASE32.indexOf(character);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return bytes.length ? new Uint8Array(bytes) : null;
}

export const totp: typeof Contract.totp = {
  parse(uri) {
    const parsed = parsedUrl(uri);
    if (!parsed || parsed.protocol !== "otpauth:" || parsed.host !== "totp") return null;
    const secret = base32(parsed.searchParams.get("secret") ?? "");
    if (!secret) return null;
    const period = Number(parsed.searchParams.get("period") ?? 30);
    const digits = Number(parsed.searchParams.get("digits") ?? 6);
    const algorithm = (parsed.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
    if (!Number.isInteger(period) || period < 1 || ![6, 7, 8].includes(digits)) return null;
    if (algorithm !== "SHA1" && algorithm !== "SHA256" && algorithm !== "SHA512") return null;
    return { secret, period, digits, algorithm };
  },
  period: (uri) => totp.parse(uri)?.period,
  code(secret, atMs) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(atMs / 1000 / secret.period)));
    const digest = createHmac(secret.algorithm.toLowerCase().replace("sha", "sha"), secret.secret).update(counter).digest();
    const offset = digest[digest.length - 1]! & 0xf;
    const number = (digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** secret.digits;
    return String(number).padStart(secret.digits, "0");
  },
  same: (a, b) => a.length === b.length && a === b,
};

export const base64url: typeof Contract.base64url = {
  encode: (bytes) => Buffer.from(bytes).toString("base64url"),
  decode(text, longest) {
    if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
    const bytes = new Uint8Array(Buffer.from(text, "base64url"));
    return longest !== undefined && bytes.length > longest ? null : bytes;
  },
};

export const uuids: typeof Contract.uuids = {
  bytes(uuid) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) return null;
    return new Uint8Array(Buffer.from(uuid.replace(/-/g, ""), "hex"));
  },
  string(bytes) {
    if (bytes.length !== 16) return null;
    const hex = Buffer.from(bytes).toString("hex");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  },
};

const UNREACHABLE_HINTS = [
  "getaddrinfo", "enotfound", "econnrefused", "econnreset", "etimedout", "ehostunreach", "enetunreach", "fetch failed",
  "network error", "unable to connect", "could not resolve host", "no such host", "certificate",
];
const OUTDATED_HINTS = ["unknown option", "unknown command", "unrecognized option", "unexpected argument", "please update"];
const ESCAPE_CODES = /\x1B\[[0-9;?]*[A-Za-z]/g;

export const verbs: typeof Contract.verbs = {
  mentions(result, needles) {
    const haystack = result.stderr.toLowerCase();
    return needles.some((needle) => haystack.includes(needle.toLowerCase()));
  },
  problem(result, offline) {
    if (result.cancelled) return "cancelled";
    if (!result.launched) return "notLaunched";
    if (result.timedOut) return "timedOut";
    if (result.overflowed) return "overflowed";
    if (result.succeeded) return "unreadable";
    if (verbs.mentions(result, UNREACHABLE_HINTS)) return offline ? "offline" : "unreachable";
    if (verbs.mentions(result, OUTDATED_HINTS)) return "outdated";
    return "failed";
  },
  check(result, hints: RunHints, offline) {
    if (result.succeeded) return;
    if (!result.cancelled && !result.timedOut && result.launched) {
      if (hints.locked && verbs.mentions(result, hints.locked)) throw CredentialError.locked();
      if (hints.signedOut && verbs.mentions(result, hints.signedOut)) throw CredentialError.signedOut();
      if (hints.notFound && verbs.mentions(result, hints.notFound)) throw CredentialError.notFound();
    }
    const problem = verbs.problem(result, offline);
    const line = problem === "failed" ? verbs.firstLine(result) : null;
    throw CredentialError.failed(problem, line ? { detail: line } : {});
  },
  firstLine(result) {
    const lines = result.stderr.replace(ESCAPE_CODES, "").split(/\r?\n/).map((line) => line.trim());
    let line = lines.find((entry) => entry) ?? "";
    if (line.toLowerCase().startsWith("error:")) line = line.slice(6).trim();
    if (!line) return null;
    return line.length > CREDENTIAL_LIMITS.detailLength ? line.slice(0, CREDENTIAL_LIMITS.detailLength) : line;
  },
  unreachableHints: UNREACHABLE_HINTS,
  outdatedHints: OUTDATED_HINTS,
};

export const credentialHandlersOf: typeof Contract.credentialHandlersOf = (provider) =>
  CREDENTIAL_HANDLERS.filter((name) => handlerOf(provider, name) !== undefined);

let defined: CredentialProvider | null = null;

export const definedProvider = () => defined;

export const defineCredentialProvider: typeof Contract.defineCredentialProvider = async (provider) => {
  defined = provider;
};

type AnyHandler = (input: unknown, ctx: CredentialContext) => unknown;

function handlerOf(provider: CredentialProvider, name: CredentialHandlerName): AnyHandler | undefined {
  if (name === "passkeys.list") return provider.passkeys?.list as AnyHandler | undefined;
  if (name === "passkeys.get") return provider.passkeys?.get as AnyHandler | undefined;
  if (name === "passkeys.save") return provider.passkeys?.save as AnyHandler | undefined;
  return provider[name] as AnyHandler | undefined;
}

export function missingHandlers(provider: CredentialProvider, capabilities: readonly string[]): string[] {
  const handled = new Set(credentialHandlersOf(provider));
  const missing = REQUIRED_CREDENTIAL_HANDLERS.filter((name) => !handled.has(name)).map((name) => `missing ${name}`);
  for (const capability of capabilities) {
    const options = CAPABILITY_HANDLERS[capability as keyof typeof CAPABILITY_HANDLERS] ?? [];
    if (options.length && !options.some((set) => set.every((name) => handled.has(name)))) missing.push(`doesn't handle ${capability}`);
  }
  return missing;
}

type Slot = { type: string; pattern?: string; values?: string[]; optional?: boolean };
type ArgvElement = string | { slot?: string; flag?: string; when?: string };
type EnvEntry = { name: string; literal?: string; secretSlot?: string; testFolder?: string; testLiteral?: string };
type Verb = {
  argv: ArgvElement[];
  slots?: Record<string, Slot>;
  env?: EnvEntry[];
  stdin?: { slot: string; encoding: "utf8" | "base64" };
  timeoutMs?: number;
  outputLimitBytes?: number;
  output: { mode: "json" | "lines" | "lastLineSecret" | "stream"; items?: string };
  signIn?: boolean;
  unlocks?: boolean | { persistent: boolean };
  outlivesCall?: boolean;
  hints?: Record<string, string[]>;
};
type CliSpec = { name: string; patterns?: Record<string, string>; env?: EnvEntry[]; verbs: Record<string, Verb> };

export const contributionOf = (manifest: unknown) =>
  (manifest as { name: string; contributes: { credentialProvider: { title: string; capabilities?: string[]; cli: CliSpec } } }).contributes.credentialProvider;

const VALUE_FLAGS = new Set(["--account", "--config", "--encoding", "--format", "--session", "--output", "--response"]);

function sortedJson(value: unknown, depth = 0): string {
  if (depth > CREDENTIAL_LIMITS.stdinJsonDepth) throw new Error("too deep");
  if (Array.isArray(value)) return `[${value.map((entry) => sortedJson(entry, depth + 1)).join(",")}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${sortedJson(value[key], depth + 1)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const envNameDenied = (name: string) =>
  DENIED_ENV_PATTERNS.some((pattern) => (pattern.startsWith("*") ? name.endsWith(pattern.slice(1)) : pattern.endsWith("*") ? name.startsWith(pattern.slice(0, -1)) : name === pattern));

function deniedCommand(program: string, argv: readonly string[]): string | null {
  const globals = GLOBAL_FLAGS[program] ?? [];
  let start = 0;
  while (start < argv.length) {
    const token = argv[start]!;
    const name = token.split("=")[0]!;
    if (!globals.includes(name)) break;
    start += !token.includes("=") && VALUE_FLAGS.has(name) ? 2 : 1;
  }
  const rest = argv.slice(start);
  for (const denied of DENIED_COMMANDS[program] ?? []) {
    const matches = denied.argv.every((token, index) => rest[index] === token);
    const flagged = denied.withFlag === undefined || rest.some((token) => token === denied.withFlag || token.startsWith(`${denied.withFlag}=`));
    if (matches && flagged) return `${program} ${denied.argv.join(" ")} is never allowed.`;
  }
  return null;
}

export const buildVerbLaunch: typeof Contract.buildVerbLaunch = (manifest, verbId, params, secrets, testFolder) => {
  const cli = contributionOf(manifest).cli;
  const verb = cli.verbs[verbId];
  if (!verb) return { refused: `${cli.name} has no verb ${verbId}.` };
  const slots = verb.slots ?? {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && !slots[key]) return { refused: `${verbId} has no slot named ${key}.` };
  }
  if (Object.keys(params).length > CREDENTIAL_LIMITS.verbParams) return { refused: `${verbId} takes at most ${CREDENTIAL_LIMITS.verbParams} params.` };
  const values = new Map<string, string | boolean | unknown>();
  for (const [name, slot] of Object.entries(slots)) {
    const value = params[name];
    if (value === undefined) {
      if (!slot.optional) return { refused: `${name} is required for ${verbId}.` };
      continue;
    }
    if (isSecretHandle(value) && slot.type !== "secret") return { refused: "a handle only goes in a secret slot." };
    const text = typeof value === "string" ? value : null;
    switch (slot.type) {
      case "id": {
        const pattern = cli.patterns?.[slot.pattern ?? ""];
        if (text === null || !pattern || text.length > CREDENTIAL_LIMITS.idSlotLength || text.startsWith("-") || !new RegExp(pattern).test(text)) {
          return { refused: `${name} for ${verbId} must match ${slot.pattern}.` };
        }
        values.set(name, text);
        break;
      }
      case "enum":
        if (text === null || !(slot.values ?? []).includes(text)) return { refused: `${name} for ${verbId} must be one of ${(slot.values ?? []).join(", ")}.` };
        values.set(name, text);
        break;
      case "flag":
        if (typeof value !== "boolean") return { refused: `${name} for ${verbId} must be true or false.` };
        values.set(name, value);
        break;
      case "url": {
        const parsed = text === null ? null : parsedUrl(text);
        if (!parsed || parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || /\s/.test(text!) || text!.length > CREDENTIAL_LIMITS.urlSlotLength) {
          return { refused: `${name} for ${verbId} must be an https address.` };
        }
        values.set(name, text);
        break;
      }
      case "email":
        if (text === null || !text.includes("@") || /\s/.test(text) || text.startsWith("-") || text.length > CREDENTIAL_LIMITS.emailSlotLength) {
          return { refused: `${name} for ${verbId} must be an email address.` };
        }
        values.set(name, text);
        break;
      case "code":
        if (text === null || !new RegExp(CREDENTIAL_LIMITS.codeSlotPattern).test(text)) return { refused: `${name} for ${verbId} must be 1 to 64 letters and digits.` };
        values.set(name, text);
        break;
      case "secret": {
        if (!isSecretHandle(value)) return { refused: `${name} for ${verbId} must be a handle.` };
        const secret = secrets(value);
        if (secret === null) return { refused: `${value.$secret} was used or has ended.` };
        if (new TextEncoder().encode(secret).length > CREDENTIAL_LIMITS.secretBytes) return { refused: `${name} for ${verbId} is too long.` };
        values.set(name, secret);
        break;
      }
      case "json": {
        let encoded: string;
        try {
          encoded = sortedJson(value);
        } catch {
          return { refused: `${name} for ${verbId} is nested too deeply.` };
        }
        if (encoded.length > CREDENTIAL_LIMITS.stdinBytes) return { refused: `${name} for ${verbId} is too big.` };
        values.set(name, encoded);
        break;
      }
      default:
        return { refused: `${name} for ${verbId} has an unknown type.` };
    }
  }
  const argv: string[] = [];
  for (const element of verb.argv) {
    if (typeof element === "string") {
      argv.push(element);
    } else if (element.when !== undefined) {
      if (values.get(element.when) === true) argv.push(element.flag!);
    } else if (values.has(element.slot!)) {
      const value = String(values.get(element.slot!));
      if (/[\u0000\n\r]/.test(value)) return { refused: `${element.slot} for ${verbId} has a newline or NUL.` };
      if (element.flag) argv.push(`${element.flag}=${value}`);
      else if (value.startsWith("-")) return { refused: `${element.slot} for ${verbId} can't start with -.` };
      else argv.push(value);
    }
  }
  if (argv.includes("--")) return { refused: "a lone -- is never allowed." };
  const denied = deniedCommand(cli.name, argv);
  if (denied) return { refused: denied };
  const env: Record<string, string> = {};
  for (const entry of [...(cli.env ?? []), ...(verb.env ?? [])]) {
    if (entry.testFolder === undefined && envNameDenied(entry.name)) return { refused: `${entry.name} is never passed.` };
    if (entry.literal !== undefined) env[entry.name] = entry.literal;
    else if (entry.secretSlot !== undefined) {
      const value = values.get(entry.secretSlot);
      if (typeof value === "string") env[entry.name] = value;
    } else if (entry.testFolder !== undefined) {
      if (testFolder !== null) env[entry.name] = entry.testFolder ? `${testFolder}/${entry.testFolder}` : testFolder;
    } else if (entry.testLiteral !== undefined) {
      if (testFolder !== null) env[entry.name] = entry.testLiteral;
    }
  }
  let stdin = "";
  if (verb.stdin) {
    const raw = String(values.get(verb.stdin.slot) ?? "");
    stdin = verb.stdin.encoding === "base64" ? Buffer.from(raw, "utf8").toString("base64") : raw;
  }
  const timeoutMs = Math.min(Math.max(verb.timeoutMs ?? VERB_TIMEOUTS_MS.default, VERB_TIMEOUTS_MS.least), VERB_TIMEOUTS_MS.most);
  return { verb: verbId, argv, env, stdin, timeoutMs, signIn: verb.signIn === true };
};

function lenientJson(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    const closing = Math.max(text.lastIndexOf("}"), text.lastIndexOf("]"));
    for (let start = 0, tried = 0; start < closing && tried < 64; start++) {
      if (text[start] !== "{" && text[start] !== "[") continue;
      tried++;
      try {
        return { ok: true, value: JSON.parse(text.slice(start, closing + 1)) };
      } catch {
        continue;
      }
    }
    return { ok: false };
  }
}

function refusalCode(reason: string): string {
  if (reason.includes("was used or has ended")) return "expired";
  if (reason.includes("is never allowed")) return "denied";
  if (reason.includes("has no verb")) return "refused";
  return "bad_request";
}

function containsHandle(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsHandle);
  if (isRecord(value)) return "$secret" in value || Object.values(value).some(containsHandle);
  return false;
}

const encodedBytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

function pagesOf(items: readonly ListedItem[]): ListedItem[][] {
  const pages: ListedItem[][] = [];
  let page: ListedItem[] = [];
  let bytes = 0;
  for (const item of items) {
    const size = encodedBytes(item) + 1;
    if (page.length && bytes + size > CREDENTIAL_LIMITS.pageBytes) {
      pages.push(page);
      page = [];
      bytes = 0;
    }
    page.push(item);
    bytes += size;
  }
  pages.push(page);
  return pages;
}

type Running = { callId: string; outlivesCall: boolean; signIn: boolean; finish(result: Partial<VerbResult>): void };
type TypedHandle = { value: string; call: string; epoch: number; launches: number; spent: boolean };
type OpenCall = { id: string; open: boolean; answer(answer: HarnessAnswer): void; cancelListeners: Set<() => void> };

export function createCredentialHarness(options: { provider: CredentialProvider; manifest: unknown; cli: FakeCli; context?: HarnessContext }): CredentialHarness & {
  readonly signInRun: SignInRunState;
  readonly confirmations: readonly string[];
  readonly running: number;
  cancel(): Promise<void>;
} {
  const contribution = contributionOf(options.manifest);
  const context = options.context ?? {};
  const testFolder = context.testInstance ? "/scratch/Password Managers/protonpass" : null;
  let epoch = 0;
  let calls = 0;
  let handles = 0;
  let verbIds = 0;
  let session: { key: string | null } | null = context.session === undefined ? null : context.session;
  let storedSession = context.storedSession ?? null;
  let signInRun: SignInRunState = { state: "none", hints: [] };
  const scratch: Record<string, string> = { ...context.scratch };
  const preferences: Record<string, string> = { ...context.preferences };
  const launches: FakeLaunch[] = [];
  const refused: { verb: string; reason: string }[] = [];
  const confirmations: string[] = [];
  const typed = new Map<string, TypedHandle>();
  const reusable = new Map<string, { value: string; call: string; epoch: number }>();
  const running = new Set<Running>();
  const openCalls = new Set<OpenCall>();
  const held = new Map<string, { pages: ListedItem[][]; until: number }>();
  let currentSignIn: Running | null = null;
  let snapshots = 0;

  const mint = () => `h${++handles}`;

  const resolveSecret = (callId: string, handle: SecretHandle): string | null => {
    const typedHandle = typed.get(handle.$secret);
    if (typedHandle) return typedHandle.spent || typedHandle.epoch !== epoch ? null : typedHandle.value;
    const kept = reusable.get(handle.$secret);
    return kept && kept.call === callId && kept.epoch === epoch ? kept.value : null;
  };

  const consumedHandles = (verbId: string, params: VerbParams) => {
    const slots = contribution.cli.verbs[verbId]?.slots ?? {};
    return Object.entries(params).flatMap(([name, value]) => (slots[name]?.type === "secret" && isSecretHandle(value) ? [value.$secret] : []));
  };

  function redact(text: string, secretValues: readonly string[]): string {
    let cleaned = text;
    for (const value of secretValues) if (value.length >= 3) cleaned = cleaned.split(value).join("[hidden]");
    return cleaned;
  }

  function redactValue(value: unknown, secretValues: readonly string[]): unknown {
    if (typeof value === "string") return redact(value, secretValues);
    if (Array.isArray(value)) return value.map((entry) => redactValue(entry, secretValues));
    if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, redactValue(entry, secretValues)]));
    return value;
  }

  function jsonStrings(value: unknown): string[] {
    if (typeof value === "string") return value.length >= 6 ? [value] : [];
    if (Array.isArray(value)) return value.flatMap(jsonStrings);
    if (isRecord(value)) return Object.values(value).flatMap(jsonStrings);
    return [];
  }

  function makeVerb(call: OpenCall, verbId: string, params: VerbParams, verbOptions: VerbOptions): RunningVerb {
    const id = ++verbIds;
    let cancelRun: () => void = () => {};
    const promise = new Promise<VerbResult>((resolve, reject) => {
      if (!call.open) return reject(new PluginError("closed", `The call ${call.id} has ended.`));
      const startEpoch = epoch;
      const verb = contribution.cli.verbs[verbId];
      if (verb && [...running].filter((entry) => !entry.outlivesCall || entry.callId === call.id).length >= CREDENTIAL_LIMITS.runningVerbs) {
        return reject(new PluginError("overloaded", `${contribution.title} has ${CREDENTIAL_LIMITS.runningVerbs} commands running.`));
      }
      const built = buildVerbLaunch(options.manifest, verbId, params, (handle) => resolveSecret(call.id, handle), testFolder);
      if ("refused" in built) {
        refused.push({ verb: verbId, reason: built.refused });
        return reject(new PluginError(refusalCode(built.refused), built.refused));
      }
      const spec = verb!;
      const timeoutMs = Math.min(verbOptions.timeoutMs ?? built.timeoutMs, built.timeoutMs);
      const launch: FakeLaunch = { ...built, timeoutMs };
      const usedHandles = consumedHandles(verbId, params);
      const secretValues = usedHandles.flatMap((handle) => {
        const value = typed.get(handle)?.value ?? reusable.get(handle)?.value;
        return value ? [value] : [];
      });
      for (const handle of usedHandles) {
        const entry = typed.get(handle);
        if (entry) entry.launches += 1;
      }
      const stdinStrings = spec.stdin ? jsonStrings(params[spec.stdin.slot]) : [];
      launches.push(launch);
      let finished = false;
      const entry: Running = {
        callId: call.id,
        outlivesCall: spec.outlivesCall === true,
        signIn: spec.signIn === true,
        finish: (partial) => complete({ stdout: "", stderr: "" }, partial),
      };
      running.add(entry);
      if (entry.signIn) {
        currentSignIn?.finish({ cancelled: true });
        currentSignIn = entry;
        signInRun = { state: "running", hints: [] };
      }
      cancelRun = () => entry.finish({ cancelled: true });

      const complete = (reply: FakeReply, override: Partial<VerbResult> = {}) => {
        if (finished) return;
        finished = true;
        running.delete(entry);
        if (currentSignIn === entry) currentSignIn = null;
        const rawStderr = reply.stderr ?? "";
        const stdout = reply.stdout ?? "";
        const overflowed = new TextEncoder().encode(stdout).length > (spec.outputLimitBytes ?? CREDENTIAL_LIMITS.defaultOutputBytes);
        const cancelled = override.cancelled === true;
        const timedOut = !cancelled && (override.timedOut === true || reply.timedOut === true);
        const status = cancelled || timedOut ? -1 : (reply.status ?? 0);
        let jsonValue: unknown = null;
        let items = 0;
        let lines: string[] = [];
        let itemOverflow = false;
        let unlockedKey: string | null = null;
        if (!cancelled && !timedOut && !overflowed) {
          if (spec.output.mode === "json") {
            const parsed = lenientJson(stdout);
            if (parsed.ok) {
              const value = redactValue(parsed.value, secretValues);
              const key = spec.output.items;
              const array = key === undefined ? null : key === "$" ? value : isRecord(value) ? value[key] : undefined;
              if (key === undefined) jsonValue = value;
              else if (Array.isArray(array)) {
                for (const element of array) {
                  if (encodedBytes(element) > CREDENTIAL_LIMITS.outputItemBytes) {
                    itemOverflow = true;
                    break;
                  }
                  verbOptions.onItem?.(element, items++);
                }
                jsonValue = key === "$" ? [] : Object.fromEntries(Object.entries(value as JsonRecord).filter(([name]) => name !== key));
              }
            }
          } else if (spec.output.mode === "lines") {
            lines = stdout.split("\n").map((line) => line.replace(/\r$/, ""));
            if (lines.at(-1) === "") lines.pop();
            lines = lines.map((line) => redact(line, secretValues));
          } else if (spec.output.mode === "lastLineSecret") {
            const last = stdout.split("\n").map((line) => line.trim()).filter(Boolean).at(-1) ?? "";
            if (/^\S{16,4096}$/.test(last)) unlockedKey = last;
          }
        }
        const finalOverflowed = overflowed || itemOverflow;
        const succeeded = !cancelled && !timedOut && !finalOverflowed && status === 0;
        const hints = Object.entries(spec.hints ?? {}).flatMap(([hint, needles]) => (needles.some((needle) => rawStderr.toLowerCase().includes(needle.toLowerCase())) ? [hint] : []));
        const stderr = redact(redact(rawStderr.replace(ESCAPE_CODES, ""), secretValues), stdinStrings).slice(0, CREDENTIAL_LIMITS.stderrBytes);
        let unlocked = false;
        if (succeeded && spec.unlocks && epoch === startEpoch) {
          session = { key: spec.output.mode === "lastLineSecret" ? unlockedKey : null };
          unlocked = true;
        }
        for (const handle of usedHandles) {
          const typedHandle = typed.get(handle);
          if (typedHandle && (succeeded || typedHandle.launches >= CREDENTIAL_LIMITS.typedSecretLaunches)) typedHandle.spent = true;
        }
        if (entry.signIn && !cancelled) {
          const failedLine = verbs.firstLine({ stderr } as VerbResult);
          signInRun = succeeded ? { state: "succeeded", hints } : { state: "failed", hints, ...(failedLine ? { detail: failedLine } : {}), ...(timedOut ? { timedOut } : {}) };
        }
        resolve({
          verb: verbId,
          status,
          launched: true,
          timedOut,
          cancelled,
          overflowed: finalOverflowed,
          succeeded,
          stderr,
          hints,
          json: jsonValue,
          lines,
          items,
          droppedLines: 0,
          unlocked,
        });
      };

      Promise.resolve()
        .then(() => options.cli(launch))
        .then(
          (reply) => {
            if (finished) return;
            for (const line of reply.lines ?? []) {
              if (spec.output.mode === "stream" && call.open) verbOptions.onLine?.({ stream: line.stream, text: redact(line.text, secretValues) });
            }
            const after = reply.finishAfterMs ?? 0;
            if (after > timeoutMs) setTimeout(() => complete(reply, { timedOut: true }), timeoutMs);
            else if (after > 0) setTimeout(() => complete(reply), after);
            else complete(reply);
          },
          () => {
            if (finished) return;
            finished = true;
            running.delete(entry);
            resolve({ verb: verbId, status: -1, launched: false, timedOut: false, cancelled: false, overflowed: false, succeeded: false, stderr: "", hints: [], json: null, lines: [], items: 0, droppedLines: 0, unlocked: false });
          },
        );
    });
    return Object.assign(promise, { id, cancel: () => cancelRun() });
  }

  const valueStore = (store: Record<string, string>) => ({
    get: (key: string) => store[key],
    async set(key: string, value: string | null) {
      if (!/^[A-Za-z0-9_-]{1,40}$/.test(key) || (value !== null && new TextEncoder().encode(value).length > CREDENTIAL_LIMITS.valueBytes)) {
        throw new PluginError("bad_request", `${key} can't be stored.`);
      }
      if (value === null) delete store[key];
      else store[key] = value;
    },
  });

  function contextFor(call: OpenCall, name: CredentialHandlerName, deadline: number): CredentialContext {
    const callEpoch = epoch;
    const guard = () => {
      if (!call.open) throw new PluginError("closed", `The call ${call.id} has ended.`);
      if (epoch !== callEpoch) throw new PluginError("stale", `${contribution.title} locked, so this call ended.`);
    };
    const sessionHandle = session?.key ? (() => {
      const handle = mint();
      reusable.set(handle, { value: session!.key!, call: call.id, epoch });
      return { $secret: handle };
    })() : null;
    const sessionView = session ? { key: sessionHandle } : null;
    return {
      kind: "credentials",
      name,
      callId: call.id,
      context: {},
      caller: null,
      deadline,
      signal: {
        get cancelled() {
          return !call.open;
        },
        onCancel(listener: () => void) {
          call.cancelListeners.add(listener);
          return { dispose: () => call.cancelListeners.delete(listener) };
        },
      },
      epoch: `e${callEpoch}`,
      provider: (options.manifest as { name: string }).name,
      touchID: context.touchID ?? false,
      offline: context.offline ?? false,
      cli: {
        name: contribution.cli.name,
        version: "1.0.0",
        get signInRun() {
          return signInRun;
        },
        verb(id, params = {}, verbOptions = {}) {
          try {
            guard();
          } catch (error) {
            return Object.assign(Promise.reject(error), { id: ++verbIds, cancel() {} });
          }
          return makeVerb(call, id, params, verbOptions);
        },
        async cancelSigningIn() {
          guard();
          currentSignIn?.finish({ cancelled: true });
          signInRun = { state: "none", hints: [] };
        },
      },
      session: {
        get current() {
          return epoch === callEpoch ? sessionView : null;
        },
        get hasStored() {
          return storedSession !== null;
        },
        async takeStored(reason) {
          guard();
          if (reason.length > CREDENTIAL_LIMITS.ownerReasonLength) throw new PluginError("bad_request", "reason is too long.");
          if (storedSession === null) return null;
          const handle = mint();
          reusable.set(handle, { value: storedSession, call: call.id, epoch });
          return { $secret: handle };
        },
        async dropStored() {
          guard();
          storedSession = null;
        },
      },
      scratch: valueStore(scratch),
      preferences: valueStore(preferences),
      owner: {
        async confirm(reason) {
          guard();
          if (reason.length > CREDENTIAL_LIMITS.ownerReasonLength) throw new PluginError("bad_request", "reason is too long.");
          confirmations.push(reason);
          return context.ownerConfirms ?? true;
        },
      },
    };
  }

  function wireError(error: unknown): HarnessAnswer {
    if (error instanceof CredentialError) return { ok: false, error: error.toWire() };
    if (error instanceof PluginError && error.code === "stale") return { ok: false, error: { code: "stale" } };
    const detail = error instanceof Error ? error.message : String(error);
    return { ok: false, error: { code: "failed", problem: "failed", detail } };
  }

  function finishCall(call: OpenCall, answer: HarnessAnswer, stopsEverything = false) {
    if (!call.open) return;
    call.open = false;
    openCalls.delete(call);
    for (const listener of [...call.cancelListeners]) listener();
    for (const entry of [...running]) if (entry.callId === call.id && (stopsEverything || !entry.outlivesCall)) entry.finish({ cancelled: true });
    for (const [handle, entry] of typed) if (entry.call === call.id) typed.set(handle, { ...entry, spent: true });
    for (const [handle, entry] of reusable) if (entry.call === call.id) reusable.delete(handle);
    call.answer(answer);
  }

  function pageAnswer(snapshot: string, cursor: number): HarnessAnswer {
    const kept = held.get(snapshot);
    if (!kept || kept.until < Date.now()) return { ok: false, error: { code: "failed", problem: "failed", detail: "That listing ended." } };
    const page = kept.pages[cursor] ?? [];
    const next = cursor + 1 < kept.pages.length ? { cursor: String(cursor + 1) } : {};
    if (!("cursor" in next)) held.delete(snapshot);
    const result: ItemPage = { snapshot, items: page, ...next };
    return { ok: true, result };
  }

  function settle(name: CredentialHandlerName, callEpoch: number, value: unknown): HarnessAnswer {
    if (name === "signIn" || name === "unlock") {
      const outcome = value as SignInOutcome;
      if (outcome.ok) {
        const handle = outcome.session?.$secret;
        if (handle && !reusable.has(handle)) return { ok: false, error: { code: "invalid" } };
        if (epoch === callEpoch && (handle || !session)) session = { key: handle ? reusable.get(handle)!.value : null };
        return { ok: true, result: { ok: true } };
      }
    }
    if (containsHandle(value)) return { ok: false, error: { code: "invalid" } };
    if (name === "list" && Array.isArray(value)) {
      const snapshot = `s${++snapshots}`;
      held.set(snapshot, { pages: pagesOf(value as ListedItem[]), until: Date.now() + CREDENTIAL_LIMITS.heldSnapshotMs });
      return pageAnswer(snapshot, 0);
    }
    if (encodedBytes(value ?? null) > CREDENTIAL_LIMITS.resultBytes) return { ok: false, error: { code: "tooLarge" } };
    return { ok: true, result: value ?? null };
  }

  return {
    get launches() {
      return launches;
    },
    get refused() {
      return refused;
    },
    get session() {
      return session;
    },
    get storedSession() {
      return storedSession;
    },
    get scratch() {
      return scratch;
    },
    get preferences() {
      return preferences;
    },
    get signInRun() {
      return signInRun;
    },
    get confirmations() {
      return confirmations;
    },
    get running() {
      return running.size;
    },
    secret(value) {
      const handle = mint();
      typed.set(handle, { value, call: "", epoch, launches: 0, spent: false });
      return { $secret: handle };
    },
    async lock() {
      epoch += 1;
      session = null;
      for (const entry of [...running]) entry.finish({ cancelled: true });
      for (const call of [...openCalls]) finishCall(call, { ok: false, error: { code: "stale" } });
    },
    async cancel() {
      for (const call of [...openCalls]) finishCall(call, { ok: false, error: { code: "cancelled" } }, true);
    },
    async advance(ms) {
      const step = 250;
      for (let passed = 0; passed < ms; passed += step) {
        mock.timers.tick(Math.min(step, ms - passed));
        for (let flush = 0; flush < 5; flush++) await new Promise((resolve) => setImmediate(resolve));
      }
    },
    call(name, input) {
      const id = `v${++calls}`;
      const callEpoch = epoch;
      if (name === "list") {
        const request = input as { snapshot: string | null; cursor: string | null };
        if (request.snapshot !== null) return Promise.resolve(pageAnswer(request.snapshot, Number(request.cursor ?? 0)));
      }
      return new Promise<HarnessAnswer>((resolve) => {
        const call: OpenCall = { id, open: true, answer: resolve, cancelListeners: new Set() };
        openCalls.add(call);
        for (const [handle, entry] of typed) if (entry.call === "") typed.set(handle, { ...entry, call: id, epoch: callEpoch });
        const handler = handlerOf(options.provider, name);
        if (!handler) return finishCall(call, { ok: false, error: { code: "unsupported" } });
        const deadline = CREDENTIAL_DEADLINES_MS[name];
        const timer = setTimeout(() => finishCall(call, { ok: false, error: { code: "timedOut" } }, true), deadline);
        Promise.resolve()
          .then(() => handler(input, contextFor(call, name, deadline)))
          .then(
            (value) => finishCall(call, settle(name, callEpoch, value)),
            (error) => finishCall(call, wireError(error)),
          )
          .finally(() => clearTimeout(timer));
      });
    },
  };
}

export const PROTOCOL = { current: CREDENTIALS_PROTOCOL, supported: CREDENTIALS_PROTOCOLS_SUPPORTED };
export type { StreamLine };
