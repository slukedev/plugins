import type { Transport } from "./rpc";
import {
  CREDENTIALS_PROTOCOL,
  CREDENTIALS_PROTOCOLS_SUPPORTED,
  CREDENTIAL_LIMITS,
  DENIED_COMMANDS,
  GLOBAL_FLAGS,
  HOST_ENV,
  VERB_TIMEOUTS_MS,
  type CredentialHandlerName,
  type CredentialHarness,
  type CredentialProvider,
  type FakeCli,
  type FakeLaunch,
  type FakeReply,
  type HarnessAnswer,
  type HarnessContext,
  type HarnessInputs,
  type SecretHandle,
  type StreamLine,
  type VerbParams,
  type WireCredentialError,
} from "./credentials";
import { isSecretHandle, runCredentialProvider, utf8Bytes, utf8Length } from "./credentialsRuntime";

type JsonObject = Record<string, unknown>;

type SlotDefinition = { type: string; pattern?: string; values?: string[]; optional?: boolean };
type ArgvElement = string | { slot?: string; flag?: string; when?: string };
type EnvEntry = { name: string; literal?: string; secretSlot?: string; testFolder?: string; testLiteral?: string };
type VerbDefinition = {
  argv: ArgvElement[];
  slots?: Record<string, SlotDefinition>;
  env?: EnvEntry[];
  stdin?: { slot: string; encoding?: "utf8" | "base64" };
  timeoutMs?: number;
  outputLimitBytes?: number;
  output?: { mode?: "json" | "lines" | "lastLineSecret" | "stream"; items?: string };
  signIn?: boolean;
  unlocks?: boolean | { persistent?: boolean };
  outlivesCall?: boolean;
  hints?: Record<string, string[]>;
};
type CliDefinition = {
  name: string;
  patterns?: Record<string, string>;
  env?: EnvEntry[];
  onLock?: { verb: string; params?: Record<string, { from?: string; key?: string; literal?: string }>; skipWithTouchID?: boolean };
  verbs: Record<string, VerbDefinition>;
};
type Contribution = { title?: string; cli: CliDefinition };

type RefusalCode = "refused" | "bad_request" | "expired" | "denied";
type Built = { launch: FakeLaunch; definition: VerbDefinition; consumed: string[]; jsonStrings: string[] } | { code: RefusalCode; message: string };

const isObject = (value: unknown): value is JsonObject => typeof value === "object" && value !== null && !Array.isArray(value);

export function contributionOf(manifest: unknown): Contribution {
  const root = isObject(manifest) ? manifest : {};
  const contributes = isObject(root.contributes) ? root.contributes : null;
  const contribution = contributes && isObject(contributes.credentialProvider) ? contributes.credentialProvider : root;
  if (!isObject(contribution) || !isObject(contribution.cli)) throw new Error("The manifest has no contributes.credentialProvider.cli.");
  return contribution as unknown as Contribution;
}

const CODE_SLOT = new RegExp(CREDENTIAL_LIMITS.codeSlotPattern);
const VALUED_GLOBAL_FLAGS: Readonly<Record<string, readonly string[]>> = {
  op: ["--account", "--config", "--encoding", "--format", "--session", "--cache"],
  bw: ["--session", "--response"],
  "pass-cli": ["--output"],
};

function hasBreak(text: string): boolean {
  return /[\n\r\0]/.test(text);
}

function isHttpsUrl(text: string): boolean {
  if (text.length > CREDENTIAL_LIMITS.urlSlotLength || /\s/.test(text)) return false;
  const match = /^https:\/\/([^/?#]*)/i.exec(text);
  if (!match) return false;
  const authority = match[1]!;
  return authority.length > 0 && !authority.includes("@");
}

function sortedJson(value: unknown, depth = 0): string {
  if (depth > CREDENTIAL_LIMITS.stdinJsonDepth) throw new Error("too deep");
  if (Array.isArray(value)) return `[${value.map((entry) => sortedJson(entry, depth + 1)).join(",")}]`;
  if (isObject(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${sortedJson(value[key], depth + 1)}`).join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("not JSON");
  return encoded;
}

function stringsOf(value: unknown, into: string[] = []): string[] {
  if (typeof value === "string") into.push(value);
  else if (Array.isArray(value)) for (const entry of value) stringsOf(entry, into);
  else if (isObject(value)) for (const entry of Object.values(value)) stringsOf(entry, into);
  return into;
}

function base64(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const chunk = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += alphabet[(chunk >> 18) & 63]! + alphabet[(chunk >> 12) & 63]!;
    out += i + 1 < bytes.length ? alphabet[(chunk >> 6) & 63]! : "=";
    out += i + 2 < bytes.length ? alphabet[chunk & 63]! : "=";
  }
  return out;
}

function deniedReason(program: string, argv: readonly string[]): string | null {
  if (argv.some((token) => token === "--" || hasBreak(token))) return `${program} ${argv[0] ?? ""} is never allowed.`;
  const globals = GLOBAL_FLAGS[program] ?? [];
  const valued = VALUED_GLOBAL_FLAGS[program] ?? [];
  const command: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    const flag = token.split("=")[0]!;
    if (command.length === 0 && token.startsWith("-") && globals.includes(flag)) {
      if (!token.includes("=") && valued.includes(flag)) i++;
      continue;
    }
    if (token.startsWith("-")) break;
    command.push(token);
  }
  for (const denied of DENIED_COMMANDS[program] ?? []) {
    if (denied.argv.every((part, i) => command[i] === part)) {
      const flagged = denied.withFlag === undefined || argv.some((token) => token === denied.withFlag || token.startsWith(`${denied.withFlag}=`));
      if (flagged) return `${program} ${denied.argv.join(" ")}${denied.withFlag ? ` ${denied.withFlag}` : ""} is never allowed.`;
    }
  }
  return null;
}

function buildVerb(manifest: unknown, verbId: string, params: VerbParams, secrets: (handle: SecretHandle) => string | null, testFolder: string | null): Built {
  const contribution = contributionOf(manifest);
  const cli = contribution.cli;
  const definition = Object.prototype.hasOwnProperty.call(cli.verbs, verbId) ? cli.verbs[verbId] : undefined;
  if (!definition) return { code: "refused", message: `${cli.name} has no verb ${verbId}.` };
  const slots = definition.slots ?? {};
  const values: Record<string, unknown> = {};
  const consumed: string[] = [];
  const bad = (message: string): Built => ({ code: "bad_request", message });
  for (const key of Object.keys(params)) {
    if (params[key] === undefined) continue;
    if (!Object.prototype.hasOwnProperty.call(slots, key)) return bad(`${verbId} has no slot named ${key}.`);
  }
  for (const [name, slot] of Object.entries(slots)) {
    const value = params[name];
    if (value === undefined) {
      if (!slot.optional) return bad(`${name} is required for ${verbId}.`);
      continue;
    }
    if (slot.type !== "secret" && isSecretHandle(value)) return bad("a handle only goes in a secret slot.");
    switch (slot.type) {
      case "id": {
        const pattern = slot.pattern ? cli.patterns?.[slot.pattern] : undefined;
        if (typeof value !== "string" || !pattern || value.length > CREDENTIAL_LIMITS.idSlotLength || value.startsWith("-") || hasBreak(value) || !new RegExp(pattern).test(value)) {
          return bad(`${name} for ${verbId} must match ${slot.pattern}.`);
        }
        values[name] = value;
        break;
      }
      case "enum":
        if (typeof value !== "string" || !(slot.values ?? []).includes(value)) return bad(`${name} for ${verbId} must be one of ${(slot.values ?? []).join(", ")}.`);
        values[name] = value;
        break;
      case "flag":
        if (typeof value !== "boolean") return bad(`${name} for ${verbId} must be true or false.`);
        values[name] = value;
        break;
      case "url":
        if (typeof value !== "string" || !isHttpsUrl(value)) return bad(`${name} for ${verbId} must be an https address.`);
        values[name] = value;
        break;
      case "email":
        if (typeof value !== "string" || !value.includes("@") || /\s/.test(value) || value.startsWith("-") || value.length > CREDENTIAL_LIMITS.emailSlotLength) {
          return bad(`${name} for ${verbId} must be an email address.`);
        }
        values[name] = value;
        break;
      case "code":
        if (typeof value !== "string" || !CODE_SLOT.test(value)) return bad(`${name} for ${verbId} must be 1 to 64 letters and digits.`);
        values[name] = value;
        break;
      case "secret": {
        if (!isSecretHandle(value)) return bad(`${name} for ${verbId} must be a secret handle.`);
        const secret = secrets(value);
        if (secret === null) return { code: "expired", message: `${value.$secret} was used or has ended.` };
        if (utf8Length(secret) > CREDENTIAL_LIMITS.secretBytes) return bad(`${name} for ${verbId} is over ${CREDENTIAL_LIMITS.secretBytes} bytes.`);
        values[name] = secret;
        consumed.push(secret);
        break;
      }
      case "json": {
        let encoded: string;
        try {
          encoded = sortedJson(value);
        } catch {
          return bad(`${name} for ${verbId} must be JSON at most ${CREDENTIAL_LIMITS.stdinJsonDepth} deep.`);
        }
        if (utf8Length(encoded) > CREDENTIAL_LIMITS.stdinBytes) return bad(`${name} for ${verbId} is over 4 MB.`);
        values[name] = encoded;
        break;
      }
      default:
        return bad(`${name} for ${verbId} has an unknown type.`);
    }
  }
  const argv: string[] = [];
  for (const element of definition.argv) {
    if (typeof element === "string") {
      argv.push(element);
      continue;
    }
    if (element.when !== undefined) {
      if (values[element.when] === true) argv.push(element.flag!);
      continue;
    }
    const value = element.slot !== undefined ? values[element.slot] : undefined;
    if (value === undefined) continue;
    if (typeof value !== "string" || hasBreak(value)) return bad(`${element.slot} for ${verbId} can't go in argv.`);
    if (element.flag) argv.push(`${element.flag}=${value}`);
    else {
      if (value.startsWith("-")) return bad(`${element.slot} for ${verbId} can't start with -.`);
      argv.push(value);
    }
  }
  const denied = deniedReason(cli.name, argv);
  if (denied) return { code: "denied", message: denied };
  const env: Record<string, string> = {};
  for (const entry of [...(cli.env ?? []), ...(definition.env ?? [])]) {
    if (HOST_ENV.includes(entry.name)) continue;
    if (entry.literal !== undefined) env[entry.name] = entry.literal;
    else if (entry.testLiteral !== undefined) {
      if (testFolder !== null) env[entry.name] = entry.testLiteral;
    } else if (entry.testFolder !== undefined) {
      if (testFolder !== null) env[entry.name] = entry.testFolder ? `${testFolder}/${entry.testFolder}` : testFolder;
    } else if (entry.secretSlot !== undefined) {
      const value = values[entry.secretSlot];
      if (typeof value === "string") env[entry.name] = value;
    }
  }
  let stdin = "";
  const jsonStrings: string[] = [];
  if (definition.stdin) {
    const value = values[definition.stdin.slot];
    const slot = slots[definition.stdin.slot];
    if (typeof value === "string") {
      if (slot?.type === "json") stringsOf(params[definition.stdin.slot], jsonStrings);
      stdin = definition.stdin.encoding === "base64" ? base64(utf8Bytes(value)) : value;
    }
  }
  const timeoutMs = definition.timeoutMs ?? VERB_TIMEOUTS_MS.default;
  return { launch: { verb: verbId, argv, env, stdin, timeoutMs, signIn: definition.signIn === true }, definition, consumed, jsonStrings };
}

export function buildVerbLaunch(manifest: unknown, verb: string, params: VerbParams, secrets: (handle: SecretHandle) => string | null, testFolder: string | null): FakeLaunch | { refused: string } {
  const built = buildVerb(manifest, verb, params, secrets, testFolder);
  return "launch" in built ? built.launch : { refused: built.message };
}

const ESCAPE_CODES = /\x1B\[[0-9;?]*[A-Za-z]/g;
const LOG_PREFIX = /^\[[A-Za-z]+\]\s+\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+/;

function cleanStderr(text: string): string {
  const cleaned = text
    .replace(ESCAPE_CODES, "")
    .split("\n")
    .map((line) => line.replace(LOG_PREFIX, ""))
    .join("\n");
  return cleaned.length > CREDENTIAL_LIMITS.stderrBytes ? cleaned.slice(0, CREDENTIAL_LIMITS.stderrBytes) : cleaned;
}

const MOST_JSON_STARTS = 64;
const NOISE_SCAN_LIMIT = 64 * 1024;

export function tolerantJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {}
  const closing = Math.max(text.lastIndexOf("}"), text.lastIndexOf("]"));
  if (closing < 0) return undefined;
  const scanEnd = Math.min(closing, NOISE_SCAN_LIMIT);
  let tried = 0;
  for (let start = 0; start < scanEnd; start++) {
    const character = text[start];
    if (character !== "{" && character !== "[") continue;
    try {
      return JSON.parse(text.slice(start, closing + 1));
    } catch {}
    tried++;
    if (tried >= MOST_JSON_STARTS) break;
  }
  return undefined;
}

function redactText(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) if (secret.length >= 3) out = out.split(secret).join("[hidden]");
  return out;
}

function redactJson(value: unknown, secrets: readonly string[]): unknown {
  if (!secrets.length) return value;
  if (typeof value === "string") return redactText(value, secrets);
  if (Array.isArray(value)) return value.map((entry) => redactJson(entry, secrets));
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, redactJson(entry, secrets)]));
  return value;
}

type Handle = { value: string; call: string; epoch: number; kind: "typed" | "session" | "stored"; launches: number; spent: boolean };

type OpenVerb = { id: number; call: string; signIn: boolean; finish: (outcome: "cancelled") => void };

type OpenCall = { id: string; name: CredentialHandlerName; epoch: number; resolve: (answer: HarnessAnswer) => void; verbsRunning: number; sessionSet: boolean };

type Timer = { at: number; fire: () => void };

const hostTimers = globalThis as unknown as { setTimeout(callback: () => void, ms: number): unknown };

function delay(): Promise<void> {
  return new Promise((resolve) => hostTimers.setTimeout(resolve, 0));
}

export function createCredentialHarness(options: { provider: CredentialProvider; manifest: unknown; cli: FakeCli; context?: HarnessContext }): CredentialHarness {
  const contribution = contributionOf(options.manifest);
  const program = contribution.cli.name;
  const context = options.context ?? {};
  const testFolder = context.testInstance ? "/tmp/ardia-test/Password Managers/provider" : null;
  const launches: FakeLaunch[] = [];
  const refused: { verb: string; reason: string }[] = [];
  const handles = new Map<string, Handle>();
  const pendingTyped = new Map<string, string>();
  const openCalls = new Map<string, OpenCall>();
  const openVerbs = new Map<number, OpenVerb>();
  const timers: Timer[] = [];
  let epoch = 0;
  let clock = 1_763_800_000_000;
  let session: { key: string | null } | null = context.session === undefined ? null : context.session;
  let storedSession: string | null = context.storedSession ?? null;
  let scratch: Record<string, string> = { ...(context.scratch ?? {}) };
  let preferences: Record<string, string> = { ...(context.preferences ?? {}) };
  let signInRun: { state: "none" | "running" | "succeeded" | "failed"; hints: string[]; detail?: string; timedOut?: boolean } = { state: "none", hints: [] };
  let nextHandle = 0;
  let nextCall = 0;
  let pluginListener: (line: string) => void = () => {};
  let runtime: { stop(): void } | null = null;
  let ready: Promise<void> = Promise.resolve();
  let readyResolve: () => void = () => {};

  const mint = (value: string, call: string, kind: Handle["kind"]): SecretHandle => {
    const id = `h${++nextHandle}`;
    handles.set(id, { value, call, epoch, kind, launches: 0, spent: false });
    return { $secret: id };
  };

  const toPlugin = (message: Record<string, unknown>) => {
    const line = JSON.stringify(message);
    void Promise.resolve().then(() => pluginListener(line));
  };
  const reply = (id: unknown, result: unknown) => toPlugin({ id: id as number, result });
  const refuse = (id: unknown, code: string, message: string) => toPlugin({ id: id as number, error: { code, message } });

  function startRun() {
    runtime?.stop();
    ready = new Promise<void>((resolve) => (readyResolve = resolve));
    let listener: (line: string) => void = () => {};
    const transport: Transport = {
      send: (line) => onPluginLine(line),
      onLine: (registered) => (listener = registered),
    };
    pluginListener = (line) => listener(line);
    runtime = runCredentialProvider(transport, options.provider, { now: () => clock, onError: () => {} });
  }

  function onPluginLine(line: string) {
    const message = JSON.parse(line) as JsonObject;
    const id = message.id;
    const params = isObject(message.params) ? message.params : {};
    switch (message.method) {
      case "hello":
        if (params.credentials !== CREDENTIALS_PROTOCOL) return refuse(id, "refused", "This plugin speaks another credentials protocol.");
        reply(id, { app: "Ardia", version: "1.41.0", protocol: 2, plugin: "provider", values: {}, credentials: { protocol: CREDENTIALS_PROTOCOL, supported: CREDENTIALS_PROTOCOLS_SUPPORTED, provider: "provider" } });
        return;
      case "ready":
        reply(id, { ok: true });
        readyResolve();
        return;
      case "result":
        return onResult(id, params);
      default:
        if (typeof message.method === "string" && message.method.startsWith("credentials.")) return void onRequest(id, message.method, params);
        return refuse(id, "refused", "A password manager plugin can only use hello, ready, result and credentials requests.");
    }
  }

  function containsHandle(value: unknown): boolean {
    if (isSecretHandle(value)) return true;
    if (Array.isArray(value)) return value.some(containsHandle);
    if (isObject(value)) return Object.values(value).some(containsHandle);
    return false;
  }

  function endCallHandles(callId: string) {
    for (const [id, handle] of handles) if (handle.call === callId) handles.delete(id);
  }

  function onResult(id: unknown, params: JsonObject) {
    const call = typeof params.call === "string" ? openCalls.get(params.call) : undefined;
    if (!call) return refuse(id, "bad_request", `There's no call ${String(params.call)} waiting.`);
    reply(id, { ok: true });
    openCalls.delete(call.id);
    for (const verb of [...openVerbs.values()]) if (verb.call === call.id) verb.finish("cancelled");
    let answer: HarnessAnswer;
    if ("error" in params) answer = { ok: false, error: params.error as WireCredentialError };
    else {
      const result = params.result;
      if ((call.name === "signIn" || call.name === "unlock") && isObject(result) && result.ok === true && call.epoch === epoch) {
        const sessionHandle = isSecretHandle(result.session) ? handles.get(result.session.$secret) : undefined;
        if (result.session !== undefined && (!sessionHandle || sessionHandle.kind !== "stored")) answer = { ok: false, error: { code: "invalid" } };
        else {
          if (sessionHandle) session = { key: sessionHandle.value };
          else if (!call.sessionSet) session = { key: session?.key ?? null };
          const { session: _hidden, ...visible } = result;
          answer = { ok: true, result: visible };
        }
      } else if (containsHandle(result)) answer = { ok: false, error: { code: "invalid" } };
      else answer = { ok: true, result };
      if (answer.ok && call.name === "signOut") {
        epoch++;
        session = null;
        storedSession = null;
        scratch = {};
        preferences = {};
      }
    }
    endCallHandles(call.id);
    call.resolve(answer);
  }

  async function onRequest(id: unknown, method: string, params: JsonObject) {
    const call = typeof params.call === "string" ? openCalls.get(params.call) : undefined;
    if (!call) return refuse(id, "closed", `The call ${String(params.call)} has ended.`);
    if (call.epoch !== epoch) return refuse(id, "stale", "The provider locked, so this call ended.");
    switch (method) {
      case "credentials.verb":
        return runVerb(id, call, params);
      case "credentials.verb.cancel": {
        const verb = typeof params.verbOf === "number" ? openVerbs.get(params.verbOf) : undefined;
        if (verb && verb.call === call.id) verb.finish("cancelled");
        return reply(id, { ok: true });
      }
      case "credentials.signIn.cancel":
        for (const verb of [...openVerbs.values()]) if (verb.signIn) verb.finish("cancelled");
        return reply(id, { ok: true });
      case "credentials.session.takeStored": {
        if (typeof params.reason !== "string" || params.reason.length > CREDENTIAL_LIMITS.ownerReasonLength) return refuse(id, "bad_request", "reason must be at most 60 characters.");
        const handle = storedSession !== null && context.touchID ? mint(storedSession, call.id, "stored") : null;
        return reply(id, { handle });
      }
      case "credentials.session.dropStored":
        storedSession = null;
        return reply(id, { ok: true });
      case "credentials.values.set": {
        const store = params.store === "scratch" ? scratch : params.store === "preferences" ? preferences : null;
        const key = params.key;
        const value = params.value;
        if (!store || typeof key !== "string" || !/^[A-Za-z0-9_-]{1,40}$/.test(key)) return refuse(id, "bad_request", "key must be 1 to 40 letters, digits, - and _.");
        if (value !== null && (typeof value !== "string" || utf8Length(value) > CREDENTIAL_LIMITS.valueBytes)) return refuse(id, "bad_request", "value must be text of at most 1024 bytes.");
        if (value !== null && !(key in store) && Object.keys(store).length >= CREDENTIAL_LIMITS.valueKeys) return refuse(id, "bad_request", "a store holds at most 16 keys.");
        if (value === null) delete store[key];
        else store[key] = value;
        return reply(id, { ok: true });
      }
      case "credentials.owner.confirm":
        return reply(id, { confirmed: context.ownerConfirms !== false });
      default:
        return refuse(id, "refused", `${method} isn't a credentials request.`);
    }
  }

  function resolveSecret(call: OpenCall, used: Handle[]) {
    return (handle: SecretHandle): string | null => {
      const held = handles.get(handle.$secret);
      if (!held || held.spent || held.call !== call.id || held.epoch !== epoch) return null;
      used.push(held);
      return held.value;
    };
  }

  async function runVerb(id: unknown, call: OpenCall, params: JsonObject) {
    const verbId = typeof params.verb === "string" ? params.verb : "";
    const verbParams = (isObject(params.params) ? params.params : {}) as VerbParams;
    const used: Handle[] = [];
    const built = buildVerb(options.manifest, verbId, verbParams, resolveSecret(call, used), testFolder);
    if (!("launch" in built)) {
      refused.push({ verb: verbId, reason: built.message });
      return refuse(id, built.code, built.message);
    }
    if (call.verbsRunning >= CREDENTIAL_LIMITS.runningVerbs) return refuse(id, "overloaded", `The provider has ${CREDENTIAL_LIMITS.runningVerbs} commands running.`);
    const { launch, definition, consumed, jsonStrings } = built;
    const requested = typeof params.timeoutMs === "number" ? params.timeoutMs : launch.timeoutMs;
    const timeoutMs = Math.max(VERB_TIMEOUTS_MS.least, Math.min(requested, launch.timeoutMs));
    const effective = { ...launch, timeoutMs };
    launches.push(effective);
    for (const handle of used) if (handle.kind === "typed") handle.launches++;
    if (launch.signIn) {
      for (const verb of [...openVerbs.values()]) if (verb.signIn) verb.finish("cancelled");
      signInRun = { state: "running", hints: [] };
    }
    call.verbsRunning++;
    const verbOf = id as number;
    let settle: (outcome: { reply?: FakeReply; launched: boolean; cancelled?: boolean }) => void = () => {};
    const outcome = new Promise<{ reply?: FakeReply; launched: boolean; cancelled?: boolean }>((resolve) => (settle = resolve));
    openVerbs.set(verbOf, { id: verbOf, call: call.id, signIn: launch.signIn, finish: () => settle({ launched: true, cancelled: true }) });
    Promise.resolve()
      .then(() => options.cli(effective))
      .then(
        (answer) => {
          const finishAfter = answer.finishAfterMs ?? 0;
          if (answer.timedOut || finishAfter > timeoutMs) return settle({ reply: { ...answer, timedOut: true }, launched: true });
          if (finishAfter > 0) timers.push({ at: clock + finishAfter, fire: () => settle({ reply: answer, launched: true }) });
          else settle({ reply: answer, launched: true });
        },
        () => settle({ launched: false }),
      );
    const done = await outcome;
    openVerbs.delete(verbOf);
    call.verbsRunning--;
    const answer = done.reply ?? {};
    const cancelled = done.cancelled === true;
    const timedOut = !cancelled && answer.timedOut === true;
    const status = !done.launched ? -1 : cancelled || timedOut ? -1 : (answer.status ?? 0);
    const rawStderr = cancelled ? "" : (answer.stderr ?? "");
    const stdout = cancelled || timedOut ? "" : (answer.stdout ?? "");
    const limit = definition.outputLimitBytes ?? CREDENTIAL_LIMITS.defaultOutputBytes;
    let overflowed = utf8Length(stdout) > limit;
    const mode = definition.output?.mode ?? "lines";
    const lowered = rawStderr.toLowerCase();
    const hints = Object.entries(definition.hints ?? {})
      .filter(([, needles]) => needles.some((needle) => lowered.includes(needle.toLowerCase())))
      .map(([hint]) => hint);
    const stderrSecrets = [...consumed, ...jsonStrings.filter((text) => text.length >= 6)];
    const stderr = redactText(cleanStderr(rawStderr), stderrSecrets);
    let json: unknown = null;
    let lines: string[] = [];
    let items = 0;
    let parts = 0;
    let lastLine: string | null = null;
    if (!overflowed && done.launched && !cancelled) {
      if (mode === "json") {
        const parsed = stdout.trim() ? tolerantJson(stdout) : undefined;
        const itemsKey = definition.output?.items;
        let array: unknown[] | null = null;
        let container: unknown = parsed === undefined ? null : parsed;
        if (itemsKey === "$" && Array.isArray(parsed)) {
          array = parsed;
          container = [];
        } else if (itemsKey && itemsKey !== "$" && isObject(parsed) && Array.isArray(parsed[itemsKey])) {
          array = parsed[itemsKey] as unknown[];
          container = { ...parsed, [itemsKey]: [] };
        }
        if (array) {
          for (const element of array) {
            if (utf8Length(JSON.stringify(element) ?? "") > CREDENTIAL_LIMITS.outputItemBytes) {
              overflowed = true;
              break;
            }
          }
          if (!overflowed) {
            array.forEach((element, index) => toPlugin({ verbOf, item: redactJson(element, consumed), index }));
            items = array.length;
          }
        }
        json = overflowed ? null : redactJson(container, consumed);
        const encoded = JSON.stringify(json);
        if (!overflowed && encoded.length > CREDENTIAL_LIMITS.chunkBytes) {
          for (let start = 0; start < encoded.length; start += CREDENTIAL_LIMITS.chunkBytes) {
            toPlugin({ verbOf, part: encoded.slice(start, start + CREDENTIAL_LIMITS.chunkBytes) });
            parts++;
          }
          json = null;
        }
      } else if (mode === "lines") {
        lines = stdout.split("\n").map((line) => line.replace(/\r$/, ""));
        if (lines.length && lines[lines.length - 1] === "") lines.pop();
        lines = lines.map((line) => redactText(line, consumed));
      } else if (mode === "lastLineSecret") {
        const candidates = stdout.split("\n").map((line) => line.trim()).filter(Boolean);
        const last = candidates[candidates.length - 1] ?? "";
        lastLine = /^\S{16,4096}$/.test(last) ? last : null;
      } else if (mode === "stream") {
        for (const line of answer.lines ?? ([] as StreamLine[])) toPlugin({ verbOf, line: { stream: line.stream, text: redactText(line.text, consumed) } });
      }
    }
    if (overflowed) json = null;
    const succeeded = done.launched && !cancelled && !timedOut && !overflowed && status === 0;
    for (const handle of used) if (handle.kind === "typed" && (succeeded || handle.launches >= CREDENTIAL_LIMITS.typedSecretLaunches)) handle.spent = true;
    let unlocked = false;
    if (succeeded && definition.unlocks && call.epoch === epoch) {
      if (mode === "lastLineSecret") {
        if (lastLine) {
          session = { key: lastLine };
          if (isObject(definition.unlocks) && definition.unlocks.persistent && context.touchID) storedSession = lastLine;
          unlocked = true;
        }
      } else {
        session = { key: session?.key ?? null };
        unlocked = true;
      }
      if (unlocked) call.sessionSet = true;
    }
    if (launch.signIn) {
      signInRun = { state: succeeded ? "succeeded" : "failed", hints, ...(timedOut ? { timedOut: true } : {}) };
      if (cancelled) signInRun = { state: "none", hints: [] };
    }
    if (openCalls.get(call.id) !== call) return;
    reply(id, {
      verb: verbId,
      status,
      launched: done.launched,
      timedOut,
      cancelled,
      overflowed,
      succeeded,
      stderr,
      hints,
      json,
      parts,
      lines,
      items,
      unlocked,
      droppedLines: 0,
      signInRun,
    });
  }

  function contextFor(callId: string): JsonObject {
    const sessionView = session === null ? null : { key: session.key === null ? null : mint(session.key, callId, "session") };
    return {
      epoch: `e${epoch}`,
      provider: "provider",
      touchID: context.touchID === true,
      offline: context.offline === true,
      session: sessionView,
      hasStored: storedSession !== null,
      signInRun,
      scratch: { ...scratch },
      preferences: { ...preferences },
      cli: { name: program, version: "2.31.0" },
    };
  }

  function bindTyped(value: unknown, callId: string): unknown {
    if (isSecretHandle(value)) {
      const typed = pendingTyped.get(value.$secret);
      if (typed === undefined) return value;
      pendingTyped.delete(value.$secret);
      handles.set(value.$secret, { value: typed, call: callId, epoch, kind: "typed", launches: 0, spent: false });
      return value;
    }
    if (Array.isArray(value)) return value.map((entry) => bindTyped(entry, callId));
    if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, bindTyped(entry, callId)]));
    return value;
  }

  async function runLockVerb() {
    const onLock = contribution.cli.onLock;
    if (!onLock || (onLock.skipWithTouchID && context.touchID)) return;
    const params: Record<string, string> = {};
    for (const [slot, source] of Object.entries(onLock.params ?? {})) {
      if (source.literal !== undefined) params[slot] = source.literal;
      else if (source.from === "preference" && source.key && preferences[source.key] !== undefined) params[slot] = preferences[source.key]!;
      else if (source.from === "session" && session?.key) params[slot] = session.key;
    }
    const built = buildVerb(options.manifest, onLock.verb, params, () => null, testFolder);
    if (!("launch" in built)) {
      refused.push({ verb: onLock.verb, reason: built.message });
      return;
    }
    launches.push(built.launch);
    try {
      await options.cli(built.launch);
    } catch {}
  }

  startRun();

  return {
    async call<N extends CredentialHandlerName>(name: N, input: HarnessInputs[N]): Promise<HarnessAnswer> {
      await ready;
      const id = `v${++nextCall}`;
      const answer = new Promise<HarnessAnswer>((resolve) => openCalls.set(id, { id, name, epoch, resolve, verbsRunning: 0, sessionSet: false }));
      const bound = bindTyped(input, id);
      toPlugin({ call: id, kind: "credentials", name, input: bound, deadline: 60_000, context: contextFor(id) });
      return answer;
    },
    secret(value: string): SecretHandle {
      const id = `h${++nextHandle}`;
      pendingTyped.set(id, value);
      return { $secret: id };
    },
    async lock() {
      epoch++;
      for (const call of [...openCalls.values()]) {
        openCalls.delete(call.id);
        endCallHandles(call.id);
        call.resolve({ ok: false, error: { code: "stale" } });
      }
      for (const verb of [...openVerbs.values()]) verb.finish("cancelled");
      await runLockVerb();
      session = null;
      scratch = {};
      startRun();
      await ready;
    },
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
    async advance(ms: number) {
      clock += ms;
      for (const timer of timers.splice(0).sort((a, b) => a.at - b.at)) {
        if (timer.at <= clock) timer.fire();
        else timers.push(timer);
      }
      for (let i = 0; i < 5; i++) await delay();
    },
  };
}

