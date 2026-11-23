import type * as Contract from "./credentials";
import {
  CAPABILITY_HANDLERS,
  CREDENTIAL_CAPABILITIES,
  CREDENTIAL_DEADLINES_MS,
  CREDENTIAL_ERROR_CODES,
  CREDENTIAL_LIMITS,
  CREDENTIALS_PROTOCOLS_SUPPORTED,
  DENIED_COMMANDS,
  DENIED_ENV_PATTERNS,
  GLOBAL_FLAGS,
  HOST_ENV,
  REQUIRED_CREDENTIAL_HANDLERS,
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
  type SignInRunState,
  type VerbParams,
} from "./credentials";
import { createCredentialRuntime, isSecretHandle, type CredentialRuntime } from "./credentialsRuntime";
import type { Transport } from "./rpc";

type JsonRecord = Record<string, unknown>;
const isRecord = (value: unknown): value is JsonRecord => typeof value === "object" && value !== null && !Array.isArray(value);

type Slot = { type: string; optional?: boolean; pattern?: string; values?: string[]; allowLocalHttp?: boolean };
type ArgvElement = string | { slot?: string; flag?: string; when?: string };
type EnvEntry = { name: string; literal?: string; secretSlot?: string; testFolder?: string; testLiteral?: string };
type Verb = {
  argv: ArgvElement[];
  slots?: Record<string, Slot>;
  env?: EnvEntry[];
  stdin?: { slot: string; encoding: "utf8" | "base64" };
  timeoutMs?: number;
  outputLimitBytes?: number;
  output?: { mode: "json" | "lines" | "lastLineSecret" | "stream"; items?: string };
  signIn?: boolean;
  unlocks?: boolean | { persistent?: boolean };
  outlivesCall?: boolean;
  hints?: Record<string, string[]>;
};
type CliSection = {
  name: string;
  patterns?: Record<string, string>;
  env?: EnvEntry[];
  onLock?: { verb: string; params?: Record<string, { from?: string; key?: string; literal?: string }>; skipWithTouchID?: boolean };
  verbs: Record<string, Verb>;
};
type Contribution = { title: string; capabilities?: string[]; cli: CliSection; signIn: JsonRecord };

export function contributionOf(manifest: unknown): Contribution {
  if (isRecord(manifest) && isRecord(manifest.contributes) && isRecord(manifest.contributes.credentialProvider)) {
    return manifest.contributes.credentialProvider as unknown as Contribution;
  }
  return manifest as Contribution;
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

function urlProblem(value: string, allowLocalHttp: boolean): string | null {
  if (value.length > CREDENTIAL_LIMITS.urlSlotLength || /\s/.test(value) || CONTROL_CHARACTERS.test(value)) return "must be an https address";
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)/.exec(value);
  if (!match) return "must be an https address";
  const scheme = match[1]!.toLowerCase();
  const authority = match[2]!;
  if (authority.includes("@")) return "must be an https address";
  const host = (authority.startsWith("[") ? authority.slice(0, authority.indexOf("]") + 1) : authority.split(":", 1)[0]!).toLowerCase();
  if (!host) return "must be an https address";
  if (scheme === "https") return null;
  if (scheme === "http" && allowLocalHttp && LOCAL_HOSTS.has(host)) return null;
  return "must be an https address";
}

function jsonDepth(value: unknown, depth = 0): number {
  if (depth > CREDENTIAL_LIMITS.stdinJsonDepth) return depth;
  if (Array.isArray(value)) return value.reduce<number>((most, entry) => Math.max(most, jsonDepth(entry, depth + 1)), depth + 1);
  if (isRecord(value)) return Object.values(value).reduce<number>((most, entry) => Math.max(most, jsonDepth(entry, depth + 1)), depth + 1);
  return depth;
}

export function sortedJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((entry) => sortedJson(entry)).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${sortedJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function utf8Bytes(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let point = text.charCodeAt(i);
    if (point >= 0xd800 && point <= 0xdbff && i + 1 < text.length) {
      const low = text.charCodeAt(i + 1);
      if ((low & 0xfc00) === 0xdc00) {
        point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
        i++;
      }
    }
    if (point < 0x80) out.push(point);
    else if (point < 0x800) out.push(0xc0 | (point >> 6), 0x80 | (point & 63));
    else if (point < 0x10000) out.push(0xe0 | (point >> 12), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63));
    else out.push(0xf0 | (point >> 18), 0x80 | ((point >> 12) & 63), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63));
  }
  return Uint8Array.from(out);
}

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function base64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const triple = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += BASE64[(triple >> 18) & 63]! + BASE64[(triple >> 12) & 63]!;
    out += i + 1 < bytes.length ? BASE64[(triple >> 6) & 63]! : "=";
    out += i + 2 < bytes.length ? BASE64[triple & 63]! : "=";
  }
  return out;
}

function deniedCommand(program: string, argv: readonly string[]): string | null {
  const globals = GLOBAL_FLAGS[program] ?? [];
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    const flag = token.split("=", 1)[0]!;
    if (globals.includes(flag)) {
      if (flag === "--session" && !token.includes("=")) i++;
      continue;
    }
    rest.push(token);
  }
  for (const denied of DENIED_COMMANDS[program] ?? []) {
    const leading = denied.argv.every((word, index) => rest[index] === word);
    if (!leading) continue;
    if (denied.withFlag && !argv.some((token) => token === denied.withFlag || token.startsWith(`${denied.withFlag}=`))) continue;
    return `${program} ${denied.argv.join(" ")} is never allowed.`;
  }
  return null;
}

function envDenied(name: string): string | null {
  for (const pattern of DENIED_ENV_PATTERNS) {
    const matches = pattern.startsWith("*") ? name.endsWith(pattern.slice(1)) : pattern.endsWith("*") ? name.startsWith(pattern.slice(0, -1)) : name === pattern;
    if (matches) return pattern;
  }
  return null;
}

export const buildVerbLaunch: typeof Contract.buildVerbLaunch = (manifest, verbId, params, secrets, testFolder) => {
  const contribution = contributionOf(manifest);
  const cli = contribution.cli;
  const verb = cli.verbs[verbId];
  if (!verb) return { refused: `${cli.name} has no verb ${verbId}.` };
  const slots = verb.slots ?? {};
  for (const key of Object.keys(params)) {
    if (params[key] !== undefined && !slots[key]) return { refused: `${verbId} has no slot named ${key}.` };
  }
  const values: Record<string, string | boolean | unknown> = {};
  const secretValues: Record<string, string> = {};
  for (const [name, slot] of Object.entries(slots)) {
    const value = params[name];
    if (value === undefined) {
      if (!slot.optional && slot.type !== "flag") return { refused: `${name} is required for ${verbId}.` };
      continue;
    }
    if (slot.type !== "secret" && isSecretHandle(value)) return { refused: "a handle only goes in a secret slot." };
    switch (slot.type) {
      case "secret": {
        if (!isSecretHandle(value)) return { refused: `${name} for ${verbId} must be a handle.` };
        const secret = secrets(value);
        if (secret === null) return { refused: `${value.$secret} was used or has ended.` };
        if (utf8Bytes(secret).length > CREDENTIAL_LIMITS.secretBytes) return { refused: `${name} for ${verbId} is longer than Ardia passes.` };
        secretValues[name] = secret;
        continue;
      }
      case "id": {
        const pattern = slot.pattern ? cli.patterns?.[slot.pattern] : undefined;
        if (typeof value !== "string" || !pattern || value.length > CREDENTIAL_LIMITS.idSlotLength || value.startsWith("-") || !new RegExp(pattern).test(value)) {
          return { refused: `${name} for ${verbId} must match ${slot.pattern ?? "its pattern"}.` };
        }
        break;
      }
      case "enum":
        if (typeof value !== "string" || !(slot.values ?? []).includes(value)) return { refused: `${name} for ${verbId} must be one of ${(slot.values ?? []).join(", ")}.` };
        break;
      case "flag":
        if (typeof value !== "boolean") return { refused: `${name} for ${verbId} must be true or false.` };
        break;
      case "url": {
        const problem = typeof value === "string" ? urlProblem(value, slot.allowLocalHttp === true) : "must be an https address";
        if (problem) return { refused: `${name} for ${verbId} ${problem}.` };
        break;
      }
      case "email":
        if (typeof value !== "string" || !value.includes("@") || /\s/.test(value) || value.startsWith("-") || value.length > CREDENTIAL_LIMITS.emailSlotLength) {
          return { refused: `${name} for ${verbId} must be an email address.` };
        }
        break;
      case "code":
        if (typeof value !== "string" || !new RegExp(CREDENTIAL_LIMITS.codeSlotPattern).test(value)) return { refused: `${name} for ${verbId} must be 1 to 64 letters and digits.` };
        break;
      case "json":
        if (utf8Bytes(sortedJson(value)).length > CREDENTIAL_LIMITS.stdinBytes || jsonDepth(value) > CREDENTIAL_LIMITS.stdinJsonDepth) {
          return { refused: `${name} for ${verbId} is bigger than Ardia passes.` };
        }
        break;
      default:
        return { refused: `${name} for ${verbId} has an unknown slot type.` };
    }
    values[name] = value;
  }
  const argv: string[] = [];
  for (const element of verb.argv) {
    if (typeof element === "string") {
      argv.push(element);
      continue;
    }
    if (element.when) {
      if (values[element.when] === true) argv.push(element.flag!);
      continue;
    }
    const value = element.slot ? values[element.slot] : undefined;
    if (value === undefined) continue;
    const text = String(value);
    if (element.flag) argv.push(`${element.flag}=${text}`);
    else {
      if (text.startsWith("-")) return { refused: `${element.slot} for ${verbId} can't start with -.` };
      argv.push(text);
    }
  }
  if (argv.some((token) => token === "--" || token.includes("\u0000") || token.includes("\n"))) return { refused: `${cli.name} ${verbId} has an argument Ardia never passes.` };
  const denied = deniedCommand(cli.name, argv);
  if (denied) return { refused: denied };
  const env: Record<string, string> = {};
  for (const entry of [...(cli.env ?? []), ...(verb.env ?? [])]) {
    if (entry.testFolder !== undefined) {
      if (testFolder !== null) env[entry.name] = entry.testFolder ? `${testFolder}/${entry.testFolder}` : testFolder;
      continue;
    }
    if (envDenied(entry.name) || HOST_ENV.includes(entry.name)) return { refused: `${entry.name} is set by Ardia or never passed.` };
    if (entry.literal !== undefined) env[entry.name] = entry.literal;
    else if (entry.testLiteral !== undefined) {
      if (testFolder !== null) env[entry.name] = entry.testLiteral;
    } else if (entry.secretSlot !== undefined) {
      const secret = secretValues[entry.secretSlot];
      if (secret !== undefined) env[entry.name] = secret;
    }
  }
  let stdin = "";
  if (verb.stdin) {
    const slot = verb.stdin.slot;
    const raw = slots[slot]?.type === "secret" ? secretValues[slot] : values[slot] === undefined ? undefined : sortedJson(values[slot]);
    if (raw !== undefined) stdin = verb.stdin.encoding === "base64" ? base64(utf8Bytes(raw)) : raw;
  }
  return { verb: verbId, argv, env, stdin, timeoutMs: verb.timeoutMs ?? 30_000, signIn: verb.signIn === true };
};

const KEY_PATTERN = /^[A-Za-z0-9_-]{1,40}$/;
const VERB_ID = /^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*){0,3}$/;
const P = "contributes.credentialProvider";

export function checkCredentialManifest(manifest: unknown): string[] {
  const problems: string[] = [];
  const plugin = isRecord(manifest) ? manifest : {};
  const contributes = isRecord(plugin.contributes) ? plugin.contributes : {};
  const provider = isRecord(contributes.credentialProvider) ? contributes.credentialProvider : null;
  if (!provider) return [`${P} must be an object`];
  if (typeof plugin.main !== "string") problems.push(`${P} needs a main`);
  if (plugin.sidecar !== undefined) problems.push(`${P} runs in main, not a sidecar`);
  for (const key of Object.keys(contributes)) if (key !== "credentialProvider") problems.push(`contributes.${key}: a credential provider contributes nothing else`);
  if (isRecord(plugin.permissions) && Object.keys(plugin.permissions).length > 0) problems.push("permissions: a credential provider asks for no permissions");
  if (plugin.activationEvents !== undefined) problems.push("activationEvents: a credential provider starts when Ardia asks it, so it takes no activation events");
  if (plugin.official !== true) problems.push(`${P} needs official: true`);
  if (plugin.memoryMB !== undefined && !(Number.isInteger(plugin.memoryMB) && (plugin.memoryMB as number) >= 256 && (plugin.memoryMB as number) <= 4096)) {
    problems.push("memoryMB must be a whole number from 256 to 4096");
  }
  const allowed = ["title", "symbol", "icon", "accent", "readsOffline", "approvalLastsSeconds", "capabilities", "signIn", "cli"];
  for (const key of Object.keys(provider)) if (!allowed.includes(key)) problems.push(`${P}.${key} isn't a key of ${P}`);
  if (typeof provider.title !== "string" || provider.title.length < 1 || provider.title.length > 40) problems.push(`${P}.title must be text of 1 to 40 characters`);
  if (provider.accent !== undefined && !/^#[0-9A-Fa-f]{6}$/.test(String(provider.accent))) problems.push(`${P}.accent must be a color like #175DDC`);
  const capabilities = Array.isArray(provider.capabilities) ? (provider.capabilities as string[]) : [];
  capabilities.forEach((capability, index) => {
    if (!(CREDENTIAL_CAPABILITIES as readonly string[]).includes(capability)) problems.push(`${P}.capabilities[${index}] must be one of ${CREDENTIAL_CAPABILITIES.join(", ")}`);
    if (capabilities.indexOf(capability) !== index) problems.push(`${P}.capabilities has ${capability} twice`);
  });
  const signIn = isRecord(provider.signIn) ? provider.signIn : null;
  if (!signIn) problems.push(`${P}.signIn must be an object`);
  const methods = signIn && Array.isArray(signIn.methods) ? (signIn.methods as JsonRecord[]) : [];
  if (methods.length < 1 || methods.length > 4) problems.push(`${P}.signIn.methods must be a list of 1 to 4`);
  const fieldTypes = new Map<string, string>();
  methods.forEach((method, index) => {
    if (!KEY_PATTERN.test(String(method.id))) problems.push(`${P}.signIn.methods[${index}].id must be 1 to 40 letters, digits, - and _`);
    const fields = Array.isArray(method.fields) ? (method.fields as JsonRecord[]) : [];
    if ((method.kind ?? "fields") === "fields" && (fields.length < 1 || fields.length > 6)) problems.push(`${P}.signIn.methods[${index}].fields must be a list of 1 to 6`);
    fields.forEach((field, fieldIndex) => {
      const id = String(field.id);
      if (!KEY_PATTERN.test(id)) problems.push(`${P}.signIn.methods[${index}].fields[${fieldIndex}].id must be 1 to 40 letters, digits, - and _`);
      if (!["text", "email", "secret"].includes(String(field.type))) problems.push(`${P}.signIn.methods[${index}].fields[${fieldIndex}].type must be text, email or secret`);
      if (field.placeholder !== undefined && (String(field.placeholder).length < 1 || String(field.placeholder).length > 60)) {
        problems.push(`${P}.signIn.methods[${index}].fields[${fieldIndex}].placeholder must be text of 1 to 60 characters`);
      }
      if (field.masked !== undefined && field.type !== "secret") problems.push(`${P}.signIn.methods[${index}].fields[${fieldIndex}].masked only goes with type secret`);
      const seen = fieldTypes.get(id);
      if (seen && seen !== field.type) problems.push(`${P}.signIn has a field ${id} that is secret in one method and text in another`);
      fieldTypes.set(id, String(field.type));
    });
  });
  const servers = signIn && Array.isArray(signIn.servers) ? (signIn.servers as JsonRecord[]) : [];
  if (servers.filter((server) => server.custom !== undefined).length > 1) problems.push(`${P}.signIn.servers has two custom servers`);
  if (capabilities.includes("selfHosted") && !servers.some((server) => server.custom !== undefined)) problems.push(`${P}.capabilities: selfHosted needs a custom server in ${P}.signIn.servers`);
  const unlock = signIn && isRecord(signIn.unlock) ? signIn.unlock : null;
  if (capabilities.includes("masterPassword") && !unlock) problems.push(`${P}.capabilities: masterPassword needs ${P}.signIn.unlock`);
  if (unlock && fieldTypes.get(String(unlock.field)) !== "secret") problems.push(`${P}.signIn.unlock.field must name a secret field of ${P}.signIn.methods`);
  const cli = isRecord(provider.cli) ? (provider.cli as unknown as CliSection & JsonRecord) : null;
  if (!cli) return [...problems, `${P}.cli must be an object`];
  if (!/^[a-z][a-z0-9._-]{0,31}$/.test(String(cli.name))) problems.push(`${P}.cli.name must be a program name, like bw`);
  const install = isRecord(cli.install) ? cli.install : {};
  if (typeof install.command !== "string" || install.command.length < 1 || install.command.length > 200) problems.push(`${P}.cli.install.command must be text of 1 to 200 characters`);
  if (install.url !== undefined && !String(install.url).startsWith("https://")) problems.push(`${P}.cli.install.url must be an https address`);
  if (cli.minimumVersion !== undefined && !/^\d{1,6}(\.\d{1,6}){1,3}$/.test(String(cli.minimumVersion))) problems.push(`${P}.cli.minimumVersion must be a version, like 2024.6.0`);
  for (const [key, pattern] of Object.entries(cli.patterns ?? {})) {
    if (!pattern.startsWith("^") || !pattern.endsWith("$") || pattern.length > 200 || /\\\d|\(\?[=!<]/.test(pattern)) {
      problems.push(`${P}.cli.patterns.${key} must be a regular expression of 1 to 200 characters that starts with ^ and ends with $`);
    }
  }
  const envNames = new Set<string>();
  const checkEnv = (entries: EnvEntry[], path: string, verb: Verb | null) => {
    entries.forEach((entry, index) => {
      const kinds = ["literal", "secretSlot", "testFolder", "testLiteral"].filter((kind) => (entry as JsonRecord)[kind] !== undefined);
      if (typeof entry.name !== "string" || kinds.length !== 1) problems.push(`${path}[${index}] needs a name and exactly one of literal, secretSlot, testFolder or testLiteral`);
      if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(String(entry.name))) problems.push(`${path}[${index}].name must be an environment variable name, like BW_NOINTERACTION`);
      if (HOST_ENV.includes(entry.name)) problems.push(`${path}[${index}].name: ${entry.name} is set by Ardia`);
      const denied = entry.testFolder === undefined ? envDenied(entry.name) : null;
      if (denied) problems.push(`${path}[${index}].name: ${entry.name} matches ${denied}, which Ardia never passes`);
      if (envNames.has(entry.name) && !verb) problems.push(`${P}.cli.env has ${entry.name} twice`);
      if (entry.secretSlot !== undefined) {
        if (!verb) problems.push(`${path}[${index}].secretSlot: only a verb's env can name a slot`);
        else if (verb.slots?.[entry.secretSlot]?.type !== "secret") problems.push(`${path}[${index}].secretSlot: ${entry.secretSlot} isn't a secret slot of this verb`);
      }
      if (!verb) envNames.add(entry.name);
    });
  };
  checkEnv(cli.env ?? [], `${P}.cli.env`, null);
  const verbs = isRecord(cli.verbs) ? cli.verbs : {};
  const verbIds = Object.keys(verbs);
  if (verbIds.length < 1 || verbIds.length > 48) problems.push(`${P}.cli.verbs must be an object of 1 to 48 verbs`);
  const verbKeys = ["argv", "slots", "env", "stdin", "timeoutMs", "outputLimitBytes", "output", "signIn", "unlocks", "outlivesCall", "hints"];
  for (const [id, verb] of Object.entries(verbs)) {
    const path = `${P}.cli.verbs.${id}`;
    if (!VERB_ID.test(id) || id.length > 48) problems.push(`${P}.cli.verbs: ${id} isn't a verb id, like list.items`);
    for (const key of Object.keys(verb)) if (!verbKeys.includes(key)) problems.push(`${path}.${key} isn't a key of a verb`);
    const slots = verb.slots ?? {};
    const used = new Set<string>();
    if (!Array.isArray(verb.argv) || verb.argv.length < 1 || verb.argv.length > 32) problems.push(`${path}.argv must be a list of 1 to 32 tokens and slots`);
    (verb.argv ?? []).forEach((element, index) => {
      if (typeof element === "string") {
        if (!element || element.length > 256 || /\s/.test(element) || element.includes("\u0000") || element === "--") problems.push(`${path}.argv[${index}] must be a plain token: no spaces, newlines, NUL or a lone --`);
        return;
      }
      if (index === 0) problems.push(`${path}.argv[0] must be a plain token, the subcommand`);
      if (element.flag !== undefined && !/^--[a-z][a-z0-9-]{0,40}$/.test(element.flag)) problems.push(`${path}.argv[${index}].flag must be a long option, like --method`);
      if (element.slot && element.when) problems.push(`${path}.argv[${index}] takes a slot or a when, not both`);
      if (element.when) {
        if (slots[element.when]?.type !== "flag") problems.push(`${path}.argv[${index}].when: ${element.when} isn't a flag slot of this verb`);
        used.add(element.when);
        return;
      }
      const slot = element.slot ? slots[element.slot] : undefined;
      if (!slot) return problems.push(`${path}.argv[${index}].slot: ${element.slot} isn't one of this verb's slots`);
      if (slot.type === "secret") problems.push(`${path}.argv[${index}]: a secret slot can't go in argv, where other programs see it`);
      if (slot.type === "json") problems.push(`${path}.argv[${index}]: a json slot only goes in stdin`);
      if (slot.type === "flag") problems.push(`${path}.argv[${index}]: a flag slot goes in a when`);
      used.add(element.slot!);
    });
    if (typeof verb.argv?.[0] !== "string") problems.push(`${path}.argv[0] must be a plain token, the subcommand`);
    for (const [name, slot] of Object.entries(slots)) {
      if (!KEY_PATTERN.test(name)) problems.push(`${path}.slots.${name} must be a key`);
      if (slot.type === "id" && !(slot.pattern && cli.patterns?.[slot.pattern])) problems.push(`${path}.slots.${name}.pattern must name one of ${P}.cli.patterns`);
      if (slot.type === "enum" && (!Array.isArray(slot.values) || slot.values.length < 1 || slot.values.length > 16 || slot.values.some((value) => value.startsWith("-")))) {
        problems.push(`${path}.slots.${name}.values must be a list of 1 to 16 tokens`);
      }
    }
    checkEnv(verb.env ?? [], `${path}.env`, verb);
    for (const entry of verb.env ?? []) {
      if (entry.secretSlot) used.add(entry.secretSlot);
      if (envNames.has(entry.name)) problems.push(`${P}.cli.env has ${entry.name} twice`);
    }
    if (verb.stdin) {
      const type = slots[verb.stdin.slot]?.type;
      if (type !== "json" && type !== "secret") problems.push(`${path}.stdin.slot: ${verb.stdin.slot} must be a json or secret slot of this verb`);
      if (verb.stdin.encoding !== "utf8" && verb.stdin.encoding !== "base64") problems.push(`${path}.stdin.encoding must be utf8 or base64`);
      used.add(verb.stdin.slot);
    }
    for (const name of Object.keys(slots)) if (!used.has(name)) problems.push(`${path}.slots.${name} isn't used in argv, env or stdin`);
    if (verb.timeoutMs !== undefined && !(Number.isInteger(verb.timeoutMs) && verb.timeoutMs >= 1000 && verb.timeoutMs <= 900_000)) problems.push(`${path}.timeoutMs must be a whole number from 1000 to 900000`);
    if (verb.outputLimitBytes !== undefined && !(Number.isInteger(verb.outputLimitBytes) && verb.outputLimitBytes >= 1024 && verb.outputLimitBytes <= CREDENTIAL_LIMITS.mostOutputBytes)) {
      problems.push(`${path}.outputLimitBytes must be a whole number from 1024 to 167772160`);
    }
    const mode = verb.output?.mode;
    if (!["json", "lines", "lastLineSecret", "stream"].includes(String(mode))) problems.push(`${path}.output.mode must be json, lines, lastLineSecret or stream`);
    if (verb.output?.items !== undefined && mode !== "json") problems.push(`${path}.output.items only goes with mode json`);
    if (verb.unlocks !== undefined && verb.signIn !== true) problems.push(`${path}.unlocks needs signIn: true`);
    if (isRecord(verb.unlocks) && verb.unlocks.persistent && mode !== "lastLineSecret") problems.push(`${path}.unlocks.persistent only goes with mode lastLineSecret`);
    if (mode === "lastLineSecret" && !verb.unlocks) problems.push(`${path}: a lastLineSecret verb must unlock, since its secret goes nowhere else`);
    if (verb.outlivesCall && (verb.signIn !== true || mode !== "stream")) problems.push(`${path}.outlivesCall needs signIn: true and mode stream`);
    for (const [hint, needles] of Object.entries(verb.hints ?? {})) {
      if (!Array.isArray(needles) || needles.length < 1 || needles.length > 16 || needles.some((needle) => needle.length < 1 || needle.length > 120)) {
        problems.push(`${path}.hints.${hint} must be a list of 1 to 16 texts of 1 to 120 characters`);
      }
    }
    const literal: string[] = [];
    for (const element of verb.argv ?? []) {
      if (typeof element !== "string" || element.startsWith("-")) break;
      literal.push(element);
    }
    const denied = deniedCommand(String(cli.name), literal);
    if (denied) problems.push(`${path}: ${denied.replace(/\.$/, "")}`);
  }
  if (cli.onLock) {
    if (!verbs[cli.onLock.verb]) problems.push(`${P}.cli.onLock.verb: ${cli.onLock.verb} isn't one of ${P}.cli.verbs`);
    for (const [name, source] of Object.entries(cli.onLock.params ?? {})) {
      const ok = source.from === "session" || (source.from === "preference" && typeof source.key === "string") || typeof source.literal === "string";
      if (!ok) problems.push(`${P}.cli.onLock.params.${name} must be { from: session }, { from: preference, key } or { literal }`);
    }
  }
  return problems;
}

type Timer = { at: number; fire(): void };

type HandleRecord = { value: string; kind: "typed" | "session" | "stored"; call: string | null; epoch: number; launches: number; spent: boolean };

type RunningFake = { verb: string; signIn: boolean; outlives: boolean; finish(cancelled: boolean): void };

type OpenCall = {
  id: string;
  name: CredentialHandlerName;
  epoch: number;
  run: number;
  handles: Set<string>;
  running: Set<RunningFake>;
  settle(answer: HarnessAnswer): void;
  deadline: Timer;
};

const ESCAPE_CODES = /\u001b\[[0-9;?]*[A-Za-z]/g;
const LOG_PREFIX = /^\[[A-Za-z]+\]\s+\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+/;

function cleanStderr(text: string): string {
  const cleaned = text
    .replace(ESCAPE_CODES, "")
    .split("\n")
    .map((line) => line.replace(LOG_PREFIX, ""))
    .join("\n");
  return cleaned.length > CREDENTIAL_LIMITS.stderrBytes ? cleaned.slice(0, CREDENTIAL_LIMITS.stderrBytes) : cleaned;
}

export function parseNoisyJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    const closing = Math.max(text.lastIndexOf("}"), text.lastIndexOf("]"));
    if (closing < 0) return undefined;
    let tried = 0;
    for (let start = 0; start < Math.min(closing, 64 * 1024); start++) {
      const character = text[start];
      if (character !== "{" && character !== "[") continue;
      try {
        return JSON.parse(text.slice(start, closing + 1));
      } catch {
        tried += 1;
        if (tried >= 64) break;
      }
    }
    return undefined;
  }
}

function redactor(secrets: readonly string[]): (text: string) => string {
  const sorted = [...new Set(secrets.filter((secret) => secret.length >= 3))].sort((a, b) => b.length - a.length);
  return (text) => sorted.reduce((current, secret) => current.split(secret).join("[hidden]"), text);
}

function redactDeep(value: unknown, redact: (text: string) => string): unknown {
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map((entry) => redactDeep(entry, redact));
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, redactDeep(entry, redact)]));
  return value;
}

function stringsIn(value: unknown, into: string[] = []): string[] {
  if (typeof value === "string") into.push(value);
  else if (Array.isArray(value)) for (const entry of value) stringsIn(entry, into);
  else if (isRecord(value)) for (const entry of Object.values(value)) stringsIn(entry, into);
  return into;
}

function containsHandle(value: unknown): boolean {
  if (isSecretHandle(value)) return true;
  if (Array.isArray(value)) return value.some(containsHandle);
  if (isRecord(value)) return Object.values(value).some(containsHandle);
  return false;
}

function handlesIn(value: unknown, into: string[] = []): string[] {
  if (isSecretHandle(value)) into.push(value.$secret);
  else if (Array.isArray(value)) for (const entry of value) handlesIn(entry, into);
  else if (isRecord(value)) for (const entry of Object.values(value)) handlesIn(entry, into);
  return into;
}

const flush = () => new Promise<void>((resolve) => (globalThis as unknown as { setTimeout: (callback: () => void, ms: number) => unknown }).setTimeout(resolve, 0));

export type HarnessExtras = {
  readonly epoch: number;
  readonly runs: number;
  readonly signInRun: SignInRunState;
  readonly handlers: readonly string[];
  readonly problems: readonly unknown[];
  readonly lines: readonly JsonRecord[];
  cancel(): Promise<void>;
};

export function createCredentialHarness(options: {
  provider: CredentialProvider;
  manifest: unknown;
  cli: FakeCli;
  context?: HarnessContext;
  helloCredentials?: number;
}): CredentialHarness & HarnessExtras {
  const contribution = contributionOf(options.manifest);
  const cliSection = contribution.cli;
  const program = cliSection.name;
  const context = options.context ?? {};
  const providerName = isRecord(options.manifest) && typeof options.manifest.name === "string" ? options.manifest.name : program;
  const testFolder = context.testInstance ? `/tmp/ardia-test/Password Managers/${providerName}` : null;
  const handles = new Map<string, HandleRecord>();
  const launches: FakeLaunch[] = [];
  const refused: { verb: string; reason: string }[] = [];
  const problems: unknown[] = [];
  const lines: JsonRecord[] = [];
  const openCalls = new Map<string, OpenCall>();
  let timers: Timer[] = [];
  let clock = 0;
  let epoch = 1;
  let callCount = 0;
  let handleCount = 0;
  let run = 0;
  let session: { key: string | null } | null = context.session ?? null;
  let storedSession: string | null = context.storedSession ?? null;
  let scratch: Record<string, string> = { ...(context.scratch ?? {}) };
  let preferences: Record<string, string> = { ...(context.preferences ?? {}) };
  let signInRun: SignInRunState = { state: "none", hints: [] };
  let signInVerb: RunningFake | null = null;
  let handlers: string[] = [];
  let current: { runtime: CredentialRuntime; deliver(line: JsonRecord): void; ready: Promise<boolean>; run: number; alive: boolean } | null = null;

  const schedule = (ms: number, fire: () => void): Timer => {
    const timer = { at: clock + ms, fire };
    timers.push(timer);
    return timer;
  };
  const unschedule = (timer: Timer) => {
    timers = timers.filter((entry) => entry !== timer);
  };

  const mint = (value: string, kind: HandleRecord["kind"], call: string | null): SecretHandle => {
    handleCount += 1;
    const id = `h${handleCount}`;
    handles.set(id, { value, kind, call, epoch, launches: 0, spent: false });
    return { $secret: id };
  };

  function startRun() {
    run += 1;
    const thisRun = run;
    let listener: (line: string) => void = () => {};
    let readyResolve!: (ok: boolean) => void;
    const ready = new Promise<boolean>((resolve) => (readyResolve = resolve));
    const state = {
      alive: true,
      run: thisRun,
      ready,
      deliver(message: JsonRecord) {
        const line = JSON.stringify(message);
        void Promise.resolve().then(() => {
          if (state.alive) listener(line);
        });
      },
      runtime: null as unknown as CredentialRuntime,
    };
    const transport: Transport = {
      send(line) {
        void Promise.resolve().then(() => {
          if (state.alive) receive(line, state, readyResolve);
        });
      },
      onLine(next) {
        listener = next;
      },
    };
    state.runtime = createCredentialRuntime(transport, { onError: (error) => problems.push(error), now: () => clock + 1_700_000_000_000 });
    current = state;
    void state.runtime.define(options.provider);
  }

  function reply(state: NonNullable<typeof current>, id: unknown, body: { result?: unknown; error?: { code: string; message: string } }) {
    state.deliver({ id, ...body });
  }

  function receive(line: string, state: NonNullable<typeof current>, readyResolve: (ok: boolean) => void) {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (!isRecord(message)) return;
    lines.push(message);
    const params = isRecord(message.params) ? message.params : {};
    const id = message.id;
    switch (message.method) {
      case "hello": {
        const speaks = typeof params.credentials === "number" ? params.credentials : 0;
        const wanted = options.helloCredentials ?? speaks;
        if (!CREDENTIALS_PROTOCOLS_SUPPORTED.includes(wanted)) {
          reply(state, id, { error: { code: "refused", message: `This ${contribution.title} plugin speaks credentials protocol ${wanted}, and this Ardia speaks 1. Update Ardia.` } });
          readyResolve(false);
          return;
        }
        reply(state, id, {
          result: { app: "Ardia", version: "1.41.0", protocol: 2, plugin: providerName, values: {}, credentials: { protocol: 1, supported: [...CREDENTIALS_PROTOCOLS_SUPPORTED], provider: providerName } },
        });
        return;
      }
      case "ready": {
        const offered = isRecord(params.credentialProvider) && Array.isArray(params.credentialProvider.handlers) ? (params.credentialProvider.handlers as string[]) : [];
        handlers = offered;
        reply(state, id, { result: { ok: true } });
        readyResolve(true);
        return;
      }
      case "result":
        return takeResult(state, id, params);
      case "credentials.verb":
        return void runVerb(state, id, params);
      case "credentials.verb.cancel": {
        const open = openCalls.get(String(params.call));
        reply(state, id, { result: { ok: true } });
        const verbOf = params.verbOf;
        for (const running of open?.running ?? []) if ((running as RunningFake & { requestId?: unknown }).requestId === verbOf) running.finish(true);
        return;
      }
      case "credentials.signIn.cancel":
        reply(state, id, { result: { ok: true } });
        signInVerb?.finish(true);
        return;
      case "credentials.session.takeStored": {
        const open = guard(state, id, params);
        if (!open) return;
        if (typeof params.reason !== "string" || params.reason.length > CREDENTIAL_LIMITS.ownerReasonLength) {
          return reply(state, id, { error: { code: "bad_request", message: "The reason is over 60 characters." } });
        }
        const handle = storedSession !== null && context.touchID ? mint(storedSession, "stored", open.id) : null;
        if (handle) open.handles.add(handle.$secret);
        return reply(state, id, { result: { handle } });
      }
      case "credentials.session.dropStored": {
        if (!guard(state, id, params)) return;
        storedSession = null;
        return reply(state, id, { result: { ok: true } });
      }
      case "credentials.values.set": {
        if (!guard(state, id, params)) return;
        const store = params.store === "preferences" ? preferences : params.store === "scratch" ? scratch : null;
        const key = params.key;
        const value = params.value;
        if (!store || typeof key !== "string" || !KEY_PATTERN.test(key) || (value !== null && (typeof value !== "string" || utf8Bytes(value).length > CREDENTIAL_LIMITS.valueBytes))) {
          return reply(state, id, { error: { code: "bad_request", message: "That value can't be kept." } });
        }
        if (value === null) delete store[key];
        else {
          if (!(key in store) && Object.keys(store).length >= CREDENTIAL_LIMITS.valueKeys) return reply(state, id, { error: { code: "bad_request", message: "There are 16 keys already." } });
          store[key] = value;
        }
        return reply(state, id, { result: { ok: true } });
      }
      case "credentials.owner.confirm":
        if (!guard(state, id, params)) return;
        return reply(state, id, { result: { confirmed: context.ownerConfirms ?? true } });
      default:
        if (typeof message.method === "string") {
          reply(state, id, { error: { code: "refused", message: "A password manager plugin can only use hello, ready, result and credentials requests." } });
        }
    }
  }

  function guard(state: NonNullable<typeof current>, id: unknown, params: JsonRecord): OpenCall | null {
    const open = openCalls.get(String(params.call));
    if (!open || open.run !== state.run) {
      reply(state, id, { error: { code: "closed", message: `The call ${String(params.call)} has ended.` } });
      return null;
    }
    if (open.epoch !== epoch) {
      reply(state, id, { error: { code: "stale", message: `${contribution.title} locked, so this call ended.` } });
      return null;
    }
    return open;
  }

  async function runVerb(state: NonNullable<typeof current>, id: unknown, params: JsonRecord) {
    const open = guard(state, id, params);
    if (!open) return;
    const verbId = String(params.verb);
    const definition = cliSection.verbs[verbId];
    if (!definition) {
      refused.push({ verb: verbId, reason: `${program} has no verb ${verbId}.` });
      return reply(state, id, { error: { code: "refused", message: `${program} has no verb ${verbId}.` } });
    }
    if (open.running.size >= CREDENTIAL_LIMITS.runningVerbs) {
      return reply(state, id, { error: { code: "overloaded", message: `${contribution.title} has 4 commands running.` } });
    }
    const consumed: string[] = [];
    const typed: HandleRecord[] = [];
    const resolve = (handle: SecretHandle) => {
      const record = handles.get(handle.$secret);
      if (!record || record.spent || record.call !== open.id || record.epoch !== open.epoch) return null;
      consumed.push(record.value);
      if (record.kind === "typed") typed.push(record);
      return record.value;
    };
    const launch = buildVerbLaunch(options.manifest, verbId, (isRecord(params.params) ? params.params : {}) as VerbParams, resolve, testFolder);
    if ("refused" in launch) {
      refused.push({ verb: verbId, reason: launch.refused });
      const code = launch.refused.includes("was used or has ended") ? "expired" : launch.refused.includes("never allowed") ? "denied" : "bad_request";
      return reply(state, id, { error: { code, message: launch.refused } });
    }
    const asked = typeof params.timeoutMs === "number" ? params.timeoutMs : launch.timeoutMs;
    const timeoutMs = Math.min(asked, launch.timeoutMs);
    const placed: FakeLaunch = { ...launch, timeoutMs };
    launches.push(placed);
    for (const record of typed) record.launches += 1;
    const mode = definition.output?.mode ?? "lines";
    type Outcome = { reply: FakeReply | null; cancelled: boolean; timedOut: boolean; notLaunched?: boolean };
    let settle!: (outcome: Outcome) => void;
    const outcome = new Promise<Outcome>((resolveOutcome) => (settle = resolveOutcome));
    let done = false;
    let timer: Timer | null = null;
    const fake: RunningFake & { requestId: unknown } = {
      requestId: id,
      verb: verbId,
      signIn: definition.signIn === true,
      outlives: definition.outlivesCall === true,
      finish(cancelled) {
        if (done) return;
        done = true;
        if (timer) unschedule(timer);
        settle({ reply: null, cancelled, timedOut: !cancelled });
      },
    };
    if (fake.signIn) {
      signInVerb?.finish(true);
      signInVerb = fake;
      signInRun = { state: "running", hints: [] };
    }
    open.running.add(fake);
    void Promise.resolve()
      .then(() => options.cli(placed))
      .then(
        (fakeReply) => {
          if (done) return;
          const finishAfter = fakeReply.finishAfterMs ?? 0;
          const end = () => {
            if (done) return;
            done = true;
            if (timer) unschedule(timer);
            settle({ reply: fakeReply, cancelled: false, timedOut: fakeReply.timedOut === true });
          };
          if (finishAfter > timeoutMs) {
            timer = schedule(timeoutMs, () => fake.finish(false));
          } else if (finishAfter > 0) {
            timer = schedule(finishAfter, end);
          } else end();
        },
        () => {
          if (done) return;
          done = true;
          settle({ reply: null, cancelled: false, timedOut: false, notLaunched: true });
        },
      );
    const ended = await outcome;
    open.running.delete(fake);
    if (signInVerb === fake) signInVerb = null;
    const fakeReply = ended.reply;
    const status = fakeReply ? (fakeReply.status ?? 0) : -1;
    const launched = !ended.notLaunched;
    const stdout = fakeReply?.stdout ?? "";
    const rawStderr = fakeReply?.stderr ?? "";
    const limit = definition.outputLimitBytes ?? CREDENTIAL_LIMITS.defaultOutputBytes;
    const overflowed = utf8Bytes(stdout).length > limit;
    const succeeded = launched && status === 0 && !ended.timedOut && !ended.cancelled && !overflowed;
    const stdinStrings = definition.stdin && definition.slots?.[definition.stdin.slot]?.type === "json" ? stringsIn((params.params as JsonRecord)[definition.stdin.slot]) : [];
    const redact = redactor(consumed);
    const redactStderr = redactor([...consumed, ...stdinStrings.filter((text) => text.length >= 6)]);
    const hints = Object.entries(definition.hints ?? {})
      .filter(([, needles]) => needles.some((needle) => rawStderr.toLowerCase().includes(needle.toLowerCase())))
      .map(([hint]) => hint);
    let jsonValue: unknown = null;
    let parts = 0;
    let itemCount = 0;
    let outputLines: string[] = [];
    let itemOverflow = false;
    let unlocked = false;
    if (!overflowed && fakeReply) {
      if (mode === "json") {
        const parsed = parseNoisyJson(stdout);
        if (parsed !== undefined) {
          const path = definition.output?.items;
          const array = path === "$" ? parsed : path && isRecord(parsed) ? parsed[path] : undefined;
          if (path && Array.isArray(array)) {
            for (const [index, element] of array.entries()) {
              const cleaned = redactDeep(element, redact);
              if (utf8Bytes(JSON.stringify(cleaned)).length > CREDENTIAL_LIMITS.outputItemBytes) {
                itemOverflow = true;
                break;
              }
              state.deliver({ verbOf: id, item: cleaned, index });
              itemCount += 1;
            }
            jsonValue = path === "$" ? [] : { ...(parsed as JsonRecord), [path]: [] };
          } else if (!path) {
            const cleaned = redactDeep(parsed, redact);
            const text = JSON.stringify(cleaned);
            if (text.length > CREDENTIAL_LIMITS.chunkBytes) {
              for (let start = 0; start < text.length; start += CREDENTIAL_LIMITS.chunkBytes) {
                state.deliver({ verbOf: id, part: text.slice(start, start + CREDENTIAL_LIMITS.chunkBytes) });
                parts += 1;
              }
            } else jsonValue = cleaned;
          }
        }
      } else if (mode === "lines") {
        outputLines = stdout.split("\n").map((line) => redact(line.replace(/\r$/, "")));
        if (outputLines.length > 0 && outputLines[outputLines.length - 1] === "") outputLines.pop();
      } else if (mode === "stream") {
        for (const line of fakeReply.lines ?? []) state.deliver({ verbOf: id, line: { stream: line.stream, text: redact(line.text) } });
      } else if (mode === "lastLineSecret" && succeeded) {
        const last = stdout
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line.length > 0)
          .pop();
        if (last && last.length >= 16 && last.length <= 4096 && !/\s/.test(last) && definition.unlocks && open.epoch === epoch) {
          session = { key: last };
          if (isRecord(definition.unlocks) && definition.unlocks.persistent && context.touchID) storedSession = last;
          unlocked = true;
        }
      }
    }
    if (definition.unlocks === true && succeeded && open.epoch === epoch) {
      session = session ?? { key: null };
      unlocked = true;
    }
    const finalSucceeded = succeeded && !itemOverflow;
    for (const record of typed) if ((status === 0 && finalSucceeded) || record.launches >= CREDENTIAL_LIMITS.typedSecretLaunches) record.spent = true;
    if (fake.signIn) signInRun = { state: finalSucceeded ? "succeeded" : "failed", hints, ...(ended.timedOut ? { timedOut: true } : {}) };
    if (!state.alive) return;
    reply(state, id, {
      result: {
        verb: verbId,
        status,
        launched,
        timedOut: ended.timedOut,
        cancelled: ended.cancelled,
        overflowed: overflowed || itemOverflow,
        succeeded: finalSucceeded,
        stderr: redactStderr(cleanStderr(rawStderr)),
        hints,
        json: jsonValue,
        parts,
        lines: outputLines,
        items: itemCount,
        unlocked,
        droppedLines: 0,
        signInRun,
      },
    });
  }

  function closeCall(open: OpenCall) {
    openCalls.delete(open.id);
    unschedule(open.deadline);
    for (const handle of open.handles) {
      const record = handles.get(handle);
      if (record) record.spent = true;
    }
    for (const running of [...open.running]) if (!running.outlives) running.finish(true);
  }

  function takeResult(state: NonNullable<typeof current>, id: unknown, params: JsonRecord) {
    const open = openCalls.get(String(params.call));
    if (!open || open.run !== state.run) return reply(state, id, { error: { code: "bad_request", message: `There's no call ${String(params.call)} waiting.` } });
    reply(state, id, { result: { ok: true } });
    closeCall(open);
    if ("error" in params) {
      const error = params.error;
      if (!isRecord(error) || !(CREDENTIAL_ERROR_CODES as readonly string[]).includes(String(error.code))) return open.settle({ ok: false, error: { code: "invalid" } });
      const wire: JsonRecord = { code: error.code };
      for (const key of ["problem", "detail", "state", "field"]) if (typeof error[key] === "string") wire[key] = error[key];
      return open.settle({ ok: false, error: wire as never });
    }
    const result = params.result;
    if (utf8Bytes(JSON.stringify(result ?? null)).length > CREDENTIAL_LIMITS.resultBytes) return open.settle({ ok: false, error: { code: "tooLarge" } });
    if ((open.name === "signIn" || open.name === "unlock") && isRecord(result) && result.ok === true) {
      if (open.epoch !== epoch) return open.settle({ ok: false, error: { code: "stale" } });
      if (result.session !== undefined) {
        const record = isSecretHandle(result.session) ? handles.get(result.session.$secret) : undefined;
        if (!record || record.kind !== "stored" || record.call !== open.id) return open.settle({ ok: false, error: { code: "invalid" } });
        session = { key: record.value };
        const { session: _handle, ...rest } = result;
        return open.settle({ ok: true, result: rest });
      }
      session = session ?? { key: null };
    } else if (containsHandle(result)) {
      return open.settle({ ok: false, error: { code: "invalid" } });
    }
    if (open.name === "signOut") {
      epoch += 1;
      session = null;
      storedSession = null;
      scratch = {};
      preferences = {};
    }
    open.settle({ ok: true, result });
  }

  async function ensureRun() {
    if (!current || !current.alive) startRun();
    return current!.ready;
  }

  const harness: CredentialHarness & HarnessExtras = {
    async call<N extends CredentialHandlerName>(name: N, input: HarnessInputs[N]): Promise<HarnessAnswer> {
      const ready = await ensureRun();
      const state = current!;
      if (!ready) return { ok: false, error: { code: "stopped" } };
      const missing = [...REQUIRED_CREDENTIAL_HANDLERS.filter((handler) => !handlers.includes(handler))];
      for (const capability of contribution.capabilities ?? []) {
        const options = CAPABILITY_HANDLERS[capability as keyof typeof CAPABILITY_HANDLERS] ?? [];
        if (options.length > 0 && !options.some((set) => set.every((handler) => handlers.includes(handler)))) missing.push(capability as CredentialHandlerName);
      }
      if (missing.length > 0) return { ok: false, error: { code: "invalid" } };
      callCount += 1;
      const callId = `v${callCount}`;
      const typedHandles = handlesIn(input);
      for (const handle of typedHandles) {
        const record = handles.get(handle);
        if (record && record.kind === "typed" && record.call === null) record.call = callId;
      }
      let sessionHandle: SecretHandle | null = null;
      if (session?.key) sessionHandle = mint(session.key, "session", callId);
      const deadlineMs = CREDENTIAL_DEADLINES_MS[name];
      return new Promise<HarnessAnswer>((resolveAnswer) => {
        let settled = false;
        const open: OpenCall = {
          id: callId,
          name,
          epoch,
          run: state.run,
          handles: new Set([...typedHandles, ...(sessionHandle ? [sessionHandle.$secret] : [])]),
          running: new Set(),
          settle(answer) {
            if (settled) return;
            settled = true;
            resolveAnswer(answer);
          },
          deadline: schedule(deadlineMs, () => {
            if (!openCalls.has(callId)) return;
            closeCall(open);
            state.deliver({ call: callId, cancel: true });
            open.settle({ ok: false, error: { code: "timedOut" } });
          }),
        };
        openCalls.set(callId, open);
        state.deliver({
          call: callId,
          kind: "credentials",
          name,
          input,
          deadline: deadlineMs,
          context: {
            epoch: `e${epoch}`,
            provider: providerName,
            touchID: context.touchID === true,
            offline: context.offline === true,
            session: session ? { key: sessionHandle } : null,
            hasStored: storedSession !== null,
            signInRun,
            scratch: { ...scratch },
            preferences: { ...preferences },
            cli: { name: program, version: "2026.11.0" },
          },
        });
      });
    },
    secret(value: string): SecretHandle {
      return mint(value, "typed", null);
    },
    async lock() {
      epoch += 1;
      for (const open of [...openCalls.values()]) {
        closeCall(open);
        for (const running of [...open.running]) running.finish(true);
        open.settle({ ok: false, error: { code: "stale" } });
      }
      signInVerb?.finish(true);
      if (current) {
        current.alive = false;
        current.runtime.dispose();
        current = null;
      }
      const onLock = cliSection.onLock;
      if (onLock && !(onLock.skipWithTouchID && context.touchID)) {
        const params: Record<string, string | SecretHandle> = {};
        for (const [slot, source] of Object.entries(onLock.params ?? {})) {
          if (source.from === "session" && session?.key) params[slot] = mint(session.key, "session", "lock");
          else if (source.from === "preference" && source.key && preferences[source.key] !== undefined) params[slot] = preferences[source.key]!;
          else if (source.literal !== undefined) params[slot] = source.literal;
        }
        const launch = buildVerbLaunch(options.manifest, onLock.verb, params, (handle) => handles.get(handle.$secret)?.value ?? null, testFolder);
        if (!("refused" in launch)) {
          launches.push(launch);
          await options.cli(launch);
        } else refused.push({ verb: onLock.verb, reason: launch.refused });
      }
      session = null;
      scratch = {};
      await flush();
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
      const until = clock + ms;
      for (;;) {
        await flush();
        const due = timers.filter((timer) => timer.at <= until).sort((a, b) => a.at - b.at)[0];
        if (!due) break;
        unschedule(due);
        clock = due.at;
        due.fire();
      }
      clock = until;
      await flush();
    },
    get epoch() {
      return epoch;
    },
    get runs() {
      return run;
    },
    get signInRun() {
      return signInRun;
    },
    get handlers() {
      return handlers;
    },
    get problems() {
      return problems;
    },
    get lines() {
      return lines;
    },
    async cancel() {
      for (const open of [...openCalls.values()]) {
        closeCall(open);
        current?.deliver({ call: open.id, cancel: true });
        open.settle({ ok: false, error: { code: "cancelled" } });
      }
      await flush();
    },
  };
  return harness;
}

type Assignable<T extends U, U> = T;
export type HarnessMatchesContract = Assignable<typeof createCredentialHarness, typeof Contract.createCredentialHarness>;
