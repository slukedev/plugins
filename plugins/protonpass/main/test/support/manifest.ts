import { CREDENTIAL_CAPABILITIES, DENIED_COMMANDS, DENIED_ENV_PATTERNS, HOST_ENV } from "../../vendor/plugin-sdk/src/credentials.ts";

type Json = Record<string, unknown>;

const KEY = /^[A-Za-z0-9_-]{1,40}$/;
const VERB_ID = /^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*){0,3}$/;
const TOP_KEYS = ["title", "symbol", "icon", "accent", "readsOffline", "approvalLastsSeconds", "capabilities", "signIn", "cli"];
const SIGN_IN_KEYS = ["methods", "servers", "unlock", "approvalHosts"];
const CLI_KEYS = ["name", "install", "minimumVersion", "patterns", "env", "onLock", "verbs"];
const VERB_KEYS = ["argv", "slots", "env", "stdin", "timeoutMs", "outputLimitBytes", "output", "signIn", "unlocks", "outlivesCall", "hints"];
const SLOT_TYPES = ["id", "enum", "flag", "url", "email", "code", "secret", "json"];
const ARGV_SLOT_TYPES = ["id", "enum", "url", "email", "code"];

const isText = (value: unknown, longest: number) => typeof value === "string" && value.length >= 1 && value.length <= longest;
const record = (value: unknown): Json => (typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Json) : {});

function envDenied(name: string) {
  return DENIED_ENV_PATTERNS.find((pattern) => (pattern.startsWith("*") ? name.endsWith(pattern.slice(1)) : pattern.endsWith("*") ? name.startsWith(pattern.slice(0, -1)) : name === pattern));
}

export function credentialManifestProblems(manifest: Json): string[] {
  const problems: string[] = [];
  const P = "contributes.credentialProvider";
  const contributes = record(manifest.contributes);
  const provider = record(contributes.credentialProvider);
  if (typeof manifest.main !== "string") problems.push(`${P} needs a main`);
  if ("sidecar" in manifest) problems.push(`${P} runs in main, not a sidecar`);
  for (const key of Object.keys(contributes)) if (key !== "credentialProvider") problems.push(`contributes.${key}: a credential provider contributes nothing else`);
  if (manifest.permissions !== undefined && Object.keys(record(manifest.permissions)).length) problems.push("permissions: a credential provider asks for no permissions");
  if ("activationEvents" in manifest) problems.push("activationEvents: a credential provider starts when Ardia asks it, so it takes no activation events");
  if (manifest.memoryMB !== undefined && !(Number.isInteger(manifest.memoryMB) && (manifest.memoryMB as number) >= 256 && (manifest.memoryMB as number) <= 4096)) {
    problems.push("memoryMB must be a whole number from 256 to 4096");
  }
  if (manifest.official !== true) problems.push(`${P} needs official: true`);
  for (const key of Object.keys(provider)) if (!TOP_KEYS.includes(key)) problems.push(`${P}.${key} isn't a key of ${P}`);
  if (!isText(provider.title, 40)) problems.push(`${P}.title must be text of 1 to 40 characters`);
  if ("symbol" in provider && "icon" in provider) problems.push(`${P} takes a symbol or an icon, not both`);
  if (provider.accent !== undefined && !/^#[0-9A-Fa-f]{6}$/.test(String(provider.accent))) problems.push(`${P}.accent must be a color like #175DDC`);
  if (provider.readsOffline !== undefined && typeof provider.readsOffline !== "boolean") problems.push(`${P}.readsOffline must be true or false`);
  const capabilities = Array.isArray(provider.capabilities) ? (provider.capabilities as string[]) : [];
  if (capabilities.length > 8) problems.push(`${P}.capabilities must be a list of at most 8`);
  capabilities.forEach((capability, index) => {
    if (!(CREDENTIAL_CAPABILITIES as readonly string[]).includes(capability)) problems.push(`${P}.capabilities[${index}] must be one of ${CREDENTIAL_CAPABILITIES.join(", ")}`);
    if (capabilities.indexOf(capability) !== index) problems.push(`${P}.capabilities has ${capability} twice`);
  });

  const signIn = record(provider.signIn);
  for (const key of Object.keys(signIn)) if (!SIGN_IN_KEYS.includes(key)) problems.push(`${P}.signIn.${key} isn't a key of ${P}.signIn`);
  const methods = Array.isArray(signIn.methods) ? (signIn.methods as Json[]) : [];
  if (methods.length < 1 || methods.length > 4) problems.push(`${P}.signIn.methods must be a list of 1 to 4`);
  const fieldTypes = new Map<string, string>();
  const secretFields = new Set<string>();
  methods.forEach((method, index) => {
    const at = `${P}.signIn.methods[${index}]`;
    if (!KEY.test(String(method.id))) problems.push(`${at}.id must be 1 to 40 letters, digits, - and _`);
    if (methods.findIndex((other) => other.id === method.id) !== index) problems.push(`${P}.signIn.methods has two methods named ${method.id}`);
    if (!isText(method.title, 40)) problems.push(`${at}.title must be text of 1 to 40 characters`);
    const kind = method.kind ?? "fields";
    if (!["fields", "desktopApproval", "browserApproval"].includes(String(kind))) problems.push(`${at}.kind must be fields, desktopApproval or browserApproval`);
    const fields = Array.isArray(method.fields) ? (method.fields as Json[]) : [];
    if (fields.length > 6 || (kind === "fields" && fields.length < 1)) problems.push(`${at}.fields must be a list of 1 to 6`);
    if (method.twoStep !== undefined && kind !== "fields") problems.push(`${at}.twoStep only goes with kind fields`);
    if (kind === "browserApproval" && !Array.isArray(signIn.approvalHosts)) problems.push(`${at} needs ${P}.signIn.approvalHosts`);
    fields.forEach((field, fieldIndex) => {
      const fieldAt = `${at}.fields[${fieldIndex}]`;
      if (!KEY.test(String(field.id))) problems.push(`${fieldAt}.id must be 1 to 40 letters, digits, - and _`);
      if (!isText(field.title, 40)) problems.push(`${fieldAt}.title must be text of 1 to 40 characters`);
      if (!["text", "email", "secret"].includes(String(field.type))) problems.push(`${fieldAt}.type must be text, email or secret`);
      if (field.placeholder !== undefined && !isText(field.placeholder, 60)) problems.push(`${fieldAt}.placeholder must be text of 1 to 60 characters`);
      if (field.hint !== undefined && !isText(field.hint, 120)) problems.push(`${fieldAt}.hint must be text of 1 to 120 characters`);
      if (field.optional !== undefined && typeof field.optional !== "boolean") problems.push(`${fieldAt}.optional must be true or false`);
      if (field.masked !== undefined && field.type !== "secret") problems.push(`${fieldAt}.masked only goes with type secret`);
      const known = fieldTypes.get(String(field.id));
      if (known && known !== field.type) problems.push(`${P}.signIn has a field ${field.id} that is ${known} in one method and ${field.type} in another`);
      fieldTypes.set(String(field.id), String(field.type));
      if (field.type === "secret") secretFields.add(String(field.id));
    });
  });
  const hosts = Array.isArray(signIn.approvalHosts) ? (signIn.approvalHosts as unknown[]) : [];
  if (signIn.approvalHosts !== undefined && (hosts.length < 1 || hosts.length > 8)) problems.push(`${P}.signIn.approvalHosts must be a list of 1 to 8`);
  hosts.forEach((host, index) => {
    if (!/^[a-z0-9.-]{1,253}$/.test(String(host))) problems.push(`${P}.signIn.approvalHosts[${index}] must be a host name, like proton.me`);
  });
  if (signIn.unlock !== undefined && !secretFields.has(String(record(signIn.unlock).field))) problems.push(`${P}.signIn.unlock.field must name a secret field of ${P}.signIn.methods`);
  if (capabilities.includes("masterPassword") && signIn.unlock === undefined) problems.push(`${P}.capabilities: masterPassword needs ${P}.signIn.unlock`);
  if (capabilities.includes("selfHosted") && !(Array.isArray(signIn.servers) && (signIn.servers as Json[]).some((server) => server.custom))) {
    problems.push(`${P}.capabilities: selfHosted needs a custom server in ${P}.signIn.servers`);
  }

  const cli = record(provider.cli);
  for (const key of Object.keys(cli)) if (!CLI_KEYS.includes(key)) problems.push(`${P}.cli.${key} isn't a key of ${P}.cli`);
  const program = String(cli.name);
  if (!/^[a-z][a-z0-9._-]{0,31}$/.test(program)) problems.push(`${P}.cli.name must be a program name, like bw`);
  const install = record(cli.install);
  if (!isText(install.command, 200)) problems.push(`${P}.cli.install.command must be text of 1 to 200 characters`);
  if (install.update !== undefined && !isText(install.update, 200)) problems.push(`${P}.cli.install.update must be text of 1 to 200 characters`);
  if (install.url !== undefined && !(typeof install.url === "string" && install.url.startsWith("https://") && install.url.length <= 2048)) problems.push(`${P}.cli.install.url must be an https address`);
  const patterns = record(cli.patterns);
  if (Object.keys(patterns).length > 8) problems.push(`${P}.cli.patterns must have at most 8 entries`);
  for (const [name, pattern] of Object.entries(patterns)) {
    const text = String(pattern);
    if (!KEY.test(name) || !isText(text, 200) || !text.startsWith("^") || !text.endsWith("$") || /\\[1-9]|\(\?[=!<]/.test(text)) {
      problems.push(`${P}.cli.patterns.${name} must be a regular expression of 1 to 200 characters that starts with ^ and ends with $`);
    }
  }
  const sharedEnv = new Set<string>();
  const checkEnv = (entries: unknown, at: string, slots: Json | null) => {
    const seenEnv = new Set(slots ? sharedEnv : []);
    (Array.isArray(entries) ? (entries as Json[]) : []).forEach((entry, index) => {
      const sources = ["literal", "secretSlot", "testFolder", "testLiteral"].filter((key) => key in entry);
      if (typeof entry.name !== "string" || sources.length !== 1) problems.push(`${at}[${index}] needs a name and exactly one of literal, secretSlot, testFolder or testLiteral`);
      const name = String(entry.name);
      if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(name)) problems.push(`${at}[${index}].name must be an environment variable name, like BW_NOINTERACTION`);
      if (HOST_ENV.includes(name)) problems.push(`${at}[${index}].name: ${name} is set by Ardia`);
      const denied = envDenied(name);
      if (denied && !("testFolder" in entry)) problems.push(`${at}[${index}].name: ${name} matches ${denied}, which Ardia never passes`);
      if (seenEnv.has(name)) problems.push(`${P}.cli.env has ${name} twice`);
      seenEnv.add(name);
      if (!slots) sharedEnv.add(name);
      if ("secretSlot" in entry) {
        if (!slots) problems.push(`${at}[${index}].secretSlot: only a verb's env can name a slot`);
        else if (record(slots[String(entry.secretSlot)]).type !== "secret") problems.push(`${at}[${index}].secretSlot: ${entry.secretSlot} isn't a secret slot of this verb`);
      }
      if (("testFolder" in entry || "testLiteral" in entry) && slots) problems.push(`${at}[${index}]: test entries only go in ${P}.cli.env`);
    });
  };
  checkEnv(cli.env, `${P}.cli.env`, null);

  const verbs = record(cli.verbs);
  const verbIds = Object.keys(verbs);
  if (verbIds.length < 1 || verbIds.length > 48) problems.push(`${P}.cli.verbs must be an object of 1 to 48 verbs`);
  for (const id of verbIds) {
    const at = `${P}.cli.verbs.${id}`;
    if (!VERB_ID.test(id) || id.length > 48) problems.push(`${P}.cli.verbs: ${id} isn't a verb id, like list.items`);
    const verb = record(verbs[id]);
    for (const key of Object.keys(verb)) if (!VERB_KEYS.includes(key)) problems.push(`${at}.${key} isn't a key of a verb`);
    const slots = record(verb.slots);
    if (Object.keys(slots).length > 16) problems.push(`${at}.slots must be an object of at most 16 slots`);
    const used = new Set<string>();
    for (const [name, slot] of Object.entries(slots)) {
      const type = String(record(slot).type);
      if (!KEY.test(name) || !SLOT_TYPES.includes(type)) problems.push(`${at}.slots.${name} must be a slot`);
      if (type === "id" && !(String(record(slot).pattern) in patterns)) problems.push(`${at}.slots.${name}.pattern must name one of ${P}.cli.patterns`);
    }
    const argv = Array.isArray(verb.argv) ? (verb.argv as unknown[]) : [];
    if (argv.length < 1 || argv.length > 32) problems.push(`${at}.argv must be a list of 1 to 32 tokens and slots`);
    if (typeof argv[0] !== "string") problems.push(`${at}.argv[0] must be a plain token, the subcommand`);
    const literals: string[] = [];
    argv.forEach((element, index) => {
      if (typeof element === "string") {
        if (!/^\S{1,256}$/.test(element) || element === "--" || element.includes("\0")) problems.push(`${at}.argv[${index}] must be a plain token: no spaces, newlines, NUL or a lone --`);
        literals.push(element);
        return;
      }
      const shaped = record(element);
      if (shaped.flag !== undefined && !/^--[a-z][a-z0-9-]{0,40}$/.test(String(shaped.flag))) problems.push(`${at}.argv[${index}].flag must be a long option, like --method`);
      if ("slot" in shaped && "when" in shaped) problems.push(`${at}.argv[${index}] takes a slot or a when, not both`);
      if ("when" in shaped) {
        if (record(slots[String(shaped.when)]).type !== "flag") problems.push(`${at}.argv[${index}].when: ${shaped.when} isn't a flag slot of this verb`);
        used.add(String(shaped.when));
        return;
      }
      const name = String(shaped.slot);
      const type = record(slots[name]).type;
      if (!(name in slots)) problems.push(`${at}.argv[${index}].slot: ${name} isn't one of this verb's slots`);
      else if (type === "secret") problems.push(`${at}.argv[${index}]: a secret slot can't go in argv, where other programs see it`);
      else if (type === "json") problems.push(`${at}.argv[${index}]: a json slot only goes in stdin`);
      else if (type === "flag") problems.push(`${at}.argv[${index}]: a flag slot goes in a when`);
      else if (!ARGV_SLOT_TYPES.includes(String(type))) problems.push(`${at}.argv[${index}] has an unknown slot type`);
      used.add(name);
    });
    for (const denied of DENIED_COMMANDS[program] ?? []) {
      if (denied.argv.every((token, index) => literals[index] === token) && (denied.withFlag === undefined || literals.includes(denied.withFlag))) {
        problems.push(`${at}: ${program} ${denied.argv.join(" ")} is never allowed`);
      }
    }
    checkEnv(verb.env, `${at}.env`, slots);
    for (const entry of Array.isArray(verb.env) ? (verb.env as Json[]) : []) if ("secretSlot" in entry) used.add(String(entry.secretSlot));
    if (verb.stdin !== undefined) {
      const stdin = record(verb.stdin);
      const type = record(slots[String(stdin.slot)]).type;
      if (type !== "json" && type !== "secret") problems.push(`${at}.stdin.slot: ${stdin.slot} must be a json or secret slot of this verb`);
      if (stdin.encoding !== "utf8" && stdin.encoding !== "base64") problems.push(`${at}.stdin.encoding must be utf8 or base64`);
      used.add(String(stdin.slot));
    }
    for (const name of Object.keys(slots)) if (!used.has(name)) problems.push(`${at}.slots.${name} isn't used in argv, env or stdin`);
    if (verb.timeoutMs !== undefined && !(Number.isInteger(verb.timeoutMs) && (verb.timeoutMs as number) >= 1000 && (verb.timeoutMs as number) <= 900000)) {
      problems.push(`${at}.timeoutMs must be a whole number from 1000 to 900000`);
    }
    if (verb.outputLimitBytes !== undefined && !(Number.isInteger(verb.outputLimitBytes) && (verb.outputLimitBytes as number) >= 1024 && (verb.outputLimitBytes as number) <= 167772160)) {
      problems.push(`${at}.outputLimitBytes must be a whole number from 1024 to 167772160`);
    }
    const output = record(verb.output);
    if (!["json", "lines", "lastLineSecret", "stream"].includes(String(output.mode))) problems.push(`${at}.output.mode must be json, lines, lastLineSecret or stream`);
    if (output.items !== undefined && output.mode !== "json") problems.push(`${at}.output.items only goes with mode json`);
    if (verb.unlocks !== undefined && verb.signIn !== true) problems.push(`${at}.unlocks needs signIn: true`);
    if (verb.outlivesCall !== undefined && !(verb.signIn === true && output.mode === "stream")) problems.push(`${at}.outlivesCall needs signIn: true and mode stream`);
    if (output.mode === "lastLineSecret" && !verb.unlocks) problems.push(`${at}: a lastLineSecret verb must unlock, since its secret goes nowhere else`);
    const hints = record(verb.hints);
    if (Object.keys(hints).length > 16) problems.push(`${at}.hints must have at most 16 hints`);
    for (const [hint, needles] of Object.entries(hints)) {
      if (!KEY.test(hint) || !Array.isArray(needles) || needles.length < 1 || needles.length > 16 || !needles.every((needle) => isText(needle, 120))) {
        problems.push(`${at}.hints.${hint} must be a list of 1 to 16 texts of 1 to 120 characters`);
      }
    }
  }
  return problems;
}

export function consentVerbs(manifest: Json): string[] {
  const verbs = record(record(record(record(manifest.contributes).credentialProvider).cli).verbs);
  const names: string[] = [];
  for (const verb of Object.values(verbs)) {
    const leading: string[] = [];
    for (const element of record(verb).argv as unknown[]) {
      if (typeof element !== "string" || element.startsWith("-")) break;
      leading.push(element);
    }
    const name = leading.join(" ");
    if (!names.includes(name)) names.push(name);
  }
  return names;
}
