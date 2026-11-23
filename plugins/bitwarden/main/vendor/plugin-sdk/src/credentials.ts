import { PluginError } from "./rpc";
import type { Awaitable, CallContext } from "./types";

export const CREDENTIALS_PROTOCOL = 1;
export const CREDENTIALS_PROTOCOLS_SUPPORTED: readonly number[] = [1];
export const CREDENTIALS_SDK_VERSION = "2.1.0";
export const CREDENTIAL_CALL_KIND = "credentials";
export const CREDENTIAL_CALL_ID_PATTERN = "^v[1-9][0-9]{0,15}$";
export const SECRET_HANDLE_PATTERN = "^h[1-9][0-9]{0,15}$";
export const SNAPSHOT_PATTERN = "^[A-Za-z0-9_-]{1,64}$";
export const EPOCH_PATTERN = "^e[0-9]{1,16}$";
export const CREDENTIAL_MEMORY_MB = { default: 1024, least: 256, most: 4096 } as const;

export const CREDENTIAL_LIMITS = {
  resultBytes: 1 << 20,
  pageBytes: 960 << 10,
  listedItems: 50_000,
  listPages: 1_000,
  pageCursorLength: 256,
  heldSnapshotMs: 60_000,
  itemIdLength: 512,
  itemTitleLength: 1024,
  usernameLength: 1024,
  passwordLength: 4096,
  urlLength: 2048,
  urlsPerItem: 64,
  vaultNameLength: 256,
  passkeysPerItem: 16,
  passkeyNameLength: 256,
  accountLength: 320,
  detailLength: 240,
  choices: 16,
  choiceTitleLength: 60,
  waitingCalls: 8,
  runningVerbs: 4,
  signInVerbs: 1,
  verbParams: 16,
  idSlotLength: 512,
  enumValueLength: 64,
  codeSlotPattern: "^[A-Za-z0-9]{1,64}$",
  emailSlotLength: 320,
  urlSlotLength: 2048,
  stdinBytes: 4 << 20,
  stdinJsonDepth: 32,
  defaultOutputBytes: 32 << 20,
  mostOutputBytes: 160 << 20,
  outputItemBytes: 1 << 20,
  stderrBytes: 64 << 10,
  chunkBytes: 256 << 10,
  streamLineBytes: 16 << 10,
  streamLinesPerSecond: 200,
  handlesPerCall: 16,
  secretBytes: 4096,
  typedSecretLaunches: 3,
  valueKeys: 16,
  valueBytes: 1024,
  ownerReasonLength: 60,
} as const;

export const CREDENTIAL_DEADLINES_MS = {
  state: 45_000,
  signIn: 180_000,
  unlock: 120_000,
  signOut: 30_000,
  configure: 60_000,
  list: 240_000,
  reveal: 90_000,
  save: 300_000,
  edit: 300_000,
  addTotp: 300_000,
  "passkeys.list": 120_000,
  "passkeys.get": 90_000,
  "passkeys.save": 300_000,
} as const;

export const VERB_TIMEOUTS_MS = { default: 30_000, least: 1_000, most: 900_000, killGrace: 2_000, drainGrace: 2_000 } as const;

export const DENIED_ENV_PATTERNS: readonly string[] = ["DYLD_*", "LD_*", "NODE_*", "*_PROXY", "SSL_*", "NODE_TLS_*", "HOME", "PATH", "TMPDIR", "XDG_*", "OP_CONNECT_*", "BITWARDENCLI_*"];

export const HOST_ENV: readonly string[] = ["HOME", "USER", "LOGNAME", "TMPDIR", "PATH", "LANG", "http_proxy", "https_proxy", "no_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"];

export type DeniedCommand = { argv: readonly string[]; withFlag?: string };

export const DENIED_COMMANDS: Readonly<Record<string, readonly DeniedCommand[]>> = {
  op: [
    { argv: ["run"] },
    { argv: ["inject"] },
    { argv: ["plugin"] },
    { argv: ["read"], withFlag: "--out-file" },
    { argv: ["document", "get"], withFlag: "--out-file" },
    { argv: ["service-account"] },
  ],
  bw: [{ argv: ["serve"] }, { argv: ["send"] }, { argv: ["export"] }, { argv: ["encode"] }, { argv: ["get", "attachment"] }],
  "pass-cli": [{ argv: ["run"] }, { argv: ["inject"] }, { argv: ["ssh-agent"] }],
};

export const GLOBAL_FLAGS: Readonly<Record<string, readonly string[]>> = {
  op: ["--account", "--config", "--encoding", "--format", "--iso-timestamps", "--no-color", "--session", "--cache", "--debug"],
  bw: ["--nointeraction", "--raw", "--pretty", "--response", "--cleanexit", "--quiet", "--session"],
  "pass-cli": ["--output", "--quiet", "--verbose"],
};

export const CLAIMED_PROGRAMS: readonly string[] = ["op", "bw", "pass-cli", "node"];

export type CredentialHandlerName =
  | "state"
  | "signIn"
  | "unlock"
  | "signOut"
  | "configure"
  | "list"
  | "reveal"
  | "save"
  | "edit"
  | "addTotp"
  | "passkeys.list"
  | "passkeys.get"
  | "passkeys.save";

export const CREDENTIAL_HANDLERS: readonly CredentialHandlerName[] = ["state", "signIn", "unlock", "signOut", "configure", "list", "reveal", "save", "edit", "addTotp", "passkeys.list", "passkeys.get", "passkeys.save"];

export const REQUIRED_CREDENTIAL_HANDLERS: readonly CredentialHandlerName[] = ["state", "signIn", "unlock", "signOut", "list", "reveal"];

export type CredentialCapability = "totp" | "save" | "edit" | "addTotp" | "passkeys" | "selfHosted" | "masterPassword" | "touchID";

export const CREDENTIAL_CAPABILITIES: readonly CredentialCapability[] = ["totp", "save", "edit", "addTotp", "passkeys", "selfHosted", "masterPassword", "touchID"];

export const CAPABILITY_HANDLERS: Readonly<Record<CredentialCapability, readonly (readonly CredentialHandlerName[])[]>> = {
  totp: [],
  save: [["save"]],
  edit: [["edit"]],
  addTotp: [["addTotp"], ["edit"]],
  passkeys: [["passkeys.get", "passkeys.save"]],
  selfHosted: [["configure"]],
  masterPassword: [],
  touchID: [],
};

export type SecretHandle = { readonly $secret: string };

export type ProviderStateName = "signedOut" | "locked" | "unlocked" | "unavailable";
export type HostProviderStateName = ProviderStateName | "notInstalled";
export type FailureState = "signedOut" | "locked" | "unavailable";

export type ServerRef = { readonly preset: string } | { readonly url: string };

export type ProviderState = { state: ProviderStateName; account?: string; server?: ServerRef; detail?: string; problem?: ProblemCode };

export type UrlMatch = "" | "host" | "exact";

export type ItemPasskey = { credentialId: string; rpId: string; userName: string; displayName: string; discoverable: boolean; counter: number };

export type Item = {
  id: string;
  title: string;
  username: string;
  urls: string[];
  urlMatch?: UrlMatch[];
  hasTotp?: boolean;
  totpPeriod?: number;
  vault?: string;
  favorite?: boolean;
  updatedAt?: number;
  passkeys?: ItemPasskey[];
};

export type ItemSecrets = { password?: string; totp?: string };

export type ListedItem = Item & { secrets?: ItemSecrets };

export type ListRequest = { snapshot: string | null; cursor: string | null };

export type ItemPage = { snapshot: string; items: readonly ListedItem[]; cursor?: string };

export type RevealField = "username" | "password" | "totp";

export type RevealRequest = { id: string; fields: readonly RevealField[] };

export type RevealedTotp = { uri: string } | { code: string; period?: number };

export type Revealed = { username?: string; password?: string; totp?: RevealedTotp };

export type NewLogin = { title: string; username: string; password: string; url: string };

export type SaveRequest = { login: NewLogin };

export type TotpChange = { set: string } | "remove";

export type LoginChange = { username?: string; password?: string; url?: string; totp?: TotpChange };

export type EditRequest = { id: string; change: LoginChange };

export type AddTotpRequest = { id: string; uri: string };

export type StateRequest = { explicit: boolean };

export type SignInStep = "start" | "code" | "account";

export type SignInRequest = {
  method: string;
  step: SignInStep;
  fields: Readonly<Record<string, string | SecretHandle>>;
  server?: ServerRef;
  code?: string;
  codeMethod?: string;
  account?: string;
};

export type UnlockRequest = { password: SecretHandle | null };

export type ConfigureRequest = { server: ServerRef | null };

export type Choice = { id: string; title: string };

export type CodeMethod = Choice & { sendsCode?: boolean };

export type SignInNeed =
  | { kind: "code"; methods?: readonly CodeMethod[]; method?: string }
  | { kind: "field"; field: string }
  | { kind: "approval"; url: string }
  | { kind: "account"; choices: readonly Choice[] };

export type ProblemCode =
  | "wrongPassword"
  | "wrongCredentials"
  | "wrongCode"
  | "badCode"
  | "badServer"
  | "chooseMethod"
  | "codeOrNewDevice"
  | "needsApiKey"
  | "organizationKey"
  | "notAccepted"
  | "unlockNext"
  | "signOutFirst"
  | "signInFirst"
  | "lockedSinceLastUnlock"
  | "stayedLocked"
  | "approvalTimedOut"
  | "appUnreachable"
  | "setupNeeded"
  | "sessionLock"
  | "extraPassword"
  | "finishInBrowser"
  | "didntStart"
  | "premiumNeeded"
  | "noVault"
  | "unknownVault"
  | "cantPrepare"
  | "savedNotReturned"
  | "incomplete"
  | "notTaken"
  | "unreadable"
  | "tooSlow"
  | "notLaunched"
  | "timedOut"
  | "overflowed"
  | "offline"
  | "unreachable"
  | "outdated"
  | "cancelled"
  | "failed";

export const PROBLEM_CODES: readonly ProblemCode[] = [
  "wrongPassword",
  "wrongCredentials",
  "wrongCode",
  "badCode",
  "badServer",
  "chooseMethod",
  "codeOrNewDevice",
  "needsApiKey",
  "organizationKey",
  "notAccepted",
  "unlockNext",
  "signOutFirst",
  "signInFirst",
  "lockedSinceLastUnlock",
  "stayedLocked",
  "approvalTimedOut",
  "appUnreachable",
  "setupNeeded",
  "sessionLock",
  "extraPassword",
  "finishInBrowser",
  "didntStart",
  "premiumNeeded",
  "noVault",
  "unknownVault",
  "cantPrepare",
  "savedNotReturned",
  "incomplete",
  "notTaken",
  "unreadable",
  "tooSlow",
  "notLaunched",
  "timedOut",
  "overflowed",
  "offline",
  "unreachable",
  "outdated",
  "cancelled",
  "failed",
];

export type SignInOutcome =
  | { ok: true; session?: SecretHandle }
  | { ok: false; need: SignInNeed; problem?: ProblemCode; detail?: string; state?: FailureState }
  | { ok: false; need?: undefined; problem: ProblemCode; detail?: string; state?: FailureState; field?: string };

export type PasskeyListRequest = { rpId: string | null };

export type ListedPasskey = ItemPasskey & { item: string };

export type PasskeyGetRequest = { item: string; credentialId: string; rpId: string };

export type PrivateKeyMaterial = { format: "pkcs8"; der: string };

export type PasskeyKey = { credentialId: string; rpId: string; privateKey: PrivateKeyMaterial; userHandle: string; counter: number };

export type NewPasskey = {
  credentialId: string;
  credentialUuid: string;
  privateKey: PrivateKeyMaterial;
  publicKey: string;
  rpId: string;
  rpName: string;
  userHandle: string;
  userName: string;
  displayName: string;
  createdAt: number;
};

export type PasskeySaveRequest = { credential: NewPasskey; attachTo: string | null; title: string; url: string };

export type PasskeySaved = { item: string };

export type CredentialErrorCode = "locked" | "signedOut" | "notFound" | "unsupported" | "failed";

export const CREDENTIAL_ERROR_CODES: readonly CredentialErrorCode[] = ["locked", "signedOut", "notFound", "unsupported", "failed"];

export type HostCredentialErrorCode = CredentialErrorCode | "cancelled" | "timedOut" | "stopped" | "invalid" | "tooLarge" | "overloaded" | "stale";

export type CredentialRequestErrorCode = "refused" | "bad_request" | "failed" | "overloaded" | "stale" | "expired" | "denied" | "closed";

export type WireCredentialError = { code: CredentialErrorCode; problem?: ProblemCode; detail?: string; state?: FailureState; field?: string };

export declare class CredentialError extends PluginError {
  readonly code: CredentialErrorCode;
  readonly problem: ProblemCode | undefined;
  readonly detail: string | undefined;
  readonly state: FailureState | undefined;
  readonly field: string | undefined;
  private constructor(code: CredentialErrorCode, options?: { problem?: ProblemCode; detail?: string; state?: FailureState; field?: string });
  static locked(): CredentialError;
  static signedOut(): CredentialError;
  static notFound(): CredentialError;
  static unsupported(): CredentialError;
  static failed(problem: ProblemCode, options?: { detail?: string; state?: FailureState; field?: string }): CredentialError;
  static is(error: unknown, code?: CredentialErrorCode): error is CredentialError;
  toWire(): WireCredentialError;
}

export declare const SignIn: {
  done(options?: { session?: SecretHandle }): SignInOutcome;
  needs(need: SignInNeed, options?: { problem?: ProblemCode; detail?: string; state?: FailureState }): SignInOutcome;
  failed(problem: ProblemCode, options?: { detail?: string; state?: FailureState; field?: string }): SignInOutcome;
  cancelled(state?: FailureState): SignInOutcome;
};

export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export type VerbParam = string | boolean | SecretHandle | JsonValue;

export type VerbParams = Readonly<Record<string, VerbParam | undefined>>;

export type StreamLine = { stream: "stdout" | "stderr"; text: string };

export type VerbOptions = {
  timeoutMs?: number;
  onItem?(item: unknown, index: number): void;
  onLine?(line: StreamLine): void;
};

export type VerbResult = {
  readonly verb: string;
  readonly status: number;
  readonly launched: boolean;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  readonly overflowed: boolean;
  readonly succeeded: boolean;
  readonly stderr: string;
  readonly hints: readonly string[];
  readonly json: unknown;
  readonly lines: readonly string[];
  readonly items: number;
  readonly droppedLines: number;
  readonly unlocked: boolean;
};

export type RunningVerb = PromiseLike<VerbResult> & { readonly id: number; cancel(): void };

export type SignInRunState = { state: "none" | "running" | "succeeded" | "failed"; hints: readonly string[]; detail?: string; timedOut?: boolean };

export type Cli = {
  readonly name: string;
  readonly version: string | null;
  readonly signInRun: SignInRunState;
  verb(id: string, params?: VerbParams, options?: VerbOptions): RunningVerb;
  cancelSigningIn(): Promise<void>;
};

export type SessionStore = {
  readonly current: { readonly key: SecretHandle | null } | null;
  readonly hasStored: boolean;
  takeStored(reason: string): Promise<SecretHandle | null>;
  dropStored(): Promise<void>;
};

export type ValueStore = {
  get(key: string): string | undefined;
  set(key: string, value: string | null): Promise<void>;
};

export type Owner = { confirm(reason: string): Promise<boolean> };

export type CredentialContext = Omit<CallContext, "kind" | "name"> & {
  readonly kind: "credentials";
  readonly name: CredentialHandlerName;
  readonly epoch: string;
  readonly provider: string;
  readonly touchID: boolean;
  readonly offline: boolean;
  readonly cli: Cli;
  readonly session: SessionStore;
  readonly scratch: ValueStore;
  readonly preferences: ValueStore;
  readonly owner: Owner;
};

export type CredentialHandler<I, O> = (input: I, ctx: CredentialContext) => Awaitable<O>;

export type PasskeyHandlers = {
  list?: CredentialHandler<PasskeyListRequest, readonly ListedPasskey[]>;
  get: CredentialHandler<PasskeyGetRequest, PasskeyKey | null>;
  save: CredentialHandler<PasskeySaveRequest, PasskeySaved>;
};

export type CredentialProvider = {
  state: CredentialHandler<StateRequest, ProviderState>;
  signIn: CredentialHandler<SignInRequest, SignInOutcome>;
  unlock: CredentialHandler<UnlockRequest, SignInOutcome>;
  signOut: CredentialHandler<Record<string, never>, void>;
  configure?: CredentialHandler<ConfigureRequest, void>;
  list: CredentialHandler<ListRequest, ItemPage | readonly ListedItem[]>;
  reveal: CredentialHandler<RevealRequest, Revealed>;
  save?: CredentialHandler<SaveRequest, Item>;
  edit?: CredentialHandler<EditRequest, Item>;
  addTotp?: CredentialHandler<AddTotpRequest, Item>;
  passkeys?: PasskeyHandlers;
};

export type CredentialHello = { credentials: typeof CREDENTIALS_PROTOCOL };

export type CredentialHelloResult = { credentials: { protocol: number; supported: readonly number[]; provider: string } };

export type CredentialReady = { credentialProvider: { handlers: CredentialHandlerName[] } };

export declare function credentialHandlersOf(provider: CredentialProvider): CredentialHandlerName[];

export declare function defineCredentialProvider(provider: CredentialProvider): Promise<void>;

export declare function isSecretHandle(value: unknown): value is SecretHandle;

export type RunHints = { locked?: readonly string[]; signedOut?: readonly string[]; notFound?: readonly string[] };

export declare const verbs: {
  mentions(result: Pick<VerbResult, "stderr">, needles: readonly string[]): boolean;
  problem(result: VerbResult, offline: boolean): ProblemCode;
  check(result: VerbResult, hints: RunHints, offline: boolean): void;
  firstLine(result: VerbResult): string | null;
  unreachableHints: readonly string[];
  outdatedHints: readonly string[];
};

export type JsonRecord = Record<string, unknown>;

export declare const json: {
  record(value: unknown): JsonRecord;
  list(value: unknown): JsonRecord[];
  listAt(value: unknown, key: string): JsonRecord[];
  dict(value: unknown): JsonRecord | undefined;
  dicts(value: unknown): JsonRecord[];
  string(value: unknown): string | undefined;
  strings(value: unknown): string[];
  int(value: unknown): number | undefined;
  bool(value: unknown): boolean | undefined;
  milliseconds(value: unknown): number | undefined;
};

export declare const origins: {
  host(url: string): string | undefined;
  isLocalHost(host: string): boolean;
  isWebOrigin(url: string): boolean;
  hostIn(url: string, allowed: readonly string[]): boolean;
};

export type TotpSecret = { secret: Uint8Array; period: number; digits: number; algorithm: "SHA1" | "SHA256" | "SHA512" };

export declare const totp: {
  parse(uri: string): TotpSecret | null;
  period(uri: string): number | undefined;
  code(secret: TotpSecret, atMs: number): string;
  same(a: string, b: string): boolean;
};

export declare const base64url: {
  encode(bytes: Uint8Array): string;
  decode(text: string, longest?: number): Uint8Array | null;
};

export declare const uuids: {
  bytes(uuid: string): Uint8Array | null;
  string(bytes: Uint8Array): string | null;
};

export type FakeLaunch = { verb: string; argv: readonly string[]; env: Readonly<Record<string, string>>; stdin: string; timeoutMs: number; signIn: boolean };

export type FakeReply = {
  status?: number;
  stdout?: string;
  stderr?: string;
  timedOut?: boolean;
  lines?: readonly StreamLine[];
  finishAfterMs?: number;
};

export type FakeCli = (launch: FakeLaunch) => Awaitable<FakeReply>;

export type HarnessContext = {
  touchID?: boolean;
  offline?: boolean;
  session?: { key: string | null } | null;
  storedSession?: string | null;
  scratch?: Record<string, string>;
  preferences?: Record<string, string>;
  ownerConfirms?: boolean;
  testInstance?: boolean;
};

export type HarnessInputs = {
  state: StateRequest;
  signIn: SignInRequest;
  unlock: UnlockRequest;
  signOut: Record<string, never>;
  configure: ConfigureRequest;
  list: ListRequest;
  reveal: RevealRequest;
  save: SaveRequest;
  edit: EditRequest;
  addTotp: AddTotpRequest;
  "passkeys.list": PasskeyListRequest;
  "passkeys.get": PasskeyGetRequest;
  "passkeys.save": PasskeySaveRequest;
};

export type HarnessAnswer = { ok: true; result: unknown } | { ok: false; error: WireCredentialError | { code: HostCredentialErrorCode } };

export type CredentialHarness = {
  call<N extends CredentialHandlerName>(name: N, input: HarnessInputs[N]): Promise<HarnessAnswer>;
  secret(value: string): SecretHandle;
  lock(): Promise<void>;
  readonly launches: readonly FakeLaunch[];
  readonly refused: readonly { verb: string; reason: string }[];
  readonly session: { key: string | null } | null;
  readonly storedSession: string | null;
  readonly scratch: Readonly<Record<string, string>>;
  readonly preferences: Readonly<Record<string, string>>;
  advance(ms: number): Promise<void>;
};

export declare function buildVerbLaunch(manifest: unknown, verb: string, params: VerbParams, secrets: (handle: SecretHandle) => string | null, testFolder: string | null): FakeLaunch | { refused: string };

export declare function createCredentialHarness(options: { provider: CredentialProvider; manifest: unknown; cli: FakeCli; context?: HarnessContext }): CredentialHarness;
