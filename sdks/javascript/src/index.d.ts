// Type declarations for the PromptSentinel JavaScript SDK.
// Hand-written to keep the package dependency-free and tsc-free.

/** Discriminator for the category of failure carried by a {@link GuardError}. */
export type GuardErrorKind =
  | "timeout"
  | "network"
  | "unauthorized"
  | "http"
  | "parse";

/** Error thrown for every failure surfaced by the SDK. */
export class GuardError extends Error {
  name: "GuardError";
  /** Category of failure, for branching without parsing the message. */
  kind: GuardErrorKind;
  /** HTTP status code, when the failure came from a response. */
  status?: number;
  /** Underlying cause (e.g. the original fetch/abort error), when available. */
  cause?: unknown;
  constructor(
    message: string,
    opts?: { kind?: GuardErrorKind; status?: number; cause?: unknown }
  );
}

/** Result of {@link Client.health}. */
export interface HealthResult {
  status: string;
  team: string;
  agent: string;
  llmGuard: boolean;
  llmJudge: boolean;
  protectedTerms: number;
  /** Operating mode of the gateway (e.g. "enforce", "shadow"); "" when absent. */
  mode: string;
  /** Whether the ML injection classifier is loaded server-side. */
  mlClassifier: boolean;
}

/** Result of {@link Client.version}. */
export interface VersionResult {
  service: string;
  version: string;
  scanners: Record<string, boolean>;
}

/** Result of {@link Client.buildSystemPrompt} (POST /v1/system-prompt/build). */
export interface BuildResult {
  /** Hardened system prompt to send to your model. */
  hardenedSystemPrompt: string;
  /** Canary token to persist and later pass to {@link Client.screenOutput}. */
  canary: string;
}

/** Result of {@link Client.screenInput} (POST /v1/screen/input). */
export interface InputResult {
  /** When false, do not call the model; return {@link InputResult.refusal}. */
  allowed: boolean;
  /** Risk score in [0, 1]. */
  risk: number;
  /** Human-readable scanner reasons. */
  reasons: string[];
  /** Possibly sanitized version of the input. */
  sanitized: string;
  /** Refusal text to return to the user when blocked; null when allowed. */
  refusal: string | null;
  /**
   * Whether this verdict would block under enforce mode. Stays true even in
   * shadow mode (where {@link InputResult.allowed} remains true). Default false.
   */
  wouldBlock: boolean;
  /** Gateway mode that produced this verdict (e.g. "enforce", "shadow"). */
  mode: string;
}

/** Result of {@link Client.screenOutput} (POST /v1/screen/output). */
export interface OutputResult {
  /** Whether the output passed screening. */
  allowed: boolean;
  /** Risk score in [0, 1]. */
  risk: number;
  /** Human-readable scanner reasons. */
  reasons: string[];
  /**
   * Safe text to return to the caller verbatim: either the cleared model
   * output or a refusal message when the output was blocked.
   */
  text: string;
  /**
   * Whether this verdict would block under enforce mode. Stays true even in
   * shadow mode (where {@link OutputResult.allowed} remains true). Default false.
   */
  wouldBlock: boolean;
  /** Gateway mode that produced this verdict (e.g. "enforce", "shadow"). */
  mode: string;
}

/** Which screening stage produced the final {@link GuardResult.text}. */
export type GuardStage = "input" | "output";

/** Result of the high-level {@link Client.guard} helper. */
export interface GuardResult {
  /** Whether the request completed without being blocked at any stage. */
  allowed: boolean;
  /** Safe text to return to the end user verbatim. */
  text: string;
  /** Stage that produced {@link GuardResult.text}. */
  stage: GuardStage;
  /** The input-screening result. */
  input: InputResult;
  /** The output-screening result; null when blocked at the input stage. */
  output: OutputResult | null;
}

/** Constructor options for {@link Client}. */
export interface ClientOptions {
  /** Base URL of the PromptSentinel service. Default "http://localhost:8000". */
  baseUrl?: string;
  /** Optional bearer token; required when the service has server.auth_token set. */
  token?: string | null;
  /** Per-attempt timeout in milliseconds. Default 10000. */
  timeout?: number;
  /** Number of retries on transient failures (network/5xx/429). Default 2. */
  retries?: number;
  /** Override the fetch implementation (primarily for testing). */
  fetch?: typeof fetch;
}

/** Arguments for the {@link Client.guard} helper. */
export interface GuardArgs {
  /** Raw user input to screen. */
  userInput: string;
  /**
   * Business callback. Receives the system prompt to use (typically your
   * hardened prompt, i.e. {@link GuardArgs.systemPrompt}) and returns the raw
   * model output string (sync or async).
   */
  callModel: (systemPrompt: string) => string | Promise<string>;
  /** Optional untrusted context (tool/RAG output) to screen alongside input. */
  untrustedContext?: string | null;
  /** Canary token from {@link Client.buildSystemPrompt} for leak detection. */
  canary?: string | null;
  /** Hardened system prompt passed to callModel and to output screening. */
  systemPrompt?: string | null;
}

/** PromptSentinel API client. */
export class Client {
  baseUrl: string;
  token: string | null;
  timeout: number;
  retries: number;
  constructor(options?: ClientOptions);
  health(): Promise<HealthResult>;
  version(): Promise<VersionResult>;
  buildSystemPrompt(basePrompt: string): Promise<BuildResult>;
  screenInput(
    userInput: string,
    untrustedContext?: string | null
  ): Promise<InputResult>;
  screenOutput(
    modelOutput: string,
    canary?: string | null,
    systemPrompt?: string | null
  ): Promise<OutputResult>;
  guard(args: GuardArgs): Promise<GuardResult>;
}

export default Client;
