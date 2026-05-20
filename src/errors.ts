export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

export class DtrackHttpError extends Error {
  readonly status: number;
  readonly details: string;

  constructor(status: number, details: string) {
    super(`Dependency-Track request failed with status ${status}: ${details}`);
    this.name = "DtrackHttpError";
    this.status = status;
    this.details = details;
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export class AmbiguousMatchError extends Error {
  readonly candidates: readonly Record<string, unknown>[];

  constructor(message: string, candidates: readonly Record<string, unknown>[]) {
    super(message);
    this.name = "AmbiguousMatchError";
    this.candidates = candidates;
  }
}

export class InvalidTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidTargetError";
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}
