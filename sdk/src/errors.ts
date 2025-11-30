/**
 * Error classes for SMB Replay SDK.
 */

/**
 * Base error class for SDK errors.
 */
export class SMBReplayError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
    public readonly statusCode?: number
  ) {
    super(message);
    this.name = 'SMBReplayError';
    Object.setPrototypeOf(this, SMBReplayError.prototype);
  }
}

/**
 * Error thrown when API request fails.
 */
export class APIError extends SMBReplayError {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly response?: unknown,
    code?: string
  ) {
    super(message, code, statusCode);
    this.name = 'APIError';
    Object.setPrototypeOf(this, APIError.prototype);
  }
}

/**
 * Error thrown when network request fails.
 */
export class NetworkError extends SMBReplayError {
  constructor(message: string, public readonly cause?: Error) {
    super(message, 'NETWORK_ERROR');
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/**
 * Error thrown when validation fails.
 */
export class ValidationError extends SMBReplayError {
  constructor(
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/**
 * Error thrown when a resource is not found.
 */
export class NotFoundError extends SMBReplayError {
  constructor(message: string, public readonly resource?: string) {
    super(message, 'NOT_FOUND', 404);
    this.name = 'NotFoundError';
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}
