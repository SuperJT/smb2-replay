/**
 * SMB Replay SDK
 *
 * TypeScript SDK for interacting with the SMB Replay REST API.
 *
 * @packageDocumentation
 */

// Main client
export { SMBReplayClient } from './client';
export type { SMBReplayClientOptions } from './client';

// Errors
export {
  SMBReplayError,
  APIError,
  NetworkError,
  ValidationError,
  NotFoundError,
} from './errors';

// Types
export type {
  // Common
  ErrorResponse,
  HealthResponse,
  SystemInfo,
  JobStatus,
  // Config
  Config,
  ConfigUpdate,
  ConfigValue,
  // Trace
  TraceFile,
  TraceListResponse,
  IngestOptions,
  IngestResult,
  // Session
  SessionSummary,
  SessionListResponse,
  Operation,
  OperationFilter,
  OperationsResponse,
  // Replay
  ValidateOptions,
  ValidationResult,
  SetupOptions,
  SetupResult,
  ReplayOptions,
  ReplayResult,
} from './types';
