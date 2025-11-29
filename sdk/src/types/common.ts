/**
 * Common types shared across the SDK.
 */

/**
 * Standard error response from the API.
 */
export interface ErrorResponse {
  error: string;
  detail?: string;
  code?: string;
}

/**
 * Health check response.
 */
export interface HealthResponse {
  status: 'ok' | 'degraded' | 'error';
  version: string;
  tshark_available: boolean;
}

/**
 * System information response.
 */
export interface SystemInfo {
  version: string;
  tshark_available: boolean;
  capture_path: string | null;
  capture_valid: boolean;
  supported_commands: Record<string, string>;
  traces_folder: string;
  verbosity_level: number;
  packet_count?: number;
}

/**
 * Generic async job status.
 */
export interface JobStatus<T = unknown> {
  job_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress?: number;
  message?: string;
  result?: T;
  error?: string;
}
