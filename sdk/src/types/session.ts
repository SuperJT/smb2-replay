/**
 * Session-related types.
 */

/**
 * Summary information about a session.
 */
export interface SessionSummary {
  session_id: string;
  file_name: string;
  operation_count?: number;
}

/**
 * Response for listing sessions.
 */
export interface SessionListResponse {
  sessions: SessionSummary[];
  capture_path: string | null;
  total: number;
}

/**
 * An SMB2 operation from a session.
 */
export interface Operation {
  Frame: string;
  Command: string;
  Path?: string;
  Status?: string;
  StatusDesc?: string;
  Tree?: string;
  /** Additional dynamic fields */
  [key: string]: unknown;
}

/**
 * Options for filtering session operations.
 */
export interface OperationFilter {
  /** Filter by specific file path */
  file_filter?: string;
  /** Specific fields to include */
  fields?: string[];
  /** Override capture path */
  capture_path?: string;
}

/**
 * Response containing session operations.
 */
export interface OperationsResponse {
  session_id: string;
  operations: Operation[];
  total: number;
  file_filter?: string;
}
