/**
 * Trace/PCAP-related types.
 */

/**
 * Information about a trace file.
 */
export interface TraceFile {
  path: string;
  name: string;
  case_id: string | null;
}

/**
 * Response for listing traces.
 */
export interface TraceListResponse {
  traces: TraceFile[];
  case_id: string | null;
  total: number;
}

/**
 * Options for ingesting a PCAP file.
 */
export interface IngestOptions {
  /** Force re-ingestion even if data exists */
  force?: boolean;
  /** Enable TCP reassembly during parsing */
  reassembly?: boolean;
  /** Case ID for relative paths */
  case_id?: string;
}

/**
 * Result of PCAP ingestion.
 */
export interface IngestResult {
  success: boolean;
  sessions: string[];
  session_count: number;
  total_frames?: number;
  processing_time?: number;
  error?: string;
}
