/**
 * SMB Replay API Client.
 *
 * Type-safe client for interacting with the SMB Replay REST API.
 */

import { APIError, NetworkError, NotFoundError } from './errors';
import type {
  Config,
  ConfigUpdate,
  ConfigValue,
  HealthResponse,
  IngestOptions,
  IngestResult,
  OperationFilter,
  OperationsResponse,
  ReplayOptions,
  ReplayResult,
  SessionListResponse,
  SetupOptions,
  SetupResult,
  SystemInfo,
  TraceListResponse,
  ValidateOptions,
  ValidationResult,
} from './types';

/**
 * Client configuration options.
 */
export interface SMBReplayClientOptions {
  /** Base URL of the SMB Replay API (e.g., 'http://localhost:3004') */
  baseUrl: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom fetch implementation (for testing or custom environments) */
  fetch?: typeof fetch;
  /** Custom headers to include with all requests */
  headers?: Record<string, string>;
}

/**
 * Type-safe client for the SMB Replay API.
 *
 * @example
 * ```typescript
 * const client = new SMBReplayClient({ baseUrl: 'http://localhost:3004' });
 *
 * // Health check
 * const health = await client.healthCheck();
 * console.log(health.status);
 *
 * // List sessions
 * const sessions = await client.listSessions();
 * console.log(sessions.sessions);
 *
 * // Execute replay
 * const result = await client.executeReplay('0x1234567890abcdef');
 * console.log(result.success);
 * ```
 */
export class SMBReplayClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly fetchFn: typeof fetch;
  private readonly headers: Record<string, string>;

  constructor(options: SMBReplayClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.timeout = options.timeout ?? 30000;
    this.fetchFn = options.fetch ?? fetch;
    this.headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
  }

  // =========================================================================
  // Internal helpers
  // =========================================================================

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    queryParams?: Record<string, string | undefined>
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);

    // Add query parameters
    if (queryParams) {
      Object.entries(queryParams).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.set(key, value);
        }
      });
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchFn(url.toString(), {
        method,
        headers: this.headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));

        if (response.status === 404) {
          throw new NotFoundError(
            errorData.error || errorData.detail || 'Resource not found',
            path
          );
        }

        throw new APIError(
          errorData.error || errorData.detail || `HTTP ${response.status}`,
          response.status,
          errorData,
          errorData.code
        );
      }

      return (await response.json()) as T;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof APIError || error instanceof NotFoundError) {
        throw error;
      }

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new NetworkError('Request timeout', error);
        }
        throw new NetworkError(error.message, error);
      }

      throw new NetworkError('Unknown network error');
    }
  }

  private get<T>(
    path: string,
    queryParams?: Record<string, string | undefined>
  ): Promise<T> {
    return this.request<T>('GET', path, undefined, queryParams);
  }

  private post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PUT', path, body);
  }

  // =========================================================================
  // Health & Info
  // =========================================================================

  /**
   * Check API health status.
   *
   * @returns Health status including API version and tshark availability.
   */
  async healthCheck(): Promise<HealthResponse> {
    return this.get<HealthResponse>('/health');
  }

  /**
   * Get detailed system information.
   *
   * @returns System configuration and status information.
   */
  async getSystemInfo(): Promise<SystemInfo> {
    return this.get<SystemInfo>('/info');
  }

  // =========================================================================
  // Configuration
  // =========================================================================

  /**
   * Get current configuration.
   *
   * @returns Full configuration object.
   */
  async getConfig(): Promise<Config> {
    return this.get<Config>('/api/config');
  }

  /**
   * Update configuration values.
   *
   * @param updates - Partial configuration updates.
   * @returns Updated configuration object.
   */
  async updateConfig(updates: ConfigUpdate): Promise<Config> {
    return this.put<Config>('/api/config', updates);
  }

  /**
   * Get a specific configuration value.
   *
   * @param key - Configuration key name.
   * @returns Configuration key and value.
   */
  async getConfigValue(key: string): Promise<ConfigValue> {
    return this.get<ConfigValue>(`/api/config/${key}`);
  }

  // =========================================================================
  // Traces
  // =========================================================================

  /**
   * List available trace files.
   *
   * @param caseId - Optional case ID to filter traces.
   * @returns List of trace files.
   */
  async listTraces(caseId?: string): Promise<TraceListResponse> {
    return this.get<TraceListResponse>('/api/traces', { case_id: caseId });
  }

  /**
   * Ingest a PCAP file.
   *
   * @param path - Path to PCAP file (absolute or relative to case folder).
   * @param options - Ingestion options.
   * @returns Ingestion result.
   */
  async ingestTrace(
    path: string,
    options?: IngestOptions
  ): Promise<IngestResult> {
    return this.post<IngestResult>('/api/traces/ingest', {
      path,
      force: options?.force ?? false,
      reassembly: options?.reassembly ?? false,
      case_id: options?.case_id,
    });
  }

  // =========================================================================
  // Sessions
  // =========================================================================

  /**
   * List available sessions.
   *
   * @param capturePath - Optional capture path to filter sessions.
   * @returns List of sessions.
   */
  async listSessions(capturePath?: string): Promise<SessionListResponse> {
    return this.get<SessionListResponse>('/api/sessions', {
      capture_path: capturePath,
    });
  }

  /**
   * Get session operations.
   *
   * @param sessionId - Session ID (hex format) or file name.
   * @param filter - Optional filter parameters.
   * @returns Session operations.
   */
  async getOperations(
    sessionId: string,
    filter?: OperationFilter
  ): Promise<OperationsResponse> {
    if (filter && (filter.fields || filter.file_filter)) {
      // Use POST for complex filters
      return this.post<OperationsResponse>(
        `/api/sessions/${sessionId}/operations`,
        filter
      );
    }

    return this.get<OperationsResponse>(`/api/sessions/${sessionId}`, {
      capture_path: filter?.capture_path,
      file_filter: filter?.file_filter,
    });
  }

  // =========================================================================
  // Replay
  // =========================================================================

  /**
   * Validate replay readiness.
   *
   * @param sessionId - Session ID to validate.
   * @param options - Validation options.
   * @returns Validation result.
   */
  async validateReplay(
    sessionId: string,
    options?: ValidateOptions
  ): Promise<ValidationResult> {
    return this.post<ValidationResult>('/api/replay/validate', {
      session_id: sessionId,
      capture_path: options?.capture_path,
      file_filter: options?.file_filter,
      check_fs: options?.check_fs ?? true,
      check_ops: options?.check_ops ?? true,
    });
  }

  /**
   * Setup file system infrastructure for replay.
   *
   * @param sessionId - Session ID to setup for.
   * @param options - Setup options.
   * @returns Setup result.
   */
  async setupInfrastructure(
    sessionId: string,
    options?: SetupOptions
  ): Promise<SetupResult> {
    return this.post<SetupResult>('/api/replay/setup', {
      session_id: sessionId,
      capture_path: options?.capture_path,
      file_filter: options?.file_filter,
      dry_run: options?.dry_run ?? false,
      force: options?.force ?? false,
      server_ip: options?.server_ip,
      username: options?.username,
      password: options?.password,
      tree_name: options?.tree_name,
    });
  }

  /**
   * Execute a replay operation.
   *
   * @param sessionId - Session ID to replay.
   * @param options - Replay options.
   * @returns Replay result.
   */
  async executeReplay(
    sessionId: string,
    options?: ReplayOptions
  ): Promise<ReplayResult> {
    return this.post<ReplayResult>('/api/replay/execute', {
      session_id: sessionId,
      capture_path: options?.capture_path,
      file_filter: options?.file_filter,
      server_ip: options?.server_ip,
      domain: options?.domain,
      username: options?.username,
      password: options?.password,
      tree_name: options?.tree_name,
      validate_first: options?.validate_first ?? true,
      enable_ping: options?.enable_ping ?? true,
    });
  }
}
