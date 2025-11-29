/**
 * Configuration-related types.
 */

/**
 * Full configuration response.
 */
export interface Config {
  traces_folder: string;
  capture_path: string | null;
  verbosity_level: number;
  session_id: string | null;
  case_id: string | null;
  trace_name: string | null;
  server_ip: string;
  port: number;
  domain: string;
  username: string;
  password_set: boolean;
  tree_name: string;
  max_wait: number;
}

/**
 * Configuration update request.
 * All fields are optional for partial updates.
 */
export interface ConfigUpdate {
  traces_folder?: string;
  capture_path?: string;
  verbosity_level?: number;
  session_id?: string;
  case_id?: string;
  trace_name?: string;
  server_ip?: string;
  port?: number;
  domain?: string;
  username?: string;
  password?: string;
  tree_name?: string;
  max_wait?: number;
}

/**
 * Single configuration value response.
 */
export interface ConfigValue {
  key: string;
  value: string | null;
}
