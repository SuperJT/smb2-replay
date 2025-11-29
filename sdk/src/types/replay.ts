/**
 * Replay-related types.
 */

/**
 * Options for replay validation.
 */
export interface ValidateOptions {
  /** Override capture path */
  capture_path?: string;
  /** Filter by file path */
  file_filter?: string;
  /** Check file system structure */
  check_fs?: boolean;
  /** Check operation validity */
  check_ops?: boolean;
}

/**
 * Result of validation checks.
 */
export interface ValidationResult {
  ready: boolean;
  checks: {
    operations?: {
      valid: boolean;
      total_operations: number;
      supported_operations: number;
      issues: string[];
    };
    file_system?: {
      ready: boolean;
      total_paths?: number;
      accessible_paths?: number;
      missing_directories: string[];
      created_files?: number;
      existing_files?: number;
      warnings: string[];
    };
  };
  errors: string[];
  warnings: string[];
}

/**
 * Options for infrastructure setup.
 */
export interface SetupOptions {
  /** Override capture path */
  capture_path?: string;
  /** Filter by file path */
  file_filter?: string;
  /** Show what would be created without changes */
  dry_run?: boolean;
  /** Continue despite errors */
  force?: boolean;
  /** Override server IP */
  server_ip?: string;
  /** Override username */
  username?: string;
  /** Override password */
  password?: string;
  /** Override tree/share name */
  tree_name?: string;
}

/**
 * Result of infrastructure setup.
 */
export interface SetupResult {
  success: boolean;
  directories_created: number;
  files_created: number;
  errors: string[];
  warnings: string[];
  dry_run: boolean;
}

/**
 * Options for replay execution.
 */
export interface ReplayOptions {
  /** Override capture path */
  capture_path?: string;
  /** Filter by file path */
  file_filter?: string;
  /** Override server IP */
  server_ip?: string;
  /** Override domain */
  domain?: string;
  /** Override username */
  username?: string;
  /** Override password */
  password?: string;
  /** Override tree/share name */
  tree_name?: string;
  /** Validate before replaying (default: true) */
  validate_first?: boolean;
  /** Ping server before starting (default: true) */
  enable_ping?: boolean;
}

/**
 * Result of replay execution.
 */
export interface ReplayResult {
  success: boolean;
  total_operations: number;
  successful_operations: number;
  failed_operations: number;
  errors: string[];
  validation?: ValidationResult;
}
