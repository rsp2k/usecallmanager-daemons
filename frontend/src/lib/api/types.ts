// TVS Types
export type RoleType = 'SAST' | 'CCM' | 'CCM+TFTP' | 'TFTP' | 'CAPF' | 'APP-SERVER' | 'TVS';

export const ROLE_OPTIONS: RoleType[] = ['SAST', 'CCM', 'CCM+TFTP', 'TFTP', 'CAPF', 'APP-SERVER', 'TVS'];

export interface Certificate {
  certificate_hash: string;
  serial_number: string;
  subject_name: string;
  issuer_name: string;
  roles: string[];
  ttl: number;
}

export interface CertificateListResponse {
  items: Certificate[];
  total: number;
  limit: number;
  offset: number;
}

export interface TvsStats {
  total_certificates: number;
  active_connections: number;
}

// CAPF Types
export type OperationType = 'install' | 'fetch' | 'delete' | 'none';
export type AuthenticationType = 'password' | 'certificate' | 'no password';
export type CurveType = 'secp256r1' | 'secp384r1' | 'secp521r1';

export const OPERATION_OPTIONS: OperationType[] = ['install', 'fetch', 'delete', 'none'];
export const AUTHENTICATION_OPTIONS: AuthenticationType[] = ['password', 'certificate', 'no password'];
export const CURVE_OPTIONS: CurveType[] = ['secp256r1', 'secp384r1', 'secp521r1'];
export const KEY_SIZE_OPTIONS = [512, 1024, 2048, 3072, 4096] as const;

export interface Device {
  device_name: string;
  operation: string;
  authentication: string | null;
  key_size: number | null;
  curve_name: string | null;
  has_certificate: boolean;
  serial_number: string | null;
  not_valid_before: string | null;
  not_valid_after: string | null;
}

export interface DeviceCreate {
  device_name: string;
  operation: OperationType;
  authentication?: AuthenticationType;
  password?: string | null;
  key_size?: number | null;
  curve_name?: CurveType | null;
}

export interface DeviceOperationUpdate {
  operation: OperationType;
  authentication?: AuthenticationType;
  password?: string | null;
  key_size?: number | null;
  curve_name?: CurveType | null;
}

export interface DeviceListResponse {
  items: Device[];
  total: number;
  limit: number;
  offset: number;
}

export interface CapfStats {
  total_devices: number;
  pending_install: number;
  pending_fetch: number;
  pending_delete: number;
  active_connections: number;
}

export interface IssuerCertificate {
  subject: string;
  issuer: string;
  serial_number: string;
  not_valid_before: string;
  not_valid_after: string;
  fingerprint_sha256: string;
  fingerprint_sha1: string;
  public_key_algorithm: string;
  public_key_size: number;
  signature_algorithm: string;
  is_ca: boolean;
  pem: string;
}

// Common Types
export interface HealthResponse {
  status: string;
  service: string;
  protocol_port: number;
  api_port: number;
}

export interface ApiError {
  detail: string;
}
