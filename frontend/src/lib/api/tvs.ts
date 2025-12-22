import { createTvsClient } from './client';
import type { Certificate, CertificateListResponse, HealthResponse, RoleType, TvsStats } from './types';

// Server-side functions
export async function getTvsHealth(): Promise<HealthResponse> {
  const client = createTvsClient(true);
  return client.get<HealthResponse>('/health');
}

export async function getTvsStats(): Promise<TvsStats> {
  const client = createTvsClient(true);
  return client.get<TvsStats>('/stats');
}

export async function listCertificates(limit = 100, offset = 0): Promise<CertificateListResponse> {
  const client = createTvsClient(true);
  return client.get<CertificateListResponse>(`/certificates?limit=${limit}&offset=${offset}`);
}

export async function getCertificate(hash: string): Promise<Certificate> {
  const client = createTvsClient(true);
  return client.get<Certificate>(`/certificates/${hash}`);
}

export async function exportCertificatePem(hash: string): Promise<string> {
  const client = createTvsClient(true);
  return client.getText(`/certificates/${hash}/export`);
}

// Client-side functions (for React components)
export function createTvsApi() {
  const client = createTvsClient(false);

  return {
    async getHealth(): Promise<HealthResponse> {
      return client.get<HealthResponse>('/health');
    },

    async getStats(): Promise<TvsStats> {
      return client.get<TvsStats>('/stats');
    },

    async listCertificates(limit = 100, offset = 0): Promise<CertificateListResponse> {
      return client.get<CertificateListResponse>(`/certificates?limit=${limit}&offset=${offset}`);
    },

    async getCertificate(hash: string): Promise<Certificate> {
      return client.get<Certificate>(`/certificates/${hash}`);
    },

    async addCertificate(file: File, roles: RoleType[], ttl: number): Promise<Certificate> {
      const formData = new FormData();
      formData.append('file', file);
      roles.forEach((role) => formData.append('roles', role));
      formData.append('ttl', String(ttl));
      return client.postFormData<Certificate>('/certificates', formData);
    },

    async deleteCertificate(hash: string): Promise<void> {
      return client.delete(`/certificates/${hash}`);
    },

    async exportCertificatePem(hash: string): Promise<string> {
      return client.getText(`/certificates/${hash}/export`);
    },
  };
}
