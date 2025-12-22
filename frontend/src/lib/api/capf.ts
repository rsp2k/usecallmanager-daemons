import { createCapfClient } from './client';
import type {
  CapfStats,
  Device,
  DeviceCreate,
  DeviceListResponse,
  DeviceOperationUpdate,
  EncryptConfigRequest,
  HealthResponse,
  IssuerCertificate,
  ITLFileRequest,
  OperationType,
} from './types';

// Server-side functions
export async function getCapfHealth(): Promise<HealthResponse> {
  const client = createCapfClient(true);
  return client.get<HealthResponse>('/health');
}

export async function getCapfStats(): Promise<CapfStats> {
  const client = createCapfClient(true);
  return client.get<CapfStats>('/stats');
}

export async function listDevices(
  limit = 100,
  offset = 0,
  operation?: OperationType
): Promise<DeviceListResponse> {
  const client = createCapfClient(true);
  let url = `/devices?limit=${limit}&offset=${offset}`;
  if (operation) {
    url += `&operation=${operation}`;
  }
  return client.get<DeviceListResponse>(url);
}

export async function getDevice(name: string): Promise<Device> {
  const client = createCapfClient(true);
  return client.get<Device>(`/devices/${name}`);
}

export async function exportDeviceCertificate(name: string): Promise<string> {
  const client = createCapfClient(true);
  return client.getText(`/devices/${name}/certificate`);
}

export async function getIssuerCertificate(): Promise<IssuerCertificate> {
  const client = createCapfClient(true);
  return client.get<IssuerCertificate>('/issuer-certificate');
}

// Client-side functions (for React components)
export function createCapfApi() {
  const client = createCapfClient(false);

  return {
    async getHealth(): Promise<HealthResponse> {
      return client.get<HealthResponse>('/health');
    },

    async getStats(): Promise<CapfStats> {
      return client.get<CapfStats>('/stats');
    },

    async listDevices(
      limit = 100,
      offset = 0,
      operation?: OperationType
    ): Promise<DeviceListResponse> {
      let url = `/devices?limit=${limit}&offset=${offset}`;
      if (operation) {
        url += `&operation=${operation}`;
      }
      return client.get<DeviceListResponse>(url);
    },

    async getDevice(name: string): Promise<Device> {
      return client.get<Device>(`/devices/${name}`);
    },

    async addDevice(device: DeviceCreate): Promise<Device> {
      return client.post<Device>('/devices', device);
    },

    async updateDeviceOperation(name: string, update: DeviceOperationUpdate): Promise<Device> {
      return client.patch<Device>(`/devices/${name}/operation`, update);
    },

    async deleteDevice(name: string): Promise<void> {
      return client.delete(`/devices/${name}`);
    },

    async exportDeviceCertificate(name: string): Promise<string> {
      return client.getText(`/devices/${name}/certificate`);
    },

    async getIssuerCertificate(): Promise<IssuerCertificate> {
      return client.get<IssuerCertificate>('/issuer-certificate');
    },

    async generateItlFile(request: ITLFileRequest): Promise<Blob> {
      return client.postBlob('/itl-file', request);
    },

    async encryptConfig(request: EncryptConfigRequest): Promise<Blob> {
      return client.postBlob('/encrypt-config', request);
    },
  };
}
