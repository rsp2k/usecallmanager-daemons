import { useState, useEffect } from 'react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../ui/select';
import type { Device } from '../../lib/api/types';
import { createCapfApi } from '../../lib/api/capf';

export default function ConfigEncryptor() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>('');
  const [configXml, setConfigXml] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingDevices, setLoadingDevices] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    setLoadingDevices(true);
    try {
      const api = createCapfApi();
      const response = await api.listDevices(100, 0);
      // Only show devices that have certificates
      setDevices(response.items.filter((d) => d.has_certificate));
    } catch (err) {
      console.error('Failed to load devices:', err);
    } finally {
      setLoadingDevices(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const text = await file.text();
      setConfigXml(text);
    }
  };

  const handleEncrypt = async () => {
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const api = createCapfApi();
      const blob = await api.encryptConfig({
        device_name: selectedDevice,
        config_xml: configXml,
      });

      // Download the file
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${selectedDevice}.cnf.xml.enc.sgn`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setSuccess(`Encrypted config for ${selectedDevice} (${blob.size} bytes)`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to encrypt config');
    } finally {
      setLoading(false);
    }
  };

  const isValid = selectedDevice && configXml.length > 0;

  return (
    <div className="space-y-4">
      <div>
        <Label className="text-xs">Target Device</Label>
        {loadingDevices ? (
          <div className="h-10 bg-muted animate-pulse rounded-md" />
        ) : devices.length === 0 ? (
          <div className="text-sm text-muted-foreground p-3 border rounded-md">
            No devices with certificates found. Add a device and install a certificate first.
          </div>
        ) : (
          <Select value={selectedDevice} onValueChange={setSelectedDevice}>
            <SelectTrigger>
              <SelectValue placeholder="Select a device" />
            </SelectTrigger>
            <SelectContent>
              {devices.map((device) => (
                <SelectItem key={device.device_name} value={device.device_name}>
                  {device.device_name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {selectedDevice && (
          <p className="text-xs text-muted-foreground mt-1">
            Config will be encrypted with this device&apos;s certificate
          </p>
        )}
      </div>

      <div>
        <Label className="text-xs">Configuration File (XML)</Label>
        <Input
          type="file"
          accept=".xml,.cnf"
          onChange={handleFileUpload}
          className="text-xs"
        />
        {configXml && (
          <p className="text-xs text-green-600 mt-1">
            Config loaded ({configXml.length} characters)
          </p>
        )}
      </div>

      <div>
        <Label className="text-xs">Or paste configuration</Label>
        <textarea
          value={configXml}
          onChange={(e) => setConfigXml(e.target.value)}
          placeholder="<?xml version='1.0'?>&#10;<device>...</device>"
          className="w-full h-32 px-3 py-2 text-xs font-mono border rounded-md bg-background resize-none"
        />
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-500/10 text-green-600 text-sm p-3 rounded-md">
          {success}
        </div>
      )}

      <Button
        onClick={handleEncrypt}
        disabled={!isValid || loading || devices.length === 0}
        className="w-full"
      >
        {loading ? 'Encrypting...' : 'Encrypt Configuration'}
      </Button>
    </div>
  );
}
