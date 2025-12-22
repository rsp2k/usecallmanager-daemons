import { useState } from 'react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import type { RoleType } from '../../lib/api/types';
import { createCapfApi } from '../../lib/api/capf';

const ROLE_OPTIONS: RoleType[] = ['SAST', 'CCM', 'CCM+TFTP', 'TFTP', 'CAPF', 'APP-SERVER', 'TVS'];

interface CertEntry {
  id: number;
  pem: string;
  roles: RoleType[];
}

export default function ITLGenerator() {
  const [certificates, setCertificates] = useState<CertEntry[]>([
    { id: 1, pem: '', roles: ['CCM'] },
  ]);
  const [signerCert, setSignerCert] = useState('');
  const [signerKey, setSignerKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const addCertificate = () => {
    setCertificates([
      ...certificates,
      { id: Date.now(), pem: '', roles: ['CCM'] },
    ]);
  };

  const removeCertificate = (id: number) => {
    if (certificates.length > 1) {
      setCertificates(certificates.filter((c) => c.id !== id));
    }
  };

  const updateCertificate = (id: number, field: 'pem' | 'roles', value: string | RoleType[]) => {
    setCertificates(
      certificates.map((c) =>
        c.id === id ? { ...c, [field]: value } : c
      )
    );
  };

  const toggleRole = (id: number, role: RoleType) => {
    const cert = certificates.find((c) => c.id === id);
    if (!cert) return;

    const newRoles = cert.roles.includes(role)
      ? cert.roles.filter((r) => r !== role)
      : [...cert.roles, role];

    if (newRoles.length > 0) {
      updateCertificate(id, 'roles', newRoles);
    }
  };

  const handleFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>,
    setter: (value: string) => void
  ) => {
    const file = e.target.files?.[0];
    if (file) {
      const text = await file.text();
      setter(text);
    }
  };

  const handleCertFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>,
    certId: number
  ) => {
    const file = e.target.files?.[0];
    if (file) {
      const text = await file.text();
      updateCertificate(certId, 'pem', text);
    }
  };

  const handleGenerate = async () => {
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const api = createCapfApi();
      const blob = await api.generateItlFile({
        certificates: certificates.map((c) => ({
          pem: c.pem,
          roles: c.roles,
        })),
        signer: {
          certificate_pem: signerCert,
          private_key_pem: signerKey,
        },
      });

      // Download the file
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ITLFile.tlv';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setSuccess(`Generated ITLFile.tlv (${blob.size} bytes)`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate ITL file');
    } finally {
      setLoading(false);
    }
  };

  const isValid =
    certificates.every((c) => c.pem.includes('BEGIN CERTIFICATE') && c.roles.length > 0) &&
    signerCert.includes('BEGIN CERTIFICATE') &&
    signerKey.includes('BEGIN');

  return (
    <div className="space-y-4">
      <div className="space-y-4">
        <Label className="text-sm font-medium">Certificates</Label>
        {certificates.map((cert, index) => (
          <div key={cert.id} className="border rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Certificate {index + 1}</span>
              {certificates.length > 1 && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removeCertificate(cert.id)}
                >
                  Remove
                </Button>
              )}
            </div>
            <div>
              <Label className="text-xs">PEM File</Label>
              <Input
                type="file"
                accept=".pem,.crt,.cer"
                onChange={(e) => handleCertFileUpload(e, cert.id)}
                className="text-xs"
              />
              {cert.pem && (
                <p className="text-xs text-green-600 mt-1">Certificate loaded</p>
              )}
            </div>
            <div>
              <Label className="text-xs">Roles</Label>
              <div className="flex flex-wrap gap-1 mt-1">
                {ROLE_OPTIONS.map((role) => (
                  <button
                    key={role}
                    type="button"
                    onClick={() => toggleRole(cert.id, role)}
                    className={`px-2 py-0.5 text-xs rounded-full border transition-colors ${
                      cert.roles.includes(role)
                        ? 'bg-primary text-primary-foreground border-primary'
                        : 'bg-muted text-muted-foreground hover:bg-muted/80'
                    }`}
                  >
                    {role}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ))}
        <Button variant="outline" size="sm" onClick={addCertificate}>
          Add Certificate
        </Button>
      </div>

      <div className="border-t pt-4 space-y-3">
        <Label className="text-sm font-medium">Signer Credentials</Label>
        <div>
          <Label className="text-xs">Signer Certificate (PEM)</Label>
          <Input
            type="file"
            accept=".pem,.crt,.cer"
            onChange={(e) => handleFileUpload(e, setSignerCert)}
            className="text-xs"
          />
          {signerCert && (
            <p className="text-xs text-green-600 mt-1">Signer certificate loaded</p>
          )}
        </div>
        <div>
          <Label className="text-xs">Signer Private Key (PEM)</Label>
          <Input
            type="file"
            accept=".pem,.key"
            onChange={(e) => handleFileUpload(e, setSignerKey)}
            className="text-xs"
          />
          {signerKey && (
            <p className="text-xs text-green-600 mt-1">Private key loaded</p>
          )}
        </div>
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
        onClick={handleGenerate}
        disabled={!isValid || loading}
        className="w-full"
      >
        {loading ? 'Generating...' : 'Generate ITL File'}
      </Button>
    </div>
  );
}
