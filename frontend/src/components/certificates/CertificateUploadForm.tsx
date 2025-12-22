import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { createTvsApi } from '@/lib/api/tvs';
import { ROLE_OPTIONS, type RoleType } from '@/lib/api/types';

export default function CertificateUploadForm() {
  const [file, setFile] = useState<File | null>(null);
  const [selectedRoles, setSelectedRoles] = useState<RoleType[]>([]);
  const [ttl, setTtl] = useState(86400);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleRole = (role: RoleType) => {
    if (selectedRoles.includes(role)) {
      setSelectedRoles(selectedRoles.filter((r) => r !== role));
    } else {
      setSelectedRoles([...selectedRoles, role]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!file) {
      setError('Please select a PEM file');
      return;
    }

    if (selectedRoles.length === 0) {
      setError('Please select at least one role');
      return;
    }

    setIsUploading(true);

    try {
      const api = createTvsApi();
      const cert = await api.addCertificate(file, selectedRoles, ttl);
      window.location.href = `/certificates/${cert.certificate_hash}`;
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to upload certificate');
      setIsUploading(false);
    }
  };

  const ttlPresets = [
    { label: '1 hour', value: 3600 },
    { label: '1 day', value: 86400 },
    { label: '7 days', value: 604800 },
    { label: '30 days', value: 2592000 },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Upload Certificate</CardTitle>
        <CardDescription>
          Upload a PEM-encoded X.509 certificate to add to the trust store.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* File Input */}
          <div className="space-y-2">
            <Label htmlFor="file">Certificate File (PEM)</Label>
            <Input
              id="file"
              type="file"
              accept=".pem,.crt,.cer"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            {file && (
              <p className="text-sm text-muted-foreground">
                Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
              </p>
            )}
          </div>

          {/* Roles Selection */}
          <div className="space-y-2">
            <Label>Roles</Label>
            <p className="text-sm text-muted-foreground mb-2">
              Select the roles this certificate is trusted for:
            </p>
            <div className="flex flex-wrap gap-2">
              {ROLE_OPTIONS.map((role) => (
                <Badge
                  key={role}
                  variant={selectedRoles.includes(role) ? 'default' : 'outline'}
                  className="cursor-pointer select-none"
                  onClick={() => toggleRole(role)}
                >
                  {role}
                </Badge>
              ))}
            </div>
          </div>

          {/* TTL Selection */}
          <div className="space-y-2">
            <Label htmlFor="ttl">Time to Live (TTL)</Label>
            <div className="flex flex-wrap gap-2 mb-2">
              {ttlPresets.map((preset) => (
                <Button
                  key={preset.value}
                  type="button"
                  variant={ttl === preset.value ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setTtl(preset.value)}
                >
                  {preset.label}
                </Button>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <Input
                id="ttl"
                type="number"
                min={1}
                max={2592000}
                value={ttl}
                onChange={(e) => setTtl(Number(e.target.value))}
                className="w-32"
              />
              <span className="text-sm text-muted-foreground">seconds</span>
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="rounded-lg bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
          )}

          {/* Submit */}
          <div className="flex gap-4">
            <Button type="submit" disabled={isUploading}>
              {isUploading ? (
                <>
                  <svg
                    className="mr-2 h-4 w-4 animate-spin"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    />
                  </svg>
                  Uploading...
                </>
              ) : (
                'Upload Certificate'
              )}
            </Button>
            <Button type="button" variant="outline" asChild>
              <a href="/certificates">Cancel</a>
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
