import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { createCapfApi } from '@/lib/api/capf';
import {
  OPERATION_OPTIONS,
  AUTHENTICATION_OPTIONS,
  CURVE_OPTIONS,
  KEY_SIZE_OPTIONS,
  type OperationType,
  type AuthenticationType,
  type CurveType,
} from '@/lib/api/types';

interface DeviceFormProps {
  mode: 'add' | 'edit';
  initialData?: {
    device_name: string;
    operation: string;
    authentication: string | null;
    key_size: number | null;
    curve_name: string | null;
  };
}

export default function DeviceForm({ mode, initialData }: DeviceFormProps) {
  const [deviceName, setDeviceName] = useState(initialData?.device_name || '');
  const [operation, setOperation] = useState<OperationType>(
    (initialData?.operation as OperationType) || 'none'
  );
  const [authentication, setAuthentication] = useState<AuthenticationType>(
    (initialData?.authentication as AuthenticationType) || 'no password'
  );
  const [password, setPassword] = useState('');
  const [keySize, setKeySize] = useState<number | null>(initialData?.key_size || null);
  const [curveName, setCurveName] = useState<CurveType | null>(
    (initialData?.curve_name as CurveType) || null
  );
  const [keyType, setKeyType] = useState<'rsa' | 'ec'>(initialData?.curve_name ? 'ec' : 'rsa');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate device name format
    if (!/^SEP[0-9A-F]{12}$/.test(deviceName)) {
      setError('Device name must be in format SEP + 12 hex digits (e.g., SEP001A2B3C4D5E)');
      return;
    }

    // Validate password if required
    if (authentication === 'password' && (!password || password.length < 4 || password.length > 15)) {
      setError('Password must be between 4 and 15 characters');
      return;
    }

    setIsSubmitting(true);

    try {
      const api = createCapfApi();

      if (mode === 'add') {
        const device = await api.addDevice({
          device_name: deviceName,
          operation,
          authentication,
          password: authentication === 'password' ? password : null,
          key_size: keyType === 'rsa' ? keySize : null,
          curve_name: keyType === 'ec' ? curveName : null,
        });
        window.location.href = `/devices/${device.device_name}`;
      } else {
        const device = await api.updateDeviceOperation(deviceName, {
          operation,
          authentication,
          password: authentication === 'password' ? password : null,
          key_size: keyType === 'rsa' ? keySize : null,
          curve_name: keyType === 'ec' ? curveName : null,
        });
        window.location.href = `/devices/${device.device_name}`;
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save device');
      setIsSubmitting(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{mode === 'add' ? 'Add Device' : 'Edit Device Operation'}</CardTitle>
        <CardDescription>
          {mode === 'add'
            ? 'Register a new device for certificate enrollment.'
            : 'Update the certificate operation for this device.'}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Device Name */}
          <div className="space-y-2">
            <Label htmlFor="deviceName">Device Name</Label>
            <Input
              id="deviceName"
              placeholder="SEP001A2B3C4D5E"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value.toUpperCase())}
              disabled={mode === 'edit'}
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Format: SEP + 12 hex digits (MAC address)
            </p>
          </div>

          {/* Operation */}
          <div className="space-y-2">
            <Label htmlFor="operation">Operation</Label>
            <Select value={operation} onValueChange={(v) => setOperation(v as OperationType)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {OPERATION_OPTIONS.map((op) => (
                  <SelectItem key={op} value={op}>
                    {op.charAt(0).toUpperCase() + op.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              install: Generate new certificate, fetch: Retrieve existing, delete: Remove certificate
            </p>
          </div>

          {/* Authentication */}
          <div className="space-y-2">
            <Label htmlFor="authentication">Authentication</Label>
            <Select
              value={authentication}
              onValueChange={(v) => setAuthentication(v as AuthenticationType)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AUTHENTICATION_OPTIONS.map((auth) => (
                  <SelectItem key={auth} value={auth}>
                    {auth.charAt(0).toUpperCase() + auth.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Password (conditional) */}
          {authentication === 'password' && (
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="4-15 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={4}
                maxLength={15}
              />
            </div>
          )}

          {/* Key Type for install operation */}
          {operation === 'install' && (
            <>
              <div className="space-y-2">
                <Label>Key Type</Label>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant={keyType === 'rsa' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setKeyType('rsa')}
                  >
                    RSA
                  </Button>
                  <Button
                    type="button"
                    variant={keyType === 'ec' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setKeyType('ec')}
                  >
                    Elliptic Curve
                  </Button>
                </div>
              </div>

              {keyType === 'rsa' && (
                <div className="space-y-2">
                  <Label htmlFor="keySize">RSA Key Size</Label>
                  <Select
                    value={keySize?.toString() || ''}
                    onValueChange={(v) => setKeySize(Number(v))}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select key size" />
                    </SelectTrigger>
                    <SelectContent>
                      {KEY_SIZE_OPTIONS.map((size) => (
                        <SelectItem key={size} value={size.toString()}>
                          {size} bits
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              {keyType === 'ec' && (
                <div className="space-y-2">
                  <Label htmlFor="curveName">EC Curve</Label>
                  <Select
                    value={curveName || ''}
                    onValueChange={(v) => setCurveName(v as CurveType)}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select curve" />
                    </SelectTrigger>
                    <SelectContent>
                      {CURVE_OPTIONS.map((curve) => (
                        <SelectItem key={curve} value={curve}>
                          {curve}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </>
          )}

          {/* Error Message */}
          {error && (
            <div className="rounded-lg bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
          )}

          {/* Submit */}
          <div className="flex gap-4">
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
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
                  Saving...
                </>
              ) : mode === 'add' ? (
                'Add Device'
              ) : (
                'Update Operation'
              )}
            </Button>
            <Button type="button" variant="outline" asChild>
              <a href="/devices">Cancel</a>
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
