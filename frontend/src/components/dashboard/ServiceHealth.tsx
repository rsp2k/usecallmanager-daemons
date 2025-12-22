import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { HealthResponse } from '@/lib/api/types';

interface ServiceHealthProps {
  tvs: HealthResponse | null;
  capf: HealthResponse | null;
  tvsError?: string;
  capfError?: string;
}

export function ServiceHealth({ tvs, capf, tvsError, capfError }: ServiceHealthProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Service Health</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`h-2.5 w-2.5 rounded-full ${tvs?.status === 'healthy' ? 'bg-success' : 'bg-destructive'}`}
            />
            <div>
              <p className="text-sm font-medium">TVS (Trust Verification)</p>
              <p className="text-xs text-muted-foreground">
                Port {tvs?.protocol_port ?? 2445}
              </p>
            </div>
          </div>
          <Badge variant={tvs?.status === 'healthy' ? 'success' : 'destructive'}>
            {tvsError ? 'Offline' : tvs?.status ?? 'Unknown'}
          </Badge>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`h-2.5 w-2.5 rounded-full ${capf?.status === 'healthy' ? 'bg-success' : 'bg-destructive'}`}
            />
            <div>
              <p className="text-sm font-medium">CAPF (Certificate Authority)</p>
              <p className="text-xs text-muted-foreground">
                Port {capf?.protocol_port ?? 3804}
              </p>
            </div>
          </div>
          <Badge variant={capf?.status === 'healthy' ? 'success' : 'destructive'}>
            {capfError ? 'Offline' : capf?.status ?? 'Unknown'}
          </Badge>
        </div>
      </CardContent>
    </Card>
  );
}
