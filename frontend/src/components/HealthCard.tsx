import { Badge, Button, Card } from './ui';
import { EmptyState, ErrorState, LoadingSkeleton } from './StateIndicators';
import { formatRelativeTime, formatUptime, getHealthBadgeClass } from '../lib/utils';
import type { HealthResponse } from '../types/api';

interface HealthCardProps {
  data: HealthResponse | undefined;
  isLoading: boolean;
  errorMessage: string | null;
  onRetry: () => void;
}

export function HealthCard({ data, isLoading, errorMessage, onRetry }: HealthCardProps) {
  if (isLoading) {
    return (
      <Card title="System Health" description="Checking backend status">
        <LoadingSkeleton lines={4} />
      </Card>
    );
  }

  if (errorMessage) {
    return (
      <Card title="System Health" description="Backend status unavailable">
        <ErrorState message={errorMessage} onRetry={onRetry} />
      </Card>
    );
  }

  if (!data) {
    return (
      <Card title="System Health">
        <EmptyState message="No health data is currently available." />
      </Card>
    );
  }

  const statusLabel = data.status || 'unknown';

  return (
    <Card
      title="System Health"
      description={`Version ${data.version || 'unknown'} · Uptime ${formatUptime(data.uptime_seconds)}`}
      action={
        <Button onClick={onRetry} className="text-xs">
          Refresh
        </Button>
      }
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <Badge className={getHealthBadgeClass(statusLabel)}>{statusLabel}</Badge>
          <span className="text-xs text-muted-foreground">
            Checked {formatRelativeTime(data.checked_at)}
          </span>
        </div>

        {data.components.length > 0 ? (
          <ul className="divide-y divide-border">
            {data.components.map((component) => (
              <li key={component.name} className="flex items-start justify-between gap-3 py-2 first:pt-0 last:pb-0">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-foreground">{component.name}</p>
                  {component.message && (
                    <p className="mt-0.5 text-xs text-muted-foreground">{component.message}</p>
                  )}
                </div>
                <Badge className={getHealthBadgeClass(component.status)}>{component.status}</Badge>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No component health details were returned.</p>
        )}
      </div>
    </Card>
  );
}