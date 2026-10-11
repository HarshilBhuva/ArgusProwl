import { Link } from 'react-router-dom';
import { Badge, Button, Card } from './ui';
import { EmptyState, ErrorState, LoadingSkeleton } from './StateIndicators';
import {
  formatRelativeTime,
  formatTimestamp,
  getLifecycleBadgeClass,
  getPriorityBadgeClass,
  getSeverityBadgeClass,
  truncateString,
} from '../lib/utils';
import type { AlertSearchResponse } from '../types/api';

interface AlertsCardProps {
  data: AlertSearchResponse | undefined;
  isLoading: boolean;
  errorMessage: string | null;
  onRetry: () => void;
  onViewAll: () => void;
}

export function AlertsCard({ data, isLoading, errorMessage, onRetry, onViewAll }: AlertsCardProps) {
  if (isLoading) {
    return (
      <Card title="Recent Alerts" description="Loading recent alerts">
        <LoadingSkeleton lines={5} />
      </Card>
    );
  }

  if (errorMessage) {
    return (
      <Card title="Recent Alerts" description="Alert source unavailable">
        <ErrorState message={errorMessage} onRetry={onRetry} />
      </Card>
    );
  }

  if (!data || data.alerts.length === 0) {
    return (
      <Card
        title="Recent Alerts"
        description={data?.status ? `Search status: ${data.status}` : 'No alerts returned'}
        action={
          <Button onClick={onViewAll} className="text-xs">
            Open alerts
          </Button>
        }
      >
        <EmptyState message="No alerts are currently available. This is not an error." />
      </Card>
    );
  }

  return (
    <Card
      title="Recent Alerts"
      description={`${data.total_count} alert${data.total_count === 1 ? '' : 's'} returned · Status ${data.status}`}
      action={
        <Button onClick={onViewAll} className="text-xs">
          View alerts
        </Button>
      }
    >
      {data.reason && (
        <p className="mb-3 text-xs text-amber-300" role="status">
          Search note: {data.reason}
        </p>
      )}
      <ul className="divide-y divide-border">
        {data.alerts.map((alert) => (
          <li key={alert.alert_id} className="py-3 first:pt-0 last:pb-0">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={getSeverityBadgeClass(alert.severity)}>
                    Severity {alert.severity}
                  </Badge>
                  {alert.priority && (
                    <Badge className={getPriorityBadgeClass(alert.priority)}>
                      Priority {alert.priority}
                    </Badge>
                  )}
                  <Badge className={getLifecycleBadgeClass(alert.lifecycle_state)}>
                    {alert.lifecycle_state}
                  </Badge>
                </div>
                <p className="mt-2 text-sm font-medium text-foreground">{alert.title}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {truncateString(alert.description, 140)}
                </p>
                <p className="mt-2 text-xs text-muted-foreground">
                  Source {alert.source} · {formatTimestamp(alert.created_at)}
                </p>
              </div>
              <p className="shrink-0 text-xs text-muted-foreground" title={formatTimestamp(alert.created_at)}>
                {formatRelativeTime(alert.created_at)}
              </p>
            </div>
          </li>
        ))}
      </ul>
      <div className="mt-4">
        <Link
          to="/alerts"
          className="text-sm font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Continue to alerts
        </Link>
      </div>
    </Card>
  );
}