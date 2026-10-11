import { Link } from 'react-router-dom';
import { Badge, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useAlerts } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';
import {
  formatRelativeTime,
  formatTimestamp,
  getLifecycleBadgeClass,
  getPriorityBadgeClass,
  getSeverityBadgeClass,
} from '../lib/utils';

export function AlertsPage() {
  const alertsQuery = useAlerts({ limit: 20 });

  let body;
  if (alertsQuery.isLoading) {
    body = <LoadingSkeleton lines={6} />;
  } else if (alertsQuery.error) {
    const message =
      alertsQuery.error instanceof ApiClientError
        ? alertsQuery.error.userMessage
        : 'Unable to load alerts from the backend.';
    body = (
      <ErrorState
        message={message}
        onRetry={() => {
          void alertsQuery.refetch();
        }}
      />
    );
  } else if (!alertsQuery.data || alertsQuery.data.alerts.length === 0) {
    body = <EmptyState message="No alerts are currently available. This is not an error." />;
  } else {
    body = (
      <div className="overflow-hidden border border-border bg-surface">
        <div className="grid grid-cols-[128px_minmax(0,1fr)_180px_100px_96px] gap-px border-b border-border bg-border px-3 py-2 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
          <span>Signal</span>
          <span>Alert</span>
          <span>Observed</span>
          <span>Source</span>
          <span>State</span>
        </div>
        <ul className="divide-y divide-border">
          {alertsQuery.data.alerts.map((alert) => (
            <li key={alert.alert_id} className="group grid grid-cols-[128px_minmax(0,1fr)_180px_100px_96px] items-center gap-px bg-surface px-3 py-3 transition-colors hover:bg-surface-muted">
              <div className="flex flex-col gap-1 pr-4">
                <Badge className={getSeverityBadgeClass(alert.severity)}>{alert.severity}</Badge>
                {alert.priority && (
                  <Badge className={getPriorityBadgeClass(alert.priority)}>{alert.priority}</Badge>
                )}
              </div>
              <div className="min-w-0 pr-4">
                <Link to={`/alerts/${alert.alert_id}`} className="block truncate text-sm font-medium text-foreground hover:text-primary">
                  {alert.title}
                </Link>
                <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">{alert.description}</p>
                <p className="mt-1 text-[10px] font-mono text-muted-foreground">{alert.alert_id}</p>
              </div>
              <div className="pr-4 text-xs text-muted-foreground">
                <p className="font-mono text-[10px] uppercase text-muted-foreground/70">Observed</p>
                <p>{formatTimestamp(alert.created_at)}</p>
                <p className="text-[10px]">{formatRelativeTime(alert.created_at)}</p>
              </div>
              <div className="truncate text-xs font-mono text-muted-foreground" title={alert.source}>
                {alert.source}
              </div>
              <div>
                <Badge className={getLifecycleBadgeClass(alert.lifecycle_state)}>{alert.lifecycle_state}</Badge>
              </div>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-foreground uppercase tracking-tight">Alerts</h1>
          <p className="mt-0.5 text-[11px] font-mono text-muted-foreground">{alertsQuery.data?.total_count ?? 0} signals observed</p>
        </div>
      </div>
      <Card title="Alert Log" description={`Backend-provided signals — ${alertsQuery.data?.alerts.length ?? 0} entries`}>
        {body}
      </Card>
    </div>
  );
}