import { Button, Card } from './ui';
import { EmptyState, ErrorState, LoadingSkeleton } from './StateIndicators';
import { formatMetricName, formatRelativeTime, formatUptime } from '../lib/utils';
import type { MetricItem, MetricsResponse } from '../types/api';

interface MetricsCardProps {
  data: MetricsResponse | undefined;
  isLoading: boolean;
  errorMessage: string | null;
  onRetry: () => void;
}

const PREFERRED_METRIC_HINTS = [
  'alert',
  'detection',
  'event',
  'queue',
  'uptime',
  'error',
  'health',
];

function formatMetricValue(value: MetricItem['value']): string {
  if (typeof value === 'number') {
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2);
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (value === null) {
    return 'n/a';
  }
  return value;
}

function selectMetrics(metrics: MetricItem[]): MetricItem[] {
  const preferred = metrics.filter((metric) =>
    PREFERRED_METRIC_HINTS.some((hint) => metric.name.toLowerCase().includes(hint)),
  );
  return (preferred.length > 0 ? preferred : metrics).slice(0, 8);
}

export function MetricsCard({ data, isLoading, errorMessage, onRetry }: MetricsCardProps) {
  if (isLoading) {
    return (
      <Card title="Metrics" description="Loading operational metrics">
        <LoadingSkeleton lines={5} />
      </Card>
    );
  }

  if (errorMessage) {
    return (
      <Card title="Metrics" description="Metrics source unavailable">
        <ErrorState message={errorMessage} onRetry={onRetry} />
      </Card>
    );
  }

  if (!data || data.metrics.length === 0) {
    return (
      <Card title="Metrics">
        <EmptyState message="No metrics are currently available from the backend." />
      </Card>
    );
  }

  const selected = selectMetrics(data.metrics);

  return (
    <Card
      title="Metrics"
      description={`Uptime ${formatUptime(data.uptime_seconds)} · Captured ${formatRelativeTime(data.captured_at)}`}
      action={
        <Button onClick={onRetry} className="text-xs">
          Refresh
        </Button>
      }
    >
      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {selected.map((metric) => (
          <div key={metric.name} className="rounded-md border border-border p-3">
            <dt className="truncate text-xs text-muted-foreground" title={metric.description || metric.name}>
              {formatMetricName(metric.name)}
            </dt>
            <dd className="mt-1 font-mono text-lg font-semibold text-foreground">
              {formatMetricValue(metric.value)}
            </dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}