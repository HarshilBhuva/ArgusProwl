import { useNavigate } from 'react-router-dom';
import { HealthCard } from '../components/HealthCard';
import { MetricsCard } from '../components/MetricsCard';
import { AlertsCard } from '../components/AlertsCard';
import { useAlerts, useHealth, useMetrics } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';

function toErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiClientError) {
    return error.userMessage;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return fallback;
}

export function DashboardPage() {
  const navigate = useNavigate();
  const healthQuery = useHealth();
  const metricsQuery = useMetrics();
  const alertsQuery = useAlerts({ limit: 10 });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Operations Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Backend health, selected metrics, and recent alerts from the Phase 7.0 API.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <HealthCard
          data={healthQuery.data}
          isLoading={healthQuery.isLoading}
          errorMessage={healthQuery.error ? toErrorMessage(healthQuery.error, 'Unable to load system health.') : null}
          onRetry={() => {
            void healthQuery.refetch();
          }}
        />
        <MetricsCard
          data={metricsQuery.data}
          isLoading={metricsQuery.isLoading}
          errorMessage={metricsQuery.error ? toErrorMessage(metricsQuery.error, 'Unable to load metrics.') : null}
          onRetry={() => {
            void metricsQuery.refetch();
          }}
        />
      </div>

      <AlertsCard
        data={alertsQuery.data}
        isLoading={alertsQuery.isLoading}
        errorMessage={alertsQuery.error ? toErrorMessage(alertsQuery.error, 'Unable to load alerts.') : null}
        onRetry={() => {
          void alertsQuery.refetch();
        }}
        onViewAll={() => navigate('/alerts')}
      />
    </div>
  );
}