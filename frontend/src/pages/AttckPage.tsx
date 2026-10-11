import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Badge, Button, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useAlerts, useAttckOverview, useAttckInvestigation } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';
import type { AttckTechniqueSummary } from '../types/api';
import { formatTimestamp } from '../lib/utils';

function tacticBadgeClass(tactic: string): string {
  const map: Record<string, string> = {
    initial_access: 'bg-red-100 text-red-700 border-red-200',
    execution: 'bg-orange-100 text-orange-700 border-orange-200',
    persistence: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    privilege_escalation: 'bg-amber-100 text-amber-700 border-amber-200',
    defense_evasion: 'bg-amber-100 text-amber-700 border-amber-200',
    credential_access: 'bg-orange-100 text-orange-700 border-orange-200',
    discovery: 'bg-blue-100 text-blue-700 border-blue-200',
    lateral_movement: 'bg-blue-100 text-blue-700 border-blue-200',
    collection: 'bg-purple-100 text-purple-700 border-purple-200',
    command_and_control: 'bg-indigo-100 text-indigo-700 border-indigo-200',
    exfiltration: 'bg-red-100 text-red-700 border-red-200',
    impact: 'bg-red-100 text-red-700 border-red-200',
  };
  const key = tactic.toLowerCase().replace(/\s+/g, '_');
  return map[key] ?? 'bg-muted text-muted-foreground border-border';
}

function techniqueCard({ technique_id, mapping_type, technique_name, tactic, source_alert_ids, rationale }: AttckTechniqueSummary) {
  return (
    <Card title={technique_id} description={technique_name ?? ''}>
      <div className="space-y-3 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Tactic</span>
          <Badge className={tacticBadgeClass(tactic ?? '')}>{tactic ?? 'unknown'}</Badge>
          <span className="text-muted-foreground">Type</span>
          <Badge className="bg-secondary text-secondary-foreground border-border">{mapping_type}</Badge>
        </div>
        {rationale && (
          <p className="text-muted-foreground">{rationale}</p>
        )}
        <div>
          <span className="text-muted-foreground font-medium">Source alerts ({source_alert_ids.length}):</span>
          <div className="mt-1 flex flex-wrap gap-1">
            {source_alert_ids.map((aid) => (
              <Link
                key={aid}
                to={`/alerts/${encodeURIComponent(aid)}`}
                className="inline-flex items-center rounded border border-border px-2 py-0.5 font-mono text-[11px] text-primary hover:bg-primary/5"
              >
                {aid}
              </Link>
            ))}
          </div>
        </div>
      </div>
    </Card>
  );
}

function AttckOverview({ knowledge_status, attck_version, total_techniques, total_tactics, mapping_count, mapped_technique_ids }: {
  knowledge_status: string;
  attck_version: string | null;
  total_techniques: number;
  total_tactics: number;
  mapping_count: number;
  mapped_technique_ids: string[];
}) {
  return (
    <div className="grid grid-cols-2 gap-4 text-xs">
      <div>
        <span className="text-muted-foreground">Status</span>
        <div className="mt-1">
          <Badge className={knowledge_status === 'AVAILABLE' ? 'bg-primary/10 text-primary border-primary/20' : 'bg-amber-500/10 text-amber-700 border-amber-500/20'}>
            {knowledge_status}
          </Badge>
        </div>
      </div>
      <div>
        <span className="text-muted-foreground">ATT&CK Version</span>
        <p className="mt-1 font-mono text-foreground">{attck_version ?? '—'}</p>
      </div>
      <div>
        <span className="text-muted-foreground">Total Techniques</span>
        <p className="mt-1 font-mono text-foreground">{total_techniques}</p>
      </div>
      <div>
        <span className="text-muted-foreground">Total Tactics</span>
        <p className="mt-1 font-mono text-foreground">{total_tactics}</p>
      </div>
      <div>
        <span className="text-muted-foreground">Registered Mappings</span>
        <p className="mt-1 font-mono text-foreground">{mapping_count}</p>
      </div>
      <div>
        <span className="text-muted-foreground">Mapped Techniques</span>
        <p className="mt-1 font-mono text-foreground">{mapped_technique_ids.length}</p>
      </div>
    </div>
  );
}

export function AttckPage() {
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [showResults, setShowResults] = useState(false);

  const overviewQuery = useAttckOverview();
  const alertsQuery = useAlerts({ limit: 100 });
  const investigationQuery = useAttckInvestigation(showResults ? selectedAlertIds : []);

  const handleRunInvestigation = () => {
    if (selectedAlertIds.length > 0) {
      setShowResults(true);
    }
  };

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlertIds((prev) =>
      prev.includes(alertId) ? prev.filter((id) => id !== alertId) : [...prev, alertId],
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">ATT&CK</h1>
        <p className="mt-1 text-sm text-muted-foreground">Technique mapping overview and alert-based investigation</p>
      </div>

      {/* Overview */}
      <Card title="Knowledge Base" description="ATT&CK framework coverage and mapping registry status">
        {overviewQuery.isLoading ? (
          <LoadingSkeleton lines={3} />
        ) : overviewQuery.error ? (
          <ErrorState message={
            overviewQuery.error instanceof ApiClientError
              ? overviewQuery.error.userMessage
              : 'Unable to load ATT&CK knowledge status.'
          } />
        ) : overviewQuery.data ? (
          <AttckOverview {...overviewQuery.data} />
        ) : (
          <EmptyState message="No ATT&CK knowledge base available." />
        )}
      </Card>

      {/* Alert Selector */}
      <Card
        title="Alert Selection"
        description="Select alerts to investigate (min 1, max 256)"
        action={
          <Button onClick={handleRunInvestigation} disabled={selectedAlertIds.length === 0}>
            Run Investigation ({selectedAlertIds.length})
          </Button>
        }
      >
        {alertsQuery.isLoading ? (
          <LoadingSkeleton lines={4} />
        ) : alertsQuery.error ? (
          <ErrorState message="Unable to load alerts." />
        ) : alertsQuery.data && alertsQuery.data.alerts.length > 0 ? (
          <div className="space-y-2">
            {alertsQuery.data.alerts.map((alert) => (
              <div
                key={alert.alert_id}
                className={`flex items-center gap-3 rounded border px-3 py-2 cursor-pointer transition-colors ${
                  selectedAlertIds.includes(alert.alert_id)
                    ? 'border-primary bg-primary/5'
                    : 'border-border hover:bg-muted'
                }`}
                onClick={() => handleSelectAlert(alert.alert_id)}
              >
                <input
                  type="checkbox"
                  checked={selectedAlertIds.includes(alert.alert_id)}
                  onChange={() => handleSelectAlert(alert.alert_id)}
                  className="rounded border-border"
                  onClick={(e) => e.stopPropagation()}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground truncate">{alert.title}</span>
                    <Badge className={alert.severity === 'CRITICAL' ? 'bg-red-100 text-red-700 border-red-200' : alert.severity === 'HIGH' ? 'bg-orange-100 text-orange-700 border-orange-200' : 'bg-muted text-muted-foreground border-border'}>
                      {alert.severity}
                    </Badge>
                  </div>
                  <p className="mt-0.5 text-xs font-mono text-muted-foreground">{alert.alert_id}</p>
                </div>
                <span className="text-xs text-muted-foreground">{formatTimestamp(alert.created_at)}</span>
              </div>
            ))}
            {alertsQuery.data.alerts.length < (alertsQuery.data.total_count ?? 0) && (
              <p className="text-xs text-muted-foreground italic">
                Showing {alertsQuery.data.alerts.length} of {alertsQuery.data.total_count} alerts
              </p>
            )}
          </div>
        ) : (
          <EmptyState message="No alerts available for investigation." />
        )}
      </Card>

      {/* Investigation Results */}
      {showResults && (
        <Card
          title="Investigation Results"
          description={`ATT&CK technique mappings for ${selectedAlertIds.length} alert(s)`}
        >
          {investigationQuery.isLoading ? (
            <LoadingSkeleton lines={4} />
          ) : investigationQuery.error ? (
            <ErrorState message={
              investigationQuery.error instanceof ApiClientError
                ? investigationQuery.error.userMessage
                : 'Unable to run ATT&CK investigation.'
            } />
          ) : investigationQuery.data && investigationQuery.data.techniques.length > 0 ? (
            <div className="space-y-4">
              {investigationQuery.data.techniques.map((tech, idx) => (
                <div key={`${tech.technique_id}-${idx}`}>
                  {techniqueCard(tech)}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState message="No ATT&CK technique mappings found for the selected alerts." />
          )}
        </Card>
      )}
    </div>
  );
}
