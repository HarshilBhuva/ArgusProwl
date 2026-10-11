import { Link, useParams } from 'react-router-dom';
import { Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useAlertDetail } from '../hooks/useQueries';
import { api } from '../lib/api';
import { ApiClientError } from '../lib/api';
import {
  formatRelativeTime,
  formatTimestamp,
  getLifecycleBadgeClass,
  getPriorityBadgeClass,
  getSeverityBadgeClass,
} from '../lib/utils';

export function AlertDetailPage({ alertId }: { alertId?: string }) {
  const params = useParams<{ id: string }>();
  const id = alertId || params.id || 'unknown';

  const alertQuery = useAlertDetail(id);

  let body;
  if (alertQuery.isLoading) {
    body = <LoadingSkeleton lines={6} />;
  } else if (alertQuery.error) {
    const message =
      alertQuery.error instanceof ApiClientError
        ? alertQuery.error.userMessage
        : 'Unable to load alert details from the backend.';
    body = (
      <ErrorState
        message={message}
        onRetry={() => {
          void alertQuery.refetch();
        }}
      />
    );
  } else if (!alertQuery.data) {
    body = <EmptyState message="Alert not found." />;
  } else {
    const alert = alertQuery.data;
    body = (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Alert ID</span>
          <code className="text-xs font-mono">{alert.alert_id}</code>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Source</span>
          <span className="text-xs">{alert.source}</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Created</span>
          <span className="text-xs">{formatTimestamp(alert.created_at)}</span>
          <span className="text-xs text-muted-foreground">({formatRelativeTime(alert.created_at)})</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Severity</span>
          <span className={`text-xs font-medium ${getSeverityBadgeClass(alert.severity)}`}>{alert.severity}</span>
          {alert.priority && (
            <>
              <span className="text-xs text-muted-foreground">Priority</span>
              <span className={`text-xs font-medium ${getPriorityBadgeClass(alert.priority)}`}>{alert.priority}</span>
            </>
          )}
          <span className="text-xs text-muted-foreground">Lifecycle</span>
          <span className={`text-xs font-medium ${getLifecycleBadgeClass(alert.lifecycle_state)}`}>{alert.lifecycle_state}</span>
        </div>
        <div>
          <h3 className="text-sm font-medium text-foreground">Title</h3>
          <p className="text-sm text-muted-foreground">{alert.title}</p>
        </div>
        <div>
          <h3 className="text-sm font-medium text-foreground">Description</h3>
          <p className="text-sm text-muted-foreground">{alert.description}</p>
        </div>
        {alert.tags.length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-foreground">Tags</h3>
            <div className="flex flex-wrap gap-1 mt-1">
              {alert.tags.map((tag) => (
                <span key={tag} className="inline-flex items-center rounded px-2 py-0.5 text-xs bg-muted text-muted-foreground">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
        {alert.entity_context && Object.keys(alert.entity_context).length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-foreground">Entity Context</h3>
            <pre className="mt-1 text-xs font-mono bg-muted p-2 rounded overflow-x-auto">
              {JSON.stringify(alert.entity_context, null, 2)}
            </pre>
            {(['src_ip', 'dst_ip', 'domain'] as const).some(
              (field) => typeof alert.entity_context?.[field] === 'string' && String(alert.entity_context[field]).trim(),
            ) && (
              <div className="mt-2 flex flex-wrap gap-2">
                {(['src_ip', 'dst_ip', 'domain'] as const).map((field) => {
                  const value = alert.entity_context?.[field];
                  if (typeof value !== 'string' || !value.trim()) return null;
                  return (
                    <Link
                      key={field}
                      to={`/iocs/${encodeURIComponent(value)}`}
                      className="text-xs font-mono text-primary hover:underline"
                    >
                      Investigate {field}: {value}
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        )}
        {alert.supporting_evidence.length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-foreground">Supporting Evidence</h3>
            <ul className="mt-1 space-y-1">
              {alert.supporting_evidence.map((evidence, idx) => (
                <li key={idx} className="text-xs text-muted-foreground">
                  {evidence.field ? `${evidence.field}: ${evidence.observed}` : JSON.stringify(evidence)}
                </li>
              ))}
            </ul>
          </div>
        )}
        {alert.contradictory_evidence.length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-foreground">Contradictory Evidence</h3>
            <ul className="mt-1 space-y-1">
              {alert.contradictory_evidence.map((evidence, idx) => (
                <li key={idx} className="text-xs text-muted-foreground">
                  {evidence.field ? `${evidence.field}: ${evidence.observed}` : JSON.stringify(evidence)}
                </li>
              ))}
            </ul>
          </div>
        )}
        {alert.contextual_explanation && (
          <div>
            <h3 className="text-sm font-medium text-foreground">Contextual Explanation</h3>
            <p className="text-xs text-muted-foreground mt-1">{alert.contextual_explanation}</p>
          </div>
        )}
        {alert.investigation_pivots.length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-foreground">Investigation Pivots</h3>
            <ul className="mt-1 space-y-1">
              {alert.investigation_pivots.map((pivot, idx) => (
                <li key={idx} className="text-xs text-muted-foreground">{pivot}</li>
              ))}
            </ul>
          </div>
        )}
        {alert.incident_id && (
          <Card title="Associated Incident">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Incident ID</span>
                <code className="text-xs font-mono">{alert.incident_id}</code>
              </div>
              <Link
                to={`/incidents/${encodeURIComponent(alert.incident_id)}`}
                className="text-xs font-medium text-primary hover:underline inline-flex items-center"
              >
                View Full Incident Investigation →
              </Link>
            </div>
          </Card>
        )}
        {alert.metadata && Object.keys(alert.metadata).length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-foreground">Metadata</h3>
            <pre className="mt-1 text-xs font-mono bg-muted p-2 rounded overflow-x-auto">
              {JSON.stringify(alert.metadata, null, 2)}
            </pre>
          </div>
        )}
        {(alert.detection_source_event_id || (alert.contributing_event_ids?.length ?? 0) > 0) && (
          <Card title="Telemetry Evidence Provenance" description="Events referenced by this alert's detection result">
            <div className="space-y-3 text-xs">
              {alert.detection_source_event_id && (
                <div>
                  <span className="text-muted-foreground font-medium">Detection Source Event:</span>
                  <div className="mt-1 flex items-center gap-2 flex-wrap">
                    <code className="font-mono text-foreground">{alert.detection_source_event_id}</code>
                    <EvidenceLink eventId={alert.detection_source_event_id} />
                  </div>
                </div>
              )}
              {(alert.contributing_event_ids?.length ?? 0) > 0 && (
                <div>
                  <span className="text-muted-foreground font-medium">Contributing Events ({alert.contributing_event_ids!.length}):</span>
                  <div className="mt-1 flex flex-col gap-1">
                    {alert.contributing_event_ids!.map((eid) => {
                      const status = alert.contributing_event_status?.[eid];
                      const evicted = status === 'EVICTED';
                      return (
                        <div key={eid} className="flex items-center gap-2 flex-wrap">
                          <code className="font-mono text-foreground">{eid}</code>
                          {evicted ? (
                            <span className="inline-flex items-center rounded border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-700">
                              Unavailable / evicted
                            </span>
                          ) : (
                            <>
                              {status === 'AVAILABLE' && (
                                <span className="inline-flex items-center rounded border border-primary/20 bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary">
                                  Available
                                </span>
                              )}
                              <EvidenceLink eventId={eid} />
                            </>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}
        <div className="flex gap-2 pt-4">
          {alert.lifecycle_state === 'OPEN' && (
            <button
              className="inline-flex items-center rounded px-3 py-1.5 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              onClick={async () => {
                try {
                  await api.acknowledgeAlert(alert.alert_id);
                  await alertQuery.refetch();
                } catch {
                  // Error handling is done by the query client
                }
              }}
            >
              Acknowledge
            </button>
          )}
          {(alert.lifecycle_state === 'OPEN' || alert.lifecycle_state === 'ACKNOWLEDGED') && (
            <button
              className="inline-flex items-center rounded px-3 py-1.5 text-xs font-medium bg-secondary text-secondary-foreground hover:bg-secondary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-secondary"
              onClick={async () => {
                try {
                  await api.closeAlert(alert.alert_id);
                  await alertQuery.refetch();
                } catch {
                  // Error handling is done by the query client
                }
              }}
            >
              Close
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Alert detail</h1>
        <p className="mt-1 text-sm text-muted-foreground">Investigation view for alert {id}</p>
      </div>
      <Card title="Alert information" description="Full details and lifecycle actions">
        {body}
      </Card>
      <div>
        <Link
          to="/alerts"
          className="inline-block text-sm font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Back to alerts
        </Link>
      </div>
    </div>
  );
}

function EvidenceLink({ eventId }: { eventId: string }) {
  return (
    <Link
      to={`/evidence/${encodeURIComponent(eventId)}`}
      className="text-primary hover:underline"
    >
      View
    </Link>
  );
}