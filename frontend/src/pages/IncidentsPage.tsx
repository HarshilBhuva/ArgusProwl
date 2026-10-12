import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Badge, Button, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useIncidents, useIncidentDetail, useIncidentAlerts, useIncidentTimeline, useIncidentAnnotations } from '../hooks/useQueries';
import { api, ApiClientError } from '../lib/api';
import type { AnnotationCreateRequest } from '../types/api';
import {
  formatRelativeTime,
  formatTimestamp,
  getSeverityBadgeClass,
} from '../lib/utils';

export function IncidentsPage() {
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const incidentsQuery = useIncidents();

  let body;
  if (incidentsQuery.isLoading) {
    body = <LoadingSkeleton lines={6} />;
  } else if (incidentsQuery.error) {
    const message =
      incidentsQuery.error instanceof ApiClientError
        ? incidentsQuery.error.userMessage
        : 'Unable to load incidents from the backend.';
    body = (
      <ErrorState
        message={message}
        onRetry={() => {
          void incidentsQuery.refetch();
        }}
      />
    );
  } else if (!incidentsQuery.data || incidentsQuery.data.incidents.length === 0) {
    body = <EmptyState message="No incidents recorded yet." />;
  } else {
    const filtered =
      filterStatus === 'ALL'
        ? incidentsQuery.data.incidents
        : incidentsQuery.data.incidents.filter((inc) => inc.status === filterStatus);

    body = (
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'].map((s) => (
            <button
              key={s}
              onClick={() => setFilterStatus(s)}
              className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                filterStatus === s
                  ? 'bg-primary text-primary-foreground border-primary'
                  : 'bg-background text-muted-foreground border-border hover:bg-muted'
              }`}
            >
              {s}
              <span className="ml-1 text-xs opacity-75">
                ({s === 'ALL'
                  ? incidentsQuery.data!.incidents.length
                  : filtered.length})
              </span>
            </button>
          ))}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border text-xs font-semibold text-muted-foreground uppercase">
              <tr>
                <th className="py-2.5 px-3">Title</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Alerts</th>
                <th className="py-2.5 px-3">Created</th>
                <th className="py-2.5 px-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((inc) => (
                <tr key={inc.incident_id} className="hover:bg-muted/50">
                  <td className="py-2.5 px-3">
                    <div className="font-medium text-foreground">{inc.title}</div>
                    <div className="text-xs text-muted-foreground truncate max-w-xs">
                      {inc.description}
                    </div>
                  </td>
                  <td className="py-2.5 px-3">
                    <Badge className={getSeverityBadgeClass(inc.severity)}>{inc.severity}</Badge>
                  </td>
                  <td className="py-2.5 px-3">
                    <Badge
                      className={
                        inc.status === 'CLOSED'
                          ? 'bg-muted text-muted-foreground border-border'
                          : inc.status === 'RESOLVED'
                          ? 'bg-green-100 text-green-700 border-green-200'
                          : inc.status === 'INVESTIGATING'
                          ? 'bg-blue-100 text-blue-700 border-blue-200'
                          : 'bg-orange-100 text-orange-700 border-orange-200'
                      }
                    >
                      {inc.status}
                    </Badge>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-xs">{inc.alert_ids.length}</td>
                  <td className="py-2.5 px-3 text-xs text-muted-foreground">
                    {formatTimestamp(inc.created_at)} ({formatRelativeTime(inc.created_at)})
                  </td>
                  <td className="py-2.5 px-3">
                    <Link
                      to={`/incidents/${encodeURIComponent(inc.incident_id)}`}
                      className="text-xs font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                    >
                      Investigate
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Incidents</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Correlated investigation aggregates from associated alerts.
        </p>
      </div>
      <Card title="Incident Registry" description="Process-local incident records (bounded, not persisted across restarts)">
        {body}
      </Card>
    </div>
  );
}

export function IncidentDetailPage({ incidentId }: { incidentId?: string }) {
  const params = useParams<{ id: string }>();
  const id = incidentId || params.id || 'unknown';
  const detailQuery = useIncidentDetail(id);
  const alertsQuery = useIncidentAlerts(id);
  const timelineQuery = useIncidentTimeline(id, 50);
  const annotationsQuery = useIncidentAnnotations(id);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [annotationAuthor, setAnnotationAuthor] = useState('');
  const [annotationComment, setAnnotationComment] = useState('');
  const [submittingAnnotation, setSubmittingAnnotation] = useState(false);
  const [annotationError, setAnnotationError] = useState<string | null>(null);

  const handleTransition = async (status: string) => {
    setSubmitting(true);
    setActionError(null);
    try {
      await api.transitionIncident(id, status);
      void detailQuery.refetch();
      void alertsQuery.refetch();
    } catch (err) {
      if (err instanceof ApiClientError) {
        setActionError(err.userMessage);
      } else {
        setActionError(`Failed to transition incident to ${status}.`);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleAddAnnotation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!annotationAuthor.trim() || !annotationComment.trim()) return;

    setSubmittingAnnotation(true);
    setAnnotationError(null);
    try {
      const data: AnnotationCreateRequest = {
        author: annotationAuthor.trim(),
        comment: annotationComment.trim(),
      };
      await api.createIncidentAnnotation(id, data);
      setAnnotationAuthor('');
      setAnnotationComment('');
      void annotationsQuery.refetch();
    } catch (err) {
      if (err instanceof ApiClientError) {
        setAnnotationError(err.userMessage);
      } else {
        setAnnotationError('Failed to add annotation.');
      }
    } finally {
      setSubmittingAnnotation(false);
    }
  };

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Incident Detail</h1>
        </div>
        <LoadingSkeleton lines={8} />
      </div>
    );
  }

  if (detailQuery.error) {
    const message =
      detailQuery.error instanceof ApiClientError
        ? detailQuery.error.userMessage
        : 'Unable to load incident details.';
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Incident Detail</h1>
        </div>
        <ErrorState
          message={message}
          onRetry={() => {
            void detailQuery.refetch();
          }}
        />
      </div>
    );
  }

  const data = detailQuery.data;
  if (!data) {
    return <EmptyState message="Incident not found." />;
  }

  // Determine supported transitions based on current status
  const supportedTransitions: string[] = [];
  if (data.status === 'OPEN') {
    supportedTransitions.push('investigating');
  } else if (data.status === 'INVESTIGATING') {
    supportedTransitions.push('resolved');
  } else if (data.status === 'RESOLVED') {
    supportedTransitions.push('closed');
  } else if (data.status === 'CLOSED') {
    // No transitions from CLOSED
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Incident Detail</h1>
          <p className="mt-1 text-sm text-muted-foreground">{data.title}</p>
        </div>
        <Link
          to="/incidents"
          className="text-sm font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          ← Back to Incidents
        </Link>
      </div>

      {/* Overview */}
      <Card title="Overview">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-xs text-muted-foreground block">Incident ID</span>
            <span className="font-mono font-medium text-foreground">{data.incident_id}</span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Severity</span>
            <Badge className={getSeverityBadgeClass(data.severity)}>{data.severity}</Badge>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Status</span>
            <Badge
              className={
                data.status === 'CLOSED'
                  ? 'bg-muted text-muted-foreground border-border'
                  : data.status === 'RESOLVED'
                  ? 'bg-green-100 text-green-700 border-green-200'
                  : data.status === 'INVESTIGATING'
                  ? 'bg-blue-100 text-blue-700 border-blue-200'
                  : 'bg-orange-100 text-orange-700 border-orange-200'
              }
            >
              {data.status}
            </Badge>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Created</span>
            <span className="font-mono text-foreground">{formatTimestamp(data.created_at)}</span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Updated</span>
            <span className="font-mono text-foreground">{formatTimestamp(data.updated_at)}</span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Associated Alerts</span>
            <span className="font-mono text-foreground">{data.alert_ids.length}</span>
          </div>
        </div>
        <div className="mt-4">
          <span className="text-xs text-muted-foreground block">Description</span>
          <p className="mt-1 text-sm text-foreground">{data.description}</p>
        </div>
        {data.tags.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1">
            {data.tags.map((tag) => (
              <Badge key={tag} className="bg-secondary text-secondary-foreground border-border text-xs">
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </Card>

      {/* Constituent Alerts */}
      <Card
        title="Constituent Alerts"
        description={
          alertsQuery.isLoading
            ? 'Loading alerts...'
            : alertsQuery.error
            ? 'Unable to load alerts'
            : alertsQuery.data
            ? `${alertsQuery.data.retrieved_count} of ${alertsQuery.data.total_alerts} alerts retrieved${alertsQuery.data.missing_count > 0 ? `, ${alertsQuery.data.missing_count} missing` : ''}${alertsQuery.data.degraded ? ' (degraded)' : ''}`
            : `${data.alert_ids.length} alerts linked`
        }
      >
        {alertsQuery.isLoading ? (
          <LoadingSkeleton lines={4} />
        ) : alertsQuery.error ? (
          <ErrorState message="Unable to load constituent alerts." />
        ) : alertsQuery.data && alertsQuery.data.alerts.length > 0 ? (
          <ul className="divide-y divide-border">
            {alertsQuery.data.alerts.map((alert) => (
              <li key={alert.alert_id} className="py-2.5">
                <Link
                  to={`/alerts/${encodeURIComponent(alert.alert_id)}`}
                  className="text-xs font-mono text-primary hover:underline"
                >
                  {alert.alert_id}
                </Link>
                <div className="mt-1 text-xs text-muted-foreground">{alert.title}</div>
                <div className="mt-1 flex items-center gap-2">
                  <Badge className={getSeverityBadgeClass(alert.severity)}>{alert.severity}</Badge>
                  <span className="text-xs text-muted-foreground">{alert.source}</span>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState message={alertsQuery.data?.degraded ? 'Some alerts could not be retrieved (degraded state).' : 'No alerts associated with this incident.'} />
        )}
        {alertsQuery.data?.degraded && (
          <p className="mt-2 text-xs text-amber-600">
            Partial data: {alertsQuery.data.missing_count} alert(s) could not be retrieved.
          </p>
        )}
      </Card>

      {/* Investigation Timeline */}
      <Card
        title="Investigation Timeline"
        description={
          timelineQuery.isLoading
            ? 'Loading timeline...'
            : timelineQuery.error
            ? 'Unable to load timeline'
            : timelineQuery.data
            ? `${timelineQuery.data.returned_count} items${timelineQuery.data.truncated ? ' (truncated)' : ''}`
            : 'Chronological evidence from alerts and annotations'
        }
      >
        {timelineQuery.isLoading ? (
          <LoadingSkeleton lines={4} />
        ) : timelineQuery.error ? (
          <ErrorState message="Unable to load timeline data." />
        ) : timelineQuery.data && timelineQuery.data.items.length > 0 ? (
          <div className="space-y-3">
            {timelineQuery.data.correlation_status === 'PARTIAL' && (
              <div className="p-3 text-xs text-muted-foreground bg-muted/40 rounded-md">
                <span className="font-semibold">Partial Correlation:</span> {timelineQuery.data.correlation_note}
              </div>
            )}
            {timelineQuery.data.truncated && (
              <div className="p-3 text-xs text-amber-600 bg-amber-50 rounded-md">
                Timeline truncated to {timelineQuery.data.returned_count} items.
              </div>
            )}
            <ol className="space-y-3">
              {timelineQuery.data.items.map((item) => (
                <li key={item.timeline_item_id} className="border-l border-border pl-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className="bg-secondary text-secondary-foreground border-border">{item.item_type}</Badge>
                    <span className="text-xs font-medium text-foreground">{item.title}</span>
                    {item.timestamp ? (
                      <span className="text-[11px] font-mono text-muted-foreground">{formatTimestamp(item.timestamp)}</span>
                    ) : (
                      <span className="text-[11px] text-muted-foreground italic">static context</span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">{item.summary}</p>
                  {item.source_id && item.item_type === 'ALERT' && (
                    <Link
                      to={`/alerts/${encodeURIComponent(item.source_id)}`}
                      className="mt-0.5 inline-block text-[11px] font-mono text-primary hover:underline"
                    >
                      {item.source_id}
                    </Link>
                  )}
                </li>
              ))}
            </ol>
          </div>
        ) : (
          <EmptyState message={timelineQuery.data?.correlation_status === 'EMPTY' ? timelineQuery.data.correlation_note : 'No timeline data available.'} />
        )}
      </Card>

      {/* Annotations */}
      <Card
        title="Annotations"
        description="Analyst context (does not affect detection decisions)"
      >
        {annotationsQuery.isLoading ? (
          <LoadingSkeleton lines={2} />
        ) : annotationsQuery.error ? (
          <ErrorState message="Unable to load annotations." />
        ) : (
          <>
            <div className="space-y-2">
              {annotationsQuery.data && annotationsQuery.data.length > 0 ? (
                annotationsQuery.data.map((annotation) => (
                  <div key={annotation.annotation_id} className="border border-border rounded-md p-3 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-muted-foreground">{annotation.author}</span>
                      <span className="text-muted-foreground">{formatTimestamp(annotation.created_at)}</span>
                    </div>
                    <p className="text-sm text-foreground">{annotation.comment}</p>
                    {annotation.tombstoned && (
                      <span className="text-xs text-muted-foreground italic">Retracted</span>
                    )}
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted-foreground italic">No annotations yet.</p>
              )}
            </div>
            {data.status !== 'CLOSED' && (
              <form onSubmit={handleAddAnnotation} className="mt-4 space-y-2">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={annotationAuthor}
                    onChange={(e) => setAnnotationAuthor(e.target.value)}
                    placeholder="Author"
                    className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs font-mono text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                  />
                  <input
                    type="text"
                    value={annotationComment}
                    onChange={(e) => setAnnotationComment(e.target.value)}
                    placeholder="Annotation comment"
                    className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs font-mono text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                  />
                </div>
                {annotationError && <p className="text-xs text-red-500">{annotationError}</p>}
                <Button
                  type="submit"
                  className={submittingAnnotation ? 'opacity-50' : ''}
                >
                  {submittingAnnotation ? 'Adding...' : 'Add Annotation'}
                </Button>
              </form>
            )}
          </>
        )}
      </Card>

      {/* Lifecycle Controls */}
      {supportedTransitions.length > 0 && (
        <Card title="Lifecycle Actions">
          <div className="space-y-3">
            {actionError && <p className="text-xs text-red-500">{actionError}</p>}
            <div className="flex flex-wrap gap-2">
              {supportedTransitions.includes('investigating') && (
                <Button
                  onClick={() => void handleTransition('investigating')}
                  className={submitting ? 'opacity-50' : ''}
                >
                  {submitting ? 'Transitioning...' : 'Start Investigation'}
                </Button>
              )}
              {supportedTransitions.includes('resolved') && (
                <Button
                  onClick={() => void handleTransition('resolved')}
                  className={submitting ? 'opacity-50' : ''}
                >
                  {submitting ? 'Transitioning...' : 'Mark Resolved'}
                </Button>
              )}
              {supportedTransitions.includes('closed') && (
                <Button
                  onClick={() => void handleTransition('closed')}
                  className={`${submitting ? 'opacity-50' : ''} bg-secondary text-secondary-foreground hover:bg-secondary/90`}
                >
                  {submitting ? 'Transitioning...' : 'Close Incident'}
                </Button>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Transitions are authoritative. CLOSED is terminal.
            </p>
          </div>
        </Card>
      )}

      {/* Metadata */}
      <Card title="Metadata" description="Raw incident metadata">
        <pre className="text-xs font-mono text-foreground bg-muted p-3 rounded-md overflow-x-auto">
          {JSON.stringify(data.metadata, null, 2)}
        </pre>
      </Card>
    </div>
  );
}
