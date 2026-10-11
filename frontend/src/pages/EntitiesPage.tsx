import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Badge, Button, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useEntities, useEntityDetail, useEntityTimeline, useEvidence } from '../hooks/useQueries';
import { api, ApiClientError } from '../lib/api';
import type { EvidenceRecord, EvidenceEvent } from '../types/api';
import {
  formatRelativeTime,
  formatTimestamp,
  getLifecycleBadgeClass,
  getPriorityBadgeClass,
  getSeverityBadgeClass,
} from '../lib/utils';

export function EntitiesPage() {
  const entitiesQuery = useEntities();

  let body;
  if (entitiesQuery.isLoading) {
    body = <LoadingSkeleton lines={6} />;
  } else if (entitiesQuery.error) {
    const message =
      entitiesQuery.error instanceof ApiClientError
        ? entitiesQuery.error.userMessage
        : 'Unable to load entities from the backend.';
    body = (
      <ErrorState
        message={message}
        onRetry={() => {
          void entitiesQuery.refetch();
        }}
      />
    );
  } else if (!entitiesQuery.data || entitiesQuery.data.entities.length === 0) {
    body = <EmptyState message="No behavioral entities observed yet." />;
  } else {
    body = (
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-border text-xs font-semibold text-muted-foreground uppercase">
            <tr>
              <th className="py-2.5 px-3">Entity Type</th>
              <th className="py-2.5 px-3">Entity ID</th>
              <th className="py-2.5 px-3">Correlation Support</th>
              <th className="py-2.5 px-3">Maturity</th>
              <th className="py-2.5 px-3 text-right">Observations</th>
              <th className="py-2.5 px-3">Last Seen</th>
              <th className="py-2.5 px-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {entitiesQuery.data.entities.map((entity) => (
              <tr key={`${entity.entity_type}:${entity.entity_id}`} className="hover:bg-muted/50">
                <td className="py-2.5 px-3 font-mono text-xs text-foreground">{entity.entity_type}</td>
                <td className="py-2.5 px-3 font-mono text-xs font-medium text-foreground">{entity.entity_id}</td>
                <td className="py-2.5 px-3">
                  {entity.has_correlation_support ? (
                    <Badge className="bg-primary/10 text-primary border-primary/20">Partial</Badge>
                  ) : (
                    <Badge className="bg-muted text-muted-foreground border-border">Unsupported</Badge>
                  )}
                </td>
                <td className="py-2.5 px-3">
                  <Badge className="bg-secondary text-secondary-foreground border-border">{entity.maturity}</Badge>
                </td>
                <td className="py-2.5 px-3 text-right font-mono text-xs">{entity.observation_count}</td>
                <td className="py-2.5 px-3 text-xs text-muted-foreground">
                  {entity.last_seen ? formatTimestamp(entity.last_seen) : 'Never'}
                </td>
                <td className="py-2.5 px-3">
                  <Link
                    to={`/entities/${encodeURIComponent(entity.entity_type)}/${encodeURIComponent(entity.entity_id)}`}
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
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Entities</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Behavioral entity identities and observed correlation status.
        </p>
      </div>
      <Card title="Observed Entities" description="Entity identities discovered from behavioral telemetry">
        {body}
      </Card>
    </div>
  );
}

export function EntityDetailPage(props: { type?: string; id?: string }) {
  const params = useParams<{ type: string; id: string }>();
  const entityType = props.type || params.type || '';
  const entityId = props.id || params.id || '';

  const detailQuery = useEntityDetail(entityType, entityId);

  const [author, setAuthor] = useState('');
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [annotationError, setAnnotationError] = useState<string | null>(null);

  const [filterType, setFilterType] = useState<string>('ALL');
  const timelineQuery = useEntityTimeline(entityType, entityId, 50);

  const handleAddAnnotation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!author.trim() || !comment.trim()) return;

    setSubmitting(true);
    setAnnotationError(null);
    try {
      await api.createEntityAnnotation(entityType, entityId, {
        author: author.trim(),
        comment: comment.trim(),
      });
      setAuthor('');
      setComment('');
      void detailQuery.refetch();
    } catch (err) {
      if (err instanceof ApiClientError) {
        setAnnotationError(err.userMessage);
      } else {
        setAnnotationError('Failed to add annotation.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Entity Investigation</h1>
        </div>
        <LoadingSkeleton lines={8} />
      </div>
    );
  }

  if (detailQuery.error) {
    const message =
      detailQuery.error instanceof ApiClientError
        ? detailQuery.error.userMessage
        : 'Unable to load entity details.';
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Entity Investigation</h1>
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
    return <EmptyState message="Entity not found." />;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Entity Investigation</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Investigating {data.entity_type}:{data.entity_id}
          </p>
        </div>
        <Link
          to="/entities"
          className="text-sm font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          ← Back to Entities
        </Link>
      </div>

      {/* 1. Identity Section */}
      <Card title="1. Entity Identity">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-xs text-muted-foreground block">Entity Type</span>
            <span className="font-mono font-medium text-foreground">{data.entity_type}</span>
          </div>
          <div>
            <span className="text-xs text-muted-foreground block">Entity ID</span>
            <span className="font-mono font-medium text-foreground">{data.entity_id}</span>
          </div>
        </div>
      </Card>

      {/* 2. Correlation Section */}
      <Card title="2. Correlation Status">
        <div className="space-y-3 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Status:</span>
            {data.correlation_status === 'PARTIAL' ? (
              <Badge className="bg-primary/10 text-primary border-primary/20">Partial</Badge>
            ) : (
              <Badge className="bg-muted text-muted-foreground border-border">Unsupported</Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">{data.correlation_note}</p>

          <div>
            <span className="text-xs font-semibold text-foreground block mb-1">
              Observed Correlation Keys ({data.observed_correlation_keys.length}):
            </span>
            {data.observed_correlation_keys.length > 0 ? (
              <ul className="list-disc pl-5 space-y-1 font-mono text-xs text-foreground">
                {data.observed_correlation_keys.map((k) => (
                  <li key={k}>{k}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted-foreground italic">
                {data.correlation_status === 'UNSUPPORTED'
                  ? 'No correlation keys available for unsupported entity types.'
                  : 'No matching alerts with canonical correlation keys currently observed in alert data.'}
              </p>
            )}
          </div>
        </div>
      </Card>

      {/* 3. Behavioral Profiles */}
      <Card title="3. Behavioral Baseline Profiles">
        {data.behavior.length > 0 ? (
          <div className="space-y-4">
            {data.behavior.map((b, idx) => (
              <div key={idx} className="border border-border rounded-md p-3 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-semibold font-mono text-foreground">
                    Dimension: {String(b.dimension || '')}
                  </span>
                  <Badge className="bg-secondary text-secondary-foreground border-border">
                    {String(b.maturity || '')}
                  </Badge>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs text-muted-foreground">
                  <div>Observations: <span className="font-mono text-foreground">{String(b.observation_count ?? 0)}</span></div>
                  <div>Distinct Values: <span className="font-mono text-foreground">{String(b.distinct_value_count ?? 0)}</span></div>
                  <div>First Seen: <span className="text-foreground">{b.first_seen ? formatTimestamp(String(b.first_seen)) : 'N/A'}</span></div>
                  <div>Last Seen: <span className="text-foreground">{b.last_seen ? formatTimestamp(String(b.last_seen)) : 'N/A'}</span></div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No behavioral dimensions tracked for this entity." />
        )}
      </Card>

      {/* 4. Alerts by Observed Correlation Key */}
      <Card title="4. Related Alerts">
        {data.correlation_status === 'UNSUPPORTED' ? (
          <div className="p-4 text-xs text-muted-foreground bg-muted/40 rounded-md">
            Alert correlation is unsupported for entity type <code className="font-mono font-semibold">{data.entity_type}</code>. Alerts cannot be correlated to this entity identity.
          </div>
        ) : Object.keys(data.alerts).length > 0 ? (
          <div className="space-y-6">
            {Object.entries(data.alerts).map(([key, alerts]) => (
              <div key={key} className="space-y-3">
                <div className="flex items-center gap-2 border-b border-border pb-1">
                  <span className="text-xs font-semibold text-muted-foreground uppercase">Correlation Key:</span>
                  <code className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded text-foreground">{key}</code>
                  <span className="text-xs text-muted-foreground">({alerts.length} alert{alerts.length === 1 ? '' : 's'})</span>
                </div>
                {alerts.length > 0 ? (
                  <ul className="divide-y divide-border">
                    {alerts.map((alert) => (
                      <li key={alert.alert_id} className="py-3 first:pt-0 last:pb-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge className={getSeverityBadgeClass(alert.severity)}>Severity {alert.severity}</Badge>
                          {alert.priority && (
                            <Badge className={getPriorityBadgeClass(alert.priority)}>Priority {alert.priority}</Badge>
                          )}
                          <Badge className={getLifecycleBadgeClass(alert.lifecycle_state)}>{alert.lifecycle_state}</Badge>
                        </div>
                        <h3 className="mt-1 text-sm font-medium text-foreground">{alert.title}</h3>
                        <p className="mt-0.5 text-xs text-muted-foreground">{alert.description}</p>
                        <p className="mt-1 text-[11px] text-muted-foreground">
                          Source {alert.source} · {formatTimestamp(alert.created_at)} ({formatRelativeTime(alert.created_at)})
                        </p>
                        <Link
                          to={`/alerts/${alert.alert_id}`}
                          className="mt-1 inline-block text-xs font-medium text-primary hover:underline"
                        >
                          View Alert Detail →
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-muted-foreground italic">No alerts found under this key.</p>
                )}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No alerts observed under any canonical correlation key for this entity." />
        )}
      </Card>

      {/* 5. Incidents */}
      <Card title="5. Associated Incidents">
        <div className="space-y-3 text-sm">
          <p className="text-xs text-muted-foreground">{data.incident_note}</p>
          {data.incidents.length > 0 ? (
            <div className="space-y-3">
              {data.incidents.map((inc) => (
                <div key={inc.incident_id} className="border border-border rounded-md p-3 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-foreground">{inc.title}</span>
                    <Badge className={getSeverityBadgeClass(inc.severity)}>{inc.severity}</Badge>
                  </div>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <div>Incident ID: <code className="font-mono text-foreground">{inc.incident_id}</code></div>
                    <div>Resolved from Key: <code className="font-mono text-foreground">{inc.correlation_key}</code></div>
                    <div>Status: <Badge className="bg-secondary text-secondary-foreground border-border">{inc.status}</Badge></div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState message="No incidents currently mapped to observed correlation keys." />
          )}
        </div>
      </Card>

      {/* 6. Timeline */}
      {data.correlation_status === 'PARTIAL' && (
        <Card title="6. Investigation Timeline" description="Chronological evidence from alerts, incidents, annotations, behavior, and telemetry">
          {timelineQuery.isLoading ? (
            <LoadingSkeleton lines={4} />
          ) : timelineQuery.error ? (
            <ErrorState message="Unable to load timeline data." />
          ) : timelineQuery.data && timelineQuery.data.items.length > 0 ? (
            <div className="space-y-4">
              {/* Filter buttons */}
              <div className="flex flex-wrap gap-2">
                {['ALL', 'ALERT', 'INCIDENT', 'ANNOTATION', 'BEHAVIOR'].map((type) => (
                  <button
                    key={type}
                    onClick={() => setFilterType(type)}
                    className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                      filterType === type
                        ? 'bg-primary text-primary-foreground border-primary'
                        : 'bg-background text-muted-foreground border-border hover:bg-muted'
                    }`}
                  >
                    {type === 'ALL' ? 'All' : type}
                    <span className="ml-1 text-xs opacity-75">
                      ({type === 'ALL' ? timelineQuery.data!.items.length : timelineQuery.data!.items.filter((i: {item_type: string}) => i.item_type === type).length})
                    </span>
                  </button>
                ))}
              </div>

              {/* Correlation status notice */}
              {timelineQuery.data.correlation_status === 'PARTIAL' && (
                <div className="p-3 text-xs text-muted-foreground bg-muted/40 rounded-md">
                  <span className="font-semibold">Partial Correlation:</span> {timelineQuery.data.correlation_note}
                </div>
              )}

              {/* Truncation notice */}
              {timelineQuery.data.truncated && (
                <div className="p-3 text-xs text-amber-600 bg-amber-50 rounded-md">
                  Timeline truncated to {timelineQuery.data.returned_count} items. More evidence may exist.
                </div>
              )}

              {/* Timeline items */}
              <div className="relative">
                <div className="absolute left-4 top-0 bottom-0 w-px bg-border" aria-hidden="true" />
                <ul className="space-y-3">
                  {timelineQuery.data.items
                    .filter((item: {item_type: string}) => filterType === 'ALL' || item.item_type === filterType)
                    .map((item: {timeline_item_id: string; timestamp: string; item_type: string; title: string; summary: string; source_id: string | null; severity_or_priority: string | null; metadata: Record<string, string>}) => (
                    <li key={item.timeline_item_id} className="relative pl-10 py-2">
                      <div
                        className={`absolute left-2.5 top-3 w-3 h-3 rounded-full border-2 ${
                          item.item_type === 'ALERT'
                            ? 'bg-red-500 border-red-600'
                            : item.item_type === 'INCIDENT'
                            ? 'bg-orange-500 border-orange-600'
                            : item.item_type === 'ANNOTATION'
                            ? 'bg-blue-500 border-blue-600'
                            : 'bg-green-500 border-green-600'
                        } bg-background`}
                        aria-hidden="true"
                      />
                      <div className="border border-border rounded-md p-3 space-y-2">
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-mono text-muted-foreground">{formatTimestamp(item.timestamp)}</span>
                          <Badge
                            className={
                              item.item_type === 'ALERT'
                                ? 'bg-red-100 text-red-700 border-red-200'
                                : item.item_type === 'INCIDENT'
                                ? 'bg-orange-100 text-orange-700 border-orange-200'
                                : item.item_type === 'ANNOTATION'
                                ? 'bg-blue-100 text-blue-700 border-blue-200'
                                : 'bg-green-100 text-green-700 border-green-200'
                            }
                          >
                            {item.item_type}
                          </Badge>
                          {item.severity_or_priority && (
                            <Badge className={getSeverityBadgeClass(item.severity_or_priority)}>
                              {item.severity_or_priority}
                            </Badge>
                          )}
                        </div>
                        <h4 className="text-sm font-medium text-foreground">{item.title}</h4>
                        <p className="text-xs text-muted-foreground">{item.summary}</p>
                        {item.metadata && Object.keys(item.metadata).length > 0 && (
                          <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                            {Object.entries(item.metadata)
                              .filter(([k, v]) => v && v !== 'null' && v !== 'False')
                              .map(([k, v]) => (
                                <span key={k} className="font-mono">
                                  {k}: {v}
                                </span>
                              ))}
                          </div>
                        )}
                        {item.item_type === 'ALERT' && item.source_id && (
                          <Link
                            to={`/alerts/${item.source_id}`}
                            className="inline-block text-xs font-medium text-primary hover:underline"
                          >
                            View Alert Detail →
                          </Link>
                        )}
                        {item.metadata && Object.keys(item.metadata).length > 0 && (
                          <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground pt-1">
                            {Object.entries(item.metadata)
                              .filter(([k, v]) => v && v !== 'null' && v !== 'False')
                              .map(([k, v]) => (
                                <span key={k} className="font-mono">
                                  {k}: {v}
                                </span>
                              ))}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <EmptyState message="No timeline evidence found for this entity." />
          )}
        </Card>
      )}

      {/* 7. Telemetry Evidence */}
      {data.correlation_status === 'PARTIAL' && (() => {
        const entityKey = `entity:${entityType}:${entityId}`;
        const evidenceQuery = useEvidence({ entity_type: entityType, entity_id: entityId, limit: 50 });

        if (evidenceQuery.isLoading) {
          return <Card title="7. Telemetry Evidence"><LoadingSkeleton lines={3} /></Card>;
        }
        if (evidenceQuery.error) {
          return <Card title="7. Telemetry Evidence"><p className="text-xs text-muted-foreground">Unable to load evidence.</p></Card>;
        }
        const records = evidenceQuery.data?.records ?? [];
        const events = evidenceQuery.data?.events ?? {};

        return (
          <Card title="7. Telemetry Evidence" description="Raw events matching this entity identity">
            {records.length > 0 ? (
              <div className="space-y-2">
                {records.map((rec: EvidenceRecord) => {
                  const evt: EvidenceEvent | undefined = events[rec.event_id];
                  return (
                    <div key={rec.event_id} className="border border-border rounded-md p-2 space-y-1">
                      <div className="flex items-center gap-2">
                        <code className="text-xs font-mono text-foreground">{rec.event_id}</code>
                        <span className="text-[11px] text-muted-foreground">{rec.provenance}</span>
                        {evt && (
                          <span className="text-[11px] font-mono text-muted-foreground">{evt.timestamp}</span>
                        )}
                      </div>
                      {evt && (
                        <div className="text-[11px] text-muted-foreground font-mono">
                          {evt.source_type}:{evt.event_type}
                          {evt.hostname && ` @${evt.hostname}`}
                          {evt.src_ip && ` src=${evt.src_ip}`}
                          {evt.dst_ip && ` dst=${evt.dst_ip}`}
                        </div>
                      )}
                      {rec.contributing_event_ids.length > 0 && (
                        <div className="text-[11px] text-muted-foreground">
                          Contributes: {rec.contributing_event_ids.length} event{rec.contributing_event_ids.length > 1 ? 's' : ''}
                        </div>
                      )}
                    </div>
                  );
                })}
                {evidenceQuery.data?.truncated && (
                  <p className="text-[11px] text-muted-foreground italic">
                    Results truncated. {evidenceQuery.data.total_count} total matching events.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground italic">No telemetry evidence found for this entity.</p>
            )}
          </Card>
        );
      })()}

      {/* 8. Annotations */}
      <Card title="8. Analyst Annotations" description="Contextual commentary on this entity target">
        <div className="space-y-4">
          {data.annotations.length > 0 ? (
            <div className="divide-y divide-border">
              {data.annotations.map((ann) => (
                <div key={ann.annotation_id} className="py-3 first:pt-0 last:pb-0 space-y-1 text-sm">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span className="font-medium text-foreground">Author: {ann.author}</span>
                    <span>{formatTimestamp(ann.created_at)}</span>
                  </div>
                  <p className="text-foreground text-sm">{ann.comment}</p>
                  {ann.tombstoned && (
                    <Badge className="bg-muted text-muted-foreground border-border">Retracted / Tombstoned</Badge>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground italic">No annotations recorded for this entity.</p>
          )}

          {/* Add Annotation Form */}
          <form onSubmit={handleAddAnnotation} className="mt-4 border-t border-border pt-4 space-y-3">
            <h3 className="text-xs font-semibold text-foreground uppercase tracking-wide">Add Entity Annotation</h3>
            {annotationError && (
              <p className="text-xs text-red-500">{annotationError}</p>
            )}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label htmlFor="annotation-author" className="text-xs text-muted-foreground block mb-1">Author</label>
                <input
                  id="annotation-author"
                  type="text"
                  required
                  maxLength={128}
                  value={author}
                  onChange={(e) => setAuthor(e.target.value)}
                  placeholder="analyst_user"
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                />
              </div>
              <div className="sm:col-span-2">
                <label htmlFor="annotation-comment" className="text-xs text-muted-foreground block mb-1">Comment</label>
                <input
                  id="annotation-comment"
                  type="text"
                  required
                  maxLength={512}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  placeholder="Context notes on this entity..."
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                />
              </div>
            </div>
            <Button type="submit" className={submitting ? 'opacity-50' : ''}>
              {submitting ? 'Submitting...' : 'Add Annotation'}
            </Button>
          </form>
        </div>
      </Card>
    </div>
  );
}