import { useParams, Link } from 'react-router-dom';
import { Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useEvidenceDetail } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';
import { formatTimestamp } from '../lib/utils';

function provenanceBadgeClass(provenance: string): string {
  if (provenance === 'DETECTION_SOURCE') return 'bg-primary/10 text-primary border-primary/20';
  if (provenance === 'CONTRIBUTING_EVENT') return 'bg-amber-500/10 text-amber-600 border-amber-500/20';
  if (provenance === 'OBSERVED_CONTEXT') return 'bg-muted text-muted-foreground border-border';
  return 'bg-muted text-muted-foreground border-border';
}

export function EvidenceDetailPage() {
  const params = useParams<{ id: string }>();
  const eventId = params.id ?? '';

  const query = useEvidenceDetail(eventId || null);

  let body;
  if (query.isLoading) {
    body = <LoadingSkeleton lines={6} />;
  } else if (query.error) {
    const message =
      query.error instanceof ApiClientError
        ? query.error.userMessage
        : 'Unable to load evidence details from the backend.';
    body = (
      <ErrorState
        message={message}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  } else if (!query.data) {
    body = <EmptyState message="Evidence record not found." />;
  } else {
    // The backend single-event response has { event: ..., record: ... }
    const record = query.data.record;
    const event = query.data.event;
    const evicted = query.data.status === 'EVICTED';

    if (!evicted && !record && !event) {
      body = <EmptyState message="Evidence record not found." />;
    } else {
      body = (
        <div className="space-y-4">
          {query.data.status === 'EVICTED' && (
            <div
              className="rounded border border-amber-500/20 bg-amber-500/10 p-3 text-xs text-amber-700"
              data-testid="evicted-evidence-banner"
            >
              <p className="font-medium">Unavailable / evicted</p>
              <p className="mt-1">
                Event ID <code className="font-mono">{query.data.event_id}</code> is preserved,
                but the telemetry payload is no longer retained in memory.
              </p>
              {query.data.reason && <p className="mt-1 text-amber-600">{query.data.reason}</p>}
            </div>
          )}
          {event && (
            <Card title="Event Details">
              <div className="space-y-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-muted-foreground font-medium">Event ID</span>
                  <code className="font-mono text-foreground">{event.event_id}</code>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-muted-foreground font-medium">Timestamp</span>
                  <span>{formatTimestamp(event.timestamp)}</span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-muted-foreground font-medium">Source Type</span>
                  <span className="font-mono">{event.source_type}</span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-muted-foreground font-medium">Event Type</span>
                  <span className="font-mono">{event.event_type}</span>
                </div>
                {event.hostname && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-muted-foreground font-medium">Hostname</span>
                    <span className="font-mono">{event.hostname}</span>
                  </div>
                )}
                {event.src_ip && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-muted-foreground font-medium">Source IP</span>
                    <Link
                      to={`/iocs/${encodeURIComponent(event.src_ip)}`}
                      className="font-mono text-primary hover:underline"
                    >
                      {event.src_ip}
                    </Link>
                  </div>
                )}
                {event.dst_ip && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-muted-foreground font-medium">Destination IP</span>
                    <Link
                      to={`/iocs/${encodeURIComponent(event.dst_ip)}`}
                      className="font-mono text-primary hover:underline"
                    >
                      {event.dst_ip}
                    </Link>
                  </div>
                )}
                {event.process_name && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-muted-foreground font-medium">Process</span>
                    <span className="font-mono">{event.process_name}</span>
                  </div>
                )}
                {event.username && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-muted-foreground font-medium">Username</span>
                    <span className="font-mono">{event.username}</span>
                  </div>
                )}
              </div>
            </Card>
          )}
          {record && (
            <Card title="Evidence Provenance">
              <div className="space-y-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-muted-foreground font-medium">Provenance</span>
                  <span
                    className={`inline-flex items-center rounded border px-2 py-0.5 font-mono ${provenanceBadgeClass(record.provenance)}`}
                  >
                    {record.provenance}
                  </span>
                </div>
                {record.detection_result_id && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-muted-foreground font-medium">Detection Result</span>
                    <code className="font-mono text-foreground">{record.detection_result_id}</code>
                  </div>
                )}
                {record.contributing_event_ids.length > 0 && (
                  <div>
                    <span className="text-muted-foreground font-medium">
                      Contributing Events ({record.contributing_event_ids.length}):
                    </span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {record.contributing_event_ids.map((eid) => (
                        <Link
                          key={eid}
                          to={`/evidence/${encodeURIComponent(eid)}`}
                          className="inline-flex items-center rounded border border-border px-2 py-0.5 font-mono text-xs text-primary hover:bg-primary/5"
                        >
                          {eid.slice(0, 8)}…
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Card>
          )}
        </div>
      );
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Evidence detail</h1>
        <p className="mt-1 text-sm text-muted-foreground">Telemetry evidence record for {eventId}</p>
      </div>
      <Card title="Evidence information">{body}</Card>
      <div>
        <Link
          to="/evidence"
          className="inline-block text-sm font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Back to evidence list
        </Link>
      </div>
    </div>
  );
}
