import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Badge, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useEvidence } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';
import type { EvidenceRecord, EvidenceEvent } from '../types/api';
import { formatTimestamp } from '../lib/utils';

function provenanceBadgeClass(provenance: string): string {
  if (provenance === 'DETECTION_SOURCE') return 'bg-primary/10 text-primary border-primary/20';
  if (provenance === 'CONTRIBUTING_EVENT') return 'bg-amber-500/10 text-amber-600 border-amber-500/20';
  if (provenance === 'OBSERVED_CONTEXT') return 'bg-muted text-muted-foreground border-border';
  return 'bg-muted text-muted-foreground border-border';
}

export function EvidencePage() {
  const [limit, setLimit] = useState(20);
  const evidenceQuery = useEvidence({ limit });

  let body;
  if (evidenceQuery.isLoading) {
    body = <LoadingSkeleton lines={6} />;
  } else if (evidenceQuery.error) {
    const message =
      evidenceQuery.error instanceof ApiClientError
        ? evidenceQuery.error.userMessage
        : 'Unable to load evidence from the backend.';
    body = (
      <ErrorState
        message={message}
        onRetry={() => {
          void evidenceQuery.refetch();
        }}
      />
    );
  } else if (!evidenceQuery.data || evidenceQuery.data.records.length === 0) {
    body = <EmptyState message="No evidence records found." />;
  } else {
    const records: EvidenceRecord[] = evidenceQuery.data.records;
    const events: Record<string, EvidenceEvent> = evidenceQuery.data.events;

    body = (
      <div className="overflow-hidden border border-border bg-surface">
        <div className="grid grid-cols-[128px_minmax(0,1fr)_140px_120px_96px] gap-px border-b border-border bg-border px-3 py-2 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
          <span>Event ID</span>
          <span>Details</span>
          <span>Timestamp</span>
          <span>Provenance</span>
          <span>Action</span>
        </div>
        <ul className="divide-y divide-border">
          {records.map((rec) => {
            const evt = events[rec.event_id];
            return (
              <li key={rec.event_id} className="group grid grid-cols-[128px_minmax(0,1fr)_140px_120px_96px] items-center gap-px bg-surface px-3 py-3 transition-colors hover:bg-surface-muted">
                <code className="font-mono text-xs text-foreground">{rec.event_id}</code>
                <div className="min-w-0 pr-4">
                  {evt ? (
                    <>
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="font-mono text-muted-foreground">{evt.source_type}</span>
                        <span className="text-muted-foreground">·</span>
                        <span className="font-mono text-muted-foreground">{evt.event_type}</span>
                      </div>
                      {evt.hostname && (
                        <p className="mt-0.5 text-[11px] text-muted-foreground truncate">
                          {evt.hostname}
                          {evt.src_ip && <span className="ml-2 font-mono">→ {evt.src_ip}</span>}
                        </p>
                      )}
                    </>
                  ) : (
                    <p className="text-xs text-muted-foreground italic">No telemetry retained</p>
                  )}
                </div>
                <div className="pr-4 text-xs text-muted-foreground">
                  {evt ? formatTimestamp(evt.timestamp) : '—'}
                </div>
                <div>
                  <Badge className={provenanceBadgeClass(rec.provenance)}>{rec.provenance}</Badge>
                </div>
                <div>
                  <Link
                    to={`/evidence/${encodeURIComponent(rec.event_id)}`}
                    className="text-xs font-medium text-primary hover:underline"
                  >
                    Detail
                  </Link>
                </div>
              </li>
            );
          })}
        </ul>
        {evidenceQuery.data.truncated && (
          <div className="border-t border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
            Results truncated. {evidenceQuery.data.total_count} total matching events.
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-foreground uppercase tracking-tight">Evidence</h1>
          <p className="mt-0.5 text-[11px] font-mono text-muted-foreground">{evidenceQuery.data?.total_count ?? 0} events indexed</p>
        </div>
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          <option value={10}>10 per page</option>
          <option value={20}>20 per page</option>
          <option value={50}>50 per page</option>
          <option value={100}>100 per page</option>
        </select>
      </div>
      <Card title="Evidence Registry" description="Telemetry events retained from detections">
        {body}
      </Card>
    </div>
  );
}
