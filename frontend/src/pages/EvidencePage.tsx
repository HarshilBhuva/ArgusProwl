import { FormEvent, useState } from 'react';
import { Link } from 'react-router-dom';
import { Badge, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useEvidence } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';
import type { EvidenceRecord, EvidenceEvent, EvidenceSearchParams } from '../types/api';
import { formatTimestamp } from '../lib/utils';

type FilterDraft = {
  event_id: string;
  start_time: string;
  end_time: string;
  source_type: string;
  event_type: string;
  entity_type: string;
  entity_id: string;
  src_ip: string;
  dst_ip: string;
  domain: string;
};

const EMPTY_FILTERS: FilterDraft = {
  event_id: '',
  start_time: '',
  end_time: '',
  source_type: '',
  event_type: '',
  entity_type: '',
  entity_id: '',
  src_ip: '',
  dst_ip: '',
  domain: '',
};

function toIsoTimestamp(value: string): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function provenanceBadgeClass(provenance: string): string {
  if (provenance === 'DETECTION_SOURCE') return 'bg-primary/10 text-primary border-primary/20';
  if (provenance === 'CONTRIBUTING_EVENT') return 'bg-amber-500/10 text-amber-600 border-amber-500/20';
  if (provenance === 'OBSERVED_CONTEXT') return 'bg-muted text-muted-foreground border-border';
  return 'bg-muted text-muted-foreground border-border';
}

export function EvidencePage() {
  const [limit, setLimit] = useState(50);
  const [draft, setDraft] = useState<FilterDraft>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<EvidenceSearchParams>({});
  const [cursor, setCursor] = useState<string | undefined>();
  const [previousCursors, setPreviousCursors] = useState<Array<string | undefined>>([]);
  const evidenceQuery = useEvidence({ limit, ...filters, cursor });

  const updateDraft = (field: keyof FilterDraft, value: string) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };

  const applyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const startTime = toIsoTimestamp(draft.start_time);
    const endTime = toIsoTimestamp(draft.end_time);
    setCursor(undefined);
    setPreviousCursors([]);
    setFilters({
      event_id: draft.event_id.trim() || undefined,
      start_time: startTime,
      end_time: endTime,
      source_type: draft.source_type.trim() || undefined,
      event_type: draft.event_type.trim() || undefined,
      entity_type: draft.entity_type || undefined,
      entity_id: draft.entity_id.trim() || undefined,
      src_ip: draft.src_ip.trim() || undefined,
      dst_ip: draft.dst_ip.trim() || undefined,
      domain: draft.domain.trim() || undefined,
    });
  };

  const clearFilters = () => {
    setDraft(EMPTY_FILTERS);
    setCursor(undefined);
    setPreviousCursors([]);
    setFilters({});
  };

  const activeFilterCount = Object.values(filters).filter(Boolean).length;

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
    body = <EmptyState message="No evidence records found for the selected filters." />;
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
                      <p className="mt-0.5 text-[11px] text-muted-foreground truncate">
                        {evt.hostname || 'Unknown host'}
                        {evt.username && <span className="ml-2">{evt.username}</span>}
                        {evt.process_name && <span className="ml-2 font-mono">{evt.process_name}</span>}
                        {evt.src_ip && <span className="ml-2 font-mono">{evt.src_ip}</span>}
                        {evt.dst_ip && <span className="ml-2 font-mono">→ {evt.dst_ip}</span>}
                      </p>
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
            Showing {evidenceQuery.data.returned_count} of {evidenceQuery.data.total_count} matching events. Increase the result limit or narrow the time range; this result is incomplete.
          </div>
        )}
      </div>
    );
  }

  const status = evidenceQuery.data?.status;
  const degraded = status && status !== 'AVAILABLE' && status !== 'OK';

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-foreground uppercase tracking-tight">Event Explorer</h1>
          <p className="mt-0.5 text-[11px] font-mono text-muted-foreground">
            {evidenceQuery.data?.total_count ?? 0} matching retained events · {activeFilterCount} active filters
          </p>
        </div>
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          Result limit
          <select
            aria-label="Result limit"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={250}>250</option>
            <option value={500}>500</option>
          </select>
        </label>
      </div>

      <Card title="Search telemetry" description="Filters are combined with AND. Time boundaries are inclusive; results are bounded by the selected limit.">
        <form onSubmit={applyFilters} className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className="space-y-1 text-xs text-muted-foreground">
            Event ID
            <input value={draft.event_id} onChange={(e) => updateDraft('event_id', e.target.value)} maxLength={36} placeholder="Exact UUID" className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Source type
            <input value={draft.source_type} onChange={(e) => updateDraft('source_type', e.target.value)} maxLength={128} placeholder="zeek, sysmon..." className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Event type
            <input value={draft.event_type} onChange={(e) => updateDraft('event_type', e.target.value)} maxLength={128} placeholder="network_connection..." className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Entity type
            <select value={draft.entity_type} onChange={(e) => updateDraft('entity_type', e.target.value)} className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground">
              <option value="">Any entity</option>
              <option value="hostname">Host</option>
              <option value="user">User</option>
              <option value="process">Process</option>
              <option value="src_ip">IP address</option>
            </select>
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Entity ID
            <input value={draft.entity_id} onChange={(e) => updateDraft('entity_id', e.target.value)} maxLength={256} placeholder="Host, user, process or IP" className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Source IP
            <input value={draft.src_ip} onChange={(e) => updateDraft('src_ip', e.target.value)} maxLength={64} placeholder="192.0.2.10" className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Destination IP
            <input value={draft.dst_ip} onChange={(e) => updateDraft('dst_ip', e.target.value)} maxLength={64} placeholder="198.51.100.20" className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Domain / hostname
            <input value={draft.domain} onChange={(e) => updateDraft('domain', e.target.value)} maxLength={256} placeholder="example.internal" className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            Start time (local)
            <input type="datetime-local" value={draft.start_time} onChange={(e) => updateDraft('start_time', e.target.value)} className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <label className="space-y-1 text-xs text-muted-foreground">
            End time (local)
            <input type="datetime-local" value={draft.end_time} onChange={(e) => updateDraft('end_time', e.target.value)} className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs text-foreground" />
          </label>
          <div className="flex items-end gap-2 md:col-span-2 xl:col-span-4">
            <button type="submit" className="rounded-md bg-primary px-3 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90">Search events</button>
            <button type="button" onClick={clearFilters} className="rounded-md border border-border px-3 py-2 text-xs text-foreground hover:bg-muted">Clear filters</button>
          </div>
        </form>
      </Card>

      <div className="flex items-center justify-between border-t border-border pt-3">
        <button
          type="button"
          onClick={() => {
            const previous = [...previousCursors];
            const next = previous.pop();
            setPreviousCursors(previous);
            setCursor(next);
          }}
          disabled={previousCursors.length === 0 || evidenceQuery.isLoading}
          className="rounded-md border border-border px-3 py-2 text-xs text-foreground disabled:cursor-not-allowed disabled:opacity-40"
        >
          Previous page
        </button>
        <span className="text-xs text-muted-foreground">
          {cursor ? 'Historical results' : 'Newest search page'}
        </span>
        <button
          type="button"
          onClick={() => {
            const next = evidenceQuery.data?.next_cursor;
            if (next) {
              setPreviousCursors((current) => [...current, cursor]);
              setCursor(next);
            }
          }}
          disabled={!evidenceQuery.data?.next_cursor || evidenceQuery.isLoading}
          className="rounded-md border border-border px-3 py-2 text-xs text-foreground disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next page
        </button>
      </div>

      {degraded && (
        <div role="status" className="border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-700">
          Evidence availability: {status}. {evidenceQuery.data?.reason || 'The returned data may be incomplete.'}
        </div>
      )}

      <Card title="Event results" description="Normalized telemetry with evidence provenance">
        {body}
      </Card>
    </div>
  );
}
