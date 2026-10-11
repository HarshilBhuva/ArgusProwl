import { FormEvent, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Badge, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useIocLookup, useEvidence } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';
import type { EvidenceRecord, EvidenceEvent } from '../types/api';
import type {
  IocInvestigationResponse,
  IocObservation,
  IocTimelineItem,
  RelatedIoc,
} from '../types/api';

function reputationVerdictClass(verdict: string): string {
  if (verdict === 'MALICIOUS') return 'bg-destructive/10 text-destructive border-destructive/20';
  if (verdict === 'SUSPICIOUS') return 'bg-amber-500/10 text-amber-600 border-amber-500/20';
  if (verdict === 'BENIGN') return 'bg-primary/10 text-primary border-primary/20';
  return 'bg-muted text-muted-foreground border-border';
}

function IocLookupForm({ initial }: { initial: string }) {
  const [value, setValue] = useState(initial);
  const navigate = useNavigate();

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) return;
    navigate(`/iocs/${encodeURIComponent(trimmed)}`);
  };

  return (
    <form onSubmit={onSubmit} className="flex flex-wrap items-center gap-2">
      <input
        type="text"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        placeholder="IP address or domain"
        className="w-72 rounded-md border border-border bg-background px-2 py-1.5 text-xs font-mono text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
      />
      <button
        type="submit"
        className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
      >
        Investigate
      </button>
    </form>
  );
}

function ObservationsTable({ observations }: { observations: IocObservation[] }) {
  if (observations.length === 0) {
    return <p className="text-xs text-muted-foreground italic">No observations in retained alert evidence.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="border-b border-border text-muted-foreground uppercase">
          <tr>
            <th className="py-1.5 px-2 font-semibold">Timestamp</th>
            <th className="py-1.5 px-2 font-semibold">Field</th>
            <th className="py-1.5 px-2 font-semibold">Value</th>
            <th className="py-1.5 px-2 font-semibold">Host</th>
            <th className="py-1.5 px-2 font-semibold">Rule</th>
            <th className="py-1.5 px-2 font-semibold">Severity</th>
            <th className="py-1.5 px-2 font-semibold">Alert</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {observations.map((obs) => (
            <tr key={`${obs.alert_id}-${obs.field}-${obs.timestamp}`}>
              <td className="py-1.5 px-2 font-mono text-muted-foreground">{obs.timestamp}</td>
              <td className="py-1.5 px-2 font-mono text-foreground">{obs.field}</td>
              <td className="py-1.5 px-2 font-mono text-foreground">{obs.value}</td>
              <td className="py-1.5 px-2 text-muted-foreground">{obs.host ?? '—'}</td>
              <td className="py-1.5 px-2 font-mono text-muted-foreground">{obs.rule_id ?? '—'}</td>
              <td className="py-1.5 px-2 text-muted-foreground">{obs.severity ?? '—'}</td>
              <td className="py-1.5 px-2">
                <Link
                  to={`/alerts/${encodeURIComponent(obs.alert_id)}`}
                  className="font-mono text-primary hover:underline"
                >
                  {obs.alert_id}
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TimelineList({ items }: { items: IocTimelineItem[] }) {
  if (items.length === 0) {
    return <p className="text-xs text-muted-foreground italic">No timeline items.</p>;
  }
  return (
    <ol className="space-y-3">
      {items.map((item) => (
        <li key={item.timeline_item_id} className="border-l border-border pl-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className="bg-secondary text-secondary-foreground border-border">{item.item_type}</Badge>
            <span className="text-xs font-medium text-foreground">{item.title}</span>
            {item.timestamp ? (
              <span className="text-[11px] font-mono text-muted-foreground">{item.timestamp}</span>
            ) : (
              <span className="text-[11px] text-muted-foreground italic">static context</span>
            )}
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">{item.summary}</p>
          {item.source_id && item.item_type === 'OBSERVATION' && (
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
  );
}

function TimelineVisual({
  items,
  indicator,
  iocType,
}: {
  items: IocTimelineItem[];
  indicator: string;
  iocType: string;
}) {
  if (items.length === 0) {
    return (
      <div className="py-4 text-center">
        <p className="text-xs text-muted-foreground italic">No timeline data available.</p>
      </div>
    );
  }

  // Separate items by type for visual grouping
  const observations = items.filter((i) => i.item_type === 'OBSERVATION');
  const intelligence = items.filter((i) => i.item_type === 'INTELLIGENCE');
  const related = items.filter((i) => i.item_type === 'RELATED_IOC');

  return (
    <div className="space-y-4">
      {/* Header with indicator info */}
      <div className="flex items-center gap-2 pb-2 border-b border-border">
        <code className="text-xs font-mono text-foreground">{indicator}</code>
        <Badge className="bg-muted text-muted-foreground border-border text-[10px]">{iocType}</Badge>
        {items.some((i) => !i.timestamp) && (
          <span className="text-[10px] text-muted-foreground italic ml-auto">Includes static context</span>
        )}
      </div>

      {/* Observations timeline */}
      {observations.length > 0 && (
        <div>
          <h4 className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            Observations
          </h4>
          <div className="relative">
            {/* Timeline spine */}
            <div className="absolute left-2 top-0 bottom-0 w-px bg-primary/30" />
            <ul className="space-y-2">
              {observations.map((obs) => (
                <li key={obs.timeline_item_id} className="relative pl-6">
                  {/* Dot marker */}
                  <div className="absolute left-0.5 top-1.5 w-3 h-3 rounded-full bg-primary border-2 border-background" />
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[11px] font-mono text-muted-foreground">{obs.timestamp ?? '—'}</span>
                    <span className="text-xs text-foreground">{obs.title}</span>
                    {obs.metadata?.field && (
                      <Badge className="bg-secondary text-secondary-foreground border-border text-[10px]">
                        {obs.metadata.field}
                      </Badge>
                    )}
                    {obs.metadata?.severity && (
                      <Badge
                        className={
                          obs.metadata.severity === 'HIGH' || obs.metadata.severity === 'CRITICAL'
                            ? 'bg-destructive/10 text-destructive border-destructive/20'
                            : 'bg-muted text-muted-foreground border-border'
                        }
                      >
                        {obs.metadata.severity}
                      </Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{obs.summary}</p>
                  {obs.source_id && (
                    <Link
                      to={`/alerts/${encodeURIComponent(obs.source_id)}`}
                      className="mt-0.5 inline-block text-[10px] font-mono text-primary hover:underline"
                    >
                      Alert: {obs.source_id}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Intelligence context */}
      {intelligence.length > 0 && (
        <div>
          <h4 className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            Intelligence Context
          </h4>
          <div className="relative">
            <div className="absolute left-2 top-0 bottom-0 w-px bg-amber-500/30" />
            <ul className="space-y-2">
              {intelligence.map((item) => (
                <li key={item.timeline_item_id} className="relative pl-6">
                  {/* Triangle marker for intelligence */}
                  <div className="absolute left-1 top-1 w-0 h-0 border-l-[5px] border-l-transparent border-r-[5px] border-r-transparent border-t-[8px] border-t-amber-500" />
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-medium text-amber-600">Intelligence</span>
                    <span className="text-xs text-foreground">{item.title}</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{item.summary}</p>
                  {item.metadata?.verdict && (
                    <Badge
                      className={
                        item.metadata.verdict === 'MALICIOUS'
                          ? 'bg-destructive/10 text-destructive border-destructive/20'
                          : item.metadata.verdict === 'SUSPICIOUS'
                          ? 'bg-amber-500/10 text-amber-600 border-amber-500/20'
                          : 'bg-primary/10 text-primary border-primary/20'
                      }
                    >
                      {item.metadata.verdict}
                    </Badge>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Related IOCs */}
      {related.length > 0 && (
        <div>
          <h4 className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            Related Indicators
          </h4>
          <div className="relative">
            <div className="absolute left-2 top-0 bottom-0 w-px bg-blue-500/30" />
            <ul className="space-y-2">
              {related.map((item) => (
                <li key={item.timeline_item_id} className="relative pl-6">
                  {/* Diamond marker for related IOCs */}
                  <div className="absolute left-1.5 top-1.5 w-2 h-2 rotate-45 bg-blue-500" />
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono text-blue-600">{item.title.replace('Related IOC: ', '')}</span>
                    {item.metadata?.field && (
                      <Badge className="bg-secondary text-secondary-foreground border-border text-[10px]">
                        {item.metadata.field}
                      </Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{item.summary}</p>
                  {item.source_id && (
                    <Link
                      to={`/alerts/${encodeURIComponent(item.source_id)}`}
                      className="mt-0.5 inline-block text-[10px] font-mono text-primary hover:underline"
                    >
                      Alert: {item.source_id}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Bounded indicator */}
      {items.length >= 100 && (
        <p className="text-[10px] text-muted-foreground italic pt-2 border-t border-border">
          Timeline bounded to 100 items
        </p>
      )}
    </div>
  );
}

function RelatedIocs({ related }: { related: RelatedIoc[] }) {
  if (related.length === 0) {
    return <p className="text-xs text-muted-foreground italic">No co-observed IOCs in matching alerts.</p>;
  }
  return (
    <ul className="space-y-1.5">
      {related.map((rel) => (
        <li key={`${rel.ioc_type}:${rel.indicator}:${rel.co_observed_in_alert_id}`} className="text-xs">
          <Link
            to={`/iocs/${encodeURIComponent(rel.indicator)}`}
            className="font-mono text-primary hover:underline"
          >
            {rel.indicator}
          </Link>
          <span className="ml-2 text-muted-foreground">
            {rel.ioc_type} · {rel.field} · alert{' '}
            <Link
              to={`/alerts/${encodeURIComponent(rel.co_observed_in_alert_id)}`}
              className="font-mono text-primary hover:underline"
            >
              {rel.co_observed_in_alert_id}
            </Link>
          </span>
        </li>
      ))}
    </ul>
  );
}

function InvestigationBody({ data }: { data: IocInvestigationResponse }) {
  const verdict = String(data.reputation.verdict ?? 'UNKNOWN');
  const confidence = String(data.reputation.confidence ?? '0');
  const source = String(data.reputation.source ?? '');
  const categories = Array.isArray(data.reputation.categories)
    ? (data.reputation.categories as string[]).join(', ')
    : '';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <code className="text-sm font-mono text-foreground">{data.indicator}</code>
        <Badge className="bg-muted text-muted-foreground border-border">{data.ioc_type}</Badge>
        <Badge className={reputationVerdictClass(verdict)}>{verdict}</Badge>
        {data.status === 'DEGRADED' && (
          <Badge className="bg-amber-500/10 text-amber-600 border-amber-500/20">DEGRADED</Badge>
        )}
        {data.truncated && (
          <Badge className="bg-muted text-muted-foreground border-border">Truncated</Badge>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Reputation</h3>
          <p className="mt-1 text-xs text-foreground">
            {verdict} · confidence {confidence}
            {source ? ` · ${source}` : ''}
          </p>
          {categories && <p className="mt-0.5 text-xs text-muted-foreground">{categories}</p>}
        </div>
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Observed window</h3>
          <p className="mt-1 text-xs font-mono text-foreground">
            {data.first_observed ?? '—'} → {data.last_observed ?? '—'}
          </p>
          <p className="mt-0.5 text-[11px] text-muted-foreground italic">{data.observation_note}</p>
        </div>
      </div>

      {data.prevalence && (
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Prevalence</h3>
          <pre className="mt-1 text-xs font-mono bg-muted p-2 rounded overflow-x-auto">
            {JSON.stringify(data.prevalence, null, 2)}
          </pre>
        </div>
      )}

      <div>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase">Associated alerts</h3>
        {data.associated_alert_ids.length === 0 ? (
          <p className="mt-1 text-xs text-muted-foreground italic">None</p>
        ) : (
          <ul className="mt-1 flex flex-wrap gap-2">
            {data.associated_alert_ids.map((id) => (
              <li key={id}>
                <Link to={`/alerts/${encodeURIComponent(id)}`} className="font-mono text-xs text-primary hover:underline">
                  {id}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Hosts</h3>
          <p className="mt-1 text-xs font-mono text-foreground">
            {data.associated_hosts.length ? data.associated_hosts.join(', ') : '—'}
          </p>
        </div>
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Rules</h3>
          <p className="mt-1 text-xs font-mono text-foreground">
            {data.associated_rule_ids.length ? data.associated_rule_ids.join(', ') : '—'}
          </p>
        </div>
      </div>

      {data.reason && (
        <p className="text-xs text-amber-600">Status reason: {data.reason}</p>
      )}
    </div>
  );
}

export function IocPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-bold text-foreground uppercase tracking-tight">IOC Investigation</h1>
        <p className="mt-0.5 text-[11px] font-mono text-muted-foreground">
          Read-only lookup against offline threat intelligence and retained alert evidence
        </p>
      </div>
      <Card title="Lookup" description="Enter an IP address or domain">
        <IocLookupForm initial="" />
      </Card>
    </div>
  );
}

export function IocDetailPage() {
  const { indicator } = useParams<{ indicator: string }>();
  const decoded = decodeURIComponent((indicator ?? '').trim());
  const query = useIocLookup(decoded || null);

  if (!decoded) {
    return <EmptyState message="Indicator is missing." />;
  }

  let body;
  if (query.isLoading) {
    body = <LoadingSkeleton lines={8} />;
  } else if (query.error) {
    const message =
      query.error instanceof ApiClientError ? query.error.userMessage : 'Unable to investigate IOC.';
    body = <ErrorState message={message} onRetry={() => { void query.refetch(); }} />;
  } else if (!query.data) {
    body = <EmptyState message="No investigation result returned." />;
  } else {
    body = <InvestigationBody data={query.data} />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-foreground uppercase tracking-tight">IOC Investigation</h1>
          <p className="mt-0.5 text-[11px] font-mono text-muted-foreground">{decoded}</p>
        </div>
        <Link
          to="/iocs"
          className="text-xs font-medium font-mono text-muted-foreground hover:text-foreground transition-colors"
        >
          ← New lookup
        </Link>
      </div>

      <Card title="Lookup" description="Investigate another indicator">
        <IocLookupForm initial={decoded} />
      </Card>

      <Card title="Investigation" description="Reputation, observations, and provenance">
        {body}
      </Card>

      {query.data && (
        <>
          <Card title="Observations" description={query.data.observation_note}>
            <ObservationsTable observations={query.data.observations} />
          </Card>
          <Card title="Timeline" description="Visual timeline of observations, intelligence, and related indicators">
            <TimelineVisual
              items={query.data.timeline}
              indicator={query.data.indicator}
              iocType={query.data.ioc_type}
            />
          </Card>
          <Card title="Related IOCs" description="Co-observed src_ip, dst_ip, or domain values">
            <RelatedIocs related={query.data.related_iocs} />
          </Card>
          <Card title="Telemetry Evidence" description="Raw events matching indicators from this investigation">
            {(() => {
              const relatedIndicators = [
                query.data.indicator,
                ...query.data.related_iocs.map((r) => r.indicator),
              ];
              const evidenceQueries = relatedIndicators.map((ind) =>
                useEvidence({ domain: ind, limit: 20 }),
              );
              const allRecords: { rec: EvidenceRecord; evt: EvidenceEvent | undefined; ind: string }[] = [];
              for (let i = 0; i < evidenceQueries.length; i++) {
                const q = evidenceQueries[i];
                if (q.data?.records) {
                  for (const rec of q.data.records) {
                    allRecords.push({ rec, evt: q.data?.events?.[rec.event_id], ind: relatedIndicators[i] });
                  }
                }
              }
              if (allRecords.length === 0) {
                return <p className="text-xs text-muted-foreground italic">No telemetry events matching these indicators.</p>;
              }
              return (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {allRecords.slice(0, 20).map(({ rec, evt, ind }) => (
                    <div key={rec.event_id} className="border border-border rounded-md p-2 space-y-1">
                      <div className="flex items-center gap-2">
                        <code className="text-xs font-mono text-foreground">{rec.event_id}</code>
                        <span className="text-[11px] text-muted-foreground">{rec.provenance}</span>
                        <span className="text-[11px] font-mono text-primary">ind: {ind}</span>
                      </div>
                      {evt && (
                        <div className="text-[11px] text-muted-foreground font-mono">
                          {evt.timestamp} · {evt.source_type}:{evt.event_type}
                          {evt.src_ip && ` · src=${evt.src_ip}`}
                          {evt.dst_ip && ` · dst=${evt.dst_ip}`}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              );
            })()}
          </Card>
        </>
      )}
    </div>
  );
}
