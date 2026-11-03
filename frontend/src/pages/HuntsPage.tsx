import { type FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Badge, Button, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { ApiClientError, api } from '../lib/api';
import type {
  Hunt,
  HuntDisposition,
  HuntEvidenceRole,
  HuntListResponse,
  HuntScopeRequest,
} from '../types/api';
import { formatTimestamp } from '../lib/utils';

const INPUT_CLASS =
  'w-full rounded-sm border border-border bg-background px-2.5 py-2 text-xs text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary';
const LABEL_CLASS = 'mb-1 block text-[10px] font-mono uppercase tracking-wider text-muted-foreground';

function errorMessage(error: unknown): string {
  return error instanceof ApiClientError ? error.userMessage : 'The investigation request failed.';
}

function toIso(value: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function toLocalInput(value: string | null): string {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function downloadReport(hunt: Hunt): void {
  const report = {
    report_schema: 'argusprowl.investigation-report.v1',
    exported_at: new Date().toISOString(),
    hunt,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `argusprowl-hunt-${hunt.hunt_id}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function StatusBadge({ status }: { status: string }) {
  const className =
    status === 'completed' || status === 'complete'
      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600'
      : status === 'failed'
        ? 'border-red-500/30 bg-red-500/10 text-red-600'
        : status === 'degraded' || status === 'partial'
          ? 'border-amber-500/30 bg-amber-500/10 text-amber-600'
          : 'border-border bg-muted text-muted-foreground';
  return <Badge className={className}>{status}</Badge>;
}

export function HuntsPage() {
  const { id: huntId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [hunts, setHunts] = useState<Hunt[]>([]);
  const [hunt, setHunt] = useState<Hunt | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [title, setTitle] = useState('');
  const [hypothesis, setHypothesis] = useState('');
  const [scopeStart, setScopeStart] = useState('');
  const [scopeEnd, setScopeEnd] = useState('');
  const [scopeHost, setScopeHost] = useState('');
  const [scopeUser, setScopeUser] = useState('');
  const [scopeSource, setScopeSource] = useState('');
  const [queryName, setQueryName] = useState('Initial telemetry search');
  const [querySource, setQuerySource] = useState('');
  const [queryEventType, setQueryEventType] = useState('');
  const [queryEntityType, setQueryEntityType] = useState('');
  const [queryEntityId, setQueryEntityId] = useState('');
  const [queryStart, setQueryStart] = useState('');
  const [queryEnd, setQueryEnd] = useState('');
  const [manualEventId, setManualEventId] = useState('');
  const [manualRole, setManualRole] = useState<HuntEvidenceRole>('context');
  const [manualNote, setManualNote] = useState('');
  const [findingTitle, setFindingTitle] = useState('');
  const [findingDescription, setFindingDescription] = useState('');
  const [findingDisposition, setFindingDisposition] = useState<HuntDisposition>('inconclusive');
  const [selectedEvidence, setSelectedEvidence] = useState<string[]>([]);
  const [conclusionSummary, setConclusionSummary] = useState('');
  const [conclusionDisposition, setConclusionDisposition] = useState<HuntDisposition>('inconclusive');
  const [conclusionConfidence, setConclusionConfidence] = useState('0.5');

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (huntId) {
        const result = await api.hunt(huntId);
        setHunt(result);
        setScopeStart(toLocalInput(result.scope.start_time));
        setScopeEnd(toLocalInput(result.scope.end_time));
        setScopeHost(result.scope.hosts[0] ?? '');
        setScopeUser(result.scope.users[0] ?? '');
        setScopeSource(result.scope.sources[0] ?? '');
        setConclusionSummary(result.conclusion?.summary ?? '');
        setConclusionDisposition(result.conclusion?.disposition ?? 'inconclusive');
        setConclusionConfidence(String(result.conclusion?.confidence ?? 0.5));
      } else {
        const result: HuntListResponse = await api.hunts();
        setHunts(result.hunts);
        setHunt(null);
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [huntId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const mutate = async (operation: () => Promise<Hunt>): Promise<void> => {
    setSaving(true);
    setError(null);
    try {
      setHunt(await operation());
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const entityPivots = useMemo(() => {
    if (!hunt) return [];
    const pivots = new Map<string, { type: string; id: string }>();
    for (const host of hunt.scope.hosts) pivots.set(`hostname:${host}`, { type: 'hostname', id: host });
    for (const user of hunt.scope.users) pivots.set(`user:${user}`, { type: 'user', id: user });
    for (const query of hunt.queries) {
      const type = query.definition.entity_type;
      const value = query.definition.entity_id;
      if (typeof type === 'string' && typeof value === 'string' && type && value) {
        pivots.set(`${type}:${value}`, { type, id: value });
      }
    }
    return [...pivots.values()];
  }, [hunt]);

  const createHunt = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const created = await api.createHunt({ title: title.trim(), hypothesis: hypothesis.trim() });
      navigate(`/hunts/${created.hunt_id}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const saveScope = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!hunt) return;
    const scope: HuntScopeRequest = {
      start_time: toIso(scopeStart),
      end_time: toIso(scopeEnd),
      hosts: scopeHost.trim() ? [scopeHost.trim()] : [],
      users: scopeUser.trim() ? [scopeUser.trim()] : [],
      sources: scopeSource.trim() ? [scopeSource.trim()] : [],
    };
    void mutate(() => api.updateHuntScope(hunt.hunt_id, scope));
  };

  const saveQuery = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!hunt) return;
    const definition: Record<string, unknown> = { limit: 500 };
    if (querySource.trim()) definition.source_type = querySource.trim();
    if (queryEventType.trim()) definition.event_type = queryEventType.trim();
    if (queryEntityType.trim()) definition.entity_type = queryEntityType.trim();
    if (queryEntityId.trim()) definition.entity_id = queryEntityId.trim();
    if (queryStart) definition.start_time = toIso(queryStart);
    if (queryEnd) definition.end_time = toIso(queryEnd);
    void mutate(() => api.saveHuntQuery(hunt.hunt_id, { name: queryName.trim(), definition }));
  };

  const executeQuery = async (queryId: string, version: number) => {
    if (!hunt) return;
    setSaving(true);
    setError(null);
    try {
      const result = await api.executeHuntQuery(hunt.hunt_id, queryId, version);
      setHunt(result.hunt);
      setSelectedEvidence(result.execution.evidence_event_ids);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const attachEvidence = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!hunt || !manualEventId.trim()) return;
    void mutate(async () => {
      const updated = await api.attachHuntEvidence(hunt.hunt_id, {
        event_id: manualEventId.trim(),
        role: manualRole,
        note: manualNote.trim(),
      });
      setManualEventId('');
      setManualNote('');
      return updated;
    });
  };

  const addFinding = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!hunt) return;
    void mutate(async () => {
      const updated = await api.addHuntFinding(hunt.hunt_id, {
        title: findingTitle.trim(),
        description: findingDescription.trim(),
        disposition: findingDisposition,
        evidence_event_ids: selectedEvidence,
      });
      setFindingTitle('');
      setFindingDescription('');
      return updated;
    });
  };

  const saveConclusion = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!hunt) return;
    const confidence = Number(conclusionConfidence);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      setError('Conclusion confidence must be between 0 and 1.');
      return;
    }
    void mutate(() =>
      api.setHuntConclusion(hunt.hunt_id, {
        summary: conclusionSummary.trim(),
        disposition: conclusionDisposition,
        confidence,
      }),
    );
  };

  const changeStatus = (status: string) => {
    if (!hunt) return;
    void mutate(() => api.transitionHunt(hunt.hunt_id, status));
  };

  if (loading) {
    return (
      <div className="space-y-5">
        <h1 className="text-xl font-semibold text-foreground">Investigation Hunts</h1>
        <LoadingSkeleton lines={7} />
      </div>
    );
  }

  if (error && !hunt && huntId) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold text-foreground">Investigation Hunt</h1>
        <ErrorState message={error} onRetry={() => void refresh()} />
        <Link to="/hunts" className="text-xs text-primary hover:underline">Back to hunts</Link>
      </div>
    );
  }

  if (!huntId) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Investigation Hunts</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            Hypothesis-driven investigations with versioned searches, durable evidence references and analyst conclusions.
          </p>
        </div>
        {error && <ErrorState message={error} onRetry={() => void refresh()} />}
        <Card title="Create investigation" description="Start with a falsifiable hypothesis and a clear objective.">
          <form onSubmit={createHunt} className="grid gap-3">
            <label>
              <span className={LABEL_CLASS}>Hunt title</span>
              <input className={INPUT_CLASS} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} required />
            </label>
            <label>
              <span className={LABEL_CLASS}>Hypothesis</span>
              <textarea className={INPUT_CLASS} value={hypothesis} onChange={(e) => setHypothesis(e.target.value)} rows={3} maxLength={4000} required />
            </label>
            <div><Button type="submit" disabled={saving || !title.trim() || !hypothesis.trim()}>Create hunt</Button></div>
          </form>
        </Card>
        <Card title="Saved investigations" description={`${hunts.length} returned`}>
          {hunts.length === 0 ? (
            <EmptyState message="No hunts have been created yet." />
          ) : (
            <div className="divide-y divide-border">
              {hunts.map((item) => (
                <Link key={item.hunt_id} to={`/hunts/${item.hunt_id}`} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0 hover:bg-muted/30">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground">{item.title}</p>
                    <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{item.hypothesis}</p>
                    <p className="mt-1 text-[10px] font-mono text-muted-foreground">Updated {formatTimestamp(item.updated_at)} · revision {item.revision}</p>
                  </div>
                  <StatusBadge status={item.status} />
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>
    );
  }

  if (!hunt) {
    return <EmptyState message="Hunt not found." />;
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link to="/hunts" className="text-[11px] text-primary hover:underline">← All hunts</Link>
          <h1 className="mt-2 text-xl font-semibold tracking-tight text-foreground">{hunt.title}</h1>
          <p className="mt-1 max-w-3xl text-xs text-muted-foreground">{hunt.hypothesis}</p>
          <p className="mt-2 text-[10px] font-mono text-muted-foreground">
            {hunt.hunt_id} · owner {hunt.created_by} · revision {hunt.revision}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={hunt.status} />
          <Button onClick={() => downloadReport(hunt)}>Export report JSON</Button>
          {hunt.status === 'draft' && <Button disabled={saving} onClick={() => changeStatus('active')}>Activate</Button>}
          {hunt.status === 'active' && <Button disabled={saving} onClick={() => changeStatus('completed')}>Complete</Button>}
        </div>
      </div>
      {error && <ErrorState message={error} onRetry={() => void refresh()} />}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="1. Investigation scope" description="The execution service enforces these bounds on every saved query.">
          <form onSubmit={saveScope} className="grid gap-3 sm:grid-cols-2">
            <label><span className={LABEL_CLASS}>Start time</span><input aria-label="Scope start time" type="datetime-local" className={INPUT_CLASS} value={scopeStart} onChange={(e) => setScopeStart(e.target.value)} /></label>
            <label><span className={LABEL_CLASS}>End time</span><input aria-label="Scope end time" type="datetime-local" className={INPUT_CLASS} value={scopeEnd} onChange={(e) => setScopeEnd(e.target.value)} /></label>
            <label><span className={LABEL_CLASS}>Hostname (single host)</span><input className={INPUT_CLASS} value={scopeHost} onChange={(e) => setScopeHost(e.target.value)} maxLength={256} /></label>
            <label><span className={LABEL_CLASS}>Username (single user)</span><input className={INPUT_CLASS} value={scopeUser} onChange={(e) => setScopeUser(e.target.value)} maxLength={256} /></label>
            <label className="sm:col-span-2"><span className={LABEL_CLASS}>Source type (single source)</span><input className={INPUT_CLASS} value={scopeSource} onChange={(e) => setScopeSource(e.target.value)} maxLength={256} placeholder="e.g. sysmon" /></label>
            <div className="sm:col-span-2"><Button type="submit" disabled={saving}>Save scope</Button></div>
          </form>
          <p className="mt-3 text-[10px] text-muted-foreground">
            Current query execution supports one host or one user scope at a time and requires an explicit source when multiple sources are in scope.
          </p>
        </Card>

        <Card title="2. Saved telemetry searches" description="Queries are immutable by version; each execution records the exact query version and evidence IDs.">
          <form onSubmit={saveQuery} className="grid gap-3 sm:grid-cols-2">
            <label className="sm:col-span-2"><span className={LABEL_CLASS}>Query name</span><input className={INPUT_CLASS} value={queryName} onChange={(e) => setQueryName(e.target.value)} maxLength={128} required /></label>
            <label><span className={LABEL_CLASS}>Source type</span><input className={INPUT_CLASS} value={querySource} onChange={(e) => setQuerySource(e.target.value)} placeholder="sysmon" /></label>
            <label><span className={LABEL_CLASS}>Event type</span><input className={INPUT_CLASS} value={queryEventType} onChange={(e) => setQueryEventType(e.target.value)} placeholder="process_start" /></label>
            <label><span className={LABEL_CLASS}>Entity type</span><input className={INPUT_CLASS} value={queryEntityType} onChange={(e) => setQueryEntityType(e.target.value)} placeholder="hostname / user / ip" /></label>
            <label><span className={LABEL_CLASS}>Entity ID</span><input className={INPUT_CLASS} value={queryEntityId} onChange={(e) => setQueryEntityId(e.target.value)} /></label>
            <label><span className={LABEL_CLASS}>Query start</span><input type="datetime-local" className={INPUT_CLASS} value={queryStart} onChange={(e) => setQueryStart(e.target.value)} /></label>
            <label><span className={LABEL_CLASS}>Query end</span><input type="datetime-local" className={INPUT_CLASS} value={queryEnd} onChange={(e) => setQueryEnd(e.target.value)} /></label>
            <div className="sm:col-span-2"><Button type="submit" disabled={saving || !queryName.trim()}>Save query version</Button></div>
          </form>
          <div className="mt-4 divide-y divide-border">
            {hunt.queries.length === 0 ? <EmptyState message="Save a telemetry search to begin." /> : hunt.queries.map((query) => (
              <div key={query.query_id + query.version} className="flex flex-wrap items-center justify-between gap-2 py-3 first:pt-0">
                <div className="min-w-0">
                  <p className="text-xs font-medium text-foreground">{query.name} <span className="font-mono text-muted-foreground">v{query.version}</span></p>
                  <p className="mt-1 break-all text-[10px] font-mono text-muted-foreground">{JSON.stringify(query.definition)}</p>
                </div>
                <Button disabled={saving || hunt.status === 'archived'} onClick={() => void executeQuery(query.query_id, query.version)}>Execute v{query.version}</Button>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="3. Entity pivots and timelines" description="Follow scoped identities into the existing entity investigation and chronological timeline views.">
        {entityPivots.length === 0 ? (
          <EmptyState message="Add a hostname/user scope or an entity filter to expose investigation pivots." />
        ) : (
          <div className="flex flex-wrap gap-2">
            {entityPivots.map((entity) => (
              <Link key={`${entity.type}:${entity.id}`} to={`/entities/${encodeURIComponent(entity.type)}/${encodeURIComponent(entity.id)}`} className="rounded-sm border border-border px-2.5 py-2 text-xs text-primary hover:bg-primary/5">
                Open {entity.type}: <span className="font-mono">{entity.id}</span> timeline and relationships
              </Link>
            ))}
          </div>
        )}
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="4. Executions and detection evidence" description="Each result is linked to its authoritative evidence record; inspect detection provenance there.">
          {hunt.executions.length === 0 ? <EmptyState message="No query executions have been recorded." /> : (
            <div className="space-y-4">
              {hunt.executions.slice().reverse().map((execution) => (
                <section key={execution.execution_id} className="border-b border-border pb-3 last:border-0 last:pb-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-xs font-medium text-foreground">Execution · query v{execution.query_version}</p>
                    <StatusBadge status={execution.status} />
                  </div>
                  <p className="mt-1 text-[10px] text-muted-foreground">
                    {execution.result_count} verified events · {execution.data_sources.join(', ') || 'no sources'} · {formatTimestamp(execution.completed_at)}
                    {execution.truncated ? ' · truncated' : ''}
                  </p>
                  {execution.error && <p className="mt-1 text-[10px] text-amber-600">{execution.error}</p>}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {execution.evidence_event_ids.map((eventId) => (
                      <Link key={eventId} to={`/evidence/${encodeURIComponent(eventId)}`} className="rounded-sm border border-border px-2 py-1 font-mono text-[10px] text-primary hover:bg-primary/5">
                        {eventId.slice(0, 8)}… evidence
                      </Link>
                    ))}
                  </div>
                </section>
              ))}
            </div>
          )}
        </Card>

        <Card title="5. Evidence register" description="Attach supporting, contradicting or contextual references without copying telemetry.">
          <form onSubmit={attachEvidence} className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_140px]">
            <label className="sm:col-span-2"><span className={LABEL_CLASS}>Telemetry event UUID</span><input className={INPUT_CLASS} value={manualEventId} onChange={(e) => setManualEventId(e.target.value)} placeholder="Event ID" required /></label>
            <label><span className={LABEL_CLASS}>Evidence role</span><select className={INPUT_CLASS} value={manualRole} onChange={(e) => setManualRole(e.target.value as HuntEvidenceRole)}><option value="context">Context</option><option value="supporting">Supporting</option><option value="contradicting">Contradicting</option></select></label>
            <label><span className={LABEL_CLASS}>Analyst note</span><input className={INPUT_CLASS} value={manualNote} onChange={(e) => setManualNote(e.target.value)} maxLength={2000} /></label>
            <div className="sm:col-span-2"><Button type="submit" disabled={saving || hunt.status === 'archived'}>Attach evidence</Button></div>
          </form>
          <div className="mt-3 divide-y divide-border">
            {hunt.evidence_references.length === 0 ? <EmptyState message="No evidence references attached." /> : hunt.evidence_references.map((reference) => (
              <label key={reference.event_id} className="flex items-start gap-2 py-2 text-xs first:pt-0">
                <input type="checkbox" checked={selectedEvidence.includes(reference.event_id)} onChange={(e) => setSelectedEvidence((current) => e.target.checked ? [...new Set([...current, reference.event_id])] : current.filter((id) => id !== reference.event_id))} />
                <span className="min-w-0 flex-1">
                  <Link to={`/evidence/${encodeURIComponent(reference.event_id)}`} className="break-all font-mono text-primary hover:underline">{reference.event_id}</Link>
                  <span className="ml-2 text-[10px] text-muted-foreground">{reference.role} · {reference.added_by}</span>
                  {reference.note && <span className="mt-0.5 block text-[10px] text-muted-foreground">{reference.note}</span>}
                </span>
              </label>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="6. Analyst findings" description="Findings are analyst-authored and explicitly state whether evidence supports or contradicts the hypothesis.">
          <form onSubmit={addFinding} className="grid gap-2">
            <label><span className={LABEL_CLASS}>Finding title</span><input className={INPUT_CLASS} value={findingTitle} onChange={(e) => setFindingTitle(e.target.value)} maxLength={200} required /></label>
            <label><span className={LABEL_CLASS}>Description</span><textarea className={INPUT_CLASS} value={findingDescription} onChange={(e) => setFindingDescription(e.target.value)} rows={3} maxLength={4000} required /></label>
            <label><span className={LABEL_CLASS}>Disposition</span><select className={INPUT_CLASS} value={findingDisposition} onChange={(e) => setFindingDisposition(e.target.value as HuntDisposition)}><option value="supports">Supports hypothesis</option><option value="contradicts">Contradicts hypothesis</option><option value="inconclusive">Inconclusive</option></select></label>
            <p className="text-[10px] text-muted-foreground">{selectedEvidence.length} selected evidence reference(s) will be attached.</p>
            <div><Button type="submit" disabled={saving || !findingTitle.trim() || !findingDescription.trim() || hunt.status === 'archived'}>Record finding</Button></div>
          </form>
          <div className="mt-4 space-y-3">
            {hunt.findings.length === 0 ? <EmptyState message="No analyst findings recorded." /> : hunt.findings.map((finding) => (
              <article key={finding.finding_id} className="border-t border-border pt-3 first:border-0 first:pt-0">
                <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs font-semibold text-foreground">{finding.title}</p><StatusBadge status={finding.disposition} /></div>
                <p className="mt-1 whitespace-pre-wrap text-xs text-muted-foreground">{finding.description}</p>
                <p className="mt-1 text-[10px] text-muted-foreground">{finding.author} · {formatTimestamp(finding.created_at)}</p>
                <div className="mt-1 flex flex-wrap gap-1">{finding.evidence_event_ids.map((eventId) => <Link key={eventId} to={`/evidence/${encodeURIComponent(eventId)}`} className="text-[10px] font-mono text-primary hover:underline">{eventId.slice(0, 8)}…</Link>)}</div>
              </article>
            ))}
          </div>
        </Card>

        <Card title="7. Conclusion and audit history" description="Conclusions are explicit analyst judgments; the audit history preserves material changes.">
          <form onSubmit={saveConclusion} className="grid gap-2">
            <label><span className={LABEL_CLASS}>Conclusion summary</span><textarea className={INPUT_CLASS} value={conclusionSummary} onChange={(e) => setConclusionSummary(e.target.value)} rows={3} maxLength={4000} required /></label>
            <div className="grid grid-cols-2 gap-2">
              <label><span className={LABEL_CLASS}>Disposition</span><select className={INPUT_CLASS} value={conclusionDisposition} onChange={(e) => setConclusionDisposition(e.target.value as HuntDisposition)}><option value="supports">Supports</option><option value="contradicts">Contradicts</option><option value="inconclusive">Inconclusive</option></select></label>
              <label><span className={LABEL_CLASS}>Confidence (0–1)</span><input className={INPUT_CLASS} type="number" min="0" max="1" step="0.01" value={conclusionConfidence} onChange={(e) => setConclusionConfidence(e.target.value)} required /></label>
            </div>
            <div><Button type="submit" disabled={saving || !conclusionSummary.trim() || hunt.status === 'archived'}>Save conclusion</Button></div>
          </form>
          {hunt.conclusion && <div className="mt-3 border-t border-border pt-3 text-xs"><div className="flex items-center justify-between gap-2"><strong>Current conclusion</strong><StatusBadge status={hunt.conclusion.disposition} /></div><p className="mt-1 whitespace-pre-wrap text-muted-foreground">{hunt.conclusion.summary}</p><p className="mt-1 text-[10px] text-muted-foreground">Confidence {hunt.conclusion.confidence.toFixed(2)} · {hunt.conclusion.author}</p></div>}
          <div className="mt-4 border-t border-border pt-3">
            <h3 className="mb-2 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Append-only audit history ({hunt.audit_history.length})</h3>
            <div className="max-h-52 space-y-2 overflow-auto">
              {hunt.audit_history.slice().reverse().map((entry) => (
                <div key={entry.entry_id} className="border-l-2 border-border pl-2">
                  <p className="text-[10px] font-medium text-foreground">{entry.action}</p>
                  <p className="text-[10px] text-muted-foreground">{entry.actor} · {formatTimestamp(entry.timestamp)}</p>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
