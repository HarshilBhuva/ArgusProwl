import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Badge, Card } from '../components/ui';
import { EmptyState, ErrorState, LoadingSkeleton } from '../components/StateIndicators';
import { useRuleDetail, useRules } from '../hooks/useQueries';
import { ApiClientError } from '../lib/api';
import type { Rule, AttckMapping } from '../types/api';

function RuleRow({ rule }: { rule: Rule }) {
  return (
    <tr className="hover:bg-muted/50">
      <td className="py-2.5 px-3 font-mono text-xs font-medium text-foreground">
        <Link
          to={`/rules/${encodeURIComponent(rule.rule_id)}`}
          className="text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary rounded px-1 -mx-1"
        >
          {rule.rule_id}
        </Link>
      </td>
      <td className="py-2.5 px-3 text-sm text-foreground">{rule.name}</td>
      <td className="py-2.5 px-3 text-sm text-muted-foreground max-w-sm truncate">
        {rule.description}
      </td>
      <td className="py-2.5 px-3">
        {rule.enabled ? (
          <Badge className="bg-primary/10 text-primary border-primary/20">Enabled</Badge>
        ) : (
          <Badge className="bg-muted text-muted-foreground border-border">Disabled</Badge>
        )}
      </td>
      <td className="py-2.5 px-3 text-xs text-muted-foreground font-mono">{rule.detector_class}</td>
      <td className="py-2.5 px-3 text-xs text-muted-foreground font-mono">{rule.version}</td>
      <td className="py-2.5 px-3 text-xs text-muted-foreground font-mono">{rule.confidence.toFixed(2)}</td>
      <td className="py-2.5 px-3">
        <Link
          to={`/rules/${encodeURIComponent(rule.rule_id)}`}
          className="text-xs font-medium text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Detail
        </Link>
      </td>
    </tr>
  );
}

function RulesList({
  data,
  isLoading,
  error,
  enabledFilter,
  detectorClassFilter,
  onFilterChange,
}: {
  data: { rules: Rule[]; total_count: number } | null | undefined;
  isLoading: boolean;
  error: unknown;
  enabledFilter: boolean | 'ALL';
  detectorClassFilter: string;
  onFilterChange: (enabled: boolean | 'ALL', detectorClass: string) => void;
}) {
  if (isLoading) {
    return <LoadingSkeleton lines={6} />;
  }

  if (error) {
    const message =
      error instanceof ApiClientError ? error.userMessage : 'Unable to load rules from the backend.';
    return <ErrorState message={message} onRetry={() => {}} />;
  }

  if (!data || data.rules.length === 0) {
    const hasFilters = enabledFilter !== 'ALL' || detectorClassFilter.length > 0;
    return (
      <EmptyState message={hasFilters ? 'No rules match the applied filters.' : 'No detection rules are currently loaded.'} />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Enabled:</span>
          <div className="inline-flex rounded-md shadow-sm" role="group">
            <button
              type="button"
              className={`rounded-l-md border px-2 py-1 text-xs font-medium transition-colors ${
                enabledFilter === 'ALL'
                  ? 'bg-primary text-primary-foreground border-primary'
                  : 'bg-background text-muted-foreground border-border hover:bg-muted'
              }`}
              onClick={() => onFilterChange('ALL', detectorClassFilter)}
            >
              All
            </button>
            <button
              type="button"
              className={`border-t border-b border-r px-2 py-1 text-xs font-medium transition-colors ${
                enabledFilter === true
                  ? 'bg-primary text-primary-foreground border-primary'
                  : 'bg-background text-muted-foreground border-border hover:bg-muted'
              }`}
              onClick={() => onFilterChange(true, detectorClassFilter)}
            >
              Enabled
            </button>
            <button
              type="button"
              className={`rounded-r-md border-t border-b border-r px-2 py-1 text-xs font-medium transition-colors ${
                enabledFilter === false
                  ? 'bg-primary text-primary-foreground border-primary'
                  : 'bg-background text-muted-foreground border-border hover:bg-muted'
              }`}
              onClick={() => onFilterChange(false, detectorClassFilter)}
            >
              Disabled
            </button>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Detector:</span>
          <input
            type="text"
            value={detectorClassFilter}
            onChange={(event) => onFilterChange(enabledFilter, event.target.value)}
            placeholder="e.g. PortScanDetector"
            className="w-48 rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          />
        </div>
        <span className="text-xs text-muted-foreground">
          {data.total_count} rule{data.total_count === 1 ? '' : 's'}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-border text-xs font-semibold text-muted-foreground uppercase">
            <tr>
              <th className="py-2.5 px-3">Rule ID</th>
              <th className="py-2.5 px-3">Name</th>
              <th className="py-2.5 px-3">Description</th>
              <th className="py-2.5 px-3">State</th>
              <th className="py-2.5 px-3">Detector Class</th>
              <th className="py-2.5 px-3 text-right">Version</th>
              <th className="py-2.5 px-3 text-right">Confidence</th>
              <th className="py-2.5 px-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {data.rules.map((rule) => (
              <RuleRow key={rule.rule_id} rule={rule} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuleDetail({
  rule,
  isLoading,
  error,
  onBack,
}: {
  rule: Rule | null;
  isLoading: boolean;
  error: unknown;
  onBack: () => void;
}) {
  if (isLoading) {
    return <LoadingSkeleton lines={8} />;
  }

  if (error) {
    const message =
      error instanceof ApiClientError ? error.userMessage : 'Unable to load rule details.';
    return <ErrorState message={message} onRetry={() => {}} />;
  }

  if (!rule) {
    return <EmptyState message="Rule not found." />;
  }

  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Rule ID</span>
        <code className="text-xs font-mono text-foreground">{rule.rule_id}</code>
        {rule.enabled ? (
          <Badge className="bg-primary/10 text-primary border-primary/20">Enabled</Badge>
        ) : (
          <Badge className="bg-muted text-muted-foreground border-border">Disabled</Badge>
        )}
      </div>
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase">Name</h3>
        <p className="mt-1 text-foreground">{rule.name}</p>
      </div>
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase">Description</h3>
        <p className="mt-1 text-foreground">{rule.description}</p>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Detector Class</h3>
          <code className="mt-1 block text-xs font-mono text-foreground">{rule.detector_class}</code>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase">Version</h3>
            <p className="mt-1 font-mono text-foreground">{rule.version}</p>
          </div>
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase">Confidence</h3>
            <p className="mt-1 font-mono text-foreground">{rule.confidence.toFixed(2)}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function AttckSection({ mappings }: { mappings: AttckMapping[] }) {
  if (mappings.length === 0) {
    return (
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase">ATT&CK Mappings</h3>
        <p className="mt-1 text-xs text-muted-foreground italic">No ATT&CK mappings registered for this rule.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold text-muted-foreground uppercase">ATT&CK Mappings</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-border text-muted-foreground">
            <tr>
              <th className="py-1.5 px-2 font-semibold">Technique</th>
              <th className="py-1.5 px-2 font-semibold">Subtechnique</th>
              <th className="py-1.5 px-2 font-semibold">Type</th>
              <th className="py-1.5 px-2 font-semibold">Rationale</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {mappings.map((mapping, idx) => (
              <tr key={idx}>
                <td className="py-1.5 px-2 font-mono text-foreground">{mapping.technique_id}</td>
                <td className="py-1.5 px-2 font-mono text-muted-foreground">
                  {mapping.subtechnique_id ?? '—'}
                </td>
                <td className="py-1.5 px-2">
                  <Badge className="bg-secondary text-secondary-foreground border-border">
                    {mapping.mapping_type}
                  </Badge>
                </td>
                <td className="py-1.5 px-2 text-muted-foreground">{mapping.rationale}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ParametersSection({ parameters }: { parameters: Record<string, unknown> }) {
  const entries = Object.entries(parameters);
  if (entries.length === 0) {
    return (
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase">Parameters</h3>
        <p className="mt-1 text-xs text-muted-foreground italic">No configuration parameters registered.</p>
      </div>
    );
  }

  return (
    <div>
      <h3 className="text-xs font-semibold text-muted-foreground uppercase">Parameters</h3>
      <pre className="mt-1 text-xs font-mono bg-muted p-3 rounded overflow-x-auto text-foreground">
        {JSON.stringify(parameters, null, 2)}
      </pre>
    </div>
  );
}

export function RulesPage() {
  const [enabledFilter, setEnabledFilter] = useState<boolean | 'ALL'>('ALL');
  const [detectorClassFilter, setDetectorClassFilter] = useState('');

  const rulesQuery = useRules({
    enabled: enabledFilter === 'ALL' ? undefined : enabledFilter,
    detector_class: detectorClassFilter || undefined,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-foreground uppercase tracking-tight">Detection Rules</h1>
          <p className="mt-0.5 text-[11px] font-mono text-muted-foreground">{rulesQuery.data?.total_count ?? 0} rules loaded</p>
        </div>
      </div>
      <Card title="Rule Catalog" description="Read-only projection from the runtime registry">
        <RulesList
          data={rulesQuery.data}
          isLoading={rulesQuery.isLoading}
          error={rulesQuery.error}
          enabledFilter={enabledFilter}
          detectorClassFilter={detectorClassFilter}
          onFilterChange={(enabled, detectorClass) => {
            setEnabledFilter(enabled);
            setDetectorClassFilter(detectorClass);
          }}
        />
      </Card>
    </div>
  );
}

export function RuleDetailPage() {
  const { ruleId } = useParams<{ ruleId: string }>();
  const cleanRuleId = (ruleId ?? '').trim();

  const ruleQuery = useRuleDetail(cleanRuleId || null);

  if (!cleanRuleId) {
    return <EmptyState message="Rule identifier is missing." />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-foreground uppercase tracking-tight">Rule Detail</h1>
          <p className="mt-0.5 text-[11px] font-mono text-muted-foreground">{cleanRuleId}</p>
        </div>
        <Link
          to="/rules"
          className="text-xs font-medium font-mono text-muted-foreground hover:text-foreground transition-colors"
        >
          ← Back to catalog
        </Link>
      </div>

      <Card title="Rule Metadata" description="Detector registry fields">
        <RuleDetail
          rule={ruleQuery.data ?? null}
          isLoading={ruleQuery.isLoading}
          error={ruleQuery.error}
          onBack={() => {}}
        />
      </Card>

      <Card title="Configuration" description="Parameters and ATT&CK mappings">
        <div className="space-y-6">
          <ParametersSection
            parameters={ruleQuery.data?.parameters ?? {}}
          />
          <AttckSection mappings={ruleQuery.data?.attck_mappings ?? []} />
        </div>
      </Card>
    </div>
  );
}
