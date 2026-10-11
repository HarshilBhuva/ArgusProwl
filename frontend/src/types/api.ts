export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

export const Severity = {
  INFO: 'INFO',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
} as const;

export type Severity = (typeof Severity)[keyof typeof Severity];

export const Priority = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
} as const;

export type Priority = (typeof Priority)[keyof typeof Priority];

export const AlertLifecycleState = {
  OPEN: 'OPEN',
  ACKNOWLEDGED: 'ACKNOWLEDGED',
  CLOSED: 'CLOSED',
} as const;

export type AlertLifecycleState = (typeof AlertLifecycleState)[keyof typeof AlertLifecycleState];

export interface HealthComponent {
  name: string;
  status: string;
  message: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  uptime_seconds: number;
  checked_at: string;
  components: HealthComponent[];
}

export interface MetricItem {
  name: string;
  description: string;
  value: string | number | boolean | null;
}

export interface MetricsResponse {
  uptime_seconds: number;
  captured_at: string;
  metrics: MetricItem[];
}

export interface Alert {
  alert_id: string;
  title: string;
  description: string;
  severity: Severity;
  priority: Priority | null;
  lifecycle_state: AlertLifecycleState;
  source: string;
  created_at: string;
  tags: string[];
  metadata: Record<string, unknown>;
  schema_version: number;
  assessment_id: string | null;
  detector_confidence: number | null;
  contextual_confidence: number | null;
  contextual_explanation: string;
  supporting_evidence: Record<string, unknown>[];
  contradictory_evidence: Record<string, unknown>[];
  investigation_pivots: string[];
  entity_context: Record<string, unknown> | null;
  incident_id: string | null;
  attck_observations?: Record<string, unknown>[];
  detection_source_event_id?: string | null;
  contributing_event_ids?: string[];
  contributing_event_status?: Record<string, 'AVAILABLE' | 'EVICTED'>;
}

export interface AlertSearchResponse {
  alerts: Alert[];
  status: string;
  reason: string | null;
  total_count: number;
}

export interface LifecycleActionResponse {
  alert_id: string;
  previous_state: string;
  current_state: string;
}

export interface AlertSearchParams {
  limit?: number;
  min_priority?: Priority;
  min_severity?: Severity;
  rule_id?: string;
  host?: string;
  lifecycle_state?: AlertLifecycleState;
  entity_key?: string;
  incident_id?: string;
}

export interface EntityItem {
  entity_type: string;
  entity_id: string;
  has_correlation_support: boolean;
  maturity: string;
  observation_count: number;
  last_seen: string | null;
}

export interface EntityListResponse {
  entities: EntityItem[];
  total_count: number;
}

export interface EntityIncidentItem {
  incident_id: string;
  correlation_key: string;
  title: string;
  severity: string;
  status: string;
}

export interface EntityDetailResponse {
  entity_type: string;
  entity_id: string;
  observed_correlation_keys: string[];
  correlation_status: string;
  correlation_note: string;
  behavior: Record<string, unknown>[];
  alerts: Record<string, Alert[]>;
  annotations: AnnotationResponse[];
  incidents: EntityIncidentItem[];
  incident_status: string;
  incident_note: string;
}

export interface AnnotationResponse {
  annotation_id: string;
  target_key: string;
  author: string;
  created_at: string;
  comment: string;
  tombstoned: boolean;
}

export interface AnnotationCreateRequest {
  author: string;
  comment: string;
}

export interface TimelineItem {
  timeline_item_id: string;
  timestamp: string;
  item_type: 'ALERT' | 'INCIDENT' | 'ANNOTATION' | 'BEHAVIOR';
  title: string;
  summary: string;
  entity_type: string;
  entity_id: string;
  source_id: string | null;
  severity_or_priority: string | null;
  metadata: Record<string, string>;
}

export interface TimelineResponse {
  entity_type: string;
  entity_id: string;
  items: TimelineItem[];
  returned_count: number;
  truncated: boolean;
  correlation_status: string;
  correlation_note: string;
}

export interface ApiError {
  detail: string;
  status_code?: number;
}
export interface AttckMapping {
  technique_id: string;
  mapping_type: string;
  subtechnique_id: string | null;
  rationale: string;
}

export interface Rule {
  rule_id: string;
  name: string;
  description: string;
  enabled: boolean;
  detector_class: string;
  version: number;
  confidence: number;
}

export interface RuleDetail extends Rule {
  parameters: Record<string, any>;
  attck_mappings: AttckMapping[];
}

export interface RuleListResponse {
  rules: Rule[];
  total_count: number;
}

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: string;
  created_at: string;
  updated_at: string;
  alert_ids: string[];
  tags: string[];
  assigned_analyst: string | null;
  investigation_notes: string;
  metadata: Record<string, unknown>;
}

export interface IncidentListResponse {
  incidents: Incident[];
  total_count: number;
}

export interface IncidentAlertsResponse {
  incident_id: string;
  total_alerts: number;
  retrieved_count: number;
  missing_count: number;
  degraded: boolean;
  alerts: Alert[];
}

export interface IncidentTimelineResponse {
  incident_id: string;
  primary_entity: string;
  items: TimelineItem[];
  returned_count: number;
  truncated: boolean;
  correlation_status: string;
  correlation_note: string;
}

export interface EvidenceEvent {
  event_id: string;
  timestamp: string;
  source_type: string;
  event_type: string;
  hostname: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  process_name: string | null;
  username: string | null;
}

export interface EvidenceRecord {
  event_id: string;
  provenance: string;
  detection_result_id: string | null;
  contributing_event_ids: string[];
}

export interface EvidenceSearchResponse {
  records: EvidenceRecord[];
  events: Record<string, EvidenceEvent>;
  status: string;
  reason: string | null;
  truncated: boolean;
  total_count: number;
  returned_count: number;
}

export interface EvidenceDetailResponse {
  event_id: string;
  status: 'AVAILABLE' | 'EVICTED';
  reason: string | null;
  event: EvidenceEvent | null;
  record: EvidenceRecord | null;
}

export interface EvidenceStatsResponse {
  retained_events: number;
  max_retained_events: number;
  eviction_count: number;
  capacity_used_pct: number;
}

export interface AttckTechniqueSummary {
  technique_id: string;
  mapping_type: string;
  technique_name: string | null;
  tactic: string | null;
  version: string;
  source_alert_ids: string[];
  evidence_refs: Record<string, any>[];
  rationale: string | null;
}

export interface AttckOverviewResponse {
  knowledge_status: string;
  attck_version: string | null;
  total_techniques: number;
  total_tactics: number;
  mapping_count: number;
  mapped_technique_ids: string[];
}

export interface AttckInvestigationResponse {
  alert_count: number;
  techniques: AttckTechniqueSummary[];
}

export interface EvidenceSearchParams {
  limit?: number;
  event_id?: string;
  start_time?: string;
  end_time?: string;
  entity_type?: string;
  entity_id?: string;
  src_ip?: string;
  dst_ip?: string;
  domain?: string;
  event_type?: string;
  source_type?: string;
}

export interface AnnotationResponse {
  annotation_id: string;
  target_key: string;
  author: string;
  created_at: string;
  comment: string;
  tombstoned: boolean;
}

export interface IocObservation {
  alert_id: string;
  timestamp: string;
  field: string;
  value: string;
  host: string | null;
  rule_id: string | null;
  severity: string | null;
}

export interface RelatedIoc {
  indicator: string;
  ioc_type: string;
  field: string;
  co_observed_in_alert_id: string;
}

export interface IocTimelineItem {
  timeline_item_id: string;
  timestamp: string | null;
  item_type: string;
  title: string;
  summary: string;
  source_id: string | null;
  metadata: Record<string, string>;
}

export interface IocInvestigationResponse {
  indicator: string;
  ioc_type: string;
  reputation: Record<string, unknown>;
  observations: IocObservation[];
  first_observed: string | null;
  last_observed: string | null;
  associated_alert_ids: string[];
  associated_hosts: string[];
  associated_rule_ids: string[];
  related_iocs: RelatedIoc[];
  timeline: IocTimelineItem[];
  prevalence: Record<string, unknown> | null;
  status: string;
  reason: string | null;
  truncated: boolean;
  inspected_alert_count: number;
  observation_note: string;
}
