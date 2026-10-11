"""API response models.

Defines explicit Pydantic response schemas for the HTTP API layer.
These models control what fields are exposed to clients and prevent
leaking internal service state.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class HealthComponent(BaseModel):
    """Health status for a single subsystem component."""

    name: str = Field(..., description="Component identifier (e.g. 'config', 'logging').")
    status: str = Field(..., description="Health state: 'healthy', 'degraded', or 'unhealthy'.")
    message: str = Field(default="", description="Optional human-readable detail.")


class HealthResponse(BaseModel):
    """Aggregated health status of the entire platform."""

    status: str = Field(..., description="Roll-up health state.")
    version: str = Field(..., description="Application version string.")
    uptime_seconds: float = Field(..., description="Seconds since application start.")
    checked_at: datetime = Field(..., description="UTC timestamp of this health check.")
    components: list[HealthComponent] = Field(
        default_factory=list, description="Per-component health details."
    )


class MetricItem(BaseModel):
    """A single metric value from the metrics snapshot."""

    name: str = Field(..., description="Metric name.")
    description: str = Field(default="", description="Metric description.")
    value: Any = Field(..., description="Current metric value.")


class MetricsResponse(BaseModel):
    """Metrics snapshot from the MetricsCollector."""

    uptime_seconds: float = Field(..., description="Seconds since application start.")
    captured_at: datetime = Field(..., description="UTC timestamp of this snapshot.")
    metrics: list[MetricItem] = Field(default_factory=list, description="List of metric values.")


class AlertResponse(BaseModel):
    """Serialized alert for API response."""

    alert_id: str = Field(..., description="Unique identifier for this alert.")
    title: str = Field(..., description="Short human-readable summary.")
    description: str = Field(..., description="Detailed explanation of the alert.")
    severity: str = Field(..., description="Assessed severity level.")
    priority: str | None = Field(
        default=None, description="Operational priority derived from severity."
    )
    lifecycle_state: str = Field(..., description="Current lifecycle state.")
    source: str = Field(..., description="Identifier of the component that generated this alert.")
    created_at: str = Field(..., description="UTC timestamp of alert creation (ISO 8601).")
    tags: list[str] = Field(default_factory=list, description="Classification tags.")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional key-value context."
    )
    schema_version: int = Field(..., description="Alert schema version.")
    assessment_id: str | None = Field(default=None, description="UUID of the ContextualAssessment.")
    detector_confidence: float | None = Field(
        default=None, description="Original detector confidence."
    )
    contextual_confidence: float | None = Field(
        default=None, description="Final confidence from contextual assessment."
    )
    contextual_explanation: str = Field(
        default="", description="Analyst-facing explanation of contextual adjustments."
    )
    supporting_evidence: list[dict[str, Any]] = Field(
        default_factory=list, description="Structured evidence that increased suspicion."
    )
    contradictory_evidence: list[dict[str, Any]] = Field(
        default_factory=list, description="Structured evidence that decreased suspicion."
    )
    investigation_pivots: list[str] = Field(
        default_factory=list, description="Recommended next investigation steps."
    )
    entity_context: dict[str, Any] | None = Field(
        default=None, description="Serialized entity attribution."
    )
    incident_id: str | None = Field(default=None, description="Associated incident ID.")
    detection_source_event_id: str | None = Field(
        default=None, description="Event ID that directly triggered the detection."
    )
    contributing_event_ids: list[str] = Field(
        default_factory=list, description="Event IDs that contributed to the detection."
    )
    contributing_event_status: dict[str, str] = Field(
        default_factory=dict, description="Per-event status: 'AVAILABLE' or 'EVICTED'."
    )


class AlertSearchResponse(BaseModel):
    """Response for alert search endpoint."""

    alerts: list[AlertResponse] = Field(
        default_factory=list, description="List of matching alerts."
    )
    status: str = Field(..., description="Search status: 'AVAILABLE' or 'DEGRADED'.")
    reason: str | None = Field(
        default=None, description="Optional explanation for DEGRADED status."
    )
    total_count: int = Field(..., description="Total number of alerts returned.")


class ErrorResponse(BaseModel):
    """Standardized error response."""

    detail: str = Field(..., description="Human-readable error description.")
    status_code: int = Field(..., description="HTTP status code.")


class ValidationErrorResponse(BaseModel):
    """Response for validation errors (422)."""

    detail: list[dict[str, Any]] = Field(..., description="List of validation errors.")
    status_code: int = Field(..., description="HTTP status code.")


class LifecycleActionResponse(BaseModel):
    """Response for lifecycle action endpoints."""

    alert_id: str = Field(..., description="The alert ID that was updated.")
    previous_state: str = Field(..., description="The lifecycle state before the action.")
    current_state: str = Field(..., description="The lifecycle state after the action.")


class EntityItemResponse(BaseModel):
    """Single entity summary item in list response."""

    entity_type: str = Field(..., description="Type of entity (e.g., 'hostname', 'src_ip').")
    entity_id: str = Field(..., description="Unique entity identifier.")
    has_correlation_support: bool = Field(
        ..., description="Whether alert correlation is supported for this entity type."
    )
    maturity: str = Field(..., description="Behavioral baseline maturity state.")
    observation_count: int = Field(..., description="Total observation count.")
    last_seen: str | None = Field(
        default=None, description="ISO 8601 timestamp of last observation."
    )


class EntityListResponse(BaseModel):
    """Response for entity listing endpoint."""

    entities: list[EntityItemResponse] = Field(
        default_factory=list, description="List of entity summaries."
    )
    total_count: int = Field(..., description="Total count of entities returned.")


class EntityDetailResponse(BaseModel):
    """Response for entity detail endpoint preserving identity vs correlation key separation."""

    entity_type: str = Field(..., description="Type of entity.")
    entity_id: str = Field(..., description="Unique entity identifier.")
    observed_correlation_keys: list[str] = Field(
        default_factory=list, description="Canonical correlation keys observed in alert data."
    )
    correlation_status: str = Field(
        ..., description="Correlation status ('PARTIAL' or 'UNSUPPORTED')."
    )
    correlation_note: str = Field(
        ..., description="Analyst note describing correlation limitations."
    )
    behavior: list[dict[str, Any]] = Field(
        default_factory=list, description="Bounded behavioral profiles."
    )
    alerts: dict[str, list[AlertResponse]] = Field(
        default_factory=dict, description="Alerts grouped by observed canonical correlation key."
    )
    annotations: list[dict[str, Any]] = Field(
        default_factory=list, description="Analyst annotations for entity target."
    )
    incidents: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Associated incidents resolved from observed correlation keys.",
    )
    incident_status: str = Field(..., description="Incident status ('PARTIAL' or 'UNSUPPORTED').")
    incident_note: str = Field(..., description="Analyst note describing incident limitations.")


class TimelineItemResponse(BaseModel):
    """A single item in the investigation timeline."""

    timeline_item_id: str = Field(..., description="Stable identifier for this timeline item.")
    timestamp: str = Field(..., description="UTC timestamp (ISO 8601).")
    item_type: str = Field(
        ..., description="Source type: ALERT, INCIDENT, ANNOTATION, or BEHAVIOR."
    )
    title: str = Field(..., description="Short human-readable summary.")
    summary: str = Field(..., description="Brief description or commentary.")
    entity_type: str = Field(..., description="The investigated entity type.")
    entity_id: str = Field(..., description="The investigated entity identifier.")
    source_id: str | None = Field(default=None, description="Originating source ID.")
    severity_or_priority: str | None = Field(
        default=None, description="Severity for alerts/incidents."
    )
    metadata: dict[str, str] = Field(default_factory=dict, description="Bounded key-value context.")


class TimelineResponse(BaseModel):
    """Response for the entity timeline endpoint."""

    entity_type: str = Field(..., description="The investigated entity type.")
    entity_id: str = Field(..., description="The investigated entity identifier.")
    items: list[TimelineItemResponse] = Field(
        default_factory=list, description="Timeline items, newest-first."
    )
    returned_count: int = Field(..., description="Number of items returned.")
    truncated: bool = Field(..., description="Whether the timeline was truncated due to limits.")
    correlation_status: str = Field(..., description="Correlation status: PARTIAL or UNSUPPORTED.")
    correlation_note: str = Field(
        ..., description="Analyst note describing correlation limitations."
    )


class AnnotationCreateRequest(BaseModel):
    """Request model for creating an entity annotation."""

    author: str = Field(..., max_length=128, description="Analyst identifier.")
    comment: str = Field(..., max_length=512, description="Annotation commentary.")


class AnnotationResponse(BaseModel):
    """Serialized annotation response."""

    annotation_id: str = Field(..., description="Unique annotation ID.")
    target_key: str = Field(..., description="Target key (entity:type:id).")
    author: str = Field(..., description="Author identifier.")
    created_at: str = Field(..., description="ISO 8601 creation timestamp.")
    comment: str = Field(..., description="Annotation commentary.")
    tombstoned: bool = Field(default=False, description="Tombstone status.")


class RuleItemResponse(BaseModel):
    """A single detection rule summary."""

    rule_id: str = Field(..., description="Unique rule identifier.")
    name: str = Field(..., description="Rule human-readable name.")
    description: str = Field(..., description="Rule description.")
    enabled: bool = Field(..., description="Whether the rule is currently enabled.")
    detector_class: str = Field(..., description="Underlying detector implementation class.")
    version: int = Field(..., description="Rule logic version.")
    confidence: float = Field(..., description="Base confidence assigned to alerts from this rule.")


class RuleListResponse(BaseModel):
    """Response for rule list projection."""

    rules: list[RuleItemResponse] = Field(default_factory=list, description="List of loaded rules.")
    total_count: int = Field(..., description="Total count of rules matched.")


class AttckMappingResponse(BaseModel):
    """Serialized ATT&CK mapping for a rule."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID.")
    mapping_type: str = Field(..., description="Type of mapping (e.g. DIRECT, SUPPORTED).")
    subtechnique_id: str | None = Field(default=None, description="Optional subtechnique ID.")
    rationale: str | None = Field(default=None, description="Why this mapping applies.")


class RuleDetailResponse(BaseModel):
    """Detailed response for a single rule's configuration."""

    rule_id: str = Field(..., description="Unique rule identifier.")
    name: str = Field(..., description="Rule human-readable name.")
    description: str = Field(..., description="Rule description.")
    enabled: bool = Field(..., description="Whether the rule is currently enabled.")
    detector_class: str = Field(..., description="Underlying detector implementation class.")
    version: int = Field(..., description="Rule logic version.")
    confidence: float = Field(..., description="Base confidence assigned to alerts from this rule.")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="JSON-safe bounded configuration parameters."
    )
    attck_mappings: list[AttckMappingResponse] = Field(
        default_factory=list, description="Associated ATT&CK mappings if available."
    )


class IocObservationResponse(BaseModel):
    """Single IOC observation from retained alert evidence."""

    alert_id: str = Field(..., description="Associated alert ID.")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp from the alert.")
    field: str = Field(..., description="Entity context field matched (src_ip/dst_ip/domain).")
    value: str = Field(..., description="Normalized indicator value.")
    host: str | None = Field(default=None, description="Source host if present.")
    rule_id: str | None = Field(default=None, description="Rule ID from alert metadata.")
    severity: str | None = Field(default=None, description="Alert severity.")


class RelatedIocResponse(BaseModel):
    """Another IOC co-observed in the same alert as the queried indicator."""

    indicator: str = Field(..., description="Normalized indicator value.")
    ioc_type: str = Field(..., description="Indicator type: 'ip' or 'domain'.")
    field: str = Field(..., description="Entity context field where the related IOC was found.")
    co_observed_in_alert_id: str = Field(..., description="Alert ID where co-observation occurred.")


class IocTimelineItemResponse(BaseModel):
    """A single item in the IOC investigation timeline."""

    timeline_item_id: str = Field(..., description="Stable identifier for this timeline item.")
    timestamp: str | None = Field(
        default=None, description="ISO 8601 UTC timestamp. Omitted for static context items."
    )
    item_type: str = Field(
        ..., description="Source type: OBSERVATION, ALERT, INTELLIGENCE, or RELATED_IOC."
    )
    title: str = Field(..., description="Short human-readable summary.")
    summary: str = Field(..., description="Brief description.")
    source_id: str | None = Field(default=None, description="Originating source ID.")
    metadata: dict[str, str] = Field(default_factory=dict, description="Bounded key-value context.")


class IncidentResponse(BaseModel):
    """Serialized incident for API response."""

    incident_id: str = Field(..., description="Unique incident identifier.")
    title: str = Field(..., description="Incident title.")
    description: str = Field(..., description="Incident description.")
    severity: str = Field(..., description="Incident severity.")
    status: str = Field(..., description="Incident lifecycle status.")
    created_at: str = Field(..., description="UTC timestamp of creation (ISO 8601).")
    updated_at: str = Field(..., description="UTC timestamp of last update (ISO 8601).")
    alert_ids: list[str] = Field(default_factory=list, description="Associated alert IDs.")
    tags: list[str] = Field(default_factory=list, description="Incident tags.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata.")


class IncidentListResponse(BaseModel):
    """Response for incident listing endpoint."""

    incidents: list[IncidentResponse] = Field(
        default_factory=list, description="List of incidents."
    )
    total_count: int = Field(..., description="Total count of incidents.")


class IocInvestigationResponse(BaseModel):
    """Response for IOC investigation endpoint."""

    indicator: str = Field(..., description="Normalized IOC indicator.")
    ioc_type: str = Field(..., description="Indicator type: 'ip' or 'domain'.")
    reputation: dict[str, Any] = Field(..., description="Threat intelligence reputation.")
    observations: list[IocObservationResponse] = Field(
        default_factory=list, description="Observations from retained alert evidence."
    )
    first_observed: str | None = Field(default=None, description="Earliest observation timestamp.")
    last_observed: str | None = Field(default=None, description="Latest observation timestamp.")
    associated_alert_ids: list[str] = Field(
        default_factory=list, description="Associated alert IDs."
    )
    associated_hosts: list[str] = Field(default_factory=list, description="Associated hostnames.")
    associated_rule_ids: list[str] = Field(default_factory=list, description="Associated rule IDs.")
    related_iocs: list[RelatedIocResponse] = Field(
        default_factory=list, description="Co-observed related IOCs."
    )
    timeline: list[IocTimelineItemResponse] = Field(
        default_factory=list, description="Investigation timeline."
    )
    prevalence: dict[str, Any] | None = Field(
        default=None, description="Environmental prevalence if destination-attributable."
    )
    status: str = Field(..., description="Investigation status: AVAILABLE, DEGRADED, or EMPTY.")
    reason: str | None = Field(
        default=None, description="Optional explanation for DEGRADED status."
    )
    truncated: bool = Field(..., description="Whether results were truncated by bounds.")
    inspected_alert_count: int = Field(..., description="Number of alerts inspected.")
    observation_note: str = Field(..., description="Provenance note for observations.")


class EvidenceRecordResponse(BaseModel):
    """Single evidence record from the telemetry evidence store."""

    event_id: str = Field(..., description="Unique event identifier.")
    provenance: str = Field(
        ...,
        description="Provenance label: DETECTION_SOURCE, CONTRIBUTING_EVENT, or OBSERVED_CONTEXT.",
    )
    detection_result_id: str | None = Field(
        default=None, description="UUID of the triggering DetectionResult."
    )
    contributing_event_ids: list[str] = Field(
        default_factory=list, description="UUIDs of contributing events."
    )


class EvidenceEventResponse(BaseModel):
    """Normalized event attached to an evidence record."""

    event_id: str = Field(..., description="Unique event identifier.")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp.")
    source_type: str = Field(..., description="Telemetry source type (e.g. zeek, sysmon).")
    event_type: str = Field(..., description="Normalized event type.")
    hostname: str | None = Field(default=None, description="Source hostname.")
    src_ip: str | None = Field(default=None, description="Source IP address.")
    dst_ip: str | None = Field(default=None, description="Destination IP address.")
    process_name: str | None = Field(default=None, description="Process name if applicable.")
    username: str | None = Field(default=None, description="Username if applicable.")


class EvidenceSearchResponse(BaseModel):
    """Response for telemetry evidence search endpoint."""

    records: list[EvidenceRecordResponse] = Field(
        default_factory=list, description="Evidence records matching the query."
    )
    events: dict[str, EvidenceEventResponse] = Field(
        default_factory=dict, description="Event details keyed by event_id."
    )
    status: str = Field(..., description="Search status: 'AVAILABLE' or 'DEGRADED'.")
    reason: str | None = Field(
        default=None, description="Optional explanation for DEGRADED status."
    )
    truncated: bool = Field(..., description="Whether results were truncated by the limit.")
    total_count: int = Field(..., description="Total matching events in the store.")
    returned_count: int = Field(..., description="Number of records returned in this response.")


class EvidenceDetailResponse(BaseModel):
    """Single evidence lookup, including an explicit evicted state."""

    event_id: str = Field(..., description="Requested event identifier.")
    status: str = Field(..., description="Evidence availability: AVAILABLE or EVICTED.")
    reason: str | None = Field(
        default=None, description="Explanation when retained telemetry is unavailable."
    )
    event: EvidenceEventResponse | None = Field(
        default=None, description="Retained telemetry event; absent when evicted."
    )
    record: EvidenceRecordResponse | None = Field(
        default=None, description="Known provenance record, if available."
    )


class EvidenceStatsResponse(BaseModel):
    """Store statistics for health reporting."""

    retained_events: int = Field(..., description="Number of events currently retained.")
    max_retained_events: int = Field(..., description="Maximum capacity of the store.")
    eviction_count: int = Field(..., description="Total events evicted since startup.")
    capacity_used_pct: float = Field(
        ..., description="Percentage of store capacity currently used."
    )


# ---------------------------------------------------------------------------
# ATT&CK Investigation (Phase 6.5)
# ---------------------------------------------------------------------------


class AttckTechniqueSummaryResponse(BaseModel):
    """Aggregated ATT&CK technique summary for an investigation context."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID.")
    mapping_type: str = Field(..., description="Mapping type: DIRECT, SUPPORTED, CONTEXTUAL.")
    technique_name: str | None = Field(default=None, description="Human-readable technique name.")
    tactic: str | None = Field(default=None, description="ATT&CK tactic/category.")
    version: str = Field(
        ..., description="ATT&CK knowledge version this observation was recorded against."
    )
    source_alert_ids: list[str] = Field(
        default_factory=list, description="Alert IDs that triggered this technique."
    )
    evidence_refs: list[dict[str, Any]] = Field(
        default_factory=list, description="Evidence references from observations."
    )
    rationale: str | None = Field(default=None, description="Why this mapping applies.")


class AttckOverviewResponse(BaseModel):
    """Global ATT&CK knowledge status and technique counts."""

    knowledge_status: str = Field(
        ..., description="Knowledge status: AVAILABLE, DEGRADED, EMPTY, UNAVAILABLE."
    )
    attck_version: str | None = Field(default=None, description="ATT&CK knowledge version.")
    total_techniques: int = Field(..., description="Number of techniques in the knowledge service.")
    total_tactics: int = Field(..., description="Number of tactics in the knowledge service.")
    mapping_count: int = Field(..., description="Total authorized mapping entries.")
    mapped_technique_ids: list[str] = Field(
        default_factory=list, description="Distinct technique IDs covered by mappings."
    )


class AttckInvestigationResponse(BaseModel):
    """ATT&CK investigation result for a set of alert IDs."""

    alert_count: int = Field(..., description="Number of alerts processed.")
    techniques: list[AttckTechniqueSummaryResponse] = Field(
        default_factory=list, description="Aggregated ATT&CK technique summaries."
    )
