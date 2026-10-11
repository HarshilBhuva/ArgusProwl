import type {
  Alert,
  AlertSearchParams,
  AlertSearchResponse,
  AnnotationCreateRequest,
  AnnotationResponse,
  ApiError,
  AttckInvestigationResponse,
  AttckOverviewResponse,
  EvidenceSearchParams,
  EvidenceSearchResponse,
  EvidenceDetailResponse,
  EvidenceStatsResponse,
  EntityDetailResponse,
  EntityListResponse,
  HealthResponse,
  Incident,
  IncidentAlertsResponse,
  IncidentListResponse,
  IncidentTimelineResponse,
  IocInvestigationResponse,
  LifecycleActionResponse,
  MetricsResponse,
  RuleDetail,
  RuleListResponse,
  TimelineResponse,
} from '../types/api';

export class ApiClientError extends Error {
  readonly statusCode: number;
  readonly userMessage: string;

  constructor(statusCode: number, userMessage: string) {
    super(userMessage);
    this.name = 'ApiClientError';
    this.statusCode = statusCode;
    this.userMessage = userMessage;
  }
}

function getApiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL;
  if (typeof configured === 'string' && configured.length > 0) {
    return configured.replace(/\/$/, '');
  }
  return '';
}

function toUserMessage(statusCode: number, fallback: string): string {
  if (statusCode === 0) {
    return 'Unable to reach the ArgusProwl API. Confirm the backend is running.';
  }
  if (statusCode === 404) {
    return 'The requested API resource was not found.';
  }
  if (statusCode === 422) {
    return 'The API rejected the request because a parameter was invalid.';
  }
  if (statusCode === 503) {
    return 'The ArgusProwl API is currently unavailable.';
  }
  if (statusCode >= 500) {
    return 'The ArgusProwl API encountered an internal error.';
  }
  return fallback;
}

function extractDetail(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const detail = (payload as ApiError).detail;
  if (typeof detail === 'string' && detail.trim().length > 0) {
    return detail;
  }
  return null;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${getApiBaseUrl()}${path}`;

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      let payload: unknown = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      throw new ApiClientError(
        response.status,
        toUserMessage(response.status, extractDetail(payload) ?? 'The API request failed.'),
      );
    }

    try {
      return (await response.json()) as T;
    } catch {
      throw new ApiClientError(response.status, 'The API returned a malformed response.');
    }
  } catch (error) {
    if (error instanceof ApiClientError) {
      throw error;
    }
    throw new ApiClientError(
      0,
      'Unable to reach the ArgusProwl API. Confirm the backend is running.',
    );
  }
}

function buildAlertQuery(params: AlertSearchParams = {}): string {
  const searchParams = new URLSearchParams();

  if (params.limit !== undefined) {
    searchParams.set('limit', String(params.limit));
  }
  if (params.min_priority) {
    searchParams.set('min_priority', params.min_priority);
  }
  if (params.min_severity) {
    searchParams.set('min_severity', params.min_severity);
  }
  if (params.rule_id) {
    searchParams.set('rule_id', params.rule_id);
  }
  if (params.host) {
    searchParams.set('host', params.host);
  }
  if (params.lifecycle_state) {
    searchParams.set('lifecycle_state', params.lifecycle_state);
  }
  if (params.entity_key) {
    searchParams.set('entity_key', params.entity_key);
  }
  if (params.incident_id) {
    searchParams.set('incident_id', params.incident_id);
  }

  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

export const api = {
  health: () => request<HealthResponse>('/api/v1/health'),
  operationalHealth: () => request<HealthResponse>('/health'),
  metrics: () => request<MetricsResponse>('/api/v1/metrics'),
  alerts: (params: AlertSearchParams = {}) =>
    request<AlertSearchResponse>(`/api/v1/alerts${buildAlertQuery(params)}`),
  alertDetail: (alertId: string) =>
    request<Alert>(`/api/v1/alerts/${alertId}`),
  acknowledgeAlert: (alertId: string) =>
    request<LifecycleActionResponse>(`/api/v1/alerts/${alertId}/acknowledge`, {
      method: 'POST',
    }),
  closeAlert: (alertId: string) =>
    request<LifecycleActionResponse>(`/api/v1/alerts/${alertId}/close`, {
      method: 'POST',
    }),
  entities: () => request<EntityListResponse>('/api/v1/entities'),
  entityDetail: (entityType: string, entityId: string) =>
    request<EntityDetailResponse>(`/api/v1/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`),
  entityAnnotations: (entityType: string, entityId: string) =>
    request<AnnotationResponse[]>(`/api/v1/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}/annotations`),
  createEntityAnnotation: (entityType: string, entityId: string, data: AnnotationCreateRequest) =>
    request<AnnotationResponse>(`/api/v1/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}/annotations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    }),
  entityTimeline: (entityType: string, entityId: string, limit: number = 50) =>
    request<TimelineResponse>(`/api/v1/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}/timeline?limit=${limit}`),

  rules: (params?: { enabled?: boolean; detector_class?: string }) => {
    const qs = new URLSearchParams();
    if (params?.enabled !== undefined) qs.set('enabled', String(params.enabled));
    if (params?.detector_class) qs.set('detector_class', params.detector_class);
    const query = qs.toString();
    return request<RuleListResponse>(`/api/v1/rules${query ? `?${query}` : ''}`);
  },

  ruleDetail: (ruleId: string) =>
    request<RuleDetail>(`/api/v1/rules/${encodeURIComponent(ruleId)}`),
  iocLookup: (indicator: string) =>
    request<IocInvestigationResponse>(`/api/v1/iocs/${encodeURIComponent(indicator)}`),

  incidents: () => request<IncidentListResponse>('/api/v1/incidents'),
  incidentDetail: (incidentId: string) =>
    request<Incident>(`/api/v1/incidents/${encodeURIComponent(incidentId)}`),
  incidentAlerts: (incidentId: string) =>
    request<IncidentAlertsResponse>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/alerts`),
  incidentTimeline: (incidentId: string, limit: number = 50) =>
    request<IncidentTimelineResponse>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/timeline?limit=${limit}`),
  incidentAnnotations: (incidentId: string) =>
    request<AnnotationResponse[]>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/annotations`),
  createIncidentAnnotation: (incidentId: string, data: AnnotationCreateRequest) =>
    request<AnnotationResponse>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/annotations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    }),
  closeIncident: (incidentId: string) =>
    request<LifecycleActionResponse>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/close`, {
      method: 'POST',
    }),
  transitionIncident: (incidentId: string, status: string) =>
    request<LifecycleActionResponse>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/transition?status=${encodeURIComponent(status)}`, {
      method: 'POST',
    }),
  evidence: (params: EvidenceSearchParams = {}) => {
    const qs = new URLSearchParams();
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.event_id) qs.set('event_id', params.event_id);
    if (params.start_time) qs.set('start_time', params.start_time);
    if (params.end_time) qs.set('end_time', params.end_time);
    if (params.entity_type) qs.set('entity_type', params.entity_type);
    if (params.entity_id) qs.set('entity_id', params.entity_id);
    if (params.src_ip) qs.set('src_ip', params.src_ip);
    if (params.dst_ip) qs.set('dst_ip', params.dst_ip);
    if (params.domain) qs.set('domain', params.domain);
    if (params.event_type) qs.set('event_type', params.event_type);
    if (params.source_type) qs.set('source_type', params.source_type);
    const query = qs.toString();
    return request<EvidenceSearchResponse>(`/api/v1/evidence${query ? `?${query}` : ''}`);
  },
  evidenceDetail: (eventId: string) =>
    request<EvidenceDetailResponse>(`/api/v1/evidence/${encodeURIComponent(eventId)}`),
  evidenceStats: () => request<EvidenceStatsResponse>('/api/v1/evidence/stats'),
  attckOverview: () => request<AttckOverviewResponse>('/api/v1/attck/overview'),
  attckInvestigation: (alertIds: string[]) => {
    const query = alertIds.map(encodeURIComponent).join(',');
    return request<AttckInvestigationResponse>(`/api/v1/attck/investigation?alert_ids=${query}`);
  },
};
