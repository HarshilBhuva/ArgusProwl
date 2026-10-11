import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { AlertSearchParams, AttckInvestigationResponse, EvidenceSearchParams, IocInvestigationResponse } from '../types/api';

export const queryKeys = {
  health: ['health'] as const,
  metrics: ['metrics'] as const,
  alerts: (params: AlertSearchParams = {}) => ['alerts', params] as const,
  alertDetail: (alertId: string) => ['alerts', alertId] as const,
  entities: ['entities'] as const,
  entityDetail: (entityType: string, entityId: string) => ['entities', entityType, entityId] as const,
  entityTimeline: (entityType: string, entityId: string, limit: number) => ['entities', entityType, entityId, 'timeline', limit] as const,
  rules: (params: any = {}) => ['rules', params] as const,
  ruleDetail: (ruleId: string) => ['rules', ruleId] as const,
  iocLookup: (indicator: string) => ['iocs', indicator] as const,
  incidents: ['incidents'] as const,
  incidentDetail: (incidentId: string) => ['incidents', incidentId] as const,
  incidentAlerts: (incidentId: string) => ['incidents', incidentId, 'alerts'] as const,
  incidentTimeline: (incidentId: string, limit: number) => ['incidents', incidentId, 'timeline', limit] as const,
  incidentAnnotations: (incidentId: string) => ['incidents', incidentId, 'annotations'] as const,
  evidence: (params: EvidenceSearchParams = {}) => ['evidence', params] as const,
  evidenceDetail: (eventId: string) => ['evidence', eventId] as const,
  evidenceStats: ['evidence', 'stats'] as const,
  attckOverview: ['attck', 'overview'] as const,
  attckInvestigation: (alertIds: string[]) => ['attck', 'investigation', alertIds] as const,
};

export function useHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: () => api.health(),
    retry: 1,
    staleTime: 30_000,
  });
}

export function useMetrics() {
  return useQuery({
    queryKey: queryKeys.metrics,
    queryFn: () => api.metrics(),
    retry: 1,
    staleTime: 30_000,
  });
}

export function useAlerts(params: AlertSearchParams = {}) {
  return useQuery({
    queryKey: queryKeys.alerts(params),
    queryFn: () => api.alerts(params),
    retry: 1,
    staleTime: 15_000,
  });
}

export function useAlertDetail(alertId: string | null) {
  return useQuery({
    queryKey: queryKeys.alertDetail(alertId ?? ''),
    queryFn: () => api.alertDetail(alertId ?? ''),
    enabled: !!alertId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useEntities() {
  return useQuery({
    queryKey: queryKeys.entities,
    queryFn: () => api.entities(),
    retry: 1,
    staleTime: 15_000,
  });
}

export function useEntityDetail(entityType: string | null, entityId: string | null) {
  return useQuery({
    queryKey: queryKeys.entityDetail(entityType ?? '', entityId ?? ''),
    queryFn: () => api.entityDetail(entityType ?? '', entityId ?? ''),
    enabled: !!entityType && !!entityId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useEntityTimeline(entityType: string | null, entityId: string | null, limit: number = 50) {
  return useQuery({
    queryKey: queryKeys.entityTimeline(entityType ?? '', entityId ?? '', limit),
    queryFn: () => api.entityTimeline(entityType ?? '', entityId ?? '', limit),
    enabled: !!entityType && !!entityId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useRules(params: { enabled?: boolean; detector_class?: string } = {}) {
  return useQuery({
    queryKey: queryKeys.rules(params),
    queryFn: () => api.rules(params),
    retry: 1,
    staleTime: 15_000,
  });
}

export function useRuleDetail(ruleId: string | null) {
  return useQuery({
    queryKey: queryKeys.ruleDetail(ruleId ?? ''),
    queryFn: () => api.ruleDetail(ruleId ?? ''),
    enabled: !!ruleId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useIocLookup(indicator: string | null) {
  return useQuery({
    queryKey: queryKeys.iocLookup(indicator ?? ''),
    queryFn: () => api.iocLookup(indicator ?? ''),
    enabled: !!indicator,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useIncidents() {
  return useQuery({
    queryKey: queryKeys.incidents,
    queryFn: () => api.incidents(),
    retry: 1,
    staleTime: 15_000,
  });
}

export function useIncidentDetail(incidentId: string | null) {
  return useQuery({
    queryKey: queryKeys.incidentDetail(incidentId ?? ''),
    queryFn: () => api.incidentDetail(incidentId ?? ''),
    enabled: !!incidentId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useIncidentAlerts(incidentId: string | null) {
  return useQuery({
    queryKey: queryKeys.incidentAlerts(incidentId ?? ''),
    queryFn: () => api.incidentAlerts(incidentId ?? ''),
    enabled: !!incidentId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useIncidentTimeline(incidentId: string | null, limit: number = 50) {
  return useQuery({
    queryKey: queryKeys.incidentTimeline(incidentId ?? '', limit),
    queryFn: () => api.incidentTimeline(incidentId ?? '', limit),
    enabled: !!incidentId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useIncidentAnnotations(incidentId: string | null) {
  return useQuery({
    queryKey: queryKeys.incidentAnnotations(incidentId ?? ''),
    queryFn: () => api.incidentAnnotations(incidentId ?? ''),
    enabled: !!incidentId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useEvidence(params: EvidenceSearchParams = {}) {
  return useQuery({
    queryKey: queryKeys.evidence(params),
    queryFn: () => api.evidence(params),
    retry: 1,
    staleTime: 15_000,
  });
}

export function useEvidenceDetail(eventId: string | null) {
  return useQuery({
    queryKey: queryKeys.evidenceDetail(eventId ?? ''),
    queryFn: () => api.evidenceDetail(eventId ?? ''),
    enabled: !!eventId,
    retry: 1,
    staleTime: 15_000,
  });
}

export function useEvidenceStats() {
  return useQuery({
    queryKey: queryKeys.evidenceStats,
    queryFn: () => api.evidenceStats(),
    retry: 1,
    staleTime: 30_000,
  });
}

export function useAttckOverview() {
  return useQuery({
    queryKey: queryKeys.attckOverview,
    queryFn: () => api.attckOverview(),
    retry: 1,
    staleTime: 60_000,
  });
}

export function useAttckInvestigation(alertIds: string[]) {
  return useQuery({
    queryKey: queryKeys.attckInvestigation(alertIds),
    queryFn: () => api.attckInvestigation(alertIds),
    enabled: alertIds.length > 0,
    retry: 1,
    staleTime: 15_000,
  });
}
