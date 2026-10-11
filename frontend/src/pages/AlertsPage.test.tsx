import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  ApiClientError: class ApiClientError extends Error {
    statusCode: number;
    userMessage: string;
    constructor(statusCode: number, userMessage: string) {
      super(userMessage);
      this.name = 'ApiClientError';
      this.statusCode = statusCode;
      this.userMessage = userMessage;
    }
  },
}));

vi.mock('../hooks/useQueries', () => ({
  useAlerts: vi.fn(),
}));

import { useAlerts } from '../hooks/useQueries';
import { AlertsPage } from './AlertsPage';

const mockUseAlerts = useAlerts as ReturnType<typeof vi.fn>;

const sampleAlertsResponse = {
  alerts: [
    {
      alert_id: '11111111-1111-1111-1111-111111111111',
      title: 'Suspicious process launch',
      description: 'Process launched with elevated privileges',
      severity: 'CRITICAL' as const,
      priority: 'CRITICAL' as const,
      lifecycle_state: 'OPEN' as const,
      source: 'process_detector',
      created_at: '2024-01-15T10:00:00Z',
      tags: ['process'],
      metadata: {},
      schema_version: 2,
      assessment_id: null,
      detector_confidence: 0.9,
      contextual_confidence: 0.8,
      contextual_explanation: '',
      supporting_evidence: [],
      contradictory_evidence: [],
      investigation_pivots: [],
      entity_context: null,
      incident_id: null,
    },
    {
      alert_id: '22222222-2222-2222-2222-222222222222',
      title: 'Port scan detected',
      description: 'Outbound port scan to internal hosts',
      severity: 'MEDIUM' as const,
      priority: 'MEDIUM' as const,
      lifecycle_state: 'ACKNOWLEDGED' as const,
      source: 'network_detector',
      created_at: '2024-01-16T08:00:00Z',
      tags: ['network'],
      metadata: {},
      schema_version: 2,
      assessment_id: null,
      detector_confidence: 0.6,
      contextual_confidence: 0.5,
      contextual_explanation: '',
      supporting_evidence: [],
      contradictory_evidence: [],
      investigation_pivots: [],
      entity_context: null,
      incident_id: '33333333-3333-3333-3333-333333333333',
    },
  ],
  status: 'OK',
  reason: null,
  total_count: 2,
};

describe('AlertsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderAlertsPage = () =>
    render(
      <MemoryRouter initialEntries={['/alerts']}>
        <Routes>
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/alerts/:id" element={<div>Alert Detail</div>} />
        </Routes>
      </MemoryRouter>
    );

  it('renders loading state', () => {
    mockUseAlerts.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    renderAlertsPage();
    expect(screen.getByText('Alerts')).toBeInTheDocument();
    // Skeleton renders, no data rows
    expect(screen.queryByText('Suspicious process launch')).toBeNull();
  });

  it('renders empty state when no alerts', () => {
    mockUseAlerts.mockReturnValue({
      isLoading: false,
      error: null,
      data: { alerts: [], status: 'OK', reason: null, total_count: 0 },
      refetch: vi.fn(),
    });
    renderAlertsPage();
    expect(screen.getByText(/no alerts are currently available/i)).toBeInTheDocument();
  });

  it('renders alert rows with data', () => {
    mockUseAlerts.mockReturnValue({
      isLoading: false,
      error: null,
      data: sampleAlertsResponse,
      refetch: vi.fn(),
    });
    renderAlertsPage();
    expect(screen.getByText('Suspicious process launch')).toBeInTheDocument();
    expect(screen.getByText('Port scan detected')).toBeInTheDocument();
    expect(screen.getByText('process_detector')).toBeInTheDocument();
    expect(screen.getByText('2 signals observed')).toBeInTheDocument();
  });

  it('renders severity and priority badges', () => {
    mockUseAlerts.mockReturnValue({
      isLoading: false,
      error: null,
      data: sampleAlertsResponse,
      refetch: vi.fn(),
    });
    renderAlertsPage();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('MEDIUM')).toBeInTheDocument();
  });

  it('links each alert to its detail page', () => {
    mockUseAlerts.mockReturnValue({
      isLoading: false,
      error: null,
      data: sampleAlertsResponse,
      refetch: vi.fn(),
    });
    renderAlertsPage();
    const link = screen.getByRole('link', { name: 'Suspicious process launch' });
    expect(link.getAttribute('href')).toBe('/alerts/11111111-1111-1111-1111-111111111111');
  });

  it('shows error state when API fails', () => {
    const err = new (class extends Error {
      constructor() {
        super('boom');
        this.name = 'ApiClientError';
      }
    })();
    mockUseAlerts.mockReturnValue({ isLoading: false, error: err, data: null, refetch: vi.fn() });
    renderAlertsPage();
    expect(screen.getByText(/boom/i)).toBeInTheDocument();
  });

  it('shows retry button in error state', () => {
    mockUseAlerts.mockReturnValue({
      isLoading: false,
      error: new Error('x'),
      data: null,
      refetch: vi.fn(),
    });
    renderAlertsPage();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
  });
});
