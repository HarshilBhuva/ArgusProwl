import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

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
  useHealth: vi.fn(),
  useMetrics: vi.fn(),
  useAlerts: vi.fn(),
}));

import { useHealth, useMetrics, useAlerts } from '../hooks/useQueries';
import { DashboardPage } from './DashboardPage';

const mockUseHealth = useHealth as ReturnType<typeof vi.fn>;
const mockUseMetrics = useMetrics as ReturnType<typeof vi.fn>;
const mockUseAlerts = useAlerts as ReturnType<typeof vi.fn>;

const mockHealth = {
  status: 'DEGRADED',
  version: '1.0.0',
  uptime_seconds: 100,
  checked_at: '2024-01-15T10:30:00Z',
  components: [
    { name: 'db', status: 'ok', message: 'connected' },
    { name: 'ingest', status: 'degraded', message: 'slow' },
  ],
};

const mockMetrics = {
  uptime_seconds: 100,
  captured_at: '2024-01-15T10:30:00Z',
  metrics: [
    { name: 'alerts_total', description: 'Total alerts', value: 42 },
  ],
};

const mockAlerts = {
  alerts: [
    {
      alert_id: 'a1',
      title: 'Suspicious activity',
      description: 'Something happened',
      severity: 'HIGH' as const,
      priority: 'HIGH' as const,
      lifecycle_state: 'OPEN' as const,
      source: 'test-detector',
      created_at: '2024-01-15T10:00:00Z',
      tags: [],
      metadata: {},
      schema_version: 2,
      assessment_id: null,
      detector_confidence: 0.8,
      contextual_confidence: 0.7,
      contextual_explanation: '',
      supporting_evidence: [],
      contradictory_evidence: [],
      investigation_pivots: [],
      entity_context: null,
      incident_id: null,
    },
  ],
  status: 'OK',
  reason: null,
  total_count: 1,
};

describe('DashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderDashboard = () =>
    render(
      <MemoryRouter>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
        </Routes>
      </MemoryRouter>
    );

  it('renders the dashboard heading', () => {
    mockUseHealth.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseMetrics.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseAlerts.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });

    renderDashboard();
    expect(screen.getByText('Operations Dashboard')).toBeInTheDocument();
  });

  it('renders health data when loaded', () => {
    mockUseHealth.mockReturnValue({ isLoading: false, error: null, data: mockHealth, refetch: vi.fn() });
    mockUseMetrics.mockReturnValue({ isLoading: false, error: null, data: mockMetrics, refetch: vi.fn() });
    mockUseAlerts.mockReturnValue({ isLoading: false, error: null, data: mockAlerts, refetch: vi.fn() });

    renderDashboard();
    expect(screen.getByText('DEGRADED')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText(/alerts_total/i)).toBeInTheDocument();
  });

  it('renders alerts data when loaded', () => {
    mockUseHealth.mockReturnValue({ isLoading: false, error: null, data: mockHealth, refetch: vi.fn() });
    mockUseMetrics.mockReturnValue({ isLoading: false, error: null, data: mockMetrics, refetch: vi.fn() });
    mockUseAlerts.mockReturnValue({ isLoading: false, error: null, data: mockAlerts, refetch: vi.fn() });

    renderDashboard();
    expect(screen.getByText('Suspicious activity')).toBeInTheDocument();
  });

  it('shows error message when health fails', () => {
    mockUseHealth.mockReturnValue({
      isLoading: false,
      error: new Error('boom'),
      data: null,
      refetch: vi.fn(),
    });
    mockUseMetrics.mockReturnValue({ isLoading: false, error: null, data: mockMetrics, refetch: vi.fn() });
    mockUseAlerts.mockReturnValue({ isLoading: false, error: null, data: mockAlerts, refetch: vi.fn() });

    renderDashboard();
    expect(screen.getByText(/boom/i)).toBeInTheDocument();
  });
});
