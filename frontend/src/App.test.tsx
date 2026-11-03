import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

vi.mock('./lib/api', () => ({
  api: {
    health: vi.fn(),
    metrics: vi.fn(),
    alerts: vi.fn(),
    authStatus: vi.fn().mockResolvedValue({ auth_enabled: false, session_ttl_seconds: 3600 }),
    authMe: vi.fn(),
    createSession: vi.fn(),
    logout: vi.fn(),
  },
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

vi.mock('./hooks/useQueries', () => ({
  useHealth: vi.fn(),
  useMetrics: vi.fn(),
  useAlerts: vi.fn(),
  useEntities: vi.fn(),
  useEntityDetail: vi.fn(),
  useEntityTimeline: vi.fn(),
  useRules: vi.fn(),
  useRuleDetail: vi.fn(),
  useEvidence: vi.fn(),
}));

import { useHealth, useMetrics, useAlerts, useEntities, useEntityDetail, useEntityTimeline, useRules, useRuleDetail, useEvidence } from './hooks/useQueries';
import { ApiClientError, api } from './lib/api';
import App from './App';

const mockUseHealth = useHealth as ReturnType<typeof vi.fn>;
const mockUseMetrics = useMetrics as ReturnType<typeof vi.fn>;
const mockUseAlerts = useAlerts as ReturnType<typeof vi.fn>;
const mockUseEntities = useEntities as ReturnType<typeof vi.fn>;
const mockUseEntityDetail = useEntityDetail as ReturnType<typeof vi.fn>;
const mockUseEntityTimeline = useEntityTimeline as ReturnType<typeof vi.fn>;
const mockUseRules = useRules as ReturnType<typeof vi.fn>;
const mockUseRuleDetail = useRuleDetail as ReturnType<typeof vi.fn>;
const mockUseEvidence = useEvidence as ReturnType<typeof vi.fn>;
const mockApi = vi.mocked(api);

describe('ArgusProwl Frontend', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockApi.authStatus.mockResolvedValue({ auth_enabled: false, session_ttl_seconds: 3600 });
    window.history.pushState({}, '', '/');
    mockUseEntities.mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() });
    mockUseEntityDetail.mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() });
    mockUseEntityTimeline.mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() });
    mockUseEvidence.mockReturnValue({ data: null, isLoading: false, error: null, refetch: vi.fn() });
  });


  it('authenticates the browser with a short-lived session without persisting the API key', async () => {
    mockApi.authStatus.mockResolvedValue({ auth_enabled: true, session_ttl_seconds: 3600 });
    mockApi.authMe
      .mockRejectedValueOnce(new ApiClientError(401, 'Unauthorized'))
      .mockResolvedValue({
        authenticated: true,
        subject: 'soc-analyst',
        role: 'analyst',
        key_id: 'analyst-key',
      });
    mockApi.createSession.mockResolvedValue({
      authenticated: true,
      subject: 'soc-analyst',
      role: 'analyst',
      key_id: 'analyst-key',
    });
    mockUseHealth.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseMetrics.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseAlerts.mockReturnValue({ data: null, isLoading: false, error: null });

    render(<App />);

    expect(await screen.findByRole('heading', { name: /Sign in/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/API key/i), { target: { value: 'one-time-secret' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    expect(await screen.findByText('soc-analyst')).toBeInTheDocument();
    await waitFor(() => expect(mockApi.createSession).toHaveBeenCalledWith('one-time-secret'));
    expect(screen.queryByLabelText(/API key/i)).not.toBeInTheDocument();

    window.dispatchEvent(new Event('argusprowl:session-expired'));
    expect(await screen.findByRole('heading', { name: /Sign in/i })).toBeInTheDocument();
  });

  it('renders the application shell', async () => {
    mockUseHealth.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseMetrics.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseAlerts.mockReturnValue({ data: null, isLoading: false, error: null });

    render(<App />);

    expect(await screen.findByRole('heading', { name: /Operations Dashboard/i })).toBeInTheDocument();
  });

  it('shows health status when available', async () => {
    mockUseHealth.mockReturnValue({
      data: { status: 'healthy', version: '0.1.0', uptime_seconds: 3600, checked_at: new Date().toISOString(), components: [] },
      isLoading: false,
      error: null,
    });
    mockUseMetrics.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseAlerts.mockReturnValue({ data: null, isLoading: false, error: null });

    render(<App />);

    expect(await screen.findByRole('heading', { name: /System Health/i })).toBeInTheDocument();
  });

  it('shows loading state while fetching', async () => {
    mockUseHealth.mockReturnValue({ data: null, isLoading: true, error: null });
    mockUseMetrics.mockReturnValue({ data: null, isLoading: true, error: null });
    mockUseAlerts.mockReturnValue({ data: null, isLoading: true, error: null });

    render(<App />);

    expect(await screen.findByRole('heading', { name: /System Health/i })).toBeInTheDocument();
  });

  it('shows error state when API is unavailable', async () => {
    mockUseHealth.mockReturnValue({ data: null, isLoading: false, error: new Error('API unavailable') });
    mockUseMetrics.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseAlerts.mockReturnValue({ data: null, isLoading: false, error: null });

    render(<App />);

    expect(await screen.findByText(/Backend status unavailable/i)).toBeInTheDocument();
  });

  it('renders metrics and alerts returned by the backend', async () => {
    mockUseHealth.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseMetrics.mockReturnValue({
      data: {
        uptime_seconds: 120,
        captured_at: new Date().toISOString(),
        metrics: [{ name: 'alert_count', description: 'Alerts', value: 3 }],
      },
      isLoading: false,
      error: null,
    });
    mockUseAlerts.mockReturnValue({
      data: {
        alerts: [
          {
            alert_id: 'alert-1',
            title: '<script>alert(1)</script>',
            description: 'Suspicious activity',
            severity: 'HIGH',
            priority: 'HIGH',
            lifecycle_state: 'OPEN',
            source: 'test',
            created_at: new Date().toISOString(),
          },
        ],
        status: 'ok',
        reason: null,
        total_count: 1,
      },
      isLoading: false,
      error: null,
    });

    render(<App />);

    expect(await screen.findByText('Alert Count')).toBeInTheDocument();
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument();
    expect(screen.queryByRole('script')).not.toBeInTheDocument();
  });

  it('shows the alerts empty state', async () => {
    mockUseHealth.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseMetrics.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseAlerts.mockReturnValue({
      data: { alerts: [], status: 'ok', reason: null, total_count: 0 },
      isLoading: false,
      error: null,
    });

    render(<App />);

    expect(await screen.findByText(/No alerts are currently available/i)).toBeInTheDocument();
  });

  it('renders placeholder routes and the 404 route', async () => {
    mockUseHealth.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseMetrics.mockReturnValue({ data: null, isLoading: false, error: null });
    mockUseAlerts.mockReturnValue({ data: null, isLoading: false, error: null });

    window.history.pushState({}, '', '/entities/host/server-1');
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'host',
        entity_id: 'server-1',
        observed_correlation_keys: [],
        correlation_status: 'PARTIAL',
        correlation_note: 'Alerts are grouped by observed canonical correlation keys.',
        behavior: [],
        alerts: {},
        annotations: [],
        incidents: [],
        incident_status: 'PARTIAL',
        incident_note: 'Incident relationships are resolved from observed canonical correlation keys.',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });
    const { unmount } = render(<App />);
    expect(await screen.findByRole('heading', { name: /Entity Investigation/i, level: 1 })).toBeInTheDocument();

    unmount();
    window.history.pushState({}, '', '/does-not-exist');
    render(<App />);
    expect(await screen.findByRole('heading', { name: /Page not found/i })).toBeInTheDocument();
  });
});
