import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    alertDetail: vi.fn(),
    acknowledgeAlert: vi.fn(),
    closeAlert: vi.fn(),
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

vi.mock('../hooks/useQueries', () => ({
  useAlertDetail: vi.fn(),
}));

import { useAlertDetail } from '../hooks/useQueries';
import { AlertDetailPage } from './AlertDetailPage';

const mockUseAlertDetail = useAlertDetail as ReturnType<typeof vi.fn>;
const mockApi = vi.mocked(await import('../lib/api')).api;

describe('AlertDetailPage', () => {
  const renderWithRouter = (initialPath: string = '/alerts/12345678-1234-1234-1234-123456789012') => {
    return render(
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/alerts/:id" element={<AlertDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  const mockAlert = {
    alert_id: '12345678-1234-1234-1234-123456789012',
    title: 'Suspicious Network Connection',
    description: 'Detected unusual outbound connection',
    severity: 'HIGH' as const,
    priority: 'HIGH' as const,
    lifecycle_state: 'OPEN' as const,
    source: 'network_detector',
    created_at: '2024-01-15T10:30:00Z',
    tags: ['network', 'suspicious'],
    metadata: { rule_id: 'net-001' },
    schema_version: 2,
    entity_context: { host: 'server-01', src_ip: '10.0.0.5' },
    supporting_evidence: [{ field: 'dst_ip', observed: '198.51.100.1' }],
    contradictory_evidence: [],
    investigation_pivots: ['Check host logs'],
    incident_id: null,
    detector_confidence: 0.85,
    contextual_confidence: 0.9,
    contextual_explanation: 'Based on historical baseline',
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders loading state', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: true,
      error: null,
      data: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    // Loading skeleton renders placeholder elements
    expect(screen.getByText(/alert detail/i)).toBeInTheDocument();
  });

  it('renders alert details when loaded', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: mockAlert,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText('Suspicious Network Connection')).toBeInTheDocument();
    expect(screen.getByText('Detected unusual outbound connection')).toBeInTheDocument();
    expect(screen.getByText('network_detector')).toBeInTheDocument();
  });

  it('renders entity context when present', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: mockAlert,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText('Entity Context')).toBeInTheDocument();
    expect(screen.getByText(/server-01/i)).toBeInTheDocument();
  });

  it('renders evidence sections', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: mockAlert,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText('Supporting Evidence')).toBeInTheDocument();
    expect(screen.getByText(/198.51.100.1/i)).toBeInTheDocument();
  });

  it('renders lifecycle actions for OPEN state', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: mockAlert,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByRole('button', { name: /acknowledge/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /close/i })).toBeInTheDocument();
  });

  it('shows acknowledge button only for OPEN state', async () => {
    const acknowledgedAlert = { ...mockAlert, lifecycle_state: 'ACKNOWLEDGED' as const };
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: acknowledgedAlert,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.queryByRole('button', { name: /acknowledge/i })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /close/i })).toBeInTheDocument();
  });

  it('shows no lifecycle buttons for CLOSED state', async () => {
    const closedAlert = { ...mockAlert, lifecycle_state: 'CLOSED' as const };
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: closedAlert,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.queryByRole('button', { name: /acknowledge/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /close/i })).not.toBeInTheDocument();
  });

  it('renders error state when API fails', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: new Error('Failed to load'),
      data: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/unable to load alert/i)).toBeInTheDocument();
  });

  it('renders not found state when alert does not exist', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/alert not found/i)).toBeInTheDocument();
  });

  it('navigates back to alerts list', () => {
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: mockAlert,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const backButton = screen.getByRole('link', { name: /back to alerts/i });
    expect(backButton).toBeInTheDocument();
    expect(backButton.getAttribute('href')).toBe('/alerts');
  });

  it('shows contributing events with status when present', () => {
    const alertWithContributing = {
      ...mockAlert,
      detection_source_event_id: 'source-event-id',
      contributing_event_ids: ['contrib-1', 'contrib-2'],
      contributing_event_status: {
        'contrib-1': 'AVAILABLE',
        'contrib-2': 'EVICTED',
      },
    };
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: alertWithContributing,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/Telemetry Evidence Provenance/i)).toBeInTheDocument();
    expect(screen.getByText(/Contributing Events \(2\)/i)).toBeInTheDocument();
    expect(screen.getByText('contrib-1')).toBeInTheDocument();
    expect(screen.getByText('contrib-2')).toBeInTheDocument();
    expect(screen.getByText('Available')).toBeInTheDocument();
    expect(screen.getByText('Unavailable / evicted')).toBeInTheDocument();
  });

  it('shows evidence link for available contributing events', () => {
    const alertWithContributing = {
      ...mockAlert,
      contributing_event_ids: ['contrib-1'],
      contributing_event_status: {
        'contrib-1': 'AVAILABLE',
      },
    };
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: alertWithContributing,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const link = screen.getByRole('link', { name: /view/i });
    expect(link).toBeInTheDocument();
    expect(link.getAttribute('href')).toBe('/evidence/contrib-1');
  });

  it('does not show evidence link for evicted contributing events', () => {
    const alertWithContributing = {
      ...mockAlert,
      contributing_event_ids: ['contrib-1'],
      contributing_event_status: {
        'contrib-1': 'EVICTED',
      },
    };
    mockUseAlertDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: alertWithContributing,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText('Unavailable / evicted')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /view/i })).not.toBeInTheDocument();
  });
});
