import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    transitionIncident: vi.fn(),
    createIncidentAnnotation: vi.fn(),
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
  useIncidents: vi.fn(),
  useIncidentDetail: vi.fn(),
  useIncidentAlerts: vi.fn(),
  useIncidentTimeline: vi.fn(),
  useIncidentAnnotations: vi.fn(),
}));

import { useIncidents, useIncidentDetail, useIncidentAlerts, useIncidentTimeline, useIncidentAnnotations } from '../hooks/useQueries';
import { IncidentsPage, IncidentDetailPage } from './IncidentsPage';

const mockUseIncidents = useIncidents as ReturnType<typeof vi.fn>;
const mockUseIncidentDetail = useIncidentDetail as ReturnType<typeof vi.fn>;
const mockUseIncidentAlerts = useIncidentAlerts as ReturnType<typeof vi.fn>;
const mockUseIncidentTimeline = useIncidentTimeline as ReturnType<typeof vi.fn>;
const mockUseIncidentAnnotations = useIncidentAnnotations as ReturnType<typeof vi.fn>;

const sampleIncident = {
  incident_id: '11111111-1111-1111-1111-111111111111',
  title: 'Breach Attempt',
  description: 'Suspicious activity detected',
  severity: 'HIGH' as const,
  status: 'OPEN',
  created_at: '2024-01-15T10:00:00Z',
  updated_at: '2024-01-15T11:00:00Z',
  alert_ids: ['alert-1', 'alert-2'],
  tags: ['breach'],
  assigned_analyst: null,
  investigation_notes: '',
  metadata: {},
};

describe('IncidentsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderPage = () =>
    render(
      <MemoryRouter initialEntries={['/incidents']}>
        <Routes>
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

  it('renders loading state', () => {
    mockUseIncidents.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    renderPage();
    expect(screen.getByText('Incidents')).toBeInTheDocument();
  });

  it('renders empty state when no incidents', () => {
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: null,
      data: { incidents: [], total_count: 0 },
      refetch: vi.fn(),
    });
    renderPage();
    expect(screen.getByText(/no incidents recorded yet/i)).toBeInTheDocument();
  });

  it('renders incident list with data', () => {
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: null,
      data: { incidents: [sampleIncident], total_count: 1 },
      refetch: vi.fn(),
    });
    renderPage();
    expect(screen.getByText('Breach Attempt')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getAllByText('OPEN')).toHaveLength(2);
  });

  it('filters incidents by status and shows the matching incident', () => {
    const closedIncident = {
      ...sampleIncident,
      incident_id: '22222222-2222-2222-2222-222222222222',
      title: 'Closed incident',
      status: 'CLOSED',
    };
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: null,
      data: { incidents: [sampleIncident, closedIncident], total_count: 2 },
      refetch: vi.fn(),
    });
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: 'CLOSED(2)' }));
    expect(screen.getByText('Closed incident')).toBeInTheDocument();
    expect(screen.queryByText('Breach Attempt')).not.toBeInTheDocument();
  });

  it('shows error state when API fails', () => {
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: new Error('boom'), data: null, refetch: vi.fn(),
    });
    renderPage();
    expect(screen.getByText(/unable to load incidents/i)).toBeInTheDocument();
  });

  it('links to incident detail page', () => {
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: null,
      data: { incidents: [sampleIncident], total_count: 1 },
      refetch: vi.fn(),
    });
    renderPage();
    const link = screen.getByRole('link', { name: /investigate/i });
    expect(link.getAttribute('href')).toContain(sampleIncident.incident_id);
  });

describe('IncidentDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderDetail = (id = '11111111-1111-1111-1111-111111111111') =>
    render(
      <MemoryRouter initialEntries={[`/incidents/${id}`]}>
        <Routes>
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

  it('renders loading state', () => {
    mockUseIncidentDetail.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    renderDetail();
    expect(screen.getByText('Incident Detail')).toBeInTheDocument();
  });

  it('renders incident overview', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: sampleIncident, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: 'No timeline data' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.getByText('Breach Attempt')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getAllByText('OPEN')).toHaveLength(2);
    expect(screen.getByText('2')).toBeInTheDocument(); // alert count
  });

  it('shows error state on detail fetch failure', () => {
    mockUseIncidentDetail.mockReturnValue({ isLoading: false, error: new Error('boom'), data: null, refetch: vi.fn() });
    renderDetail();
    expect(screen.getByText(/unable to load incident details/i)).toBeInTheDocument();
  });

  it('shows not found state', () => {
    mockUseIncidentDetail.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    renderDetail('nonexistent');
    expect(screen.getByText(/incident not found/i)).toBeInTheDocument();
  });

  it('shows transition buttons for OPEN incident', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: { ...sampleIncident, status: 'OPEN' }, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: '' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.getByRole('button', { name: /start investigation/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /mark resolved/i })).not.toBeInTheDocument();
  });

  it('renders annotation form for non-closed incident', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: { ...sampleIncident, status: 'OPEN' }, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: '' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.getByPlaceholderText('Author')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Annotation comment')).toBeInTheDocument();
  });

  it('hides annotation form for CLOSED incident', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: { ...sampleIncident, status: 'CLOSED' }, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: '' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.queryByPlaceholderText('Author')).not.toBeInTheDocument();
  });
});  it('filters incidents by status and shows the matching incident', () => {
    const closedIncident = {
      ...sampleIncident,
      incident_id: '22222222-2222-2222-2222-222222222222',
      title: 'Closed incident',
      status: 'CLOSED',
    };
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: null,
      data: { incidents: [sampleIncident, closedIncident], total_count: 2 },
      refetch: vi.fn(),
    });
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: /CLOSED\\s*\\(1\\)/ }));
    expect(screen.getByText('Closed incident')).toBeInTheDocument();
    expect(screen.queryByText('Breach Attempt')).not.toBeInTheDocument();
  });

  it('shows error state when API fails', () => {
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: new Error('boom'), data: null, refetch: vi.fn(),
    });
    renderPage();
    expect(screen.getByText(/unable to load incidents/i)).toBeInTheDocument();
  });

  it('links to incident detail page', () => {
    mockUseIncidents.mockReturnValue({
      isLoading: false, error: null,
      data: { incidents: [sampleIncident], total_count: 1 },
      refetch: vi.fn(),
    });
    renderPage();
    const link = screen.getByRole('link', { name: /investigate/i });
    expect(link.getAttribute('href')).toContain(sampleIncident.incident_id);
  });
});

describe('IncidentDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderDetail = (id = '11111111-1111-1111-1111-111111111111') =>
    render(
      <MemoryRouter initialEntries={[`/incidents/${id}`]}>
        <Routes>
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

  it('renders loading state', () => {
    mockUseIncidentDetail.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: true, error: null, data: null, refetch: vi.fn() });
    renderDetail();
    expect(screen.getByText('Incident Detail')).toBeInTheDocument();
  });

  it('renders incident overview', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: sampleIncident, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: 'No timeline data' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.getByText('Breach Attempt')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText('OPEN')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument(); // alert count
  });

  it('shows error state on detail fetch failure', () => {
    mockUseIncidentDetail.mockReturnValue({ isLoading: false, error: new Error('boom'), data: null, refetch: vi.fn() });
    renderDetail();
    expect(screen.getByText(/unable to load incident details/i)).toBeInTheDocument();
  });

  it('shows not found state', () => {
    mockUseIncidentDetail.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    renderDetail('nonexistent');
    expect(screen.getByText(/incident not found/i)).toBeInTheDocument();
  });

  it('shows transition buttons for OPEN incident', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: { ...sampleIncident, status: 'OPEN' }, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: '' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.getByRole('button', { name: /start investigation/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /mark resolved/i })).not.toBeInTheDocument();
  });

  it('renders annotation form for non-closed incident', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: { ...sampleIncident, status: 'OPEN' }, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: '' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.getByPlaceholderText('Author')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Annotation comment')).toBeInTheDocument();
  });

  it('hides annotation form for CLOSED incident', () => {
    mockUseIncidentDetail.mockReturnValue({
      isLoading: false, error: null,
      data: { ...sampleIncident, status: 'CLOSED' }, refetch: vi.fn(),
    });
    mockUseIncidentAlerts.mockReturnValue({ isLoading: false, error: null, data: null, refetch: vi.fn() });
    mockUseIncidentTimeline.mockReturnValue({ isLoading: false, error: null, data: { items: [], returned_count: 0, truncated: false, correlation_status: 'EMPTY', correlation_note: '' }, refetch: vi.fn() });
    mockUseIncidentAnnotations.mockReturnValue({ isLoading: false, error: null, data: [], refetch: vi.fn() });
    renderDetail();
    expect(screen.queryByPlaceholderText('Author')).not.toBeInTheDocument();
  });
});
