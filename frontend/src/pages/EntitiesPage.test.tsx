import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    entities: vi.fn(),
    entityDetail: vi.fn(),
    entityAnnotations: vi.fn(),
    createEntityAnnotation: vi.fn(),
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
  useEntities: vi.fn(),
  useEntityDetail: vi.fn(),
  useEntityTimeline: vi.fn(),
  useEvidence: vi.fn(),
}));

import { useEntities, useEntityDetail, useEntityTimeline, useEvidence } from '../hooks/useQueries';
import { EntitiesPage, EntityDetailPage } from './EntitiesPage';

const mockUseEntities = useEntities as ReturnType<typeof vi.fn>;
const mockUseEntityDetail = useEntityDetail as ReturnType<typeof vi.fn>;
const mockUseEntityTimeline = useEntityTimeline as ReturnType<typeof vi.fn>;
const mockUseEvidence = useEvidence as ReturnType<typeof vi.fn>;
const mockApi = vi.mocked(await import('../lib/api')).api;

describe('EntitiesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseEntityTimeline.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });
    mockUseEvidence.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });
  });

  it('renders loading state', () => {
    mockUseEntities.mockReturnValue({
      data: null,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <EntitiesPage />
      </MemoryRouter>
    );
    expect(screen.getByText(/Observed Entities/i)).toBeInTheDocument();
  });

  it('renders error state', () => {
    mockUseEntities.mockReturnValue({
      data: null,
      isLoading: false,
      error: new Error('API error'),
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <EntitiesPage />
      </MemoryRouter>
    );
    expect(screen.getByText(/Unable to load entities/i)).toBeInTheDocument();
  });

  it('renders empty state when no entities', () => {
    mockUseEntities.mockReturnValue({
      data: { entities: [], total_count: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <EntitiesPage />
      </MemoryRouter>
    );
    expect(screen.getByText(/No behavioral entities observed/i)).toBeInTheDocument();
  });

  it('renders entity list with correlation support badges', () => {
    mockUseEntities.mockReturnValue({
      data: {
        entities: [
          {
            entity_type: 'hostname',
            entity_id: 'workstation01',
            has_correlation_support: true,
            maturity: 'mature',
            observation_count: 100,
            last_seen: '2024-01-15T10:30:00Z',
          },
          {
            entity_type: 'src_ip',
            entity_id: '192.168.1.100',
            has_correlation_support: false,
            maturity: 'empty',
            observation_count: 10,
            last_seen: '2024-01-15T09:00:00Z',
          },
        ],
        total_count: 2,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <EntitiesPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/workstation01/i)).toBeInTheDocument();
    expect(screen.getByText(/192.168.1.100/i)).toBeInTheDocument();
    expect(screen.getByText(/Partial/i)).toBeInTheDocument();
    expect(screen.getByText(/Unsupported/i)).toBeInTheDocument();
  });

  it('renders investigate links', () => {
    mockUseEntities.mockReturnValue({
      data: {
        entities: [
          {
            entity_type: 'hostname',
            entity_id: 'workstation01',
            has_correlation_support: true,
            maturity: 'mature',
            observation_count: 100,
            last_seen: '2024-01-15T10:30:00Z',
          },
        ],
        total_count: 1,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <EntitiesPage />
      </MemoryRouter>
    );

    const link = screen.getByRole('link', { name: /Investigate/i });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute('href', '/entities/hostname/workstation01');
  });
});

describe('EntityDetailPage', () => {
  const renderWithRouter = (initialPath: string = '/entities/hostname/workstation01') => {
    return render(
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/entities/:type/:id" element={<EntityDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseEvidence.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });
  });

  it('renders loading state', () => {
    mockUseEntityDetail.mockReturnValue({
      data: null,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/Entity Investigation/i)).toBeInTheDocument();
  });

  it('renders error state', () => {
    mockUseEntityDetail.mockReturnValue({
      data: null,
      isLoading: false,
      error: new Error('API error'),
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/Unable to load entity details/i)).toBeInTheDocument();
  });

  it('renders entity identity section', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
        observed_correlation_keys: ['workstation01:*', 'workstation01:svchost.exe'],
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

    renderWithRouter();

    expect(screen.getByText(/Investigating hostname:workstation01/i)).toBeInTheDocument();
    expect(screen.getByText(/Partial/i)).toBeInTheDocument();
  });

  it('displays observed correlation keys', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
        observed_correlation_keys: ['workstation01:*', 'workstation01:svchost.exe'],
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

    renderWithRouter();

    expect(screen.getByText(/workstation01:\*/i)).toBeInTheDocument();
    expect(screen.getByText(/workstation01:svchost\.exe/i)).toBeInTheDocument();
  });

  it('shows partial correlation status', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
        observed_correlation_keys: ['workstation01:*'],
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

    renderWithRouter();

    expect(screen.getByText(/Partial/i)).toBeInTheDocument();
  });

  it('shows unsupported correlation for src_ip', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'src_ip',
        entity_id: '192.168.1.100',
        observed_correlation_keys: [],
        correlation_status: 'UNSUPPORTED',
        correlation_note: 'Alert correlation is unsupported for entity type \'src_ip\'.',
        behavior: [],
        alerts: {},
        annotations: [],
        incidents: [],
        incident_status: 'UNSUPPORTED',
        incident_note: 'Incident correlation is unsupported for entity type \'src_ip\'.',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter('/entities/src_ip/192.168.1.100');

    expect(screen.getAllByText(/Unsupported/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Alert correlation is unsupported/i).length).toBeGreaterThan(0);
  });

  it('renders annotations section', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
        observed_correlation_keys: [],
        correlation_status: 'PARTIAL',
        correlation_note: 'Alerts are grouped by observed canonical correlation keys.',
        behavior: [],
        alerts: {},
        annotations: [
          {
            annotation_id: 'ann-1',
            target_key: 'entity:hostname:workstation01',
            author: 'analyst1',
            created_at: '2024-01-15T10:30:00Z',
            comment: 'Test annotation',
            tombstoned: false,
          },
        ],
        incidents: [],
        incident_status: 'PARTIAL',
        incident_note: 'Incident relationships are resolved from observed canonical correlation keys.',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/analyst1/i)).toBeInTheDocument();
    expect(screen.getByText(/Test annotation/i)).toBeInTheDocument();
  });

  it('renders add annotation form', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
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

    renderWithRouter();

    expect(screen.getByText(/Add Entity Annotation/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Author/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Comment/i)).toBeInTheDocument();
  });

  it('calls createEntityAnnotation on form submit', async () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
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

    (mockApi.createEntityAnnotation as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      annotation_id: 'ann-2',
      target_key: 'entity:hostname:workstation01',
      author: 'analyst2',
      created_at: '2024-01-15T11:00:00Z',
      comment: 'New annotation',
      tombstoned: false,
    });

    renderWithRouter();

    const authorInput = screen.getByLabelText(/Author/i);
    const commentInput = screen.getByLabelText(/Comment/i);
    const submitButton = screen.getByRole('button', { name: /Add Annotation/i });

    fireEvent.change(authorInput, { target: { value: 'analyst2' } });
    fireEvent.change(commentInput, { target: { value: 'New annotation' } });
    fireEvent.click(submitButton);

    expect(mockApi.createEntityAnnotation).toHaveBeenCalledWith(
      'hostname',
      'workstation01',
      { author: 'analyst2', comment: 'New annotation' }
    );
  });

  it('shows alerts grouped by correlation key', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
        observed_correlation_keys: ['workstation01:*'],
        correlation_status: 'PARTIAL',
        correlation_note: 'Alerts are grouped by observed canonical correlation keys.',
        behavior: [],
        alerts: {
          'workstation01:*': [
            {
              alert_id: 'alert-1',
              title: 'Suspicious Activity',
              description: 'Test alert',
              severity: 'HIGH',
              priority: 'HIGH',
              lifecycle_state: 'OPEN',
              source: 'test',
              created_at: '2024-01-15T10:30:00Z',
              tags: [],
              metadata: {},
              schema_version: 2,
              entity_context: { host: 'workstation01' },
              incident_id: null,
            },
          ],
        },
        annotations: [],
        incidents: [],
        incident_status: 'PARTIAL',
        incident_note: 'Incident relationships are resolved from observed canonical correlation keys.',
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getAllByText(/workstation01:\*/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Suspicious Activity/i)).toBeInTheDocument();
  });

  it('shows empty state when no alerts', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
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

    renderWithRouter();

    expect(screen.getByText(/No alerts observed/i)).toBeInTheDocument();
  });

  it('shows empty state when no incidents', () => {
    mockUseEntityDetail.mockReturnValue({
      data: {
        entity_type: 'hostname',
        entity_id: 'workstation01',
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

    renderWithRouter();

    expect(screen.getByText(/No incidents currently mapped/i)).toBeInTheDocument();
  });
});
