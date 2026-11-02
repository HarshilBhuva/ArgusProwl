import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    evidence: vi.fn(),
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
  useEvidence: vi.fn(),
}));

import { useEvidence } from '../hooks/useQueries';
import { EvidencePage } from './EvidencePage';

const mockUseEvidence = useEvidence as ReturnType<typeof vi.fn>;

describe('EvidencePage', () => {
  const renderPage = () =>
    render(
      <MemoryRouter initialEntries={['/evidence']}>
        <EvidencePage />
      </MemoryRouter>
    );

  const mockRecords = [
    {
      event_id: 'evt-1',
      provenance: 'DETECTION_SOURCE',
      detection_result_id: 'result-1',
      contributing_event_ids: [],
    },
  ];

  const mockEvents: Record<string, unknown> = {
    'evt-1': {
      event_id: 'evt-1',
      timestamp: '2024-01-15T10:00:00Z',
      source_type: 'zeek',
      event_type: 'conn',
      hostname: 'host-1',
      src_ip: '10.0.0.1',
      dst_ip: null,
      process_name: null,
      username: null,
    },
  };

  const result = (overrides: Record<string, unknown> = {}) => ({
    isLoading: false,
    error: null,
    data: {
      records: mockRecords,
      events: mockEvents,
      status: 'AVAILABLE',
      reason: null,
      truncated: false,
      total_count: 1,
      returned_count: 1,
    },
    refetch: vi.fn(),
    ...overrides,
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseEvidence.mockReturnValue(result());
  });

  it('renders empty state when no records', () => {
    mockUseEvidence.mockReturnValue(
      result({
        data: {
          records: [],
          events: {},
          status: 'AVAILABLE',
          reason: null,
          truncated: false,
          total_count: 0,
          returned_count: 0,
        },
      })
    );

    renderPage();
    expect(screen.getByText(/no evidence records found/i)).toBeInTheDocument();
  });

  it('renders evidence records with details', () => {
    renderPage();
    expect(screen.getByText('evt-1')).toBeInTheDocument();
    expect(screen.getByText('zeek')).toBeInTheDocument();
    expect(screen.getByText('DETECTION_SOURCE')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /detail/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /event explorer/i })).toBeInTheDocument();
  });

  it('applies source, event, entity and time filters to the evidence query', () => {
    renderPage();

    fireEvent.change(screen.getByLabelText(/source type/i), {
      target: { value: 'sysmon' },
    });
    fireEvent.change(screen.getByLabelText(/event type/i), {
      target: { value: 'process_create' },
    });
    fireEvent.change(screen.getByLabelText(/entity type/i), {
      target: { value: 'hostname' },
    });
    fireEvent.change(screen.getByLabelText(/entity id/i), {
      target: { value: 'workstation-01' },
    });
    fireEvent.submit(screen.getByRole('button', { name: /search events/i }).closest('form')!);

    expect(mockUseEvidence).toHaveBeenLastCalledWith(
      expect.objectContaining({
        limit: 50,
        source_type: 'sysmon',
        event_type: 'process_create',
        entity_type: 'hostname',
        entity_id: 'workstation-01',
      })
    );
  });

  it('shows an explicit warning when evidence recovery is degraded', () => {
    mockUseEvidence.mockReturnValue(
      result({
        data: {
          records: mockRecords,
          events: mockEvents,
          status: 'DEGRADED',
          reason: 'Some persisted records could not be recovered.',
          truncated: false,
          total_count: 1,
          returned_count: 1,
        },
      })
    );

    renderPage();
    expect(screen.getByRole('status')).toHaveTextContent(/degraded/i);
    expect(screen.getByRole('status')).toHaveTextContent(/could not be recovered/i);
  });

  it('renders result truncation as an incomplete result warning', () => {
    mockUseEvidence.mockReturnValue(
      result({
        data: {
          records: mockRecords,
          events: mockEvents,
          status: 'AVAILABLE',
          reason: null,
          truncated: true,
          total_count: 101,
          returned_count: 50,
        },
      })
    );

    renderPage();
    expect(screen.getByText(/showing 50 of 101 matching events/i)).toBeInTheDocument();
  });

  it('renders error state when API fails', () => {
    mockUseEvidence.mockReturnValue({
      isLoading: false,
      error: new Error('failed'),
      data: null,
      refetch: vi.fn(),
    });

    renderPage();
    expect(screen.getByText(/unable to load evidence/i)).toBeInTheDocument();
  });
});
