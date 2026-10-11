import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
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
  const renderPage = () => {
    return render(
      <MemoryRouter initialEntries={['/evidence']}>
        <EvidencePage />
      </MemoryRouter>
    );
  };

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

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders empty state when no records', () => {
    mockUseEvidence.mockReturnValue({
      isLoading: false,
      error: null,
      data: {
        records: [],
        events: {},
        status: 'OK',
        reason: null,
        truncated: false,
        total_count: 0,
        returned_count: 0,
      },
      refetch: vi.fn(),
    });

    renderPage();
    expect(screen.getByText(/no evidence records found/i)).toBeInTheDocument();
  });

  it('renders evidence records with details', () => {
    mockUseEvidence.mockReturnValue({
      isLoading: false,
      error: null,
      data: {
        records: mockRecords,
        events: mockEvents,
        status: 'OK',
        reason: null,
        truncated: false,
        total_count: 1,
        returned_count: 1,
      },
      refetch: vi.fn(),
    });

    renderPage();
    expect(screen.getByText('evt-1')).toBeInTheDocument();
    expect(screen.getByText('zeek')).toBeInTheDocument();
    expect(screen.getByText('DETECTION_SOURCE')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /detail/i })).toBeInTheDocument();
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
