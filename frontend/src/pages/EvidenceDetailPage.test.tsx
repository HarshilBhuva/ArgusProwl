import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    evidenceDetail: vi.fn(),
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
  useEvidenceDetail: vi.fn(),
}));

import { useEvidenceDetail } from '../hooks/useQueries';
import { EvidenceDetailPage } from './EvidenceDetailPage';

const mockUseEvidenceDetail = useEvidenceDetail as ReturnType<typeof vi.fn>;

describe('EvidenceDetailPage', () => {
  const renderWithRouter = (eventId: string = 'test-event-id') => {
    return render(
      <MemoryRouter initialEntries={[`/evidence/${eventId}`]}>
        <Routes>
          <Route path="/evidence/:id" element={<EvidenceDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  it('shows evicted banner when status is EVICTED', () => {
    mockUseEvidenceDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: {
        event_id: 'test-event-id',
        status: 'EVICTED',
        reason: 'Referenced contributing telemetry is no longer retained in memory.',
        event: null,
        record: {
          event_id: 'test-event-id',
          provenance: 'CONTRIBUTING_EVENT',
          detection_result_id: null,
          contributing_event_ids: [],
        },
      },
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByTestId('evicted-evidence-banner')).toBeInTheDocument();
    expect(screen.getByText('Unavailable / evicted')).toBeInTheDocument();
    expect(screen.getByText(/Event ID.*is preserved/i)).toBeInTheDocument();
  });

  it('shows event details when status is AVAILABLE', () => {
    mockUseEvidenceDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: {
        event_id: 'test-event-id',
        status: 'AVAILABLE',
        reason: null,
        event: {
          event_id: 'test-event-id',
          timestamp: '2024-01-15T10:00:00Z',
          source_type: 'zeek',
          event_type: 'conn',
          hostname: 'server-01',
          src_ip: '10.0.0.1',
          dst_ip: '192.168.1.1',
          process_name: null,
          username: null,
        },
        record: {
          event_id: 'test-event-id',
          provenance: 'DETECTION_SOURCE',
          detection_result_id: 'result-123',
          contributing_event_ids: [],
        },
      },
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.queryByTestId('evicted-evidence-banner')).not.toBeInTheDocument();
    expect(screen.getByText('Event Details')).toBeInTheDocument();
    expect(screen.getByText('server-01')).toBeInTheDocument();
  });

  it('shows not found when no record and not evicted', () => {
    mockUseEvidenceDetail.mockReturnValue({
      isLoading: false,
      error: null,
      data: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/evidence record not found/i)).toBeInTheDocument();
  });
});
