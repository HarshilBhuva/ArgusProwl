import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    hunts: vi.fn(),
    hunt: vi.fn(),
    createHunt: vi.fn(),
    updateHuntScope: vi.fn(),
    saveHuntQuery: vi.fn(),
    executeHuntQuery: vi.fn(),
    attachHuntEvidence: vi.fn(),
    addHuntFinding: vi.fn(),
    setHuntConclusion: vi.fn(),
    transitionHunt: vi.fn(),
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

import { api } from '../lib/api';
import { HuntsPage } from './HuntsPage';

const mockApi = vi.mocked(api);

const hunt = {
  hunt_id: 'hunt-1',
  title: 'Suspicious PowerShell execution',
  hypothesis: 'A remote script was executed on the workstation.',
  created_by: 'analyst@example.test',
  status: 'active' as const,
  scope: {
    start_time: null,
    end_time: null,
    hosts: ['workstation-01'],
    users: [],
    sources: ['sysmon'],
  },
  queries: [
    {
      query_id: 'query-1',
      name: 'PowerShell process events',
      definition: { source_type: 'sysmon', event_type: 'process_start', limit: 500 },
      version: 1,
      created_at: '2026-11-01T10:00:00Z',
    },
  ],
  executions: [
    {
      execution_id: 'execution-1',
      query_id: 'query-1',
      query_version: 1,
      started_at: '2026-11-01T10:00:00Z',
      completed_at: '2026-11-01T10:00:01Z',
      result_count: 1,
      data_sources: ['sysmon'],
      evidence_event_ids: ['00000000-0000-0000-0000-000000000001'],
      status: 'complete' as const,
      error: null,
      truncated: false,
    },
  ],
  evidence_references: [
    {
      event_id: '00000000-0000-0000-0000-000000000001',
      role: 'context' as const,
      added_by: 'analyst@example.test',
      note: 'Matched saved query.',
      added_at: '2026-11-01T10:00:01Z',
    },
  ],
  findings: [],
  conclusion: null,
  audit_history: [],
  created_at: '2026-11-01T10:00:00Z',
  updated_at: '2026-11-01T10:00:01Z',
  revision: 3,
};

describe('HuntsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('lists saved hunts and opens the investigation workspace', async () => {
    mockApi.hunt.mockResolvedValue(hunt);
    mockApi.hunts.mockResolvedValue({
      hunts: [hunt],
      total_count: 1,
      returned_count: 1,
      truncated: false,
    });

    render(
      <MemoryRouter initialEntries={['/hunts']}>
        <Routes>
          <Route path="/hunts" element={<HuntsPage />} />
          <Route path="/hunts/:id" element={<HuntsPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('Suspicious PowerShell execution')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('link', { name: /Suspicious PowerShell execution/i }));

    await waitFor(() => expect(mockApi.hunt).toHaveBeenCalledWith('hunt-1'));
  });

  it('renders reproducible evidence and entity pivots in the hunt detail', async () => {
    mockApi.hunt.mockResolvedValue(hunt);

    render(
      <MemoryRouter initialEntries={['/hunts/hunt-1']}>
        <Routes>
          <Route path="/hunts/:id" element={<HuntsPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('PowerShell process events')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /workstation-01 timeline and relationships/i })).toHaveAttribute(
      'href',
      '/entities/hostname/workstation-01',
    );
    expect(screen.getByRole('link', { name: /evidence/i })).toHaveAttribute(
      'href',
      '/evidence/00000000-0000-0000-0000-000000000001',
    );
    expect(screen.getByRole('button', { name: /Export report JSON/i })).toBeInTheDocument();
  });
});
