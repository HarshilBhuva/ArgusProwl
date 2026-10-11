import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    attckOverview: vi.fn(),
    attckInvestigation: vi.fn(),
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
  useAttckOverview: vi.fn(),
  useAttckInvestigation: vi.fn(),
  useAlerts: vi.fn(),
}));

import { useAttckOverview, useAttckInvestigation, useAlerts } from '../hooks/useQueries';
import { AttckPage } from './AttckPage';

const mockUseAttckOverview = useAttckOverview as ReturnType<typeof vi.fn>;
const mockUseAttckInvestigation = useAttckInvestigation as ReturnType<typeof vi.fn>;
const mockUseAlerts = useAlerts as ReturnType<typeof vi.fn>;

describe('AttckPage', () => {
  const mockOverview = {
    knowledge_status: 'AVAILABLE',
    attck_version: 'v14',
    total_techniques: 200,
    total_tactics: 14,
    mapping_count: 45,
    mapped_technique_ids: ['T1059'],
  };

  const mockAlertsData = {
    alerts: [
      {
        alert_id: 'alert-1',
        title: 'Test Alert 1',
        description: 'desc',
        severity: 'HIGH' as const,
        priority: 'HIGH' as const,
        lifecycle_state: 'OPEN' as const,
        source: 'test',
        created_at: '2024-01-15T10:00:00Z',
        tags: [],
        metadata: {},
        schema_version: 1,
        entity_context: null,
        supporting_evidence: [],
        contradictory_evidence: [],
        investigation_pivots: [],
        incident_id: null,
      },
      {
        alert_id: 'alert-2',
        title: 'Test Alert 2',
        description: 'desc',
        severity: 'CRITICAL' as const,
        priority: 'HIGH' as const,
        lifecycle_state: 'OPEN' as const,
        source: 'test',
        created_at: '2024-01-15T11:00:00Z',
        tags: [],
        metadata: {},
        schema_version: 1,
        entity_context: null,
        supporting_evidence: [],
        contradictory_evidence: [],
        investigation_pivots: [],
        incident_id: null,
      },
    ],
    total_count: 2,
  };

  const mockTechniques = [
    {
      technique_id: 'T1059',
      mapping_type: 'DETECTS',
      technique_name: 'Command and Scripting Interpreter',
      tactic: 'execution',
      version: 'v14',
      source_alert_ids: ['alert-1'],
      evidence_refs: [],
      rationale: 'Maps to shell execution',
    },
  ];

  const renderPage = () => {
    return render(
      <MemoryRouter initialEntries={['/attck']}>
        <AttckPage />
      </MemoryRouter>
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseAttckOverview.mockReturnValue({
      isLoading: false,
      error: null,
      data: mockOverview,
      refetch: vi.fn(),
    });
    mockUseAlerts.mockReturnValue({
      isLoading: false,
      error: null,
      data: mockAlertsData,
      refetch: vi.fn(),
    });
    mockUseAttckInvestigation.mockReturnValue({
      isLoading: false,
      error: null,
      data: null,
      refetch: vi.fn(),
    });
  });

  it('renders knowledge base overview', () => {
    renderPage();
    expect(screen.getByText('AVAILABLE')).toBeInTheDocument();
    expect(screen.getByText('v14')).toBeInTheDocument();
    expect(screen.getByText('200')).toBeInTheDocument();
  });

  it('disables investigation button when no alerts selected', () => {
    renderPage();
    const button = screen.getByRole('button', { name: /run investigation/i });
    expect(button).toBeDisabled();
  });

  it('enables investigation button when alerts are selected', () => {
    renderPage();
    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[0]);
    const button = screen.getByRole('button', { name: /run investigation/i });
    expect(button).not.toBeDisabled();
  });

  it('shows technique results after running investigation', () => {
    mockUseAttckInvestigation.mockImplementation((alertIds: string[]) => ({
      isLoading: false,
      error: null,
      data: alertIds.length > 0 ? { alert_count: alertIds.length, techniques: mockTechniques } : null,
      refetch: vi.fn(),
    }));

    renderPage();
    const checkbox = screen.getAllByRole('checkbox')[0];
    fireEvent.click(checkbox);
    const button = screen.getByRole('button', { name: /run investigation/i });
    fireEvent.click(button);

    expect(screen.getByText('T1059')).toBeInTheDocument();
    expect(screen.getByText('Command and Scripting Interpreter')).toBeInTheDocument();
  });
});
