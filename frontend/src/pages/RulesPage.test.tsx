import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    rules: vi.fn(),
    ruleDetail: vi.fn(),
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
  useRules: vi.fn(),
  useRuleDetail: vi.fn(),
}));

import { useRules, useRuleDetail } from '../hooks/useQueries';
import { RulesPage, RuleDetailPage } from './RulesPage';

const mockUseRules = useRules as ReturnType<typeof vi.fn>;
const mockUseRuleDetail = useRuleDetail as ReturnType<typeof vi.fn>;
const mockApi = vi.mocked(await import('../lib/api')).api;

const sampleRules = {
  rules: [
    {
      rule_id: 'rule-001',
      name: 'Port Scan Detection',
      description: 'Detects port scanning behavior',
      enabled: true,
      detector_class: 'PortScanDetector',
      version: '1.0.0',
      confidence: 0.85,
      parameters: { threshold: 100 },
      attck_mappings: [
        {
          technique_id: 'T1046',
          subtechnique_id: null,
          mapping_type: 'detected_by',
          rationale: 'Port scanning is detected by this rule',
        },
      ],
    },
    {
      rule_id: 'rule-002',
      name: 'Brute Force Detection',
      description: 'Detects brute force login attempts',
      enabled: false,
      detector_class: 'BruteForceDetector',
      version: '2.1.0',
      confidence: 0.92,
      parameters: {},
      attck_mappings: [],
    },
  ],
  total_count: 2,
};

describe('RulesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders loading state', () => {
    mockUseRules.mockReturnValue({
      data: null,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );
    expect(screen.getByText(/Runtime detection rule registry/i)).toBeInTheDocument();
  });

  it('renders error state', () => {
    mockUseRules.mockReturnValue({
      data: null,
      isLoading: false,
      error: new Error('API error'),
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );
    expect(screen.getByText(/Unable to load rules/i)).toBeInTheDocument();
  });

  it('renders empty state when no rules', () => {
    mockUseRules.mockReturnValue({
      data: { rules: [], total_count: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );
    expect(screen.getByText(/No detection rules are currently loaded/i)).toBeInTheDocument();
  });

  it('renders empty state when filters match no rules', () => {
    mockUseRules.mockReturnValue({
      data: { rules: [], total_count: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/No detection rules are currently loaded/i)).toBeInTheDocument();
  });

  it('renders rule list with rules', () => {
    mockUseRules.mockReturnValue({
      data: sampleRules,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/rule-001/i)).toBeInTheDocument();
    expect(screen.getByText(/rule-002/i)).toBeInTheDocument();
    expect(screen.getByText(/Port Scan Detection/i)).toBeInTheDocument();
    expect(screen.getByText(/Brute Force Detection/i)).toBeInTheDocument();
    expect(screen.getByText(/2 rules loaded/i)).toBeInTheDocument();
  });

  it('renders Enabled/Disabled badges', () => {
    mockUseRules.mockReturnValue({
      data: sampleRules,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );

    expect(screen.getAllByText(/Enabled/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Disabled/i).length).toBeGreaterThan(0);
  });

  it('toggles enabled filter', () => {
    mockUseRules.mockReturnValue({
      data: sampleRules,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );

    const disabledButton = screen.getByRole('button', { name: /Disabled/i });
    fireEvent.click(disabledButton);

    const calls = mockUseRules.mock.calls;
    const filteredCall = calls.find(
      (args) => args[0]?.enabled === false,
    );
    expect(filteredCall).toBeDefined();
    expect(filteredCall![0]).toMatchObject({ enabled: false, detector_class: undefined });
  });

  it('filters by detector class', () => {
    mockUseRules.mockReturnValue({
      data: sampleRules,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );

    const detectorInput = screen.getByPlaceholderText(/PortScanDetector/i);
    fireEvent.change(detectorInput, { target: { value: 'PortScanDetector' } });

    const calls = mockUseRules.mock.calls;
    const filteredCall = calls.find(
      (args) => args[0]?.detector_class === 'PortScanDetector',
    );
    expect(filteredCall).toBeDefined();
    expect(filteredCall![0]).toMatchObject({ enabled: undefined, detector_class: 'PortScanDetector' });
  });

  it('renders detail links for rules', () => {
    mockUseRules.mockReturnValue({
      data: sampleRules,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    );

    const detailLinks = screen.getAllByText(/Detail/i);
    expect(detailLinks.length).toBeGreaterThan(0);
    expect(detailLinks[0]).toHaveAttribute('href', '/rules/rule-001');
  });
});

describe('RuleDetailPage', () => {
  const renderWithRouter = (initialPath: string = '/rules/rule-001') => {
    return render(
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders loading state', () => {
    mockUseRuleDetail.mockReturnValue({
      data: null,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/Rule detail/i)).toBeInTheDocument();
  });

  it('renders error state', () => {
    mockUseRuleDetail.mockReturnValue({
      data: null,
      isLoading: false,
      error: new Error('API error'),
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/Unable to load rule details/i)).toBeInTheDocument();
  });

  it('renders not found state', () => {
    mockUseRuleDetail.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/Rule not found/i)).toBeInTheDocument();
  });

  it('renders rule detail with populated data', () => {
    mockUseRuleDetail.mockReturnValue({
      data: {
        rule_id: 'rule-001',
        name: 'Port Scan Detection',
        description: 'Detects port scanning behavior',
        enabled: true,
        detector_class: 'PortScanDetector',
        version: '1.0.0',
        confidence: 0.85,
        parameters: { threshold: 100 },
        attck_mappings: [
          {
            technique_id: 'T1046',
            subtechnique_id: null,
            mapping_type: 'detected_by',
            rationale: 'Port scanning is detected by this rule',
          },
        ],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/Port Scan Detection/i)).toBeInTheDocument();
    expect(screen.getByText(/Detects port scanning behavior/i)).toBeInTheDocument();
    expect(screen.getByText(/PortScanDetector/i)).toBeInTheDocument();
    expect(screen.getByText(/1.0.0/i)).toBeInTheDocument();
    expect(screen.getByText(/0.85/i)).toBeInTheDocument();
  });

  it('renders ATT&CK mappings section', () => {
    mockUseRuleDetail.mockReturnValue({
      data: {
        rule_id: 'rule-001',
        name: 'Port Scan Detection',
        description: 'Detects port scanning behavior',
        enabled: true,
        detector_class: 'PortScanDetector',
        version: '1.0.0',
        confidence: 0.85,
        parameters: {},
        attck_mappings: [
          {
            technique_id: 'T1046',
            subtechnique_id: null,
            mapping_type: 'detected_by',
            rationale: 'Port scanning is detected by this rule',
          },
        ],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/T1046/i)).toBeInTheDocument();
    expect(screen.getByText(/detected_by/i)).toBeInTheDocument();
  });

  it('shows empty ATT&CK mappings message', () => {
    mockUseRuleDetail.mockReturnValue({
      data: {
        rule_id: 'rule-001',
        name: 'Port Scan Detection',
        description: 'Detects port scanning behavior',
        enabled: true,
        detector_class: 'PortScanDetector',
        version: '1.0.0',
        confidence: 0.85,
        parameters: {},
        attck_mappings: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/No ATT&CK mappings registered/i)).toBeInTheDocument();
  });

  it('renders parameters section', () => {
    mockUseRuleDetail.mockReturnValue({
      data: {
        rule_id: 'rule-001',
        name: 'Port Scan Detection',
        description: 'Detects port scanning behavior',
        enabled: true,
        detector_class: 'PortScanDetector',
        version: '1.0.0',
        confidence: 0.85,
        parameters: { threshold: 100, window_seconds: 60 },
        attck_mappings: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/threshold/i)).toBeInTheDocument();
    expect(screen.getByText(/60/i)).toBeInTheDocument();
  });

  it('shows empty parameters message', () => {
    mockUseRuleDetail.mockReturnValue({
      data: {
        rule_id: 'rule-001',
        name: 'Port Scan Detection',
        description: 'Detects port scanning behavior',
        enabled: true,
        detector_class: 'PortScanDetector',
        version: '1.0.0',
        confidence: 0.85,
        parameters: {},
        attck_mappings: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/No configuration parameters registered/i)).toBeInTheDocument();
  });

  it('renders back link to rules list', () => {
    mockUseRuleDetail.mockReturnValue({
      data: {
        rule_id: 'rule-001',
        name: 'Port Scan Detection',
        description: 'Detects port scanning behavior',
        enabled: true,
        detector_class: 'PortScanDetector',
        version: '1.0.0',
        confidence: 0.85,
        parameters: {},
        attck_mappings: [],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const backLink = screen.getByRole('link', { name: /Back to catalog/i });
    expect(backLink).toBeInTheDocument();
    expect(backLink).toHaveAttribute('href', '/rules');
  });
});
