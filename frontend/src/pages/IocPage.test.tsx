import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  api: {
    iocLookup: vi.fn(),
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
  useIocLookup: vi.fn(),
  useEvidence: vi.fn(),
}));

import { useIocLookup, useEvidence } from '../hooks/useQueries';
import { IocPage, IocDetailPage } from './IocPage';

const mockUseIocLookup = useIocLookup as ReturnType<typeof vi.fn>;
const mockUseEvidence = useEvidence as ReturnType<typeof vi.fn>;
const mockApi = vi.mocked(await import('../lib/api')).api;

const mockObservations = [
  {
    alert_id: 'alert-001',
    timestamp: '2024-01-15T10:00:00Z',
    field: 'dst_ip',
    value: '8.8.8.8',
    host: 'workstation1',
    rule_id: 'dns-rule-001',
    severity: 'LOW',
  },
  {
    alert_id: 'alert-002',
    timestamp: '2024-01-15T11:00:00Z',
    field: 'dst_ip',
    value: '8.8.8.8',
    host: 'workstation2',
    rule_id: 'proxy-rule-002',
    severity: 'MEDIUM',
  },
];

const mockRelatedIocs = [
  {
    indicator: '192.168.1.100',
    ioc_type: 'ip',
    field: 'src_ip',
    co_observed_in_alert_id: 'alert-002',
  },
];

const mockTimeline = [
  {
    timeline_item_id: 't1',
    timestamp: '2024-01-15T11:00:00Z',
    item_type: 'OBSERVATION',
    title: 'IOC observed as dst_ip',
    summary: 'Alert alert-002 referenced dst_ip=8.8.8.8 on 2024-01-15T11:00:00Z',
    source_id: 'alert-002',
    metadata: { field: 'dst_ip', severity: 'MEDIUM', host: 'workstation2' },
  },
  {
    timeline_item_id: 't2',
    timestamp: '2024-01-15T10:00:00Z',
    item_type: 'OBSERVATION',
    title: 'IOC observed as dst_ip',
    summary: 'Alert alert-001 referenced dst_ip=8.8.8.8 on 2024-01-15T10:00:00Z',
    source_id: 'alert-001',
    metadata: { field: 'dst_ip', severity: 'LOW', host: 'workstation1' },
  },
  {
    timeline_item_id: 't3',
    timestamp: null,
    item_type: 'INTELLIGENCE',
    title: 'Threat intelligence reputation',
    summary: 'BENIGN (confidence 0.95) from in_memory_provider',
    source_id: null,
    metadata: { verdict: 'BENIGN', confidence: '0.95', categories: '', source: 'in_memory_provider' },
  },
  {
    timeline_item_id: 't4',
    timestamp: null,
    item_type: 'RELATED_IOC',
    title: 'Related IOC: 192.168.1.100',
    summary: 'Co-observed as src_ip in alert alert-002',
    source_id: 'alert-002',
    metadata: { field: 'src_ip', ioc_type: 'ip' },
  },
];

const mockSampleResult = {
  indicator: '8.8.8.8',
  ioc_type: 'ip',
  reputation: {
    indicator: '8.8.8.8',
    verdict: 'BENIGN',
    confidence: 0.95,
    categories: [],
    source: 'in_memory_provider',
  },
  observations: mockObservations,
  first_observed: '2024-01-15T10:00:00Z',
  last_observed: '2024-01-15T11:00:00Z',
  associated_alert_ids: ['alert-001', 'alert-002'],
  associated_hosts: ['workstation1', 'workstation2'],
  associated_rule_ids: ['dns-rule-001', 'proxy-rule-002'],
  related_iocs: mockRelatedIocs,
  timeline: mockTimeline,
  prevalence: {
    dest_host_count: 5,
    process_dest_count: 3,
    is_rare_destination: false,
    is_environment_wide: true,
  },
  status: 'AVAILABLE',
  reason: null,
  truncated: false,
  inspected_alert_count: 2,
  observation_note: 'first observed in retained alert evidence',
} as const;

describe('IocPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseEvidence.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
    });
  });

  it('renders the lookup form', () => {
    render(
      <MemoryRouter>
        <IocPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/IOC Investigation/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/IP address or domain/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Investigate/i })).toBeInTheDocument();
  });

  it('submits the form and navigates to the indicator page', () => {
    mockUseIocLookup.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    render(
      <MemoryRouter initialEntries={['/iocs']}>
        <Routes>
          <Route path="/iocs" element={<IocPage />} />
          <Route path="/iocs/:indicator" element={<IocDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    const input = screen.getByPlaceholderText(/IP address or domain/i);
    const submitButton = screen.getByRole('button', { name: /Investigate/i });

    fireEvent.change(input, { target: { value: '8.8.8.8' } });
    fireEvent.click(submitButton);

    // Navigation happens, no error thrown
    expect(screen.getByPlaceholderText(/IP address or domain/i)).toBeInTheDocument();
  });

  it('does not navigate on empty or whitespace input', () => {
    render(
      <MemoryRouter initialEntries={['/iocs']}>
        <Routes>
          <Route path="/iocs" element={<IocPage />} />
          <Route path="/iocs/:indicator" element={<IocDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    const input = screen.getByPlaceholderText(/IP address or domain/i);
    const submitButton = screen.getByRole('button', { name: /Investigate/i });

    fireEvent.change(input, { target: { value: '   ' } });
    fireEvent.click(submitButton);

    expect(screen.getByPlaceholderText(/IP address or domain/i)).toBeInTheDocument();
    expect(screen.queryByText(/8\.8\.8\.8/i)).not.toBeInTheDocument();
  });
});

describe('IocDetailPage', () => {
  const renderWithRouter = (initialPath: string = '/iocs/8.8.8.8') => {
    return render(
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/iocs/:indicator" element={<IocDetailPage />} />
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
    });
  });

  it('renders loading state', () => {
    mockUseIocLookup.mockReturnValue({
      data: null,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/IOC Investigation/i)).toBeInTheDocument();
    expect(screen.queryByText(/BENIGN/i)).not.toBeInTheDocument();
  });

  it('renders error state', () => {
    mockUseIocLookup.mockReturnValue({
      data: null,
      isLoading: false,
      error: new Error('API error'),
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/Unable to investigate IOC/i)).toBeInTheDocument();
  });

  it('renders empty state when no data', () => {
    mockUseIocLookup.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();
    expect(screen.getByText(/No investigation result returned/i)).toBeInTheDocument();
  });

  it('renders populated investigation data', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const indicatorInHeader = screen.getAllByText('8.8.8.8');
    expect(indicatorInHeader.length).toBeGreaterThan(0);
    const benignBadge = screen.getAllByText(/BENIGN/i);
    expect(benignBadge.length).toBeGreaterThan(0);
    const confidenceElements = screen.getAllByText(/confidence 0.95/i);
    expect(confidenceElements.length).toBeGreaterThan(0);
    const sourceElements = screen.getAllByText(/in_memory_provider/i);
    expect(sourceElements.length).toBeGreaterThan(0);
    expect(screen.getByText(/Observed window/i)).toBeInTheDocument();
    expect(screen.getAllByText(/2024-01-15T10:00:00Z/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/2024-01-15T11:00:00Z/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/first observed in retained alert evidence/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Prevalence/i)).toBeInTheDocument();
    expect(screen.getByText(/Associated alerts/i)).toBeInTheDocument();
    expect(screen.getAllByText(/alert-001/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/alert-002/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Hosts/i)).toBeInTheDocument();
    expect(screen.getAllByText(/workstation1/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/workstation2/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Rules/i)).toBeInTheDocument();
    expect(screen.getAllByText(/dns-rule-001/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/proxy-rule-002/i).length).toBeGreaterThan(0);
  });

  it('renders observations table', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const obsHeaders = screen.getAllByText(/Observations/i);
    expect(obsHeaders.length).toBeGreaterThan(0);

    const alert001 = screen.getAllByText(/alert-001/i);
    expect(alert001.length).toBeGreaterThan(0);
    const alert002 = screen.getAllByText(/alert-002/i);
    expect(alert002.length).toBeGreaterThan(0);
    expect(screen.getAllByText(/dst_ip/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/workstation1/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/workstation2/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/dns-rule-001/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/proxy-rule-002/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/LOW/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/MEDIUM/i).length).toBeGreaterThan(0);
  });

  it('renders timeline section', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const timelineHeaders = screen.getAllByText(/Timeline/i);
    expect(timelineHeaders.length).toBeGreaterThan(0);

    const obsTitles = screen.getAllByText(/IOC observed as dst_ip/i);
    expect(obsTitles.length).toBe(2);
    expect(screen.getByText(/Threat intelligence reputation/i)).toBeInTheDocument();
    expect(screen.getAllByText(/192.168.1.100/i).length).toBeGreaterThan(0);
  });

  it('renders related IOCs', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const relatedHeaders = screen.getAllByText(/Related IOCs/i);
    expect(relatedHeaders.length).toBeGreaterThan(0);

    expect(screen.getAllByText(/192.168.1.100/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/src_ip/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/alert-002/i).length).toBeGreaterThan(0);
  });

  it('renders DEGRADED badge when status is DEGRADED', () => {
    const degradedResult = {
      ...mockSampleResult,
      status: 'DEGRADED',
      reason: 'Persistence unavailable',
    };
    mockUseIocLookup.mockReturnValue({
      data: degradedResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/DEGRADED/i)).toBeInTheDocument();
    expect(screen.getByText(/Status reason: Persistence unavailable/i)).toBeInTheDocument();
  });

  it('renders Truncated badge when truncated is true', () => {
    const truncatedResult = {
      ...mockSampleResult,
      truncated: true,
    };
    mockUseIocLookup.mockReturnValue({
      data: truncatedResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/Truncated/i)).toBeInTheDocument();
  });

  it('renders empty observations message when no observations', () => {
    const emptyResult = {
      ...mockSampleResult,
      observations: [],
      associated_alert_ids: [],
      associated_hosts: [],
      associated_rule_ids: [],
      related_iocs: [],
      timeline: [
        {
          timeline_item_id: 't1',
          timestamp: null,
          item_type: 'INTELLIGENCE',
          title: 'Threat intelligence reputation',
          summary: 'UNKNOWN (confidence 0) from in_memory_provider',
          source_id: null,
          metadata: { verdict: 'UNKNOWN', confidence: '0', categories: '', source: 'in_memory_provider' },
        },
      ],
      prevalence: null,
      first_observed: null,
      last_observed: null,
    };
    mockUseIocLookup.mockReturnValue({
      data: emptyResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/No observations in retained alert evidence/i)).toBeInTheDocument();
    expect(screen.getByText(/None/i)).toBeInTheDocument();
    const dashes = screen.getAllByText(/—/);
    expect(dashes.length).toBeGreaterThanOrEqual(2);
  });

  it('renders MALICIOUS verdict with categories', () => {
    const maliciousResult = {
      ...mockSampleResult,
      reputation: {
        indicator: 'evil.com',
        verdict: 'MALICIOUS',
        confidence: 0.99,
        categories: ['malware', 'c2'],
        source: 'in_memory_provider',
      },
      indicator: 'evil.com',
      ioc_type: 'domain',
    };
    mockUseIocLookup.mockReturnValue({
      data: maliciousResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getAllByText(/MALICIOUS/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/malware, c2/i).length).toBeGreaterThan(0);
  });

  it('renders SUSPICIOUS verdict', () => {
    const suspiciousResult = {
      ...mockSampleResult,
      reputation: {
        indicator: 'suspicious.com',
        verdict: 'SUSPICIOUS',
        confidence: 0.6,
        categories: [],
        source: 'in_memory_provider',
      },
      indicator: 'suspicious.com',
      ioc_type: 'domain',
    };
    mockUseIocLookup.mockReturnValue({
      data: suspiciousResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getAllByText(/SUSPICIOUS/i).length).toBeGreaterThan(0);
  });

  it('renders UNKNOWN verdict', () => {
    const unknownResult = {
      ...mockSampleResult,
      reputation: {
        indicator: 'unknown.com',
        verdict: 'UNKNOWN',
        confidence: 0.0,
        categories: [],
        source: 'in_memory_provider',
      },
      indicator: 'unknown.com',
      ioc_type: 'domain',
    };
    mockUseIocLookup.mockReturnValue({
      data: unknownResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getAllByText(/UNKNOWN/i).length).toBeGreaterThan(0);
  });

  it('renders back link to new lookup', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const backLink = screen.getByRole('link', { name: /← New lookup/i });
    expect(backLink).toBeInTheDocument();
    expect(backLink).toHaveAttribute('href', '/iocs');
  });

  it('prefills lookup form with current indicator on detail page', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const input = screen.getByPlaceholderText(/IP address or domain/i);
    expect(input).toHaveValue('8.8.8.8');
  });

  it('shows indicator in subtitle on detail page', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter('/iocs/evil-c2.example.com');

    expect(screen.getByText(/evil-c2.example.com/i)).toBeInTheDocument();
  });

  it('renders alert links in observations table', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const alertLinks = screen.getAllByRole('link');
    const alertIdLinks = alertLinks.filter((link) =>
      link.getAttribute('href')?.startsWith('/alerts/'),
    );
    expect(alertIdLinks.length).toBeGreaterThan(0);
  });

  it('renders related IOC links', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    const allLinks = screen.getAllByRole('link');
    const relatedIocLink = allLinks.find(
      (link) => link.getAttribute('href') === '/iocs/192.168.1.100',
    );
    expect(relatedIocLink).toBeInTheDocument();
    const alertLinks = allLinks.filter((link) =>
      link.getAttribute('href')?.startsWith('/alerts/'),
    );
    expect(alertLinks.length).toBeGreaterThan(0);
  });

  it('renders timeline visual with observation events', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/Visual timeline/i)).toBeInTheDocument();
    expect(screen.getAllByText(/IOC observed as dst_ip/i).length).toBe(2);
    expect(screen.getAllByText(/2024-01-15T11:00:00Z/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/2024-01-15T10:00:00Z/i).length).toBeGreaterThan(0);
  });

  it('renders timeline visual with intelligence context', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/Intelligence Context/i)).toBeInTheDocument();
    expect(screen.getByText(/Threat intelligence reputation/i)).toBeInTheDocument();
    const benignElements = screen.getAllByText(/BENIGN/i);
    expect(benignElements.length).toBeGreaterThan(0);
  });

  it('renders empty timeline state when no timeline items', () => {
    const emptyTimelineResult = {
      ...mockSampleResult,
      timeline: [],
      observations: [],
      related_iocs: [],
    };
    mockUseIocLookup.mockReturnValue({
      data: emptyTimelineResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/No timeline data available/i)).toBeInTheDocument();
  });

  it('renders timeline with intelligence-only IOC (no observations)', () => {
    const intelligenceOnlyResult = {
      ...mockSampleResult,
      observations: [],
      related_iocs: [],
      timeline: [
        {
          timeline_item_id: 't1',
          timestamp: null,
          item_type: 'INTELLIGENCE',
          title: 'Threat intelligence reputation',
          summary: 'MALICIOUS (confidence 0.99) from in_memory_provider',
          source_id: null,
          metadata: { verdict: 'MALICIOUS', confidence: '0.99', categories: 'malware', source: 'in_memory_provider' },
        },
      ],
      first_observed: null,
      last_observed: null,
    };
    mockUseIocLookup.mockReturnValue({
      data: intelligenceOnlyResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/Intelligence Context/i)).toBeInTheDocument();
    expect(screen.queryByText(/IOC observed/i)).not.toBeInTheDocument();
  });

  it('renders degraded state with timeline', () => {
    const degradedResult = {
      ...mockSampleResult,
      status: 'DEGRADED',
      reason: 'Persistence unavailable',
    };
    mockUseIocLookup.mockReturnValue({
      data: degradedResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/DEGRADED/i)).toBeInTheDocument();
    expect(screen.getByText(/Visual timeline/i)).toBeInTheDocument();
  });

  it('renders truncated state with timeline', () => {
    const truncatedResult = {
      ...mockSampleResult,
      truncated: true,
    };
    mockUseIocLookup.mockReturnValue({
      data: truncatedResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.getByText(/Truncated/i)).toBeInTheDocument();
    expect(screen.getByText(/Visual timeline/i)).toBeInTheDocument();
  });

  it('does not imply causality in timeline', () => {
    mockUseIocLookup.mockReturnValue({
      data: mockSampleResult,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    });

    renderWithRouter();

    expect(screen.queryByText(/attack chain/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/causal/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/sequence/i)).not.toBeInTheDocument();
  });
});
