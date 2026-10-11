import { BrowserRouter, Route, Routes, useParams } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { Header, MobileNav, Sidebar } from './components/Layout';
import { queryClient } from './lib/queryClient';
import { AlertDetailPage } from './pages/AlertDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { AttckPage } from './pages/AttckPage';
import { DashboardPage } from './pages/DashboardPage';
import { EntitiesPage, EntityDetailPage } from './pages/EntitiesPage';
import { IncidentDetailPage, IncidentsPage } from './pages/IncidentsPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { IocDetailPage, IocPage } from './pages/IocPage';
import { RuleDetailPage, RulesPage } from './pages/RulesPage';
import { EvidenceDetailPage } from './pages/EvidenceDetailPage';
import { EvidencePage } from './pages/EvidencePage';

function AlertDetailRoute() {
  const { id } = useParams<{ id: string }>();
  return <AlertDetailPage alertId={id ?? ''} />;
}

function IncidentDetailRoute() {
  const { id } = useParams<{ id: string }>();
  return <IncidentDetailPage incidentId={id ?? ''} />;
}

function RuleDetailRoute() {
  const { ruleId } = useParams<{ ruleId: string }>();
  return <RuleDetailPage />;
}

function EntityDetailRoute() {
  const { type, id } = useParams<{ type: string; id: string }>();
  return <EntityDetailPage type={type ?? ''} id={id ?? ''} />;
}

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Header />
        <main className="flex-1 p-4 sm:p-6">{children}</main>
        <MobileNav />
      </div>
    </div>
  );
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/alerts" element={<AlertsPage />} />
      <Route path="/alerts/:id" element={<AlertDetailRoute />} />
      <Route path="/incidents" element={<IncidentsPage />} />
      <Route path="/incidents/:id" element={<IncidentDetailRoute />} />
      <Route path="/entities/:type/:id" element={<EntityDetailRoute />} />
      <Route path="/entities" element={<EntitiesPage />} />
      <Route path="/attck" element={<AttckPage />} />
      <Route path="/rules" element={<RulesPage />} />
      <Route path="/rules/:ruleId" element={<RuleDetailRoute />} />
      <Route path="/iocs" element={<IocPage />} />
      <Route path="/iocs/:indicator" element={<IocDetailPage />} />
      <Route path="/evidence" element={<EvidencePage />} />
      <Route path="/evidence/:id" element={<EvidenceDetailPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppShell>
          <AppRoutes />
        </AppShell>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
