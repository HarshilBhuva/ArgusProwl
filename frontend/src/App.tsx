import { BrowserRouter, Route, Routes, useParams } from 'react-router-dom';
import { type FormEvent, type ReactNode, useCallback, useEffect, useState } from 'react';
import { QueryClientProvider } from '@tanstack/react-query';
import { Header, MobileNav, Sidebar } from './components/Layout';
import { queryClient } from './lib/queryClient';
import { ApiClientError, api, setBrowserSessionActive } from './lib/api';
import type { AuthPrincipalResponse } from './types/api';
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
import { HuntsPage } from './pages/HuntsPage';

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


function authErrorMessage(error: unknown): string {
  return error instanceof ApiClientError
    ? error.userMessage
    : "Unable to verify browser authentication with the ArgusProwl API.";
}

function AuthGate({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<"checking" | "ready" | "login" | "unavailable">("checking");
  const [principal, setPrincipal] = useState<AuthPrincipalResponse | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const checkAuthentication = useCallback(async () => {
    setPhase("checking");
    setError(null);
    try {
      const status = await api.authStatus();
      if (!status.auth_enabled) {
        setBrowserSessionActive(false);
        setPrincipal(null);
        setPhase("ready");
        return;
      }
      try {
        const current = await api.authMe();
        setBrowserSessionActive(true);
        setPrincipal(current);
        setPhase("ready");
      } catch (authError) {
        if (authError instanceof ApiClientError && authError.statusCode === 401) {
          setBrowserSessionActive(false);
          setPrincipal(null);
          setPhase("login");
        } else {
          throw authError;
        }
      }
    } catch (authError) {
      setError(authErrorMessage(authError));
      setPhase("unavailable");
    }
  }, []);

  useEffect(() => {
    void checkAuthentication();
  }, [checkAuthentication]);

  useEffect(() => {
    const handleSessionExpired = () => {
      setBrowserSessionActive(false);
      setPrincipal(null);
      setPhase("login");
      setError("Your session expired or the API key was revoked. Sign in again.");
    };
    window.addEventListener("argusprowl:session-expired", handleSessionExpired);
    return () => window.removeEventListener("argusprowl:session-expired", handleSessionExpired);
  }, []);

  const signIn = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!apiKey.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.createSession(apiKey);
      setApiKey("");
      const current = await api.authMe();
      setBrowserSessionActive(true);
      setPrincipal(current);
      setPhase("ready");
    } catch (authError) {
      setError(authErrorMessage(authError));
      setPhase("login");
    } finally {
      setApiKey("");
      setBusy(false);
    }
  };

  const signOut = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.logout();
      setBrowserSessionActive(false);
      setPrincipal(null);
      setPhase("login");
    } catch (authError) {
      setError(authErrorMessage(authError));
    } finally {
      setBusy(false);
    }
  };

  if (phase === "checking") {
    return <div className="min-h-screen bg-background p-8 text-sm text-muted-foreground">Checking API authentication…</div>;
  }

  if (phase === "unavailable") {
    return (
      <div className="mx-auto flex min-h-screen max-w-xl items-center justify-center bg-background p-6">
        <div className="w-full border border-border bg-surface p-5">
          <h1 className="text-lg font-semibold text-foreground">Authentication service unavailable</h1>
          <p className="mt-2 text-sm text-muted-foreground">{error}</p>
          <button type="button" onClick={() => void checkAuthentication()} className="mt-4 rounded-sm border border-border px-3 py-2 text-xs font-medium text-foreground hover:bg-muted">Retry</button>
        </div>
      </div>
    );
  }

  if (phase === "login") {
    return (
      <div className="mx-auto flex min-h-screen max-w-xl items-center justify-center bg-background p-6">
        <div className="w-full border border-border bg-surface p-5">
          <p className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">ArgusProwl · Threat Hunter Console</p>
          <h1 className="mt-2 text-xl font-semibold text-foreground">Sign in</h1>
          <p className="mt-1 text-xs text-muted-foreground">Enter an enabled ArgusProwl API key. The key is exchanged for a short-lived HttpOnly browser session and is not stored in browser storage.</p>
          <form onSubmit={signIn} className="mt-5 space-y-3">
            <label className="block">
              <span className="mb-1 block text-[10px] font-mono uppercase tracking-wider text-muted-foreground">API key</span>
              <input
                type="password"
                autoComplete="current-password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                className="w-full rounded-sm border border-border bg-background px-3 py-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                required
              />
            </label>
            {error && <p role="alert" className="text-xs text-red-600">{error}</p>}
            <button type="submit" disabled={busy || !apiKey.trim()} className="rounded-sm border border-primary bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-50">{busy ? "Signing in…" : "Sign in"}</button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <>
      {principal && (
        <div className="flex items-center justify-end gap-3 border-b border-border bg-surface px-4 py-1.5 text-[10px] text-muted-foreground">
          <span>Signed in as <strong className="text-foreground">{principal.subject}</strong> · {principal.role}</span>
          <button type="button" disabled={busy} onClick={() => void signOut()} className="font-medium text-primary hover:underline disabled:opacity-50">Sign out</button>
        </div>
      )}
      {error && principal && <p role="alert" className="bg-amber-500/10 px-4 py-2 text-xs text-amber-700">{error}</p>}
      {children}
    </>
  );
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/alerts" element={<AlertsPage />} />
      <Route path="/hunts" element={<HuntsPage />} />
      <Route path="/hunts/:id" element={<HuntsPage />} />
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
        <AuthGate>
          <AppShell>
            <AppRoutes />
          </AppShell>
        </AuthGate>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
