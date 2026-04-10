import { Component, Suspense, lazy, type ReactNode } from "react";
import { Routes, Route, Link } from "react-router-dom";
import AppShell from "./components/layout/AppShell";
import HomePage from "./pages/HomePage";

const NewScanPage = lazy(() => import("./pages/NewScanPage"));
const ScanProgressPage = lazy(() => import("./pages/ScanProgressPage"));
const ReportPage = lazy(() => import("./pages/ReportPage"));
const HistoryPage = lazy(() => import("./pages/HistoryPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div className="flex items-center justify-center h-[60vh]">
          <div className="text-center max-w-lg">
            <h1 className="text-4xl font-bold text-accent-danger mb-4">Something went wrong</h1>
            <p className="text-text-secondary mb-4">{this.state.error.message}</p>
            <button
              onClick={() => { this.setState({ error: null }); window.location.href = "/"; }}
              className="px-4 py-2 rounded bg-accent-primary text-white hover:bg-accent-primary/80"
            >
              Back to Home
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function NotFoundPage() {
  return (
    <div className="flex items-center justify-center h-[60vh]">
      <div className="text-center">
        <h1 className="text-6xl font-bold text-text-muted mb-4">404</h1>
        <p className="text-text-secondary mb-6">Page not found</p>
        <Link to="/" className="btn-primary">Back to Home</Link>
      </div>
    </div>
  );
}

function RouteFallback() {
  return (
    <div className="flex items-center justify-center h-[60vh]">
      <div className="flex items-center gap-3 text-text-secondary">
        <div className="w-5 h-5 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
        <span className="text-sm uppercase tracking-[0.2em]">Loading view</span>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppShell>
      <ErrorBoundary>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/scan/new" element={<NewScanPage />} />
            <Route path="/scan/:scanId/progress" element={<ScanProgressPage />} />
            <Route path="/scan/:scanId/report" element={<ReportPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Suspense>
      </ErrorBoundary>
    </AppShell>
  );
}
