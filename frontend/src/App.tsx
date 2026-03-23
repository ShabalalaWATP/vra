import { Component, type ReactNode } from "react";
import { Routes, Route, Link } from "react-router-dom";
import AppShell from "./components/layout/AppShell";
import HomePage from "./pages/HomePage";
import NewScanPage from "./pages/NewScanPage";
import ScanProgressPage from "./pages/ScanProgressPage";
import ReportPage from "./pages/ReportPage";
import HistoryPage from "./pages/HistoryPage";
import SettingsPage from "./pages/SettingsPage";

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

export default function App() {
  return (
    <AppShell>
      <ErrorBoundary>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/scan/new" element={<NewScanPage />} />
          <Route path="/scan/:scanId/progress" element={<ScanProgressPage />} />
          <Route path="/scan/:scanId/report" element={<ReportPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </ErrorBoundary>
    </AppShell>
  );
}
