import { Component, type ErrorInfo, type ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    hasError: false,
  };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('NetShield UI crashed', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'var(--bg-primary)',
            color: 'var(--text-primary)',
            padding: '24px',
          }}
        >
          <div
            style={{
              maxWidth: '520px',
              width: '100%',
              background: 'var(--glass-bg)',
              border: '1px solid var(--accent-red)',
              borderRadius: '12px',
              padding: '28px',
              textAlign: 'center',
            }}
          >
            <h1 style={{ fontSize: '22px', marginBottom: '12px', color: 'var(--accent-red)' }}>
              Dashboard Unavailable
            </h1>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '18px', lineHeight: 1.6 }}>
              The NetShield dashboard hit an unexpected client-side error. Refresh the page to
              retry, and check the browser console if the problem persists.
            </p>
            <button
              className="btn btn-danger"
              onClick={() => window.location.reload()}
              style={{ minWidth: '160px' }}
            >
              Reload Dashboard
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
