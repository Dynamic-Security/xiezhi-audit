import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import './shared/tokens/tokens.css';
import { ApiError, initSession } from './shared/api/client';
import { ToastProvider } from './shared/ui';
import { router } from './router';
import { SessionRequired } from './features/auth/SessionRequired';

// Sessions live in server memory; after a service restart every request returns 401 → show the
// "need a new login link" page instead of a wall of errors.
let onSessionLost: () => void = () => undefined;
const lost = (e: unknown) => { if (e instanceof ApiError && e.code === 'AUTH_SESSION_REQUIRED') onSessionLost(); };

const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError: lost }),
  mutationCache: new MutationCache({ onError: lost }),
  defaultOptions: {
    queries: {
      staleTime: 5_000, refetchOnWindowFocus: true,
      retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 2,
    },
  },
});

function App() {
  const [state, setState] = useState<'loading' | 'ok' | 'denied'>('loading');
  onSessionLost = () => setState('denied');
  useEffect(() => {
    initSession().then((s) => setState(s.authenticated ? 'ok' : 'denied'), () => setState('denied'));
  }, []);
  if (state === 'loading') return null;
  if (state === 'denied') return <SessionRequired />;
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <RouterProvider router={router} />
      </ToastProvider>
    </QueryClientProvider>
  );
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
