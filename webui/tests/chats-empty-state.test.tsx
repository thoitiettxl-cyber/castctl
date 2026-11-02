// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import '@/i18n';
import { ChatsPage } from '../src/pages/ChatsPage';

// B1 regression: a failed sessions/history load must show the
// error box + Retry only — never the "No sessions yet" /
// "No messages yet" empty states underneath it. Plain createRoot
// + act() (the button-ref-dom pattern); no Testing Library.
// The API module is mocked at the service boundary: profiles
// load fine, both chat loads reject.

vi.mock('@/services/api', () => ({
  statusApi: { get: () => Promise.resolve({ default_profile: 'muse01' }) },
  profilesApi: { list: () => Promise.resolve([{ name: 'muse01' }]) },
  chatsApi: {
    list: () => Promise.reject(new Error('sessions boom')),
    history: () => Promise.reject(new Error('history boom')),
    create: () => Promise.reject(new Error('unused')),
    job: () => Promise.reject(new Error('unused')),
    op: () => Promise.reject(new Error('unused')),
  },
}));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe('ChatsPage failed load', () => {
  let container: HTMLDivElement | null = null;
  let root: Root | null = null;

  afterEach(() => {
    if (root) {
      act(() => {
        root?.unmount();
      });
      root = null;
    }
    container?.remove();
    container = null;
    vi.clearAllMocks();
  });

  it('shows error + Retry, no EmptyState, when sessions and history fail', async () => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => {
      root?.render(
        <MemoryRouter>
          <ChatsPage />
        </MemoryRouter>,
      );
    });
    // Flush the loadProfiles -> loadSessions/loadHistory chains.
    await act(async () => {
      await vi.waitFor(() => {
        expect(container?.textContent).toContain('sessions boom');
      });
    });
    const text = container?.textContent ?? '';
    expect(text).toContain('sessions boom');
    expect(text).toContain('history boom');
    expect(text).not.toContain('No sessions yet.');
    expect(text).not.toContain('No messages yet.');
    expect(text).toContain('Retry');
  });
});
