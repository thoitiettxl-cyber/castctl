import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { profilesApi, screencastApi } from '@/services/api';
import type { ProfileSummary, ScreencastStatus } from '@/types';
import { getErrorMessage } from '@/utils/helpers';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { Select } from '@/components/ui/Select';

type Phase = 'idle' | 'checking' | 'starting' | 'live' | 'ending' | 'ended';

interface TerminalReport {
  outcome: string;
  cookies_saved: boolean;
  saved_names?: string[];
  earliest_expiry?: string;
}

const BUTTON_NAMES = ['left', 'middle', 'right', 'back', 'forward'];

function modifiersOf(event: { altKey: boolean; ctrlKey: boolean; metaKey: boolean; shiftKey: boolean }): number {
  return (
    (event.altKey ? 1 : 0) | (event.ctrlKey ? 2 : 0) | (event.metaKey ? 4 : 0) | (event.shiftKey ? 8 : 0)
  );
}

/**
 * Screencast login — FEATURE-FLAGGED (build-time
 * VITE_ENABLE_SCREENCAST_LOGIN; route + nav hidden when off).
 *
 * Real client for the Go screencast relay (phase 2 item 2): the
 * page queries /screencast/status first (unavailable without the
 * with_chromedp build or without a keeper entry for the profile),
 * then opens the WebSocket from the ws_url the server returns.
 * The ws_url carries a single-use session token; the management
 * Bearer token is never placed in a URL. Frames arrive as base64
 * JPEG; mouse/key input is forwarded with the server's allowlisted
 * vocabularies. Done/Cancel end the session server-side; the
 * terminal report names the outcome only. castctl never touches
 * captcha or 2FA codes: the user types codes into the streamed
 * browser themselves.
 *
 * No CDP from the browser: the browser runs on the server, attached
 * via the session keeper (see docs/config.md for the honest
 * description of what the attach path enables internally).
 */
export function ScreencastLoginPage() {
  const { t } = useTranslation();
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [profile, setProfile] = useState('');
  const [availability, setAvailability] = useState<ScreencastStatus | null>(null);
  const [phase, setPhase] = useState<Phase>('idle');
  const [loadError, setLoadError] = useState('');
  const [frame, setFrame] = useState<{ src: string; width: number; height: number } | null>(null);
  const [sessionPhase, setSessionPhase] = useState('');
  const [sessionDetail, setSessionDetail] = useState('');
  const [report, setReport] = useState<TerminalReport | null>(null);
  const [wsError, setWsError] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const frameSizeRef = useRef({ width: 0, height: 0 });
  const endTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const closeSocket = useCallback(() => {
    if (endTimerRef.current !== null) {
      clearTimeout(endTimerRef.current);
      endTimerRef.current = null;
    }
    const ws = wsRef.current;
    wsRef.current = null;
    if (ws && ws.readyState !== WebSocket.CLOSED) ws.close();
  }, []);

  useEffect(() => () => closeSocket(), [closeSocket]);

  useEffect(() => {
    let cancelled = false;
    void profilesApi
      .list()
      .then((list) => {
        if (cancelled) return;
        setProfiles(list);
        const def = list.find((p) => p.default) ?? list[0];
        if (def) setProfile(def.name);
      })
      .catch((err: unknown) => {
        if (!cancelled) setLoadError(getErrorMessage(err, t('common.error')));
      });
    return () => {
      cancelled = true;
    };
  }, [t]);

  const checkAvailability = useCallback(
    async (name: string) => {
      setPhase('checking');
      setAvailability(null);
      setLoadError('');
      try {
        const status = await screencastApi.status(name);
        setAvailability(status);
      } catch (err) {
        setLoadError(getErrorMessage(err, t('common.error')));
      } finally {
        setPhase('idle');
      }
    },
    [t],
  );

  useEffect(() => {
    if (profile) void checkAvailability(profile);
  }, [profile, checkAvailability]);

  const sendInput = useCallback((message: Record<string, unknown>) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message));
  }, []);

  const startSession = useCallback(async () => {
    if (!profile || phase === 'starting' || phase === 'live') return;
    setPhase('starting');
    setWsError(false);
    setReport(null);
    setFrame(null);
    setSessionPhase('');
    setSessionDetail('');
    try {
      const started = await screencastApi.start(profile);
      const wsUrl = new URL(started.ws_url, window.location.href);
      wsUrl.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(wsUrl.toString());
      wsRef.current = ws;
      ws.onmessage = (event: MessageEvent<string>) => {
        let message: Record<string, unknown>;
        try {
          message = JSON.parse(event.data) as Record<string, unknown>;
        } catch {
          return;
        }
        if (message.type === 'frame' && typeof message.data === 'string') {
          const width = Number(message.width) || 0;
          const height = Number(message.height) || 0;
          frameSizeRef.current = { width, height };
          setFrame({ src: `data:image/jpeg;base64,${message.data}`, width, height });
        } else if (message.type === 'phase') {
          setSessionPhase(String(message.phase ?? ''));
          setSessionDetail(String(message.detail ?? ''));
        } else if (message.type === 'result') {
          setReport({
            outcome: String(message.outcome ?? ''),
            cookies_saved: message.cookies_saved === true,
            saved_names: Array.isArray(message.saved_names)
              ? message.saved_names.map(String)
              : undefined,
            earliest_expiry:
              typeof message.earliest_expiry === 'string' ? message.earliest_expiry : undefined,
          });
          setPhase('ended');
          closeSocket();
        }
      };
      ws.onopen = () => setPhase('live');
      ws.onerror = () => {
        setWsError(true);
        setPhase('idle');
      };
      ws.onclose = () => {
        // A close before the terminal report means the session
        // died without a result (unless we already ended cleanly).
        setPhase((current) => {
          if (current === 'live' || current === 'starting') {
            setWsError(true);
            return 'idle';
          }
          return current;
        });
      };
    } catch (err) {
      setLoadError(getErrorMessage(err, t('common.error')));
      setPhase('idle');
    }
  }, [profile, phase, closeSocket, t]);

  const endSession = useCallback(
    (kind: 'done' | 'cancel') => {
      sendInput({ kind });
      setPhase('ending');
      // The terminal report arrives over the same socket; close
      // after a grace period if it never comes.
      endTimerRef.current = setTimeout(() => {
        setPhase('ended');
        closeSocket();
      }, 15000);
    },
    [sendInput, closeSocket],
  );

  const scalePoint = (event: MouseEvent) => {
    const rect = event.currentTarget.getBoundingClientRect();
    const { width, height } = frameSizeRef.current;
    if (!width || !height || !rect.width || !rect.height) return { x: 0, y: 0 };
    return {
      x: Math.round(((event.clientX - rect.left) / rect.width) * width),
      y: Math.round(((event.clientY - rect.top) / rect.height) * height),
    };
  };

  const handleMouseDown = (event: MouseEvent) => {
    const { x, y } = scalePoint(event);
    sendInput({
      kind: 'mouse',
      mouse_type: 'mousePressed',
      button: BUTTON_NAMES[event.button] ?? 'none',
      x,
      y,
      click_count: event.detail >= 1 && event.detail <= 3 ? event.detail : 1,
      modifiers: modifiersOf(event),
    });
  };

  const handleMouseUp = (event: MouseEvent) => {
    const { x, y } = scalePoint(event);
    sendInput({
      kind: 'mouse',
      mouse_type: 'mouseReleased',
      button: BUTTON_NAMES[event.button] ?? 'none',
      x,
      y,
      click_count: 0,
      modifiers: modifiersOf(event),
    });
  };

  const handleMouseMove = (event: MouseEvent) => {
    const { x, y } = scalePoint(event);
    sendInput({ kind: 'mouse', mouse_type: 'mouseMoved', button: 'none', x, y, click_count: 0, modifiers: modifiersOf(event) });
  };

  const handleKey = (event: KeyboardEvent, keyType: 'keyDown' | 'keyUp') => {
    if ([' ', 'ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
    }
    sendInput({
      kind: 'key',
      key_type: keyType,
      key: event.key.slice(0, 64),
      text: event.key.length === 1 ? event.key : '',
      modifiers: modifiersOf(event),
    });
  };

  const live = phase === 'live' || phase === 'ending';

  return (
    <div className="page-root" style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 860 }}>
      <Card title={t('screencast_login.title')}>
        <p style={{ marginTop: 0 }}>{t('screencast_login.intro')}</p>
        <p>{t('screencast_login.remote_note')}</p>
        <p>{t('screencast_login.no_browser')}</p>

        {loadError && (
          <div className="error-box" role="alert">
            {loadError}
          </div>
        )}

        {profiles.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <Select
              value={profile}
              options={profiles.map((p) => ({ value: p.name, label: p.name }))}
              onChange={setProfile}
              ariaLabel={t('screencast_login.profile')}
              fullWidth={false}
              size="sm"
            />
          </div>
        )}

        {phase === 'checking' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <LoadingSpinner />
            <span>{t('screencast_login.status_checking')}</span>
          </div>
        )}

        {availability && !availability.available && phase !== 'checking' && (
          <div role="status">
            <p>{t('screencast_login.unavailable')}</p>
            <p>{availability.reason}</p>
          </div>
        )}

        {availability?.available && !live && phase !== 'ended' && (
          <Button onClick={() => void startSession()} loading={phase === 'starting'}>
            {t('screencast_login.start')}
          </Button>
        )}

        {wsError && (
          <p role="alert">
            {t('screencast_login.error')}{' '}
            <Button variant="secondary" size="sm" onClick={() => void checkAvailability(profile)}>
              {t('common.retry')}
            </Button>
          </p>
        )}

        {live && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <p style={{ margin: 0 }}>
              {sessionPhase && `${t('screencast_login.phase')}: ${sessionPhase}`}
              {sessionDetail && ` — ${sessionDetail}`}
            </p>
            <div
              tabIndex={0}
              role="application"
              aria-label={t('screencast_login.frame_alt')}
              onMouseDown={handleMouseDown}
              onMouseUp={handleMouseUp}
              onMouseMove={handleMouseMove}
              onKeyDown={(event) => handleKey(event, 'keyDown')}
              onKeyUp={(event) => handleKey(event, 'keyUp')}
              style={{
                aspectRatio: frame && frame.width && frame.height ? `${frame.width} / ${frame.height}` : '9 / 16',
                maxWidth: 420,
                border: '1px solid var(--border-color)',
                borderRadius: 8,
                overflow: 'hidden',
                background: 'var(--bg-secondary)',
                outline: 'none',
              }}
            >
              {frame ? (
                <img
                  src={frame.src}
                  alt={t('screencast_login.frame_alt')}
                  draggable={false}
                  style={{ display: 'block', width: '100%', height: '100%', objectFit: 'contain' }}
                />
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', padding: 16, textAlign: 'center' }}>
                  {t('screencast_login.connecting')}
                </div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <Button variant="secondary" onClick={() => endSession('cancel')} disabled={phase !== 'live'}>
                {t('screencast_login.cancel')}
              </Button>
              <Button onClick={() => endSession('done')} disabled={phase !== 'live'}>
                {t('screencast_login.done')}
              </Button>
            </div>
          </div>
        )}

        {phase === 'ended' && report && (
          <div role="status">
            <p>
              {t('screencast_login.ended')} {report.outcome}
            </p>
            {report.cookies_saved && <p>{t('screencast_login.cookies_saved')}</p>}
            {report.saved_names && report.saved_names.length > 0 && <p>{report.saved_names.join(', ')}</p>}
            {report.earliest_expiry && <p>{report.earliest_expiry}</p>}
            <Button
              variant="secondary"
              onClick={() => {
                setReport(null);
                setPhase('idle');
                void checkAvailability(profile);
              }}
            >
              {t('screencast_login.start')}
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
}
