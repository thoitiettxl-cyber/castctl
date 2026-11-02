import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { chatsApi, profilesApi, statusApi } from '@/services/api';
import type { ApiError, ChatEvent, ChatJob, ChatSession, ChatSessionOp } from '@/types';
import { getErrorMessage } from '@/utils/helpers';
import { useNotificationStore } from '@/stores';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input } from '@/components/ui/Input';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { Modal } from '@/components/ui/Modal';
import { Select } from '@/components/ui/Select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/Table';
import { ToggleSwitch } from '@/components/ui/ToggleSwitch';

/** Poll interval for a send job, and the poll cap (80 × 2s = 160s,
 * just past the server job timeout of 150s). */
const JOB_POLL_MS = 2000;
const JOB_POLL_MAX = 80;

/** The main chat has no row in the server session list (the list
 * mirrors the stored `sessions` array); the page synthesises its
 * entry so it can be opened and sent to like any session. It is
 * addressed as "main" in the path and never renamed/pinned/
 * archived/deleted. */
const MAIN_SESSION_ID = 'main';

export function ChatsPage() {
  const { t } = useTranslation();
  const showNotification = useNotificationStore((state) => state.showNotification);

  const [profiles, setProfiles] = useState<string[]>([]);
  const [profile, setProfile] = useState('');
  const [profilesError, setProfilesError] = useState('');
  const [profilesLoaded, setProfilesLoaded] = useState(false);

  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [includeArchived, setIncludeArchived] = useState(false);
  const [sessionsError, setSessionsError] = useState('');
  const [sessionsLoaded, setSessionsLoaded] = useState(false);

  const [selectedId, setSelectedId] = useState(MAIN_SESSION_ID);
  const [events, setEvents] = useState<ChatEvent[]>([]);
  const [historyError, setHistoryError] = useState('');
  const [historyLoaded, setHistoryLoaded] = useState(false);

  const [newTitle, setNewTitle] = useState('');
  const [creating, setCreating] = useState(false);
  const [renameTarget, setRenameTarget] = useState<ChatSession | null>(null);
  const [renameTitle, setRenameTitle] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<ChatSession | null>(null);
  const [acting, setActing] = useState(false);

  const [sendText, setSendText] = useState('');
  const [job, setJob] = useState<ChatJob | null>(null);
  const [sendError, setSendError] = useState('');
  const pollCountRef = useRef(0);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadProfiles = useCallback(async () => {
    setProfilesError('');
    try {
      const [status, list] = await Promise.all([statusApi.get(), profilesApi.list()]);
      setProfiles(list.map((p) => p.name));
      setProfile((prev) => prev || status.default_profile || list[0]?.name || '');
      setProfilesLoaded(true);
    } catch (err) {
      setProfilesError(getErrorMessage(err, t('common.error')));
    }
  }, [t]);

  useEffect(() => {
    void loadProfiles();
  }, [loadProfiles]);

  const loadSessions = useCallback(async () => {
    if (!profile) return;
    setSessionsError('');
    try {
      const rows = await chatsApi.list(profile, { include_archived: includeArchived });
      // Synthesise the main-chat entry first; the server list holds
      // named sessions only. message_count/last_used are unknown
      // for it and render as a dash, never a misleading zero.
      setSessions([
        {
          id: '',
          title: t('chats.main_chat'),
          pinned: false,
          archived: false,
          last_used: '',
          message_count: 0,
        },
        ...rows,
      ]);
      setSessionsLoaded(true);
    } catch (err) {
      setSessionsError(getErrorMessage(err, t('common.error')));
    }
  }, [profile, includeArchived, t]);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current !== null) {
      clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  const loadHistory = useCallback(async () => {
    if (!profile) return;
    setHistoryError('');
    setHistoryLoaded(false);
    try {
      setEvents(await chatsApi.history(profile, selectedId));
      setHistoryLoaded(true);
    } catch (err) {
      setHistoryError(getErrorMessage(err, t('common.error')));
    }
  }, [profile, selectedId, t]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const pollJob = useCallback(
    (jobId: string) => {
      pollCountRef.current = 0;
      stopPolling();
      pollTimerRef.current = setInterval(() => {
        pollCountRef.current += 1;
        if (pollCountRef.current > JOB_POLL_MAX) {
          stopPolling();
          setSendError(t('chats.send_timeout'));
          return;
        }
        chatsApi
          .job(jobId)
          .then((current) => {
            setJob(current);
            if (current.status !== 'running') stopPolling();
          })
          .catch(() => {
            // A transient poll failure must not kill the job view;
            // the next tick retries. The server job keeps running.
          });
      }, JOB_POLL_MS);
    },
    [stopPolling, t],
  );

  const handleSend = async (event: FormEvent) => {
    event.preventDefault();
    const text = sendText.trim();
    if (!text || !profile || job?.status === 'running') return;
    setSendError('');
    setJob(null);
    try {
      const created = await chatsApi.send(profile, selectedId, { text });
      setJob(created);
      setSendText('');
      if (created.status === 'running') pollJob(created.job_id);
    } catch (err) {
      // 409 = a send is already in flight for this profile; the
      // server serialises sends per profile. Anything else is a
      // plain failure; the message body is never echoed.
      if ((err as ApiError).status === 409) setSendError(t('chats.send_in_flight'));
      else setSendError(getErrorMessage(err, t('common.error')));
    }
  };

  const handleCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (!profile) return;
    setCreating(true);
    try {
      const created = await chatsApi.start(profile, newTitle.trim() ? { title: newTitle.trim() } : {});
      setNewTitle('');
      await loadSessions();
      setSelectedId(created.id);
      showNotification(t('notification.saved'), 'success');
    } catch (err) {
      showNotification(getErrorMessage(err, t('notification.save_failed')), 'error');
    } finally {
      setCreating(false);
    }
  };

  const runOp = async (session: ChatSession, op: ChatSessionOp, title?: string) => {
    if (!profile) return;
    setActing(true);
    try {
      await chatsApi.op(profile, session.id || MAIN_SESSION_ID, {
        op,
        ...(title !== undefined ? { title } : {}),
      });
      await loadSessions();
      if (op === 'delete' && (session.id || MAIN_SESSION_ID) === selectedId) {
        setSelectedId(MAIN_SESSION_ID);
      }
      showNotification(t('notification.saved'), 'success');
    } catch (err) {
      showNotification(getErrorMessage(err, t('notification.save_failed')), 'error');
    } finally {
      setActing(false);
    }
  };

  const selectedSession = sessions.find((s) => (s.id || MAIN_SESSION_ID) === selectedId);
  const jobRunning = job?.status === 'running';
  const jobResult = job?.status !== 'running' ? job?.result : undefined;

  if (!profilesLoaded && !profilesError) {
    return (
      <div className="page-root">
        <h1>{t('chats.title')}</h1>
        <LoadingSpinner />
        <p>{t('common.loading')}</p>
      </div>
    );
  }

  return (
    <div className="page-root">
      <h1>{t('chats.title')}</h1>
      {profilesError && (
        <div className="error-box" role="alert">
          {profilesError}{' '}
          <Button variant="secondary" size="sm" onClick={() => void loadProfiles()}>
            {t('common.retry')}
          </Button>
        </div>
      )}

      <Card title={t('chats.profile_card')}>
        <Select
          value={profile}
          options={profiles.map((name) => ({ value: name, label: name }))}
          onChange={(value) => {
            setProfile(value);
            setSelectedId(MAIN_SESSION_ID);
            setJob(null);
          }}
          ariaLabel={t('chats.profile_label')}
          disabled={profiles.length === 0}
        />
        <ToggleSwitch
          checked={includeArchived}
          onChange={setIncludeArchived}
          label={t('chats.show_archived')}
        />
      </Card>

      <Card title={t('chats.sessions_card')}>
        {sessionsError && (
          <div className="error-box" role="alert">
            {sessionsError}{' '}
            <Button variant="secondary" size="sm" onClick={() => void loadSessions()}>
              {t('common.retry')}
            </Button>
          </div>
        )}
        {!sessionsLoaded && !sessionsError ? (
          <LoadingSpinner />
        ) : sessions.length === 0 ? (
          <EmptyState title={t('chats.empty_sessions')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('common.name')}</TableHead>
                <TableHead>{t('chats.last_used')}</TableHead>
                <TableHead>{t('chats.message_count')}</TableHead>
                <TableHead>{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.map((session) => {
                const key = session.id || MAIN_SESSION_ID;
                return (
                  <TableRow key={key}>
                    <TableCell>
                      {session.title}
                      {session.pinned && <span> {t('chats.pinned')}</span>}
                      {session.archived && <span> {t('chats.archived')}</span>}
                    </TableCell>
                    <TableCell>{session.last_used || '—'}</TableCell>
                    <TableCell>{key === MAIN_SESSION_ID ? '—' : session.message_count}</TableCell>
                    <TableCell>
                      <Button size="sm" variant="secondary" onClick={() => setSelectedId(key)}>
                        {t('chats.open')}
                      </Button>{' '}
                      {key !== MAIN_SESSION_ID && (
                        <>
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => {
                              setRenameTarget(session);
                              setRenameTitle(session.title);
                            }}
                          >
                            {t('common.edit')}
                          </Button>{' '}
                          <Button
                            size="sm"
                            variant="secondary"
                            disabled={acting}
                            onClick={() => void runOp(session, session.pinned ? 'unpin' : 'pin')}
                          >
                            {session.pinned ? t('chats.unpin') : t('chats.pin')}
                          </Button>{' '}
                          <Button
                            size="sm"
                            variant="secondary"
                            disabled={acting}
                            onClick={() => void runOp(session, session.archived ? 'unarchive' : 'archive')}
                          >
                            {session.archived ? t('chats.unarchive') : t('chats.archive')}
                          </Button>{' '}
                          <Button
                            size="sm"
                            variant="danger"
                            disabled={acting}
                            onClick={() => setDeleteTarget(session)}
                          >
                            {t('common.delete')}
                          </Button>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        <form onSubmit={(event) => void handleCreate(event)}>
          <Input
            label={t('chats.new_title')}
            value={newTitle}
            onChange={(event) => setNewTitle(event.target.value)}
          />
          <Button type="submit" loading={creating} disabled={!profile}>
            {t('chats.new_session')}
          </Button>
        </form>
      </Card>

      <Card title={selectedSession?.title ?? t('chats.history_card')}>
        {historyError && (
          <div className="error-box" role="alert">
            {historyError}{' '}
            <Button variant="secondary" size="sm" onClick={() => void loadHistory()}>
              {t('common.retry')}
            </Button>
          </div>
        )}
        {!historyLoaded && !historyError ? (
          <LoadingSpinner />
        ) : events.length === 0 ? (
          <EmptyState title={t('chats.empty_history')} />
        ) : (
          <div>
            {events.map((event) => (
              <p key={event.seq}>
                <strong>{event.role}</strong> <span>{event.time}</span>
                <br />
                {event.text}
              </p>
            ))}
          </div>
        )}
        <form onSubmit={(event) => void handleSend(event)}>
          <div>
            <label htmlFor="chat-send-text">{t('chats.send_label')}</label>
            <textarea
              id="chat-send-text"
              className="input"
              rows={3}
              value={sendText}
              onChange={(event) => setSendText(event.target.value)}
              disabled={jobRunning}
            />
          </div>
          <Button type="submit" loading={jobRunning} disabled={!sendText.trim() || !profile}>
            {t('chats.send')}
          </Button>
        </form>
        {sendError && (
          <div className="error-box" role="alert">
            {sendError}
          </div>
        )}
        {jobRunning && (
          <p>
            <LoadingSpinner /> {t('chats.sending')}
          </p>
        )}
        {jobResult && (
          <div>
            <p>
              {t('chats.outcome')}: {t(`chats.outcome_${jobResult.outcome}`)}
            </p>
            {jobResult.text && <p>{jobResult.text}</p>}
            {jobResult.replies.map((reply) => (
              <p key={reply.seq}>
                <strong>{reply.role}</strong> <span>{reply.time}</span>
                <br />
                {reply.text}
              </p>
            ))}
            <p>
              {t('chats.approvals')}: {jobResult.approvals_resolved}/{jobResult.approvals_requested}
            </p>
            {jobResult.note && <p>{jobResult.note}</p>}
            {jobResult.reason && <p>{jobResult.reason}</p>}
            {jobResult.question && <p>{jobResult.question}</p>}
            <Button variant="secondary" size="sm" onClick={() => void loadHistory()}>
              {t('common.refresh')}
            </Button>
          </div>
        )}
        {job?.status === 'failed' && job.error && (
          <div className="error-box" role="alert">
            {job.error}
          </div>
        )}
        {job?.status === 'timeout' && (
          <div className="error-box" role="alert">
            {t('chats.send_timeout')}
          </div>
        )}
      </Card>

      <Modal
        open={renameTarget !== null}
        onClose={() => setRenameTarget(null)}
        title={t('chats.rename_title')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setRenameTarget(null)}>
              {t('common.cancel')}
            </Button>{' '}
            <Button
              disabled={!renameTitle.trim() || acting}
              onClick={() => {
                if (renameTarget) void runOp(renameTarget, 'rename', renameTitle.trim());
                setRenameTarget(null);
              }}
            >
              {t('common.save')}
            </Button>
          </>
        }
      >
        <Input
          label={t('chats.new_title')}
          value={renameTitle}
          onChange={(event) => setRenameTitle(event.target.value)}
        />
      </Modal>

      <Modal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title={t('chats.confirm_delete')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteTarget(null)}>
              {t('common.cancel')}
            </Button>{' '}
            <Button
              variant="danger"
              disabled={acting}
              onClick={() => {
                if (deleteTarget) void runOp(deleteTarget, 'delete');
                setDeleteTarget(null);
              }}
            >
              {t('common.delete')}
            </Button>
          </>
        }
      >
        <p>{t('chats.delete_hint')}</p>
      </Modal>
    </div>
  );
}
