import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { profilesApi } from '@/services/api';
import type { LoginStatus, ProfileDetail, ProfileTestResult } from '@/types';
import { getErrorMessage } from '@/utils/helpers';
import { MAX_COOKIE_IMPORT_SIZE } from '@/utils/constants';
import { useNotificationStore } from '@/stores';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { Modal } from '@/components/ui/Modal';
import { Select } from '@/components/ui/Select';
import { ToggleSwitch } from '@/components/ui/ToggleSwitch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/Table';

// Same pattern as MainLayout: the global is declared in vite-env.d.ts and
// defined by the Vite build. typeof-check so a build without the define
// does not throw.
const SCREENCAST_LOGIN_ENABLED: boolean =
  typeof __CASTCTL_SCREENCAST_LOGIN__ !== 'undefined' && __CASTCTL_SCREENCAST_LOGIN__;

export function ProfileDetailPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { name } = useParams();
  const profileName = name ?? '';
  const showNotification = useNotificationStore((state) => state.showNotification);
  const [detail, setDetail] = useState<ProfileDetail | null>(null);
  const [login, setLogin] = useState<LoginStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [testResult, setTestResult] = useState<ProfileTestResult | null>(null);
  const [testError, setTestError] = useState('');
  const [testing, setTesting] = useState(false);
  const [renameOpen, setRenameOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [renaming, setRenaming] = useState(false);
  const [cookies, setCookies] = useState('');
  const [format, setFormat] = useState<'text' | 'file'>('text');
  const [importError, setImportError] = useState('');
  const [importing, setImporting] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [retyped, setRetyped] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [autoApprove, setAutoApprove] = useState(false);
  const [autoAllowOnce, setAutoAllowOnce] = useState(false);

  const loadLogin = useCallback(async () => {
    if (!profileName) return;
    try {
      setLogin(await profilesApi.loginStatus(profileName));
    } catch {
      // Login status is best-effort detail; the profile itself already loaded.
      setLogin(null);
    }
  }, [profileName]);

  const load = useCallback(async () => {
    if (!profileName) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const loaded = await profilesApi.get(profileName);
      setDetail(loaded);
      const entry = loaded.entry as Record<string, unknown>;
      setAutoApprove(entry.auto_approve === true);
      setAutoAllowOnce(entry.auto_allow_once === true);
    } catch (err) {
      setError(getErrorMessage(err, t('common.error')));
    } finally {
      setLoading(false);
    }
    await loadLogin();
  }, [profileName, loadLogin, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const runTest = async () => {
    setTestResult(null);
    setTestError('');
    setTesting(true);
    try {
      setTestResult(await profilesApi.test(profileName));
    } catch (err) {
      setTestError(getErrorMessage(err, t('common.error')));
    } finally {
      setTesting(false);
    }
  };

  const handleSetDefault = async () => {
    try {
      await profilesApi.setDefault(profileName);
      showNotification(t('notification.saved'), 'success');
      await load();
    } catch (err) {
      showNotification(getErrorMessage(err, t('common.error')), 'error');
    }
  };

  const handleDelete = async () => {
    if (retyped !== profileName) return;
    setDeleting(true);
    try {
      await profilesApi.remove(profileName);
      showNotification(t('notification.deleted'), 'success');
      navigate('/profiles', { replace: true });
    } catch (err) {
      showNotification(getErrorMessage(err, t('common.error')), 'error');
    } finally {
      setDeleting(false);
    }
  };

  const handlePatchToggle = async (patch: { auto_approve?: boolean; auto_allow_once?: boolean }) => {
    const previous = { autoApprove, autoAllowOnce };
    if (patch.auto_approve !== undefined) setAutoApprove(patch.auto_approve);
    if (patch.auto_allow_once !== undefined) setAutoAllowOnce(patch.auto_allow_once);
    try {
      await profilesApi.patch(profileName, patch);
      showNotification(t('notification.saved'), 'success');
    } catch (err) {
      setAutoApprove(previous.autoApprove);
      setAutoAllowOnce(previous.autoAllowOnce);
      showNotification(getErrorMessage(err, t('common.error')), 'error');
    }
  };

  const handleRename = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = newName.trim();
    if (!trimmed || trimmed === profileName) return;
    setRenaming(true);
    try {
      await profilesApi.rename(profileName, { to: trimmed });
      setRenameOpen(false);
      setNewName('');
      showNotification(t('notification.saved'), 'success');
      navigate(`/profiles/${encodeURIComponent(trimmed)}`, { replace: true });
    } catch (err) {
      showNotification(getErrorMessage(err, t('common.error')), 'error');
    } finally {
      setRenaming(false);
    }
  };

  const handleImport = async (event: FormEvent) => {
    event.preventDefault();
    setImportError('');
    if (new TextEncoder().encode(cookies).length > MAX_COOKIE_IMPORT_SIZE) {
      setImportError(t('profiles.login_card.size_error'));
      return;
    }
    if (!cookies.trim()) return;
    setImporting(true);
    try {
      const result = await profilesApi.loginImport(profileName, { format, content: cookies });
      if (result.saved && !result.error) {
        showNotification(t('profiles.login_card.import_success'), 'success');
      } else {
        showNotification(
          result.error?.message ?? t('profiles.login_card.import_failed'),
          'error',
        );
      }
      await load();
    } catch (err) {
      showNotification(getErrorMessage(err, t('profiles.login_card.import_failed')), 'error');
    } finally {
      // Cookies must not linger in the browser after the import POST.
      setCookies('');
      setImporting(false);
    }
  };

  const handleUpload = async (file: File | undefined) => {
    if (!file) return;
    const text = await file.text();
    if (new TextEncoder().encode(text).length > MAX_COOKIE_IMPORT_SIZE) {
      setImportError(t('profiles.login_card.size_error'));
      return;
    }
    setImportError('');
    setCookies(text);
    setFormat('file');
  };

  const handleRestore = async () => {
    setRestoring(true);
    try {
      await profilesApi.loginRestore(profileName);
      showNotification(t('notification.saved'), 'success');
      await load();
    } catch (err) {
      showNotification(getErrorMessage(err, t('profiles.login_card.restore_failed')), 'error');
    } finally {
      setRestoring(false);
    }
  };

  const handleCheckAgain = async () => {
    await loadLogin();
  };

  if (loading && !detail) {
    return (
      <div className="page-root">
        <LoadingSpinner />
        <p>{t('common.loading')}</p>
      </div>
    );
  }

  if (!profileName || (!detail && error)) {
    return (
      <div className="page-root">
        <Link to="/profiles">{t('profiles.detail.back')}</Link>
        <p>{error || t('common.error')}</p>
      </div>
    );
  }

  return (
    <div className="page-root">
      <Link to="/profiles">{t('profiles.detail.back')}</Link>
      <h1>
        {t('profiles.detail.title')}: {profileName}
      </h1>
      {error && <p>{error}</p>}

      {detail && (
        <>
          <Card title={t('profiles.detail.title')}>
            <p>
              {t('profiles.detail.source')}: {detail.source}
            </p>
            <p>
              {t('profiles.detail.outbound')}: {detail.outbound_tag ?? '—'}
            </p>
            <p>
              {t('profiles.detail.fingerprint')}: {detail.fingerprint}
            </p>
            <p>
              {t('profiles.detail.cookies')}: {detail.has_cookies ? t('common.yes') : t('common.no')}
            </p>
            {detail.default && <p>{t('profiles.list.default_badge')}</p>}
            {detail.warnings.length > 0 && (
              <div>
                <p>{t('profiles.detail.warnings')}</p>
                <ul>
                  {detail.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          <Card title={t('profiles.detail.paths')}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('common.name')}</TableHead>
                  <TableHead>{t('profiles.detail.paths')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(detail.paths).map(([key, value]) => (
                  <TableRow key={key}>
                    <TableCell>{key}</TableCell>
                    <TableCell>{value}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>

          <Card title={t('profiles.detail.entry')}>
            <div className="scroll-x" style={{ overflowX: 'auto' }}>
              <pre>{JSON.stringify(detail.entry, null, 2)}</pre>
            </div>
          </Card>

          <div>
            <Button variant="secondary" onClick={() => setRenameOpen(true)}>
              {t('profiles.detail.rename')}
            </Button>{' '}
            <Button variant="secondary" disabled={detail.default} onClick={() => void handleSetDefault()}>
              {t('profiles.detail.set_default')}
            </Button>{' '}
            <Button variant="danger" onClick={() => { setRetyped(''); setDeleteOpen(true); }}>
              {t('profiles.detail.delete')}
            </Button>{' '}
            <Button onClick={() => void runTest()} loading={testing}>
              {t('profiles.detail.run_test')}
            </Button>
          </div>

          <div>
            <ToggleSwitch
              checked={autoApprove}
              onChange={(value) => void handlePatchToggle({ auto_approve: value })}
              label={t('profiles.detail.auto_approve')}
            />
            <ToggleSwitch
              checked={autoAllowOnce}
              onChange={(value) => void handlePatchToggle({ auto_allow_once: value })}
              label={t('profiles.detail.auto_allow_once')}
            />
          </div>

          {(testError || testResult) && (
            <Card title={t('profiles.detail.test_result')}>
              {testError && <p>{testError}</p>}
              {testResult && (
                <div>
                  <p>
                    {t('profiles.detail.test_result')}: {testResult.overall}
                  </p>
                  {testResult.egress_ip && (
                    <p>
                      {t('profiles.detail.egress_ip')}: {testResult.egress_ip}
                    </p>
                  )}
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('profiles.detail.phases')}</TableHead>
                        <TableHead>{t('common.status')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {testResult.phases.map((phase) => (
                        <TableRow key={phase.phase}>
                          <TableCell>{phase.phase}</TableCell>
                          <TableCell>
                            {phase.status} ({phase.duration_ms} ms)
                            {phase.detail ? ` — ${phase.detail}` : ''}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </Card>
          )}
        </>
      )}

      <Card title={t('profiles.login_card.title')}>
        <p>
          {t('profiles.login_card.status')}:{' '}
          {login
            ? login.logged_in
              ? `${t('profiles.login_card.logged_in')}${login.vm_id_prefix ? ` (${login.vm_id_prefix})` : ''}`
              : t('profiles.login_card.not_logged_in')
            : t('common.unknown')}
        </p>
        {login?.expiry && (
          <p>
            {t('profiles.login_card.expiry')}: {login.expiry}
          </p>
        )}
        <form onSubmit={(event) => void handleImport(event)}>
          <div>
            <label htmlFor="cookie-import">{t('profiles.login_card.import')}</label>
            <textarea
              id="cookie-import"
              className="input"
              rows={6}
              value={cookies}
              onChange={(event) => setCookies(event.target.value)}
            />
            <p>{t('profiles.login_card.paste_hint')}</p>
          </div>
          <div>
            <label htmlFor="cookie-format">{t('profiles.login_card.format')}</label>{' '}
            <Select
              id="cookie-format"
              value={format}
              options={[
                { value: 'text', label: t('profiles.login_card.format_text') },
                { value: 'file', label: t('profiles.login_card.format_file') },
              ]}
              onChange={(value) => setFormat(value as 'text' | 'file')}
              ariaLabel={t('profiles.login_card.format')}
            />
          </div>
          <div>
            <label htmlFor="cookie-upload">{t('profiles.login_card.upload')}</label>{' '}
            <input
              id="cookie-upload"
              type="file"
              onChange={(event) => void handleUpload(event.target.files?.[0])}
            />
          </div>
          {importError && <p>{importError}</p>}
          <Button type="submit" loading={importing} disabled={!cookies.trim()}>
            {t('profiles.login_card.import_button')}
          </Button>{' '}
          <Button variant="secondary" loading={restoring} onClick={() => void handleRestore()}>
            {t('profiles.login_card.restore')}
          </Button>{' '}
          <Button variant="secondary" onClick={() => void handleCheckAgain()}>
            {t('profiles.login_card.check_again')}
          </Button>
        </form>
        {SCREENCAST_LOGIN_ENABLED && (
          <p>
            <Link to="/login-browser">{t('profiles.login_card.browser_login')}</Link>
          </p>
        )}
      </Card>

      <Modal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        title={t('profiles.detail.confirm_delete')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteOpen(false)}>
              {t('common.cancel')}
            </Button>{' '}
            <Button
              variant="danger"
              loading={deleting}
              disabled={retyped !== profileName}
              onClick={() => void handleDelete()}
            >
              {t('profiles.detail.delete')}
            </Button>
          </>
        }
      >
        <p>
          {t('profiles.list.retype_hint')}: {profileName}
        </p>
        <Input
          label={t('common.name')}
          value={retyped}
          onChange={(event) => setRetyped(event.target.value)}
          placeholder={t('profiles.list.type_name_to_confirm')}
          autoFocus
        />
      </Modal>

      <Modal
        open={renameOpen}
        onClose={() => setRenameOpen(false)}
        title={t('profiles.detail.rename')}
        footer={
          <Button variant="secondary" onClick={() => setRenameOpen(false)}>
            {t('common.cancel')}
          </Button>
        }
      >
        <form onSubmit={(event) => void handleRename(event)}>
          <Input
            label={t('profiles.detail.new_name')}
            value={newName}
            onChange={(event) => setNewName(event.target.value)}
            required
          />
          <Button type="submit" loading={renaming} disabled={!newName.trim()}>
            {t('profiles.detail.rename')}
          </Button>
        </form>
      </Modal>
    </div>
  );
}
