import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { profilesApi } from '@/services/api';
import type { ProfileSummary, ProfileTestResult } from '@/types';
import { getErrorMessage } from '@/utils/helpers';
import { useNotificationStore } from '@/stores';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input } from '@/components/ui/Input';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { Modal } from '@/components/ui/Modal';
import { SelectionCheckbox } from '@/components/ui/SelectionCheckbox';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/Table';

export function ProfilesPage() {
  const { t } = useTranslation();
  const showNotification = useNotificationStore((state) => state.showNotification);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [cookiesFile, setCookiesFile] = useState('');
  const [outbound, setOutbound] = useState('');
  const [setDefault, setSetDefault] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [testName, setTestName] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ProfileTestResult | null>(null);
  const [testError, setTestError] = useState('');
  const [testing, setTesting] = useState(false);
  const [deleteName, setDeleteName] = useState<string | null>(null);
  const [retyped, setRetyped] = useState('');
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setProfiles(await profilesApi.list());
    } catch (err) {
      setError(getErrorMessage(err, t('common.error')));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleCreate = async (event: FormEvent) => {
    event.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) return;
    setSubmitting(true);
    try {
      await profilesApi.create({
        name: trimmedName,
        ...(cookiesFile.trim() ? { cookies_file: cookiesFile.trim() } : {}),
        ...(outbound.trim() ? { outbound: outbound.trim() } : {}),
        ...(setDefault ? { set_default: true } : {}),
      });
      setName('');
      setCookiesFile('');
      setOutbound('');
      setSetDefault(false);
      showNotification(t('notification.saved'), 'success');
      await load();
    } catch (err) {
      showNotification(getErrorMessage(err, t('common.error')), 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSetDefault = async (profileName: string) => {
    try {
      await profilesApi.setDefault(profileName);
      showNotification(t('notification.saved'), 'success');
      await load();
    } catch (err) {
      showNotification(getErrorMessage(err, t('common.error')), 'error');
    }
  };

  const runTest = async (profileName: string) => {
    setTestName(profileName);
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

  const closeTest = () => {
    setTestName(null);
    setTestResult(null);
    setTestError('');
  };

  const openDelete = (profileName: string) => {
    setDeleteName(profileName);
    setRetyped('');
  };

  const closeDelete = () => {
    setDeleteName(null);
    setRetyped('');
  };

  const handleDelete = async () => {
    if (!deleteName || retyped !== deleteName) return;
    setDeleting(true);
    try {
      await profilesApi.remove(deleteName);
      showNotification(t('notification.deleted'), 'success');
      closeDelete();
      await load();
    } catch (err) {
      showNotification(getErrorMessage(err, t('common.error')), 'error');
    } finally {
      setDeleting(false);
    }
  };

  const hasLegacy = profiles.some((p) => p.source === 'legacy');

  return (
    <div className="page-root">
      <h1>{t('profiles.list.title')}</h1>
      {error && <p>{error}</p>}
      {hasLegacy && <p role="alert">{t('dashboard.legacy_warning')}</p>}

      <Card title={t('profiles.list.add')}>
        <form onSubmit={(event) => void handleCreate(event)}>
          <Input
            label={t('common.name')}
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
          />
          <Input
            label={t('profiles.list.cookies_file')}
            hint={t('common.optional')}
            value={cookiesFile}
            onChange={(event) => setCookiesFile(event.target.value)}
          />
          <Input
            label={t('profiles.list.outbound')}
            hint={t('common.optional')}
            value={outbound}
            onChange={(event) => setOutbound(event.target.value)}
          />
          <div>
            <SelectionCheckbox
              checked={setDefault}
              onChange={setSetDefault}
              label={t('profiles.list.set_default')}
            />
          </div>
          <Button type="submit" loading={submitting} disabled={!name.trim()}>
            {t('profiles.list.add')}
          </Button>
        </form>
      </Card>

      {loading && profiles.length === 0 ? (
        <div>
          <LoadingSpinner />
          <p>{t('common.loading')}</p>
        </div>
      ) : profiles.length === 0 ? (
        <EmptyState title={t('profiles.list.empty')} />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('common.name')}</TableHead>
              <TableHead>{t('profiles.detail.source')}</TableHead>
              <TableHead>{t('profiles.detail.outbound')}</TableHead>
              <TableHead>{t('profiles.detail.fingerprint')}</TableHead>
              <TableHead>{t('common.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {profiles.map((profile) => (
              <TableRow key={profile.name}>
                <TableCell>
                  <Link to={`/profiles/${encodeURIComponent(profile.name)}`}>{profile.name}</Link>
                  {profile.default && <span> {t('profiles.list.default_badge')}</span>}
                </TableCell>
                <TableCell>{profile.source}</TableCell>
                <TableCell>{profile.outbound_tag ?? '—'}</TableCell>
                <TableCell>{profile.fingerprint}</TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={profile.default}
                    onClick={() => void handleSetDefault(profile.name)}
                  >
                    {t('profiles.list.set_default')}
                  </Button>{' '}
                  <Button size="sm" variant="secondary" onClick={() => void runTest(profile.name)}>
                    {t('profiles.list.test')}
                  </Button>{' '}
                  <Button size="sm" variant="danger" onClick={() => openDelete(profile.name)}>
                    {t('profiles.list.delete')}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Modal
        open={deleteName !== null}
        onClose={closeDelete}
        title={t('profiles.list.confirm_delete')}
        footer={
          <>
            <Button variant="secondary" onClick={closeDelete}>
              {t('common.cancel')}
            </Button>{' '}
            <Button
              variant="danger"
              loading={deleting}
              disabled={!deleteName || retyped !== deleteName}
              onClick={() => void handleDelete()}
            >
              {t('profiles.list.delete')}
            </Button>
          </>
        }
      >
        <p>
          {t('profiles.list.retype_hint')}: {deleteName}
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
        open={testName !== null}
        onClose={closeTest}
        title={t('profiles.detail.test_result')}
        footer={
          <Button variant="secondary" onClick={closeTest}>
            {t('common.close')}
          </Button>
        }
      >
        {testing && <LoadingSpinner />}
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
      </Modal>
    </div>
  );
}
