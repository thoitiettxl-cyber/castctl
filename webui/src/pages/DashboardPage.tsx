import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { profilesApi, statusApi } from '@/services/api';
import type { LoginStatus, ProfileSummary, ProfileTestResult, StatusInfo } from '@/types';
import { getErrorMessage } from '@/utils/helpers';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { Modal } from '@/components/ui/Modal';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/Table';

export function DashboardPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [status, setStatus] = useState<StatusInfo | null>(null);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [loginByName, setLoginByName] = useState<Record<string, LoginStatus>>({});
  const [loginFailed, setLoginFailed] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [testName, setTestName] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ProfileTestResult | null>(null);
  const [testError, setTestError] = useState('');
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      setLoading(true);
      setError('');
      try {
        const [statusResult, profileResult] = await Promise.all([
          statusApi.get(),
          profilesApi.list(),
        ]);
        if (!alive) return;
        setStatus(statusResult);
        setProfiles(profileResult);
      } catch (err) {
        if (!alive) return;
        setError(getErrorMessage(err, t('common.error')));
      } finally {
        if (alive) setLoading(false);
      }
    };
    void load();
    return () => {
      alive = false;
    };
  }, [t]);

  // Login status is lazy per profile (design §2/§6.3); a single row failing
  // must not fail the whole page.
  useEffect(() => {
    let alive = true;
    profiles.forEach((profile) => {
      profilesApi
        .loginStatus(profile.name)
        .then((result) => {
          if (!alive) return;
          setLoginByName((prev) => ({ ...prev, [profile.name]: result }));
        })
        .catch(() => {
          if (!alive) return;
          setLoginFailed((prev) => ({ ...prev, [profile.name]: true }));
        });
    });
    return () => {
      alive = false;
    };
  }, [profiles]);

  const runTest = async (name: string) => {
    setTestName(name);
    setTestResult(null);
    setTestError('');
    setTesting(true);
    try {
      setTestResult(await profilesApi.test(name));
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

  const loggedInCount = profiles.filter((p) => loginByName[p.name]?.logged_in).length;
  const needsAttentionCount = profiles.filter(
    (p) => loginByName[p.name] && !loginByName[p.name].logged_in,
  ).length;
  const hasLegacy = profiles.some((p) => p.source === 'legacy');

  if (loading && !status) {
    return (
      <div>
        <h1>{t('dashboard.title')}</h1>
        <LoadingSpinner />
        <p>{t('common.loading')}</p>
      </div>
    );
  }

  return (
    <div>
      <h1>{t('dashboard.title')}</h1>
      {error && <p>{error}</p>}
      {status?.remote_exposure && <p role="alert">{t('dashboard.remote_banner')}</p>}
      {hasLegacy && <p role="alert">{t('dashboard.legacy_warning')}</p>}

      {status && (
        <Card title={t('dashboard.server_card')}>
          <p>
            {t('dashboard.server_version')}: {status.version}
          </p>
          <p>
            {t('dashboard.server_listen_addr')}: {status.listen_addr}
          </p>
          <p>
            {t('dashboard.server_config_source')}: {status.config_source}
          </p>
          <p>
            {t('dashboard.server_default_profile')}: {status.default_profile || t('common.unknown')}
          </p>
        </Card>
      )}

      {status && (
        <>
          <Card title={t('dashboard.profiles_card')}>
            <p>{status.profile_count}</p>
            <p>
              {t('dashboard.logged_in')}: {loggedInCount} · {t('dashboard.needs_attention')}:{' '}
              {needsAttentionCount}
            </p>
          </Card>
          <Card title={t('dashboard.outbounds_card')}>
            <p>{status.outbound_count}</p>
          </Card>
          <Card title={t('dashboard.endpoints_card')}>
            <p>{status.endpoint_count}</p>
          </Card>
        </>
      )}

      <Card
        title={t('dashboard.profiles_table')}
        extra={
          <Button size="sm" onClick={() => navigate('/profiles')}>
            {t('dashboard.view_all')}
          </Button>
        }
      >
        {profiles.length === 0 ? (
          <EmptyState
            title={t('dashboard.empty_profiles')}
            action={
              <Button onClick={() => navigate('/profiles')}>{t('dashboard.add_profile')}</Button>
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('common.name')}</TableHead>
                <TableHead>{t('profiles.detail.source')}</TableHead>
                <TableHead>{t('profiles.detail.outbound')}</TableHead>
                <TableHead>{t('dashboard.login_status')}</TableHead>
                <TableHead>{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {profiles.map((profile) => {
                const login = loginByName[profile.name];
                return (
                  <TableRow key={profile.name}>
                    <TableCell>
                      <Link to={`/profiles/${encodeURIComponent(profile.name)}`}>
                        {profile.name}
                      </Link>
                      {profile.default && <span> {t('profiles.list.default_badge')}</span>}
                    </TableCell>
                    <TableCell>{profile.source}</TableCell>
                    <TableCell>{profile.outbound_tag ?? '—'}</TableCell>
                    <TableCell>
                      {login
                        ? login.logged_in
                          ? t('dashboard.logged_in')
                          : t('dashboard.not_logged_in')
                        : loginFailed[profile.name]
                          ? t('common.unknown')
                          : t('common.loading')}
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => navigate(`/profiles/${encodeURIComponent(profile.name)}`)}
                      >
                        {t('dashboard.view')}
                      </Button>{' '}
                      <Button size="sm" variant="secondary" onClick={() => void runTest(profile.name)}>
                        {t('dashboard.run_test')}
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      <div>
        <Button onClick={() => navigate('/profiles')}>{t('dashboard.add_profile')}</Button>{' '}
        <Button variant="secondary" onClick={() => navigate('/config')}>
          {t('dashboard.open_config')}
        </Button>
      </div>

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
