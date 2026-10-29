import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { statusApi } from '@/services/api';
import type { StatusInfo } from '@/types';

const UPSTREAM_REPO = 'router-for-me/Cli-Proxy-API-Management-Center';
const UPSTREAM_HEAD = '64b4f5aed19b8f791eb21eb9e785ea379ea05b44';
const UPSTREAM_LICENCE = 'MIT';
const BUNDLE_HASH_PREFIX_LENGTH = 12;

function InfoRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        gap: 16,
        flexWrap: 'wrap',
        padding: '8px 0',
      }}
    >
      <span>{label}</span>
      <span style={{ overflowWrap: 'anywhere', textAlign: 'right' }}>{children}</span>
    </div>
  );
}

/** System info from GET /api/v1/status (design §2, §4.3).
 * listen_addr / config_path are server-returned display strings and are
 * rendered verbatim. No update check, no logout action here: the header
 * already owns logout, and updates stay CLI-only.
 */
export function SystemPage() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<StatusInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      setLoading(true);
      setFailed(false);
      try {
        setStatus(await statusApi.get(controller.signal));
      } catch {
        // AbortError (via the client's plain Error) is not a failure:
        // the effect was cleaned up. Server errors surface only as the
        // generic message below, never with a raw error body.
        if (controller.signal.aborted) return;
        setFailed(true);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    void load();
    return () => controller.abort();
  }, [refreshKey]);

  const refresh = () => setRefreshKey((key) => key + 1);

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <LoadingSpinner />
        <span>{t('common.loading')}</span>
      </div>
    );
  }

  if (failed || !status) {
    return (
      <Card title={t('system.title')}>
        <p style={{ marginTop: 0 }}>{t('common.error')}</p>
        <Button variant="secondary" onClick={refresh}>
          {t('common.retry')}
        </Button>
      </Card>
    );
  }

  const bundleHash = status.bundle_sha256;
  const bundleShort =
    bundleHash.length > BUNDLE_HASH_PREFIX_LENGTH
      ? `${bundleHash.slice(0, BUNDLE_HASH_PREFIX_LENGTH)}…`
      : bundleHash;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <h1 style={{ margin: 0 }}>{t('system.title')}</h1>
      <Card
        title={t('system.versions.title')}
        extra={
          <Button variant="secondary" size="sm" onClick={refresh}>
            {t('common.refresh')}
          </Button>
        }
      >
        <InfoRow label={t('system.versions.version')}>
          {status.version || t('common.unknown')}
        </InfoRow>
        <InfoRow label={t('system.versions.go')}>
          {status.go_version || t('common.unknown')}
        </InfoRow>
        <InfoRow label={t('system.versions.singbox')}>
          {status.singbox_version || t('common.unknown')}
        </InfoRow>
        <InfoRow label={t('system.versions.bundle')}>
          {bundleHash ? (
            <code title={bundleHash}>{bundleShort}</code>
          ) : (
            t('common.unknown')
          )}
        </InfoRow>
      </Card>
      <Card title={t('system.listen.title')}>
        <InfoRow label={t('system.listen.addr')}>
          {status.listen_addr || t('common.unknown')}
        </InfoRow>
        {status.remote_exposure && (
          <p role="alert" style={{ marginBottom: 0 }}>
            {t('system.listen.remote')}
          </p>
        )}
      </Card>
      <Card title={t('system.config.title')}>
        <InfoRow label={t('system.config.path')}>
          {status.config_path || t('common.unknown')}
        </InfoRow>
        <InfoRow label={t('system.config.source')}>
          {status.config_source || t('common.unknown')}
        </InfoRow>
        <InfoRow label={t('system.config.profiles')}>{status.profile_count}</InfoRow>
        <InfoRow label={t('system.config.outbounds')}>{status.outbound_count}</InfoRow>
        <InfoRow label={t('system.config.endpoints')}>{status.endpoint_count}</InfoRow>
      </Card>
      <Card title={t('system.about.title')}>
        <p style={{ marginTop: 0 }}>{t('system.about.attribution')}</p>
        <p style={{ marginBottom: 0, overflowWrap: 'anywhere' }}>
          {UPSTREAM_REPO} — {UPSTREAM_HEAD} — {UPSTREAM_LICENCE}
        </p>
      </Card>
    </div>
  );
}
