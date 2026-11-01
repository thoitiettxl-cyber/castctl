import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { dnsApi, settingsApi } from '@/services/api';
import type { ApiError } from '@/types';
import { getErrorMessage, isRecord } from '@/utils/helpers';
import { useNotificationStore } from '@/stores';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { ToggleSwitch } from '@/components/ui/ToggleSwitch';

export function SettingsPage() {
  const { t } = useTranslation();
  const showNotification = useNotificationStore((state) => state.showNotification);

  const [dnsText, setDnsText] = useState('');
  const [dnsBaseSha, setDnsBaseSha] = useState('');
  const [dnsLoaded, setDnsLoaded] = useState(false);
  const [dnsError, setDnsError] = useState('');
  const [dnsSaving, setDnsSaving] = useState(false);

  const [telegramConfigured, setTelegramConfigured] = useState(false);
  const [telegramMasked, setTelegramMasked] = useState('');
  const [tokenInput, setTokenInput] = useState('');
  const [profileText, setProfileText] = useState('');
  const [allowedText, setAllowedText] = useState('');
  const [tgAutoApprove, setTgAutoApprove] = useState(false);
  const [tgAutoAllowOnce, setTgAutoAllowOnce] = useState(false);
  const [telegramLoaded, setTelegramLoaded] = useState(false);
  const [telegramError, setTelegramError] = useState('');
  const [telegramSaving, setTelegramSaving] = useState(false);

  const loadDns = useCallback(async () => {
    setDnsError('');
    try {
      const result = await dnsApi.get();
      setDnsText(JSON.stringify(result.dns, null, 2));
      setDnsBaseSha(result.sha256);
      setDnsLoaded(true);
    } catch (err) {
      setDnsError(getErrorMessage(err, t('common.error')));
    }
  }, [t]);

  const loadTelegram = useCallback(async () => {
    setTelegramError('');
    try {
      const result = await settingsApi.getTelegram();
      setTelegramConfigured(result.configured);
      setTelegramMasked(result.masked);
      setProfileText(result.profile ?? '');
      setAllowedText((result.allowed_user_ids ?? []).join(', '));
      setTgAutoApprove(result.auto_approve);
      setTgAutoAllowOnce(result.auto_allow_once);
      setTelegramLoaded(true);
    } catch (err) {
      setTelegramError(getErrorMessage(err, t('common.error')));
    }
  }, [t]);

  useEffect(() => {
    void loadDns();
    void loadTelegram();
  }, [loadDns, loadTelegram]);

  const handleSaveDns = async (event: FormEvent) => {
    event.preventDefault();
    setDnsError('');
    let parsed: unknown;
    try {
      parsed = JSON.parse(dnsText);
    } catch {
      setDnsError(t('settings.dns.invalid_json'));
      return;
    }
    if (!isRecord(parsed)) {
      setDnsError(t('settings.dns.invalid_json'));
      return;
    }
    setDnsSaving(true);
    try {
      const result = await dnsApi.save({ dns: parsed, base_sha256: dnsBaseSha });
      setDnsBaseSha(result.sha256);
      showNotification(t('settings.saved'), 'success');
    } catch (err) {
      // 409 config_changed: the stored file moved under us. Reload the
      // fresh redacted slice, discarding the failed edit (including any
      // secret the user typed into it); never auto-reapply it.
      if ((err as ApiError).status === 409) await loadDns();
      showNotification(getErrorMessage(err, t('notification.save_failed')), 'error');
    } finally {
      setDnsSaving(false);
    }
  };

  const parseIdList = (text: string): number[] | null => {
    const ids: number[] = [];
    for (const part of text.split(',')) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const value = Number(trimmed);
      if (!Number.isInteger(value)) return null;
      ids.push(value);
    }
    return ids;
  };

  const handleSaveTelegram = async (event: FormEvent) => {
    event.preventDefault();
    setTelegramError('');
    const allowed = parseIdList(allowedText);
    if (allowed === null) {
      setTelegramError(t('settings.telegram.invalid_ids'));
      return;
    }
    const body: Record<string, unknown> = {
      auto_approve: tgAutoApprove,
      auto_allow_once: tgAutoAllowOnce,
      allowed_user_ids: allowed,
    };
    // Empty profile = keep the stored one (or the default profile
    // when creating the block, server-side).
    if (profileText.trim()) body.profile = profileText.trim();
    // Empty token = unchanged (write-only field, design §5.4).
    if (tokenInput.trim()) body.token = tokenInput.trim();
    setTelegramSaving(true);
    try {
      const result = await settingsApi.saveTelegram(body);
      setTelegramConfigured(result.configured);
      setTelegramMasked(result.masked);
      setTokenInput('');
      showNotification(t('settings.saved'), 'success');
    } catch (err) {
      showNotification(getErrorMessage(err, t('notification.save_failed')), 'error');
    } finally {
      setTelegramSaving(false);
    }
  };

  if (!dnsLoaded && !telegramLoaded && !dnsError && !telegramError) {
    return (
      <div className="page-root">
        <h1>{t('settings.title')}</h1>
        <LoadingSpinner />
        <p>{t('common.loading')}</p>
      </div>
    );
  }

  return (
    <div className="page-root">
      <h1>{t('settings.title')}</h1>

      <Card title={t('settings.dns.title')}>
        {dnsError && <p>{dnsError}</p>}
        {!dnsLoaded && dnsError ? (
          <Button variant="secondary" onClick={() => void loadDns()}>
            {t('common.retry')}
          </Button>
        ) : (
          <form onSubmit={(event) => void handleSaveDns(event)}>
            <div>
              <label htmlFor="dns-editor">{t('settings.dns.servers')}</label>
              <textarea
                id="dns-editor"
                className="input"
                rows={10}
                value={dnsText}
                onChange={(event) => setDnsText(event.target.value)}
              />
            </div>
            <Button type="submit" loading={dnsSaving}>
              {t('settings.dns.save')}
            </Button>
          </form>
        )}
      </Card>

      <Card title={t('settings.telegram.title')}>
        {telegramError && <p>{telegramError}</p>}
        {!telegramLoaded && telegramError ? (
          <Button variant="secondary" onClick={() => void loadTelegram()}>
            {t('common.retry')}
          </Button>
        ) : (
          <form onSubmit={(event) => void handleSaveTelegram(event)}>
            <p>
              {t('settings.telegram.configured')}:{' '}
              {telegramConfigured ? t('common.yes') : t('common.no')}
            </p>
            <p>
              {t('settings.telegram.masked')}: {telegramMasked}
            </p>
            <Input
              label={t('settings.telegram.token')}
              type="password"
              autoComplete="off"
              hint={t('common.unchanged')}
              value={tokenInput}
              onChange={(event) => setTokenInput(event.target.value)}
            />
            <Input
              label={t('settings.telegram.profile')}
              value={profileText}
              onChange={(event) => setProfileText(event.target.value)}
            />
            <Input
              label={t('settings.telegram.allowed')}
              value={allowedText}
              onChange={(event) => setAllowedText(event.target.value)}
            />
            <ToggleSwitch
              checked={tgAutoApprove}
              onChange={setTgAutoApprove}
              label={t('settings.defaults.auto_approve')}
            />
            <ToggleSwitch
              checked={tgAutoAllowOnce}
              onChange={setTgAutoAllowOnce}
              label={t('settings.defaults.auto_allow_once')}
            />
            <Button type="submit" loading={telegramSaving}>
              {t('settings.telegram.save')}
            </Button>
          </form>
        )}
      </Card>
    </div>
  );
}
