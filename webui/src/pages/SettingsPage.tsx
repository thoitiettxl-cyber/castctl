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
import { Modal } from '@/components/ui/Modal';
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

  // Keeper section editor: the entries list as JSON text, saved
  // through the same base_sha256 guard as DNS. `[]` keeps an empty
  // block; `null` removes the block (server semantics, see the
  // hint under the editor).
  const [keeperText, setKeeperText] = useState('');
  const [keeperBaseSha, setKeeperBaseSha] = useState('');
  const [keeperLoaded, setKeeperLoaded] = useState(false);
  const [keeperError, setKeeperError] = useState('');
  const [keeperSaving, setKeeperSaving] = useState(false);
  // Saving a literal `null` removes the keeper block: confirm
  // first (page-local Modal, danger variant).
  const [keeperConfirmOpen, setKeeperConfirmOpen] = useState(false);

  // Web UI section editor: partial PUT, absent = unchanged. Empty
  // listen/ui_dir/idle deletes the key (default returns); empty
  // token = unchanged (write-only); empty attempts+window leaves
  // the rate limit untouched. Deleting the rate-limit key needs
  // the whole-document Config editor.
  const [webuiListen, setWebuiListen] = useState('');
  const [webuiUiDir, setWebuiUiDir] = useState('');
  const [webuiIdle, setWebuiIdle] = useState('');
  const [webuiAttempts, setWebuiAttempts] = useState('');
  const [webuiWindow, setWebuiWindow] = useState('');
  const [webuiTokenSet, setWebuiTokenSet] = useState(false);
  const [webuiTokenInput, setWebuiTokenInput] = useState('');
  const [webuiBaseSha, setWebuiBaseSha] = useState('');
  const [webuiLoaded, setWebuiLoaded] = useState(false);
  const [webuiError, setWebuiError] = useState('');
  const [webuiSaving, setWebuiSaving] = useState(false);
  // Values as loaded, for the key-deletion confirm: emptying a
  // field that was non-empty deletes its key, so confirm first.
  // (A field empty at load stays empty: no key is deleted.)
  const [webuiInitial, setWebuiInitial] = useState({ listen: '', uiDir: '', idle: '' });
  const [webuiDeleteKeys, setWebuiDeleteKeys] = useState<string[]>([]);
  const [webuiConfirmOpen, setWebuiConfirmOpen] = useState(false);

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

  const loadKeeper = useCallback(async () => {
    setKeeperError('');
    try {
      const result = await settingsApi.getKeeper();
      setKeeperText(JSON.stringify(result.entries, null, 2));
      setKeeperBaseSha(result.sha256);
      setKeeperLoaded(true);
    } catch (err) {
      setKeeperError(getErrorMessage(err, t('common.error')));
    }
  }, [t]);

  const loadWebUI = useCallback(async () => {
    setWebuiError('');
    try {
      const result = await settingsApi.getWebUI();
      setWebuiListen(result.listen);
      setWebuiUiDir(result.ui_dir);
      setWebuiIdle(result.session_idle_timeout);
      setWebuiAttempts(String(result.login_rate_limit.attempts));
      setWebuiWindow(result.login_rate_limit.window);
      setWebuiTokenSet(result.token_set);
      setWebuiBaseSha(result.sha256);
      setWebuiInitial({
        listen: result.listen,
        uiDir: result.ui_dir,
        idle: result.session_idle_timeout,
      });
      setWebuiLoaded(true);
    } catch (err) {
      setWebuiError(getErrorMessage(err, t('common.error')));
    }
  }, [t]);

  useEffect(() => {
    void loadKeeper();
    void loadWebUI();
  }, [loadKeeper, loadWebUI]);

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

  const handleSaveKeeper = async (event: FormEvent) => {
    event.preventDefault();
    setKeeperError('');
    let parsed: unknown;
    try {
      parsed = JSON.parse(keeperText);
    } catch {
      setKeeperError(t('settings.keeper.invalid_json'));
      return;
    }
    if (!Array.isArray(parsed) && parsed !== null) {
      setKeeperError(t('settings.keeper.invalid_json'));
      return;
    }
    // A literal null removes the block: confirm before saving.
    if (parsed === null) {
      setKeeperConfirmOpen(true);
      return;
    }
    await doSaveKeeper(parsed);
  };

  const doSaveKeeper = async (parsed: unknown) => {
    setKeeperSaving(true);
    try {
      const result = await settingsApi.saveKeeper({ entries: parsed, base_sha256: keeperBaseSha });
      setKeeperBaseSha(result.sha256);
      showNotification(t('settings.saved'), 'success');
    } catch (err) {
      // 409 config_changed: reload the fresh entries, discarding
      // the failed edit; never auto-reapply it.
      if ((err as ApiError).status === 409) await loadKeeper();
      showNotification(getErrorMessage(err, t('notification.save_failed')), 'error');
    } finally {
      setKeeperSaving(false);
    }
  };

  // Builds the partial PUT body, or null after setting a
  // validation error. Shared by the submit handler and the
  // key-deletion confirm, so the confirmed save sends exactly
  // the body the user submitted.
  const buildWebUIBody = (): Record<string, unknown> | null => {
    const body: Record<string, unknown> = { base_sha256: webuiBaseSha };
    // Empty listen/ui_dir/idle = delete the key (server default
    // returns). The token is write-only: empty = unchanged.
    body.listen = webuiListen;
    body.ui_dir = webuiUiDir;
    body.session_idle_timeout = webuiIdle;
    if (webuiTokenInput.trim()) body.token = webuiTokenInput.trim();
    const limit: Record<string, unknown> = {};
    if (webuiAttempts.trim()) {
      const attempts = Number(webuiAttempts.trim());
      if (!Number.isInteger(attempts)) {
        setWebuiError(t('settings.webui.invalid_attempts'));
        return null;
      }
      limit.attempts = attempts;
    }
    if (webuiWindow.trim()) limit.window = webuiWindow.trim();
    if (Object.keys(limit).length > 0) body.login_rate_limit = limit;
    return body;
  };

  const handleSaveWebUI = async (event: FormEvent) => {
    event.preventDefault();
    setWebuiError('');
    const body = buildWebUIBody();
    if (body === null) return;
    // Emptying a field that was non-empty at load deletes its
    // key: confirm before saving, naming the keys.
    const deletedKeys: string[] = [];
    if (!webuiListen.trim() && webuiInitial.listen.trim()) deletedKeys.push('listen');
    if (!webuiUiDir.trim() && webuiInitial.uiDir.trim()) deletedKeys.push('ui_dir');
    if (!webuiIdle.trim() && webuiInitial.idle.trim()) deletedKeys.push('session_idle_timeout');
    if (deletedKeys.length > 0) {
      setWebuiDeleteKeys(deletedKeys);
      setWebuiConfirmOpen(true);
      return;
    }
    await doSaveWebUI(body);
  };

  const doSaveWebUI = async (body: Record<string, unknown>) => {
    setWebuiSaving(true);
    try {
      const result = await settingsApi.saveWebUI(body);
      setWebuiBaseSha(result.sha256);
      setWebuiTokenInput('');
      showNotification(t('settings.saved'), 'success');
    } catch (err) {
      if ((err as ApiError).status === 409) await loadWebUI();
      showNotification(getErrorMessage(err, t('notification.save_failed')), 'error');
    } finally {
      setWebuiSaving(false);
    }
  };

  if (
    !dnsLoaded &&
    !telegramLoaded &&
    !keeperLoaded &&
    !webuiLoaded &&
    !dnsError &&
    !telegramError &&
    !keeperError &&
    !webuiError
  ) {
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
        {dnsError && (
          <div className="error-box" role="alert">
            {dnsError}
          </div>
        )}
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
        {telegramError && (
          <div className="error-box" role="alert">
            {telegramError}
          </div>
        )}
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

      <Card title={t('settings.keeper.title')}>
        {keeperError && (
          <div className="error-box" role="alert">
            {keeperError}
          </div>
        )}
        {!keeperLoaded && keeperError ? (
          <Button variant="secondary" onClick={() => void loadKeeper()}>
            {t('common.retry')}
          </Button>
        ) : (
          <form onSubmit={(event) => void handleSaveKeeper(event)}>
            <div>
              <label htmlFor="keeper-editor">{t('settings.keeper.entries')}</label>
              <textarea
                id="keeper-editor"
                className="input"
                rows={10}
                value={keeperText}
                onChange={(event) => setKeeperText(event.target.value)}
              />
            </div>
            <p>{t('settings.keeper.delete_hint')}</p>
            <Button type="submit" loading={keeperSaving}>
              {t('settings.keeper.save')}
            </Button>
          </form>
        )}
      </Card>

      <Card title={t('settings.webui.title')}>
        {webuiError && (
          <div className="error-box" role="alert">
            {webuiError}
          </div>
        )}
        {!webuiLoaded && webuiError ? (
          <Button variant="secondary" onClick={() => void loadWebUI()}>
            {t('common.retry')}
          </Button>
        ) : (
          <form onSubmit={(event) => void handleSaveWebUI(event)}>
            <p>
              {t('settings.webui.token_set')}: {webuiTokenSet ? t('common.yes') : t('common.no')}
            </p>
            <Input
              label={t('settings.webui.listen')}
              value={webuiListen}
              onChange={(event) => setWebuiListen(event.target.value)}
            />
            <Input
              label={t('settings.webui.ui_dir')}
              value={webuiUiDir}
              onChange={(event) => setWebuiUiDir(event.target.value)}
            />
            <Input
              label={t('settings.webui.session_idle_timeout')}
              value={webuiIdle}
              hint={t('settings.webui.session_idle_timeout_hint')}
              onChange={(event) => setWebuiIdle(event.target.value)}
            />
            <Input
              label={t('settings.webui.attempts')}
              type="number"
              value={webuiAttempts}
              onChange={(event) => setWebuiAttempts(event.target.value)}
            />
            <Input
              label={t('settings.webui.window')}
              value={webuiWindow}
              onChange={(event) => setWebuiWindow(event.target.value)}
            />
            <Input
              label={t('settings.webui.token')}
              type="password"
              autoComplete="off"
              hint={t('common.unchanged')}
              value={webuiTokenInput}
              onChange={(event) => setWebuiTokenInput(event.target.value)}
            />
            <p>{t('settings.webui.restart_hint')}</p>
            <Button type="submit" loading={webuiSaving}>
              {t('settings.webui.save')}
            </Button>
          </form>
        )}
      </Card>

      <Modal
        open={keeperConfirmOpen}
        onClose={() => setKeeperConfirmOpen(false)}
        title={t('settings.keeper.confirm_delete_title')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setKeeperConfirmOpen(false)}>
              {t('common.cancel')}
            </Button>{' '}
            <Button
              variant="danger"
              disabled={keeperSaving}
              onClick={() => {
                setKeeperConfirmOpen(false);
                void doSaveKeeper(null);
              }}
            >
              {t('common.delete')}
            </Button>
          </>
        }
      >
        <p>{t('settings.keeper.confirm_delete_body')}</p>
      </Modal>

      <Modal
        open={webuiConfirmOpen}
        onClose={() => setWebuiConfirmOpen(false)}
        title={t('settings.webui.confirm_delete_title')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setWebuiConfirmOpen(false)}>
              {t('common.cancel')}
            </Button>{' '}
            <Button
              variant="danger"
              disabled={webuiSaving}
              onClick={() => {
                setWebuiConfirmOpen(false);
                const body = buildWebUIBody();
                if (body !== null) void doSaveWebUI(body);
              }}
            >
              {t('settings.webui.confirm_delete_save')}
            </Button>
          </>
        }
      >
        <p>{t('settings.webui.confirm_delete_body', { keys: webuiDeleteKeys.join(', ') })}</p>
      </Modal>
    </div>
  );
}
