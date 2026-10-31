import { describe, expect, it } from 'vitest';
import en from '../src/i18n/locales/en.json';
import vi from '../src/i18n/locales/vi.json';

/** Keys the Config + Logs pages (and the pages whose copy was allocated
 * in the same i18n batch) render. Parity is covered by
 * i18n-parity.test.ts; this pins presence so a key removal fails here
 * with the page that needs it named.
 */
const REQUIRED_KEYS = [
  'dashboard.view',
  'dashboard.run_test',
  'dashboard.login_status',
  'dashboard.not_logged_in',
  'dashboard.view_all',
  'profiles.list.add',
  'profiles.list.set_default',
  'profiles.list.delete',
  'profiles.list.confirm_delete',
  'profiles.list.test',
  'profiles.list.empty',
  'profiles.detail.back',
  'profiles.detail.outbound',
  'profiles.detail.fingerprint',
  'profiles.detail.source',
  'profiles.detail.cookies',
  'profiles.detail.warnings',
  'profiles.detail.rename',
  'profiles.detail.new_name',
  'profiles.detail.set_default',
  'profiles.detail.delete',
  'profiles.detail.confirm_delete',
  'profiles.detail.run_test',
  'profiles.detail.test_result',
  'profiles.detail.egress_ip',
  'profiles.detail.phases',
  'profiles.login_card.status',
  'profiles.login_card.logged_in',
  'profiles.login_card.not_logged_in',
  'profiles.login_card.expiry',
  'profiles.login_card.import',
  'profiles.login_card.paste_hint',
  'profiles.login_card.format',
  'profiles.login_card.import_button',
  'profiles.login_card.import_success',
  'profiles.login_card.import_failed',
  'profiles.login_card.browser_login',
  'profiles.login_card.size_error',
  'settings.dns.title',
  'settings.dns.servers',
  'settings.dns.save',
  'settings.telegram.title',
  'settings.telegram.configured',
  'settings.telegram.masked',
  'settings.telegram.token',
  'settings.telegram.profile',
  'settings.telegram.allowed',
  'settings.telegram.save',
  'settings.defaults.title',
  'settings.defaults.auto_approve',
  'settings.defaults.auto_allow_once',
  'settings.defaults.save',
  'settings.saved',
  'outbounds.list.empty',
  'outbounds.list.used_by',
  'outbounds.list.none',
  'outbounds.list.summary',
  'endpoints.list.empty',
  'endpoints.list.used_by',
  'endpoints.list.import_preview',
  'endpoints.list.import_hint',
  'system.versions.title',
  'system.versions.version',
  'system.versions.go',
  'system.versions.singbox',
  'system.versions.bundle',
  'system.listen.title',
  'system.listen.addr',
  'system.listen.remote',
  'system.config.title',
  'system.config.path',
  'system.config.source',
  'system.config.profiles',
  'system.config.outbounds',
  'system.config.endpoints',
  'system.keeper.title',
  'system.keeper.none',
  'system.keeper.tag',
  'system.keeper.profile',
  'system.keeper.browser',
  'system.keeper.outcome',
  'system.keeper.last_checked',
  'system.keeper.next_check',
  'system.keeper.logged_out',
  'system.keeper.stopped',
  'system.keeper.never_ticked',
  'config.editor.title',
  'config.editor.loading',
  'config.editor.save',
  'config.editor.saved',
  'config.editor.conflict',
  'config.editor.conflict_hint',
  'config.editor.reload',
  'config.editor.invalid_json',
  'config.editor.diff_title',
  'config.editor.confirm_save',
  'config.editor.cancel',
  'config.editor.source',
  'config.editor.sha',
  'config.diff.additions',
  'config.diff.deletions',
  'logs.empty',
  'logs.level',
  'logs.level_all',
  'logs.filter',
  'logs.load_more',
  'logs.auto_refresh',
  'logs.pause',
  'logs.resume',
  'logs.copy',
  'logs.copied',
  'logs.disabled',
  'logs.disabled_hint',
  'screencast_login.unavailable',
  'screencast_login.profile',
  'screencast_login.status_checking',
  'screencast_login.phase',
  'screencast_login.frame_alt',
  'screencast_login.connecting',
  'screencast_login.error',
  'screencast_login.ended',
  'screencast_login.cookies_saved',
];

function lookup(obj: Record<string, unknown>, key: string): unknown {
  return key.split('.').reduce<unknown>((cur, part) => {
    if (cur && typeof cur === 'object') return (cur as Record<string, unknown>)[part];
    return undefined;
  }, obj);
}

describe('page i18n keys', () => {
  it('every required key exists and is non-empty in en and vi', () => {
    for (const key of REQUIRED_KEYS) {
      for (const [name, locale] of [
        ['en', en],
        ['vi', vi],
      ] as const) {
        const value = lookup(locale as Record<string, unknown>, key);
        expect(typeof value, `${name}:${key}`).toBe('string');
        expect((value as string).length, `${name}:${key}`).toBeGreaterThan(0);
      }
    }
  });
});
