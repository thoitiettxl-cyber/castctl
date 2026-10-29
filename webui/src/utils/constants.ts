/** Constants for the castctl web UI. No hard-coded hosts or VM paths. */

import type { Language } from '@/types';

const defineLanguageOrder = <T extends readonly Language[]>(
  languages: T & ([Language] extends [T[number]] ? unknown : never),
) => languages;

// Network
export const DEFAULT_API_PORT = 8317;
export const MANAGEMENT_API_PREFIX = '/api/v1';
export const REQUEST_TIMEOUT_MS = 30 * 1000;

// Logs
export const LOGS_TIMEOUT_MS = 60 * 1000;

// Cookie import cap (design §6.2)
export const MAX_COOKIE_IMPORT_SIZE = 1 * 1024 * 1024;

// Local storage keys (locale preference ONLY — never the token).
export const STORAGE_KEY_THEME = 'castctl-theme';
export const STORAGE_KEY_LANGUAGE = 'castctl-language';
export const SESSION_KEY_TOKEN = 'castctl-management-token';

// Languages: English + Vietnamese only.
export const LANGUAGE_ORDER = defineLanguageOrder(['en', 'vi'] as const);
export const LANGUAGE_LABEL_KEYS: Record<Language, string> = {
  en: 'language.english',
  vi: 'language.vietnamese',
};
export const SUPPORTED_LANGUAGES = LANGUAGE_ORDER;

// Notification duration
export const NOTIFICATION_DURATION_MS = 3000;
