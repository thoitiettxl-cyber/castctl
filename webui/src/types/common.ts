/** Shared types for castctl web UI. */

export type Theme = 'light' | 'white' | 'dark' | 'auto';

export type Language = 'en' | 'vi';

export type NotificationType = 'info' | 'success' | 'warning' | 'error';

export interface Notification {
  id: string;
  message: string;
  type: NotificationType;
  duration?: number;
}
