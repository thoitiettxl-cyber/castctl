import { EditorView } from '@codemirror/view';
import type { Extension } from '@codemirror/state';
import { oneDark } from '@uiw/react-codemirror';

/**
 * Dark CodeMirror theme for the Config Editor, matching the app dark theme
 * in webui/src/styles/themes.scss ([data-theme='dark']).
 *
 * Syntax colours come from oneDark, re-exported by the already-declared
 * '@uiw/react-codemirror' dependency (its getDefaultExtensions barrel
 * re-exports '@codemirror/theme-one-dark'). No new dependency is added:
 * a bare EditorView.theme alone cannot recolour syntax tokens, because
 * the default highlight style (from basicSetup) generates its own
 * classes and would keep its light colours on a dark background.
 *
 * The EditorView.theme overlay only restates editor chrome (background,
 * text, gutters, panels) with the app dark tokens; it is placed after
 * oneDark so its rules win for the selectors it overrides. Syntax token
 * colours are left exactly as oneDark defines them.
 *
 * Palette (copied from themes.scss, dark block):
 *   background #1d1b18 (--bg-primary), text #f6f4f1 (--text-primary),
 *   gutter text #9c958d (--text-tertiary), active gutter #262320
 *   (--bg-tertiary).
 */
const appDarkChrome = EditorView.theme(
  {
    '&': {
      backgroundColor: '#1d1b18',
      color: '#f6f4f1',
    },
    '.cm-gutters': {
      backgroundColor: '#1d1b18',
      color: '#9c958d',
      border: 'none',
    },
    '.cm-activeLineGutter': {
      backgroundColor: '#262320',
    },
    '.cm-panels': {
      backgroundColor: '#1d1b18',
      color: '#f6f4f1',
    },
  },
  { dark: true },
);

/** Dark editor extension: proven oneDark syntax + app-matched chrome. */
export const codemirrorDarkTheme: Extension = [oneDark, appDarkChrome];
