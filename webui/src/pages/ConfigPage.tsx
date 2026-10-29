import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import CodeMirror from '@uiw/react-codemirror';
import { json } from '@codemirror/lang-json';
import { configApi } from '@/services/api';
import type { ApiError } from '@/types';
import { diffStats, lineDiff, type DiffLine } from '@/utils/diff';
import { getErrorMessage } from '@/utils/helpers';
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard';
import { useNotificationStore, useThemeStore } from '@/stores';
import { codemirrorDarkTheme } from '@/utils/codemirrorTheme';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { Modal } from '@/components/ui/Modal';

/** JSON language support, defined once outside the component (README advice). */
const JSON_EXTENSIONS = [json()];

function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <div
      style={{
        maxHeight: '60vh',
        overflow: 'auto',
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
        fontSize: 12,
        lineHeight: 1.6,
      }}
    >
      {lines.map((line, index) => (
        <div
          key={index}
          style={{
            whiteSpace: 'pre-wrap',
            overflowWrap: 'anywhere',
            color:
              line.kind === '+'
                ? 'var(--success-color)'
                : line.kind === '-'
                  ? 'var(--error-color)'
                  : undefined,
          }}
        >
          {`${line.kind} ${line.text}`}
        </div>
      ))}
    </div>
  );
}

/** Config editor (design §2/§7): JSON source editor + diff-before-save +
 * guarded write. All data comes through the frozen configApi client; the
 * editor itself fetches nothing. No @codemirror/merge: the diff is the
 * kept lineDiff util rendered as text.
 */
export function ConfigPage() {
  const { t } = useTranslation();
  const showNotification = useNotificationStore((state) => state.showNotification);
  // Single source of truth for the app theme (useThemeStore): resolvedTheme
  // is 'dark' exactly when the app is dark — including Auto following the
  // OS via the store's matchMedia listener — and 'light' for light/white
  // (white normalises to light in the store), so the editor follows OS
  // changes without a reload and no second matchMedia is needed here.
  const resolvedTheme = useThemeStore((state) => state.resolvedTheme);
  const [baseContent, setBaseContent] = useState<string | null>(null);
  const [baseSha, setBaseSha] = useState('');
  const [source, setSource] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [showReloadConfirm, setShowReloadConfirm] = useState(false);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      setLoading(true);
      setError('');
      try {
        const data = await configApi.get(signal);
        if (signal?.aborted) return;
        setBaseContent(data.content);
        setContent(data.content);
        setBaseSha(data.sha256);
        setSource(data.source);
        setConflict(false);
      } catch (err) {
        if (signal?.aborted) return;
        setError(getErrorMessage(err, t('common.error')));
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [t]
  );

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const dirty = baseContent !== null && content !== baseContent;
  useUnsavedChangesGuard({
    shouldBlock: dirty,
    dialog: useMemo(
      () => ({
        title: t('config.editor.unsaved_title'),
        message: t('config.editor.unsaved_message'),
        confirmText: t('common.confirm'),
        cancelText: t('common.cancel'),
      }),
      [t],
    ),
  });
  const diffLines = useMemo(
    () => (baseContent === null ? [] : lineDiff(baseContent, content)),
    [baseContent, content]
  );
  const stats = useMemo(() => diffStats(diffLines), [diffLines]);

  const handleSaveClick = () => {
    if (!dirty || baseContent === null) return;
    try {
      JSON.parse(content);
    } catch (err) {
      setError(`${t('config.editor.invalid_json')} ${getErrorMessage(err, '')}`.trim());
      return;
    }
    setError('');
    setShowDiff(true);
  };

  const handleConfirmSave = async () => {
    setSaving(true);
    try {
      const result = await configApi.save({ content, base_sha256: baseSha });
      setBaseContent(content);
      setBaseSha(result.sha256);
      setShowDiff(false);
      setConflict(false);
      setError('');
      showNotification(t('config.editor.saved'), 'success');
    } catch (err) {
      // client.ts maps the envelope `{error: {type}}` onto ApiError.apiCode
      // and the HTTP status onto ApiError.status; design §4.3 names the
      // guard failure 409 `config_changed`.
      setShowDiff(false);
      if ((err as ApiError).status === 409) {
        setConflict(true);
      } else {
        setError(getErrorMessage(err, t('common.error')));
      }
    } finally {
      setSaving(false);
    }
  };

  const handleReloadClick = () => {
    if (dirty) {
      // Discarding edits needs an explicit confirm: the same Modal pattern,
      // showing the diff that would be thrown away.
      setShowReloadConfirm(true);
      return;
    }
    void load();
  };

  const handleConfirmReload = () => {
    setShowReloadConfirm(false);
    void load();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <Card title={t('config.editor.title')}>
        {loading && baseContent === null ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <LoadingSpinner />
            <span>{t('config.editor.loading')}</span>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ overflowWrap: 'anywhere', fontSize: 13 }}>
              <div>
                {t('config.editor.source')}: {source}
              </div>
              <div>
                {t('config.editor.sha')}: <code>{baseSha}</code>
              </div>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              <Button
                onClick={handleSaveClick}
                disabled={!dirty || saving || loading}
                loading={saving}
              >
                {t('config.editor.save')}
              </Button>
              <Button variant="secondary" onClick={handleReloadClick} disabled={saving || loading}>
                {t('config.editor.reload')}
              </Button>
            </div>
            {conflict && (
              <div className="error-box" role="alert">
                <p style={{ margin: 0 }}>{t('config.editor.conflict')}</p>
                <p style={{ margin: 0 }}>{t('config.editor.conflict_hint')}</p>
              </div>
            )}
            {error && (
              <div className="error-box" role="alert">
                {error}
              </div>
            )}
            <CodeMirror
              value={content}
              height="60vh"
              extensions={JSON_EXTENSIONS}
              theme={resolvedTheme === 'dark' ? codemirrorDarkTheme : 'light'}
              editable={!saving}
              onChange={(value) => {
                setContent(value);
                setError('');
              }}
            />
          </div>
        )}
      </Card>

      <Modal
        open={showDiff}
        title={t('config.editor.diff_title')}
        onClose={() => {
          if (!saving) setShowDiff(false);
        }}
        closeDisabled={saving}
        footer={
          <>
            <Button variant="ghost" onClick={() => setShowDiff(false)} disabled={saving}>
              {t('config.editor.cancel')}
            </Button>
            <Button onClick={() => void handleConfirmSave()} loading={saving}>
              {t('config.editor.confirm_save')}
            </Button>
          </>
        }
      >
        <p style={{ marginTop: 0 }}>
          +{stats.additions} {t('config.diff.additions')} · −{stats.deletions}{' '}
          {t('config.diff.deletions')}
        </p>
        <DiffView lines={diffLines} />
      </Modal>

      <Modal
        open={showReloadConfirm}
        title={t('config.editor.reload')}
        onClose={() => setShowReloadConfirm(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setShowReloadConfirm(false)}>
              {t('config.editor.cancel')}
            </Button>
            <Button onClick={handleConfirmReload}>{t('config.editor.reload')}</Button>
          </>
        }
      >
        <p style={{ marginTop: 0 }}>
          {conflict
            ? t('config.editor.conflict_hint')
            : `${t('config.editor.diff_title')}: +${stats.additions} ${t('config.diff.additions')} · −${stats.deletions} ${t('config.diff.deletions')}`}
        </p>
        <DiffView lines={diffLines} />
      </Modal>
    </div>
  );
}
