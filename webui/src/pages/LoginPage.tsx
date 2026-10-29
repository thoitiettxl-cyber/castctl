import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/stores';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';

/** Token login (design §5): token input + `?token=` capture + sessionStorage.
 * Same-origin only. No token is ever written to disk or localStorage.
 */
export function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const login = useAuthStore((state) => state.login);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const captured = params.get('token');
    if (captured) {
      setToken(captured);
      // Strip the token from the URL bar immediately; it must not linger
      // in history or be shared via copy-paste of the URL.
      navigate(location.pathname, { replace: true });
    }
  }, [location.search, location.pathname, navigate]);

  if (isAuthenticated) {
    const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname;
    return <Navigate to={from ?? '/'} replace />;
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const value = token.trim();
    if (!value) return;
    setSubmitting(true);
    setError('');
    const result = await login(value);
    setSubmitting(false);
    if (!result.success) {
      setError(t('login.invalid_token'));
      return;
    }
    navigate('/', { replace: true });
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
    >
      <Card title={t('login.title')} className="login-card">
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 'min(420px, calc(100vw - 32px))' }}>
          <p style={{ margin: 0 }}>{t('login.subtitle')}</p>
          <Input
            label={t('login.token_label')}
            type="password"
            autoComplete="off"
            autoFocus
            placeholder={t('login.token_placeholder')}
            value={token}
            onChange={(event) => setToken(event.target.value)}
            error={error || undefined}
          />
          <p style={{ margin: 0 }}>{t('login.hint')}</p>
          <p style={{ margin: 0 }}>{t('login.paste_fallback')}</p>
          <Button type="submit" loading={submitting} disabled={!token.trim()}>
            {t('login.submit')}
          </Button>
        </form>
      </Card>
    </div>
  );
}
