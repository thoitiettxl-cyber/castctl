import type { ButtonHTMLAttributes, PropsWithChildren, Ref } from 'react';

// 'plain' is chromeless: no btn classes, no wrapper span around children.
// For sites whose styling lives entirely in a bespoke className, where the
// btn chrome would override the site styling and the wrapper span would
// break multi-child layouts. Do not use it for ordinary action buttons.
type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'plain';
type ButtonSize = 'md' | 'sm';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  fullWidth?: boolean;
  loading?: boolean;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({
  children,
  variant = 'primary',
  size = 'md',
  fullWidth = false,
  loading = false,
  className = '',
  disabled,
  ref,
  ...rest
}: PropsWithChildren<ButtonProps>) {
  const hasChildren = children !== null && children !== undefined && children !== false;
  const isPlain = variant === 'plain';
  const classes = isPlain
    ? className
    : [
        'btn',
        `btn-${variant}`,
        size === 'sm' ? 'btn-sm' : '',
        fullWidth ? 'btn-full' : '',
        className,
      ]
        .filter(Boolean)
        .join(' ');

  return (
    <button ref={ref} className={classes} disabled={disabled || loading} {...rest}>
      {loading && <span className="loading-spinner" aria-hidden="true" />}
      {isPlain ? children : hasChildren && <span>{children}</span>}
    </button>
  );
}
