// @vitest-environment jsdom
import { act, createRef, type Ref } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { Button } from '../src/components/ui/Button';

// DOM attachment proof for the Button ref (E1). The SSR test in
// button.test.tsx can only prove passing a ref renders without error
// (ref.current stays null under renderToStaticMarkup); this file proves
// the ref lands on the real mounted <button> element, by identity.
// Per-file jsdom environment only — the rest of the suite stays in node.
// No Testing Library: rendering is plain createRoot + act() from the
// already-installed React 19 packages, and jsdom is a devDependency only.

// Without Testing Library, React needs this flag or act() warns that the
// environment is not configured to support act(...).
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe('Button ref attaches to the real DOM <button>', () => {
  let container: HTMLDivElement | null = null;
  let root: Root | null = null;

  afterEach(() => {
    if (root) {
      act(() => {
        root?.unmount();
      });
      root = null;
    }
    container?.remove();
    container = null;
  });

  function renderButton(ref: Ref<HTMLButtonElement>, props: { variant?: 'plain'; className?: string } = {}) {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    act(() => {
      root?.render(
        <Button ref={ref} type="button" {...props}>
          Label
        </Button>
      );
    });
    return container.querySelector('button');
  }

  it('plain: ref.current IS the rendered button element', () => {
    const ref = createRef<HTMLButtonElement>();
    const buttonEl = renderButton(ref, { variant: 'plain', className: 'site-class' });
    expect(buttonEl).not.toBeNull();
    expect(ref.current).toBe(buttonEl);
    expect(ref.current).toBeInstanceOf(HTMLButtonElement);
    expect(ref.current?.tagName).toBe('BUTTON');
    expect(ref.current?.className).toBe('site-class');
  });

  it('default: ref.current IS the rendered button element', () => {
    const ref = createRef<HTMLButtonElement>();
    const buttonEl = renderButton(ref);
    expect(buttonEl).not.toBeNull();
    expect(ref.current).toBe(buttonEl);
    expect(ref.current).toBeInstanceOf(HTMLButtonElement);
    expect(ref.current?.tagName).toBe('BUTTON');
    expect(ref.current?.className).toContain('btn btn-primary');
  });

  it('callback ref receives the same element', () => {
    let received: HTMLButtonElement | null = null;
    const buttonEl = renderButton(
      (el) => {
        received = el;
      },
      { variant: 'plain' }
    );
    expect(buttonEl).not.toBeNull();
    expect(received).toBe(buttonEl);
  });
});
