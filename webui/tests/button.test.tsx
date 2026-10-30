import { createRef } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Button } from '../src/components/ui/Button';

/**
 * RED-FIRST (TDD): E2 `variant="plain"` contract + E1 ref smoke.
 * Written before Button gained either extension; the first run must FAIL
 * on the plain assertions (btn classes + wrapper span). See
 * ~/workspace/tmp/webui-buttons/red-first.log.
 *
 * Rendering uses react-dom/server (an existing dependency). There is no
 * DOM/render infra in this repo (no jsdom, no Testing Library), so no
 * test here can prove a ref lands on a live DOM node: the ref test below
 * only proves passing a ref renders without error. DOM attachment is
 * proved by the in-repo tsc probe (red-first.log) and carried to live
 * verification by the parent.
 */
describe('Button variant="plain" (E2)', () => {
  it('renders no btn classes and only the caller className', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="plain" className="site-class">
        Label
      </Button>
    );
    expect(markup).not.toMatch(/\bbtn\b/);
    expect(markup).not.toContain('btn-');
    expect(markup).toContain('class="site-class"');
  });

  it('renders children directly, with no wrapper span', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="plain">
        <span>First</span>
        <span>Second</span>
      </Button>
    );
    expect(markup).toContain('><span>First</span><span>Second</span></button>');
    expect(markup).not.toContain('<span><span>');
  });

  it('forwards type, disabled and aria attributes', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="plain" disabled aria-label="Close it">
        Label
      </Button>
    );
    expect(markup).toContain('type="button"');
    expect(markup).toContain('disabled=""');
    expect(markup).toContain('aria-label="Close it"');
  });

  it('loading still forces disabled and renders the spinner inline, without wrapping children', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="plain" loading>
        Label
      </Button>
    );
    expect(markup).toContain('disabled=""');
    expect(markup).toContain('loading-spinner');
    expect(markup).toContain('Label</button>');
    expect(markup).not.toContain('<span>Label</span>');
  });

  it('ignores size and fullWidth in plain mode', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="plain" size="sm" fullWidth>
        Label
      </Button>
    );
    expect(markup).not.toContain('btn-sm');
    expect(markup).not.toContain('btn-full');
  });

  it('accepts a ref prop and renders (no DOM attachment claim — see header)', () => {
    const ref = createRef<HTMLButtonElement>();
    const markup = renderToStaticMarkup(
      <Button ref={ref} type="button" variant="plain">
        Label
      </Button>
    );
    expect(markup).toContain('<button');
    expect(ref.current).toBeNull();
  });
});

describe('Button existing variants (regression guards)', () => {
  it('ghost still renders btn classes and wraps children in one span', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="ghost">
        Label
      </Button>
    );
    expect(markup).toContain('btn btn-ghost');
    expect(markup).toContain('><span>Label</span></button>');
  });

  it('secondary still forwards type="button" and wraps children in one span', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="secondary">
        Label
      </Button>
    );
    expect(markup).toContain('type="button"');
    expect(markup).toContain('btn btn-secondary');
    expect(markup).toContain('><span>Label</span></button>');
  });

  it('secondary with loading still forwards type="button" and forces disabled', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" variant="secondary" loading>
        Label
      </Button>
    );
    expect(markup).toContain('type="button"');
    expect(markup).toContain('disabled=""');
    expect(markup).toContain('loading-spinner');
  });

  it('default variant is still primary', () => {
    const markup = renderToStaticMarkup(<Button type="button">Label</Button>);
    expect(markup).toContain('btn btn-primary');
  });

  it('loading still forces disabled for non-plain variants', () => {
    const markup = renderToStaticMarkup(
      <Button type="button" loading>
        Label
      </Button>
    );
    expect(markup).toContain('disabled=""');
    expect(markup).toContain('loading-spinner');
  });
});
