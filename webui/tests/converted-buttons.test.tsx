import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Modal } from '../src/components/ui/Modal';
import { Select } from '../src/components/ui/Select';
import { Sheet } from '../src/components/ui/Sheet';
import '../src/i18n';

/**
 * Behaviour guards for the converted controls that can render under
 * react-dom/server. jsdom is now a devDependency, and
 * webui/tests/button-ref-dom.test.tsx proves ref attachment to a real
 * DOM button (per-file jsdom environment); this file's own tests remain
 * SSR/markup assertions (no Testing Library). These assert the converted <Button> adds no btn chrome and
 * no wrapper span, and that type="button" + aria/disabled forwarding
 * survive conversion.
 *
 * NOT covered here (cannot SSR-render): the Select option (S7 — the
 * dropdown renders only after a layout effect sets its style), the
 * MainLayout sites S2–S5 and the NotificationContainer site S1 (router /
 * store shells). Those are covered by the Button contract tests in
 * button.test.tsx, the verbatim diff, and the Floor grep proof.
 * Click/keyboard behaviour is not exercised here.
 */
describe('converted Select trigger (S8, in-form site)', () => {
  it('renders type="button", no btn classes, both child spans direct', () => {
    const markup = renderToStaticMarkup(
      <Select
        value="a"
        options={[
          { value: 'a', label: 'Alpha' },
          { value: 'b', label: 'Beta' },
        ]}
        onChange={() => {}}
        ariaLabel="Pick one"
      />
    );
    expect(markup).toContain('type="button"');
    expect(markup).not.toMatch(/\bbtn\b/);
    expect(markup).toContain('aria-haspopup="listbox"');
    expect(markup).toContain('aria-expanded="false"');
    expect(markup).toMatch(/triggerText/);
    expect(markup).toMatch(/triggerIcon/);
    // Two direct span children: label span then icon span, no wrapper span.
    expect(markup).toMatch(/<span[^>]*>Alpha<\/span><span[^>]*><svg/);
    expect(markup).not.toMatch(/<button[^>]*><span><span/);
  });

  it('forwards disabled with type="button"', () => {
    const markup = renderToStaticMarkup(
      <Select value="a" options={[{ value: 'a', label: 'Alpha' }]} onChange={() => {}} disabled />
    );
    expect(markup).toContain('type="button"');
    expect(markup).toContain('disabled=""');
  });
});

describe('converted Modal close button (S6)', () => {
  it('renders type="button", bespoke class only, icon as direct child', () => {
    const markup = renderToStaticMarkup(
      <Modal open onClose={() => {}} title="Title">
        Body
      </Modal>
    );
    expect(markup).toContain('type="button"');
    expect(markup).toContain('modal-close-floating');
    expect(markup).not.toMatch(/\bbtn\b/);
    expect(markup).toMatch(/<button[^>]*><svg/);
  });
});

describe('converted Sheet close button (S9)', () => {
  it('renders type="button", bespoke class only, icon as direct child', () => {
    const markup = renderToStaticMarkup(
      <Sheet open onClose={() => {}} title="Title">
        Body
      </Sheet>
    );
    expect(markup).toContain('type="button"');
    expect(markup).toMatch(/closeBtn/);
    expect(markup).not.toMatch(/\bbtn\b/);
    expect(markup).toMatch(/<button[^>]*><svg/);
  });
});
