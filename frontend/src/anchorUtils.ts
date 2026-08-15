// Command-palette/deep-link targets sometimes sit inside a collapsed
// <details> (e.g. the reverse-shell "쉘 안정화" section) -- scrolling to
// them without opening the ancestor left the target invisible, looking
// like the search found nothing.
export const revealAnchor = (anchor: HTMLElement) => {
  let el: HTMLElement | null = anchor;
  while (el) {
    if (el instanceof HTMLDetailsElement) el.open = true;
    el = el.parentElement;
  }
};
