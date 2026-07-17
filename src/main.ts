import './style.css';
import { mountApp } from './ui.ts';
import { runSearch } from './symbolic/search.ts';
import { needhamSchroeder } from './symbolic/protocol.ts';

// Dev-only self-check: shout in the console if the headline result regresses,
// without adding weight to the shipped bundle.
if (import.meta.env.DEV) {
  const lowe = runSearch(needhamSchroeder(false));
  const fixed = runSearch(needhamSchroeder(true));
  console.group('crypto-lab-protocol-checker: engine self-check');
  console.log('NSPK — attack found:', lowe.found, '· trace length:', lowe.trace.length);
  console.log('NSL  — attack found:', fixed.found, '(should be false)');
  console.groupEnd();
}

mountApp(document.querySelector<HTMLDivElement>('#app')!);
