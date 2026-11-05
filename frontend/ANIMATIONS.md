# WebProbe motion catalog

`src/styles/animations.css` is the single source of truth for motion: selectors,
keyframes, durations, easing, and reduced-motion behavior live there. Page and
component styles own layout and color, not animation. Motion is intentionally
short, monochrome, and limited to changes that help explain the interface.

| Content or interaction | Motion applied | When |
| --- | --- | --- |
| Route content: headings, paragraphs, metrics, sections, forms, tables and terminal | Fade in and rise 6px, 220ms | Once when a page mounts. Content moves as one unit, not one animation per row. |
| Navigation and action buttons | 150ms color, background and border transition; standard buttons also have a 1px pressed state | Hover, focus-related color changes or press. |
| Form fields, profile choices and tabs | 150ms border or text-color transition | Focus, hover or selection. |
| Settings switches | 150ms thumb translation and color transition | When toggled. |
| Scan, finding and catalog rows | 150ms background transition; row arrow fades in | Hover or keyboard focus. Rows are not staggered. |
| Severity meter | 150ms opacity transition | When a severity filter changes. |
| Finding details drawer | Slide in from the right, 200ms; backdrop fades in | On open. |
| Finding overview, evidence and remediation content | Moves with the drawer; no separate animation on tab changes | Keeps text stable while investigating. |
| Mobile navigation | Slide in from the left, 200ms; backdrop fades in | On open. |
| Confirmation dialog and command palette | 150ms fade in place; backdrop fades in | On open. |
| Export menu | Fade in and move down 4px, 150ms | On open. |
| Toast notifications | Fade in and rise 6px, 180ms | When a notification appears. |
| Running status and active scan phase | Gentle two-second opacity pulse | Only while active. |
| Loading indicator | One-second rotation | Only while loading. |
| Loading fallback | Route fade and loading indicator rotation | While a lazy page is being fetched. |
| Empty states, errors and inline alerts | Move with the page; no extra animation | Feedback remains immediately readable. |
| Log lines and frequently refreshed data | No individual animation | Avoids replaying motion on polling and keeps large results efficient and readable. |

The operating system's `prefers-reduced-motion: reduce` and the in-app **Reduce
motion** setting both remove animations and transitions, including infinite
spinners and pulses. Content stays visible; motion is never required to use the
interface. To add a new content type, add its rule to `animations.css` and update
this table.
