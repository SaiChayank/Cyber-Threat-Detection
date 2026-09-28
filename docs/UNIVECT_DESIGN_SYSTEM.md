# Univect identity and interface

The project owner selected **Univect** from the proposed names. It combines
unidirectional observation with a traffic vector. The tagline is **One-way
traffic. Deeper insight.**

## Original symbol

The open U forms the observation channel; an ascending red vector passes through
the opening in one direction. The mark is original vector artwork, using a
40-unit grid and five-unit strokes. It contains no shield, lock, globe or AI icon.
`components/brand.tsx` provides `BrandMark` and the wordmark. The matching SVG
favicon is `public/assets/univect.svg`; `univect-mark.svg` is a transparent standalone
export. The mark also appears in the footer,
loading states, WebGL fallback and output tokens in the procedural illustration.

## Palette

| Token | Color | Role |
| --- | --- | --- |
| ink | `#080909` | Near-black page background |
| panel | `#151616` | Charcoal translucent panels |
| line | `#303232` | Neutral borders and grid lines |
| muted | `#A8ABAB` | Secondary text |
| brand | `#C9323C` | Deep red actions and mark |
| accent | `#F07878` | Readable red text, focus and chart lines |
| signal | `#EFEFEF` | Neutral data/status emphasis |

White typography carries the hierarchy. Red is concentrated in the mark, primary
actions, active navigation, selected tabs and small evidence highlights. Severity
is differentiated by labels and surface intensity: critical uses a filled red
badge, high a red outline/tint, medium white, and low gray. Status always includes
text; connection state is never communicated only through red or white dots.

Glass panels blur the background only, with a thin neutral border and restrained
shadow. Inputs, chart labels, evidence and controls remain sharp. Chart data comes
from actual telemetry; illustrations do not portray fabricated detections.

## Layout and motion

The landing page and Monitor share a centered 1440px layout, fonts, navigation,
footer and ambient red background. The Monitor has no sidebar or reserved sidebar
gutter. Its section navigation, API reference, platform return and passive-sensor
constraints are available from the responsive top navbar.

Motion uses short opacity/position entrances, spring navigation indicators,
subtle press interactions, scroll reveals, metric fades and 300ms chart updates.
The dialog uses scale/vertical motion independently of CSS centering. Slow ambient
motion stays decorative. `MotionConfig reducedMotion="user"`, CSS media queries,
Recharts' animation flag and the Three.js media query all respect reduced motion.
Three.js rendering also pauses offscreen and in background tabs.

Keyboard users have a skip link, visible focus rings, labelled controls, Radix
tabs/tooltips/dialogs, Escape dismissal and restored focus after evidence review.
Tables scroll within their panel at small sizes; the overall page fits the viewport.
Mobile menus close after navigation, on outside pointer interaction or Escape.

## Preserved functionality

The redesign retains telemetry polling, SSE with resume/deduplication, synthetic
and public-source replays, speed selection, stopping replay, PCAP upload, dataset
readiness, seven detection modules, search, class/severity filters, pagination,
filtered JSON export, evidence inspection/copying and the saved benchmark.
Python detection, dataset access restrictions and persistent alert storage are
unchanged. No new dependencies or authentication requirements were introduced.

## Verification previews

The production build and strict TypeScript checks pass, and the Python regression
suite reports 34 passing tests. The original database retains its 130 recorded
alerts. Replay verification used an isolated database. Browser checks covered
live updates, stopping/restarting replay, all six detection tabs, navigation,
filters, pagination, JSON export/copy, dialog focus, outage/reconnection and
320/390/768px layouts. Upload requests passed through the website proxy; native
file-picker automation remained unverified. See `FRONTEND.md` for the scope and
existing detector limitations.

- [Landing preview](verification/univect-landing.png)
- [Monitor preview](verification/univect-monitor.png)
- [Alert table preview](verification/univect-alerts.png)
- [Footer preview](verification/univect-footer.png)
