# Animated design references for Univect

Research date: 28 September 2026.

Firecrawl CLI was attempted as requested. Its keyless search was rejected on this
connection and requires account authentication. The shortlist below was gathered
using the available web search and official demo pages instead. Raw fetched pages
are saved locally under the gitignored `.firecrawl/` directory.

## Recommended dashboard layout

[CyberDefend by Fuselab Creative](https://dribbble.com/shots/27376069-Cybersecurity-Dashboard-Design-Dark-UI-Data-Visualization)

The designer describes a dark cybersecurity dashboard centered on threat
visualization, geographic context and severity. Use it as a layout reference for
metric hierarchy, alert density and threat inspection. A designer showcase is
visual inspiration; its animation behavior was not independently observed.

For Univect, prioritize the event-rate chart, threat classes, evidence drawer,
replay controls and severity. A topology of the observed lab network suits our
existing metadata better than a geographic attack map with invented coordinates.

## Recommended animation demos

1. [Animated Beam — Magic UI](https://magicui.design/docs/components/animated-beam)
   animates a beam along a path. This is the strongest project-specific match:
   mirror feed → metadata features → inference → structured alerts. Configure
   motion in one direction to communicate the PS collection boundary.
2. [Background Beams — Aceternity](https://ui.aceternity.com/components/background-beams)
   uses multiple animated SVG paths. Adapt a sparse version for a Univect
   introduction or landing page, alongside a product screenshot and an Open
   Monitor action.
3. [World Map — Aceternity](https://ui.aceternity.com/components/world-map)
   animates lines and dots on a map. The connection motion can inform a network
   topology illustration. Actual geographic plotting would require trustworthy
   location metadata, which the current lab wrappers do not supply.
4. [Tracing Beam — Aceternity](https://ui.aceternity.com/components/tracing-beam)
   follows an SVG path as the reader scrolls. Useful for explaining the processing
   stages or stepping through an alert investigation timeline.
5. [Hero With Beams and Grid — Aceternity Pro](https://ui.aceternity.com/blocks/hero-sections/hero-section-with-beams-and-grid)
   demonstrates animated light paths around a framed product view. This is a
   premium block; it provides a complete landing-page composition reference.

## Suggested Univect direction

Use CyberDefend's dashboard hierarchy with a custom one-way animated pipeline
diagram inspired by Magic UI. Add a restrained beam/grid introduction for project
presentations. Animate newly received alert rows, changing metrics and panel
transitions while keeping evidence and tables stable and readable.

At the time of this initial research, the frontend used TypeScript/Vite without
React. The subsequent implementation migrated to Next.js/React and Tailwind at
the project owner's request. It supports reduced motion and derives displayed
monitor activity from actual telemetry and clearly labelled replay sources.

The completed combined AiAf/Portals design, procedural artwork and integrated
monitor are documented in [Website guide](FRONTEND.md). The reference animations
were viewed as complete loops; their videos, fonts, models and textures were not copied.
