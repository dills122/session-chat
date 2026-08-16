# Frontend Design Steering

Use this steering when a project has user-facing UI.

## Priorities

- Build the actual product experience, not a marketing shell, unless a landing page is explicitly requested.
- Match the visual density and tone to the product domain.
- Use existing design systems, component libraries, icons, and tokens before adding new primitives.
- Keep controls complete: labels, states, validation, accessibility, and responsive behavior.
- Verify in a real browser when the app can run locally.

## UI Quality

- Preserve hierarchy with spacing, typography, alignment, and contrast.
- Keep text inside its containers at mobile and desktop widths.
- Avoid generic decorative backgrounds, blobs, and one-note palettes.
- Use real or generated visual assets when a website or app needs visual content.
- Avoid nested cards and decorative card-heavy layouts for operational tools.

## Interaction States

Cover expected states:

- default
- hover
- focus
- active
- disabled
- loading
- empty
- error
- success

## Accessibility

- Use semantic HTML first.
- Preserve visible focus states.
- Make forms keyboard and screen-reader friendly.
- Respect reduced-motion preferences for animation-heavy UI.
- Check contrast and hit targets for important controls.
