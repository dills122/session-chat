# Angular Steering

Use modern Angular, TypeScript, and RxJS patterns consistent with the existing app.

## Code Style

- Prefer standalone components when the project already uses them.
- Keep components focused on presentation and interaction.
- Put reusable business logic in services or focused utilities.
- Use typed forms and explicit model types.
- Avoid broad module or routing refactors unless requested.

## State And Data Flow

- Keep async state explicit: loading, success, empty, and error states.
- Prefer existing state management patterns in the project.
- Avoid duplicate data-fetching paths for the same domain object.
- Keep API contracts typed at the boundary.

## Templates And Accessibility

- Use semantic HTML before custom interaction patterns.
- Keep keyboard and screen reader behavior intact.
- Preserve visible focus states.
- Do not hide validation or error states behind hover-only UI.

## Testing

- Add focused component or service tests for behavior changes.
- Use existing test utilities and mocking patterns.
- Cover observable error paths and cleanup behavior when relevant.
