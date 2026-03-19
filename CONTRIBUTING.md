# Contributing to mono-did

Thank you for contributing to `mono-did`.

## Development Setup

1. Install dependencies:

```bash
pnpm install
```

2. Run local checks before submitting:

```bash
pnpm test
pnpm typecheck
pnpm build
```

## Contribution Flow

1. Create a focused branch for your change.
2. Keep each PR limited to one concern (feature/fix/refactor/docs).
3. Add or update tests for behavior changes.
4. Update docs when public API or usage changes.
5. Add a changeset for publishable package changes:

```bash
pnpm changeset
```

## Coding Guidelines

- Keep APIs stable and typed.
- Prefer small, composable functions.
- Avoid breaking changes unless explicitly planned.
- Preserve package boundaries:
  - `@mono/did-core-types`: shared contracts
  - `@mono/identity`: DID identity and key-event-log logic
  - `@mono/handshake`: handshake and replay controls
  - `@mono/protocol`: transport framing helpers
  - `@mono/adapters`: stable integration surface
  - `@mono/did`: aggregate entrypoint

## Pull Request Checklist

- [ ] Tests pass locally
- [ ] Typecheck passes
- [ ] Build passes
- [ ] README/docs updated if needed
- [ ] Changeset added (if package output changes)

## Code of Conduct

By participating, you agree to follow [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
