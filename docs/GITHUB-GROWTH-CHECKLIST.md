# GitHub Growth Checklist

This file tracks repository-level discoverability settings that are configured in the GitHub UI.

## 1) Topics

Repository -> Settings -> General -> Topics

Recommended topics for this project:

- did
- decentralized-identity
- did-peer
- handshake
- p2p
- cryptography
- typescript
- identity
- openclaw
- monoclaw

## 2) Enable Discussions

Repository -> Settings -> Features -> check `Discussions`

Suggested categories:

- Announcements
- Q&A
- Ideas
- Show and tell

## 3) Create first release

Use one of:

- GitHub UI: Releases -> Draft a new release
- CLI/automation: `changeset version` + `changeset publish`

After first publish, verify:

- `/releases/latest` redirects correctly
- release badge in `README.md` renders

## 4) Pin and social preview

- Pin this repository in organization profile
- Set social preview image in repository settings

## 5) Labels hygiene

Create or align labels used by `.github/release.yml`:

- `breaking-change`
- `feature`
- `enhancement`
- `bug`
- `bugfix`
- `fix`
- `docs`
- `chore`
- `ci`
- `dependencies`
- `skip-changelog` (optional)
