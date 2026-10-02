# Changelog

## [0.1.6]

Dependency-only update: brings in `flnd` v0.2.0-beta and `go-flokicoin`
v0.26.0-alpha. No code changes in this repo.

### Changed

- Picked up [flnd v0.2.0-beta](https://github.com/flokiorg/flnd/releases/tag/v0.2.0-beta)
  and [go-flokicoin v0.26.0-alpha](https://github.com/flokiorg/go-flokicoin/releases/tag/v0.26.0-alpha).

## [0.1.5]

### Dependency Updates

- Updated core dependencies to align with `flnd v0.1.21-beta`, which includes Taproot channel support and fixes for 32-bit platforms.
- Routine `go mod tidy` cleanup.

## [0.1.4]

### Dependency Updates

- Updated dependencies to align with `flnd v0.1.20-beta` and `go-flokicoin v0.25.13-alpha`.
- Routine `go mod tidy` cleanup.

## [0.1.3]

### Bug Fixes

#### App Data Directory

- **Directory Name**: Corrected the default application data directory from `lnd` to `flnd`, aligning with the Flokicoin Lightning daemon naming convention.

### Dependency Updates

- Routine `go mod tidy` cleanup following workspace sync.
