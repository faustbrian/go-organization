# Changelog

## Unreleased

- Add experimental explicit-organization create/read and membership
  admission/list/removal policy with real session admission, scoped permission
  checks, optimistic versions, bounded limits and last-owner protection.
- Define immutable adapter transaction/recovery handoff and explicit durable
  outcomes; commands and authentication reject automatic serialization.

This is an initial experimental profile, not a stable API or full organization
unit release. Use the optional native PostgreSQL module for durable operations.
