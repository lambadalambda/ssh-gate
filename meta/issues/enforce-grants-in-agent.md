# Enforce grants in the agent

## Summary

Before signing, the agent checks the grant store. A match signs without a prompt. No match asks the approval flow; approval creates a grant. Remove the key-wide persistence for keys used with grants.

## Acceptance Criteria

- Agent tests with a stub approval: allowed in scope, asked out of scope, asked again after expiry.

## Notes

- Done in the fork. Forwarded connections get one-time approvals only; bind count capped at 16.
- Moved to the pop-up issue: removing key-wide persistence, and avoiding a second Touch ID prompt for keys that require authentication.
