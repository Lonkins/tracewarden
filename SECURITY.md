# Security Policy

## Supported versions

The latest minor release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report privately via [GitHub private vulnerability reporting](https://github.com/Lonkins/tracewarden/security/advisories/new)
or email tomprice13@pm.me. You will get an acknowledgement within 72 hours.

## Scope notes

tracewarden is a detection layer, not a prevention layer. Detector bypasses
(payloads that evade a heuristic) are welcome as *regular* issues with a synthetic
example — they are signature gaps, not vulnerabilities, unless they reveal a flaw in
the enrichment pipeline itself (e.g. a payload that crashes span processing or causes
sensitive data to be written where it should have been redacted).
