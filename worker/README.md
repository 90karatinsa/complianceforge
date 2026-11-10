# Worker

The worker service consumes scan jobs from BullMQ and orchestrates source fetching and analysis pipelines.

## Fetch pipeline

Each scan prepares a deterministic workspace under the system temporary directory before materialising the source:

- **Git artifacts** – shallow clone with an optional branch or commit checkout.
- **Archive artifacts** – download, verify optional SHA-256 checksums, and extract tar/zip payloads with size limits.
- **OCI artifacts** – fetch manifest metadata, download referenced layers with optional registry authentication, and verify digests.

Temporary directories are purged automatically after the fetch helpers complete to avoid leaking disk usage.
