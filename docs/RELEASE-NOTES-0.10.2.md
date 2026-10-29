# Hardware Monitor 0.10.2

Package build: **0.10.2-0075**.

## Backups that repeatedly restart while monitoring runs

The initial incremental database copy now pins a read transaction for its full duration. In WAL mode, ordinary monitoring and notification writes continue, while the copy sees one consistent point in time. Previously, commits between copy steps could repeatedly restart the copy and reset its byte counter. This affects the streaming backup implementation introduced in 0.8.0-0043, including 0.10.1-0074.

The read transaction is released on success, failure and cancellation. SQLite may retain additional WAL pages until the copy finishes. No monitoring settings are paused or changed by export.

The CGI bridge now describes an `api_timeout` as a monitoring-service response timeout rather than a sign-in timeout. This corrects the message; it does not claim every possible service timeout is fixed.

## Included fixes

Includes the [Redfish log deduplication correction from 0.10.1](RELEASE-NOTES-0.10.1.md). This package updates an existing installation and retains its data. It does not change the backup file format.

## Validation

A regression test commits changes from the live application connection between every copy step. The previous implementation fails to finish within 64 steps; the correction completes with a consistent original snapshot and monotonic progress. Live writes persist, database integrity checks pass, and WAL checkpoint tests verify release of the read transaction after both completion and cancellation.

The repeated-copy defect is reproduced locally. Whether the later loss of UI connectivity on the reported NAS has an additional cause remains subject to NAS acceptance testing.
