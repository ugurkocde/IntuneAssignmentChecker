# Public schemas

Version 5 emits schema-governed objects. Assignment records and snapshots use
schema version 2. `ConvertTo-IntuneAssignmentRecord` migrates version 1 records,
and snapshot readers transparently migrate version 1 snapshots in memory.

The module guarantees property names and documented enum values within a schema
major version. New optional fields may be introduced only in a new schema file.
