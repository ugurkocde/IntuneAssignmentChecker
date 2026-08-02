function ConvertTo-IntuneAssignmentRecord {
    <#
    .SYNOPSIS
    Migrates version 1 assignment records to the version 2 public schema.

    .DESCRIPTION
    Validates and canonicalizes pipeline records. Version 1 and version 2 inputs
    are accepted; output always has SchemaName, SchemaVersion 2, a deterministic
    RecordId, and the explicit beta Graph API contract marker.
    #>
    [CmdletBinding()]
    [OutputType('IntuneAssignmentChecker.AssignmentRecord')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject
    )

    process {
        foreach ($record in @($InputObject)) {
            if ($null -ne $record) { ConvertTo-IACSnapshotRecord -InputObject $record }
        }
    }
}
