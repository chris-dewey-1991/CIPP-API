function Invoke-CIPPStandardTenantAllowBlockListTemplate {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) TenantAllowBlockListTemplate
    .SYNOPSIS
        (Label) Tenant Allow/Block List Template
    .DESCRIPTION
        (Helptext) Deploy tenant allow/block list entries from a saved template.
        (DocsDescription) Deploy tenant allow/block list entries from a saved template.
    .NOTES
        CAT
            Exchange Standards
        DISABLEDFEATURES
            {"report":false,"warn":false,"remediate":false}
        IMPACT
            Medium Impact
        ADDEDDATE
            2026-04-02
        EXECUTIVETEXT
            Deploys standardized tenant allow/block list entries across tenants. These templates ensure consistent email filtering rules are applied, managing which senders, URLs, file hashes, and IP addresses are allowed or blocked across the organization.
        ADDEDCOMPONENT
            {"type":"autoComplete","name":"TenantAllowBlockListTemplate","required":false,"multiple":true,"label":"Select Tenant Allow/Block List Template","api":{"url":"/api/ListTenantAllowBlockListTemplates","labelField":"templateName","valueField":"GUID","queryKey":"ListTenantAllowBlockListTemplates","showRefresh":true}}
        REQUIREDCAPABILITIES
            "EXCHANGE_S_STANDARD"
            "EXCHANGE_S_ENTERPRISE"
            "EXCHANGE_S_STANDARD_GOV"
            "EXCHANGE_S_ENTERPRISE_GOV"
            "EXCHANGE_LITE"
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>
    param($Tenant, $Settings)

    $TestResult = Test-CIPPStandardLicense -StandardName 'TenantAllowBlockListTemplate' -TenantFilter $Tenant -RequiredCapabilities @('EXCHANGE_S_STANDARD', 'EXCHANGE_S_ENTERPRISE', 'EXCHANGE_S_STANDARD_GOV', 'EXCHANGE_S_ENTERPRISE_GOV', 'EXCHANGE_LITE')

    if ($TestResult -eq $false) {
        return $true
    }

    $Table = Get-CippTable -tablename 'templates'
    $TemplateId = $Settings.TenantAllowBlockListTemplate.value

    $ResolvedTemplates = @(foreach ($_ in @($TemplateId)) {
            $TemplateId = $_
            $Filter = "PartitionKey eq 'TenantAllowBlockListTemplate' and RowKey eq '$TemplateId'"
            $TemplateEntity = Get-CIPPAzDataTableEntity @Table -Filter $Filter

            if (-not $TemplateEntity -or [string]::IsNullOrWhiteSpace($TemplateEntity.JSON)) {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to find Tenant Allow/Block List template $TemplateId. Has it been deleted?" -sev 'Error'
                continue
            }

            try {
                $TemplateEntity.JSON | ConvertFrom-Json -Depth 10
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to parse Tenant Allow/Block List template $TemplateId. $ErrorMessage" -sev 'Error'
            }
        })

    if ($Settings.remediate -eq $true) {
        # Track entries submitted across templates to handle overlapping entries without relying on Exchange replication
        $SubmittedEntries = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($TemplateData in $ResolvedTemplates) {
            try {
                $Entries = @($TemplateData.entries -split '[,;]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
                $ListType = [string]$TemplateData.listType

                # Get existing entries to avoid duplicate errors that block the entire batch
                if (-not $SubmittedEntries.ContainsKey($ListType)) {
                    $SubmittedEntries[$ListType] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    try {
                        $ExistingItems = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-TenantAllowBlockListItems' -cmdParams @{
                            ListType = $ListType
                        }
                        foreach ($Item in @($ExistingItems)) {
                            [void]$SubmittedEntries[$ListType].Add($Item.Value)
                        }
                    } catch {
                        # If we can't fetch existing items, continue with empty set
                    }
                }

                $NewEntries = @($Entries | Where-Object { -not $SubmittedEntries[$ListType].Contains($_) })

                if ($NewEntries.Count -eq 0) {
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "All entries from Tenant Allow/Block List template '$($TemplateData.templateName)' already exist for $Tenant" -sev 'Info'
                    continue
                }

                $ExoParams = @{
                    tenantid  = $Tenant
                    cmdlet    = 'New-TenantAllowBlockListItems'
                    cmdParams = @{
                        Entries                  = $NewEntries
                        ListType                 = $ListType
                        Notes                    = [string]$TemplateData.notes
                        $TemplateData.listMethod = [bool]$true
                    }
                }

                if ($TemplateData.NoExpiration -eq $true) {
                    $ExoParams.cmdParams.NoExpiration = $true
                } elseif ($TemplateData.RemoveAfter -eq $true) {
                    $ExoParams.cmdParams.RemoveAfter = 45
                }

                New-ExoRequest @ExoParams
                foreach ($Entry in $NewEntries) {
                    [void]$SubmittedEntries[$ListType].Add($Entry)
                }
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Successfully deployed Tenant Allow/Block List template '$($TemplateData.templateName)' with entries: $($NewEntries -join ', ')" -sev 'Info'
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to deploy Tenant Allow/Block List template '$($TemplateData.templateName)' for $Tenant. Error: $ErrorMessage" -sev 'Error'
            }
        }
    }

    if ($Settings.alert -eq $true -or $Settings.report -eq $true) {
        $AllCompliant = $true
        $ComplianceDetails = [System.Collections.Generic.List[object]]::new()
        # Cache fetched list types to avoid redundant EXO calls when multiple templates share a list type
        $FetchedListTypes = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($TemplateData in $ResolvedTemplates) {
            $Entries = @($TemplateData.entries -split '[,;]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
            $ListType = [string]$TemplateData.listType

            try {
                if (-not $FetchedListTypes.ContainsKey($ListType)) {
                    $ExistingItems = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-TenantAllowBlockListItems' -cmdParams @{ ListType = $ListType }
                    $ExistingValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($Item in @($ExistingItems)) { [void]$ExistingValues.Add($Item.Value) }
                    $FetchedListTypes[$ListType] = $ExistingValues
                }

                $MissingEntries = @($Entries | Where-Object { -not $FetchedListTypes[$ListType].Contains($_) })
                $TemplateCompliant = ($MissingEntries.Count -eq 0)
                if (-not $TemplateCompliant) { $AllCompliant = $false }

                $ComplianceDetails.Add([PSCustomObject]@{
                    TemplateName    = [string]$TemplateData.templateName
                    ListType        = $ListType
                    Compliant       = $TemplateCompliant
                    MissingEntries  = ($MissingEntries -join ', ')
                    ExpectedEntries = ($Entries -join ', ')
                })
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "TenantAllowBlockListTemplate: Failed to check compliance for '$($TemplateData.templateName)'. Error: $ErrorMessage" -sev Error
                $AllCompliant = $false
                $ComplianceDetails.Add([PSCustomObject]@{
                    TemplateName    = [string]$TemplateData.templateName
                    ListType        = $ListType
                    Compliant       = $false
                    MissingEntries  = 'Error checking entries'
                    ExpectedEntries = ($Entries -join ', ')
                })
            }
        }

        if ($Settings.alert -eq $true) {
            if ($AllCompliant) {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message 'All Tenant Allow/Block List template entries are present.' -sev Info
            } else {
                $NonCompliant = @($ComplianceDetails | Where-Object { -not $_.Compliant })
                $AlertMsg = ($NonCompliant | ForEach-Object { "$($_.TemplateName) ($($_.ListType)): missing $($_.MissingEntries)" }) -join '; '
                Write-StandardsAlert -message "Tenant Allow/Block List template entries are missing: $AlertMsg" -object $ComplianceDetails -tenant $Tenant -standardName 'TenantAllowBlockListTemplate' -standardId $Settings.standardId
                Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Tenant Allow/Block List template entries are missing.' -sev Info
            }
        }

        if ($Settings.report -eq $true) {
            $NonCompliantSummary = ($ComplianceDetails | Where-Object { -not $_.Compliant } | ForEach-Object { "$($_.TemplateName) ($($_.ListType)): $($_.MissingEntries)" }) -join '; '
            $CurrentValue = [PSCustomObject]@{
                AllEntriesPresent     = $AllCompliant
                NonCompliantTemplates = $NonCompliantSummary
            }
            $ExpectedValue = [PSCustomObject]@{
                AllEntriesPresent     = $true
                NonCompliantTemplates = ''
            }
            Add-CIPPBPAField -FieldName 'TenantAllowBlockListTemplate' -FieldValue $AllCompliant -StoreAs bool -Tenant $Tenant
            Set-CIPPStandardsCompareField -FieldName 'standards.TenantAllowBlockListTemplate' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
        }
    }
}
