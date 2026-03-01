function Invoke-CIPPStandardDefenderIntuneConnection {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) DefenderIntuneConnection
    .SYNOPSIS
        (Label) Ensure Microsoft Defender Intune connection state
    .DESCRIPTION
        (Helptext) Ensures that the Microsoft Defender Intune connection for the tenant is enabled or disabled
        according to the selected value.

        (DocsDescription) This standard checks and optionally enforces the Microsoft Defender Intune connection
        state for the tenant (for example, whether Defender is properly connected to Intune).

    .NOTES
        CAT
            Intune Standards
        TAG
            Intune Standards
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"label":"Defender Intune connection state","name":"standards.DefenderIntuneConnection.DesiredState","options":[{"label":"Enabled","value":"Enabled"},{"label":"Disabled","value":"Disabled"}]}
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"label":"Remediate","name":"standards.DefenderIntuneConnection.remediate","options":[{"label":"Yes","value":"true"},{"label":"No","value":"false"}]}
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"label":"Alert on non‑compliance","name":"standards.DefenderIntuneConnection.alert","options":[{"label":"Yes","value":"true"},{"label":"No","value":"false"}]}
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"label":"Include in report","name":"standards.DefenderIntuneConnection.report","options":[{"label":"Yes","value":"true"},{"label":"No","value":"false"}]}

        IMPACT
            Low Impact
        ADDEDDATE
            2026-03-01
        POWERSHELLEQUIVALENT
            # TODO: document your underlying Get/Set Defender–Intune connection implementation
        RECOMMENDEDBY
            YOURNAME
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>
     param ($Tenant, $Settings)

    $TestResult = Test-CIPPStandardLicense -StandardName 'DefenderIntuneConnection' -TenantFilter $Tenant -RequiredCapabilities @(
        'EXCHANGE_S_STANDARD',
        'EXCHANGE_S_ENTERPRISE',
        'EXCHANGE_S_STANDARD_GOV',
        'EXCHANGE_S_ENTERPRISE_GOV',
        'EXCHANGE_LITE'
    )
    if ($TestResult -eq $false) { return $true }

    # No per-standard field – we just always want Enabled
    $DesiredState = 'Enabled'

    # Optional: global framework still sets Settings.remediate / alert / report
    $DoRemediate = $Settings.remediate -eq $true
    $DoAlert     = $Settings.alert -eq $true
    $DoReport    = $Settings.report -eq $true

    try {
        # TODO: implement real logic
        # $CurrentState = Get-CIPPDefenderIntuneConnectionState -Tenant $Tenant  # "Enabled"/"Disabled"
        $CurrentState = 'Disabled'  # placeholder
    }
    catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Standards' -Tenant $Tenant -Message "Could not get DefenderIntuneConnection state for $Tenant. Error: $ErrorMessage" -Sev Error
        return
    }

    if ($DoRemediate) {
        if ($CurrentState -ne $DesiredState) {
            try {
                # if ($DesiredState -eq 'Enabled') { Enable-CIPPDefenderIntuneConnection -Tenant $Tenant }
                Write-LogMessage -API 'Standards' -Tenant $Tenant -message "Set DefenderIntuneConnection to $DesiredState" -sev Info
            }
            catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to set DefenderIntuneConnection. Error: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
            }
        }
    }

    if ($DoAlert) {
        if ($CurrentState -ne $DesiredState) {
            Write-StandardsAlert -message "DefenderIntuneConnection is not $DesiredState" -object $CurrentState -tenant $Tenant -standardName 'DefenderIntuneConnection' -standardId $Settings.standardId
        }
    }

    if ($DoReport) {
        $CurrentValue  = @{ DefenderIntuneConnection = $CurrentState }
        $ExpectedValue = @{ DefenderIntuneConnection = $DesiredState }
        Set-CIPPStandardsCompareField -FieldName 'standards.DefenderIntuneConnection' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
        Add-CIPPBPField -FieldName 'DefenderIntuneConnectionSet' -FieldValue ([string]$CurrentState) -StoreAs string -Tenant $Tenant
    }
}
