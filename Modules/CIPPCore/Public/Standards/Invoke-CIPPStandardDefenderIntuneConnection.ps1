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

        IMPACT
            Low Impact
        ADDEDDATE
            2026-03-01
        POWERSHELLEQUIVALENT
            # TODO: document your underlying Get/Set Defender-Intune connection implementation
        RECOMMENDEDBY
            YOURNAME
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>
    param ($Tenant, $Settings)

    # License check
    $TestResult = Test-CIPPStandardLicense -StandardName 'DefenderIntuneConnection' -TenantFilter $Tenant -RequiredCapabilities @(
        'EXCHANGE_S_STANDARD',
        'EXCHANGE_S_ENTERPRISE',
        'EXCHANGE_S_STANDARD_GOV',
        'EXCHANGE_S_ENTERPRISE_GOV',
        'EXCHANGE_LITE'
    )
    if ($TestResult -eq $false) {
        return $true
    }

    # No per-standard field – we just always want Enabled
    $DesiredState = 'Enabled'

    # Framework still passes these based on the global toggle and standard config
    $DoRemediate = $Settings.remediate -eq $true
    $DoAlert     = $Settings.alert -eq $true
    $DoReport    = $Settings.report -eq $true

    # Get current state (placeholder – replace with real check)
    try {
        # TODO: implement real logic, e.g.:
        # $CurrentState = Get-CIPPDefenderIntuneConnectionState -Tenant $Tenant  # "Enabled"/"Disabled"
        $CurrentState = 'Disabled'  # placeholder
    }
    catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Standards' -Tenant $Tenant -Message "Could not get DefenderIntuneConnection state for $Tenant. Error: $ErrorMessage" -Sev Error
        return
    }

    # Remediation
    if ($DoRemediate) {
        if ($CurrentState -ne $DesiredState) {
            try {
                # TODO: implement real remediation, e.g.:
                # if ($DesiredState -eq 'Enabled') {
                #     Enable-CIPPDefenderIntuneConnection -Tenant $Tenant
                # }

                Write-LogMessage -API 'Standards' -Tenant $Tenant -message "Set DefenderIntuneConnection to $DesiredState" -sev Info
            }
            catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to set DefenderIntuneConnection. Error: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
            }
        }
        else {
            Write-LogMessage -API 'Standards' -Tenant $Tenant -message "DefenderIntuneConnection already in desired state ($DesiredState)" -sev Info
        }
    }

    # Alerting
    if ($DoAlert) {
        if ($CurrentState -ne $DesiredState) {
            Write-StandardsAlert -message "DefenderIntuneConnection is not $DesiredState" -object $CurrentState -tenant $Tenant -standardName 'DefenderIntuneConnection' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -Tenant $Tenant -message "DefenderIntuneConnection is not $DesiredState" -sev Info
        }
        else {
            Write-LogMessage -API 'Standards' -Tenant $Tenant -message "DefenderIntuneConnection is $DesiredState" -sev Info
        }
    }

    # Reporting
    if ($DoReport) {
        $CurrentValue  = @{ DefenderIntuneConnection = $CurrentState }
        $ExpectedValue = @{ DefenderIntuneConnection = $DesiredState }

        Set-CIPPStandardsCompareField -FieldName 'standards.DefenderIntuneConnection' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
        Add-CIPPBPAField -FieldName 'DefenderIntuneConnectionSet' -FieldValue ([string]$CurrentState) -StoreAs string -Tenant $Tenant
    }
}
