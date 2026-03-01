function Invoke-CIPPStandardDefenderIntuneConnection {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) DefenderIntuneConnection
    .SYNOPSIS
        (Label) Ensure Microsoft Defender Intune connection is enabled
    .DESCRIPTION
        (Helptext) Ensures that the Microsoft Defender–Intune connection is enabled for the tenant.
        This allows Defender for Endpoint to integrate with Microsoft Intune for device compliance signals.

        (DocsDescription) Enables the Microsoft Intune connection toggle in Defender for Endpoint
        (Settings > Endpoints > General > Advanced features > Microsoft Intune connection).

    .NOTES
        CAT
            Intune Standards
        TAG
            "CIS"
        EXECUTIVETEXT
            Ensures the Microsoft Defender for Endpoint–Intune connection is enabled so that device
            compliance and security signals are shared between the two services.
        ADDEDCOMPONENT
        IMPACT
            Low Impact
        ADDEDDATE
            2026-03-01
        POWERSHELLEQUIVALENT
            Invoke-CIPPStandardDefenderIntuneConnection
        RECOMMENDEDBY
            "CIPP"
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>
    param ($Tenant, $Settings)

    # 1. License check
    $TestResult = Test-CIPPStandardLicense -StandardName 'DefenderIntuneConnection' -TenantFilter $Tenant -RequiredCapabilities @(
        'EXCHANGE_S_STANDARD',
        'EXCHANGE_S_ENTERPRISE',
        'EXCHANGE_S_STANDARD_GOV',
        'EXCHANGE_S_ENTERPRISE_GOV',
        'EXCHANGE_LITE'
    )
    if ($TestResult -eq $false) { return $true }

    # 2. Get current state from Defender Security Center API
    # Uses the Defender scope, not the default Graph scope
    try {
        $CurrentInfo = New-GraphGetRequest `
            -Uri 'https://api.securitycenter.microsoft.com/api/advancedfeatures' `
            -tenantid $Tenant `
            -scope 'https://api.securitycenter.microsoft.com/.default' `
            -AsApp $true

        # Response is an array of features e.g. { name: "MicrosoftIntuneConnection", enabled: true }
        $IntuneFeature = $CurrentInfo | Where-Object { $_.name -eq 'MicrosoftIntuneConnection' }

        if (-not $IntuneFeature) {
            throw "MicrosoftIntuneConnection feature not found in Defender advanced features response."
        }

        $IntuneConnectionEnabled = [bool]$IntuneFeature.enabled
    }
    catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Standards' -Tenant $Tenant -Message "Could not get DefenderIntuneConnection state for $Tenant. Error: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        return
    }

    $CurrentValue  = [PSCustomObject]@{ MicrosoftIntuneConnection = $IntuneConnectionEnabled }
    $ExpectedValue = [PSCustomObject]@{ MicrosoftIntuneConnection = $true }

    # 3. Remediation
    if ($Settings.remediate -eq $true) {
        if ($IntuneConnectionEnabled -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Defender Intune connection is already enabled.' -sev Info
        }
        else {
            try {
                $body = '{"name":"MicrosoftIntuneConnection","enabled":true}'
                New-GraphPostRequest `
                    -tenantid $Tenant `
                    -Uri 'https://api.securitycenter.microsoft.com/api/advancedfeatures' `
                    -scope 'https://api.securitycenter.microsoft.com/.default' `
                    -Type POST `
                    -Body $body `
                    -AsApp $true
                Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Enabled Defender Intune connection.' -sev Info
                $IntuneConnectionEnabled = $true
            }
            catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to enable Defender Intune connection. Error: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
            }
        }
    }

    # 4. Alerting
    if ($Settings.alert -eq $true) {
        if ($IntuneConnectionEnabled -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Defender Intune connection is enabled.' -sev Info
        }
        else {
            Write-StandardsAlert -message 'Defender Intune connection is not enabled.' -object $CurrentValue -tenant $Tenant -standardName 'DefenderIntuneConnection' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Defender Intune connection is not enabled.' -sev Info
        }
    }

    # 5. Reporting
    if ($Settings.report -eq $true) {
        Set-CIPPStandardsCompareField -FieldName 'standards.DefenderIntuneConnection' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
        Add-CIPPBPAField -FieldName 'DefenderIntuneConnection' -FieldValue $IntuneConnectionEnabled -StoreAs bool -Tenant $Tenant
    }
}
