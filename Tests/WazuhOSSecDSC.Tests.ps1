$ModuleManifestName = 'WazuhOSSecDSC.psd1'
$ModuleResourceName = 'WazuhOSSecDSC.psm1'
$ModuleResourcePath = "$PSScriptRoot\..\$ModuleResourceName"
$ModuleManifestPath = "$PSScriptRoot\..\$ModuleManifestName"
$Manifest = Import-PowershellDataFile -Path $ModuleManifestPath -ErrorAction Ignore

Describe 'Module Manifest Tests' {
    It 'Passes Test-ModuleManifest' {
        Test-ModuleManifest -Path $ModuleManifestPath
        $? | Should Be $true
    }

    it 'Must have a module manifest with the same name as the module' {
        $ModuleManifestPath | should exist
    }

    it 'Must have the Description manifest key populated' {
        $Manifest.Description | should not benullorempty
    }

    it 'Must have the Author manifest key populated' {
        $Manifest.Author | should not benullorempty
    }

    it 'Must have either the LicenseUri or ProjectUri manifest key populated' {
        ($Manifest.PrivateData.PSData.LicenseUri + $Manifest.PrivateData.PSData.ProjectUri) | should not benullorempty
    }

    #Update path to tests
    it 'Must have associated Pester tests' {
        "$ModuleManifestPath" | should exist
    }

    it 'Must pass PSScriptAnalyzer rules' {
        Invoke-ScriptAnalyzer -Path $ModuleResourcePath -ExcludeRule 'PSDSCDscExamplesPresent' | should benullorempty
    }
}
