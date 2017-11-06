
using module ..\WazuhOSSecDSC.psm1

Describe 'Testing the Class based DSC resource WazuhAgentInstall' {

    Context 'Testing the Get() Method' {

        $myObject = New-Object -TypeName WazuhAgentInstall

        Mock Get-Service -ModuleName 'WazuhOSSecDSC' {
            return @{ Name = "OssecSvc"; Status = "Running" }
        }

        Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
            return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
        }

        It 'Return type of the Get() Method should be "WazuhAgentInstall"' {
            ($myObject.Get()).Gettype() | Should be 'WazuhAgentInstall'
        }

        It 'Get Service and Get Package should Return $true and Installed' {
            $results = $myObject.Get()
            $results.Installed | Should be "Present"
            $results.InstalledVersion | Should be "2.1.1"
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-Service -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
        }
    }

    Context 'Testing the Test() Method' {

     }

     Context 'Testing the Set() Method' {

     }

     Context 'Testing the ValidateInstallerPath() Method' {

     }

     Context 'Testing the VersionUpgrade() Method' {

     }

     Context 'Testing the WazuhInstaller() Method' {

     }
}

