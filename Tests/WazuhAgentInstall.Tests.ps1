using module ..\WazuhOSSecDSC.psm1

Describe 'Testing the Class based DSC resource WazuhAgentInstall' {

    Context 'Get() Method' {
        $myObject = [WazuhAgentInstall]::new()
        Mock Get-Service -ModuleName 'WazuhOSSecDSC' {
            return @{ Name = "OssecSvc"; Status = "Running" }
        }
        Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
            return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
        }

        It 'Return type of the Get() Method should be "WazuhAgentInstall"' {
            ($myObject.Get()).Gettype() | Should be 'WazuhAgentInstall'
        }

        It 'Get-Service and Get-ItemProperty should Return $true and Installed' {
            $results = $myObject.Get()
            $results.Installed | Should be "Present"
            $results.InstalledVersion | Should be "2.1.1"
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Scope it -Times 1 -Exactly
            Assert-MockCalled Get-Service -ModuleName 'WazuhOSSecDSC' -Scope it -Times 1 -Exactly
        }

        It 'Should return Absent if Service not installed' {
            Mock Get-Service { } -ModuleName 'WazuhOSSecDSC'
            $results = $myObject.Get()
            $results.installed | Should be "Absent"
            Assert-MockCalled Get-Service -ModuleName 'WazuhOSSecDsc' -Times 1 -Scope it -Exactly
        }

        It 'Should return Absent if Service Installed and Package not found' {
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ }
            }
            $results = $myObject.Get()
            $results.installed | Should be "Absent"
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDsc' -Times 1 -Scope it -Exactly
        }
    }

    Context 'Test() Method' {
        #Instantiate Object
        $myObject = [WazuhAgentInstall]::new()
        $myObject.InstallerPath = "C:\Software\Installer.exe"
        It 'Should return $false if Ensure is Present and Agent Not Installed' {
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ }
            }
            $myObject.Ensure = "Present"
            $results = $myObject.Test()
            $results | Should be $false
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDsc' -Times 1 -Scope it -Exactly
        }

        It 'Should return $false if Ensure is Absent and Agent Is Installed' {
            Mock Get-Service -ModuleName 'WazuhOSSecDSC' {
                return @{ Name = "OssecSvc"; Status = "Running" }
            }
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
            }
            $myObject.Ensure = "Absent"
            $results = $myObject.Test()
            $results | Should be $false
            Assert-MockCalled Get-Service -ModuleName 'WazuhOSSecDsc' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDsc' -Times 1 -Scope it -Exactly
        }

        It 'Should return $true if Ensure = Present and VersionUpgrade = $false' {
            # Mock Get-ItemProperty for VersionUpgrade() Need to return .VersionInfo.FileVersion
            #   and .VersionInfo.CompanyName
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'C:\Software\Installer.exe'} {
                return @{
                    VersionInfo = @{
                        FileVersion = "2.1.1";
                        CompanyName = "Wazuh"
                    }
                }
            }
            # Mock Get-ItemProperty for the Get() Method
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
            }
            # Mock Test-Path for ValidateInstallerPath()
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return {$true}
            }
            $myObject.Ensure = "Present"
            $results = $myObject.Test()
            $results | Should be $true
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 2 -Exactly -Scope it
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

        It 'Should return $false if Ensure is Present and is a Version Upgrade' {
            # Mock Get-ItemProperty for VersionUpgrade() Need to return .VersionInfo.FileVersion
            #   and .VersionInfo.CompanyName
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'C:\Software\Installer.exe'} {
                return @{
                    VersionInfo = @{
                        FileVersion = "2.2.1";
                        CompanyName = "Wazuh"
                    }
                }
            }
            # Mock Get-ItemProperty for the Get() Method
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
            }
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return {$true}
            }
            $myObject.Ensure = "Present"
            $results = $myObject.Test()
            $results | Should be $false
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 2 -Exactly -Scope it
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

        It 'Should return $true if Ensure is Absent and is a Version Upgrade' {
            # Mock Get-ItemProperty for VersionUpgrade() Need to return .VersionInfo.FileVersion
            #   and .VersionInfo.CompanyName
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'C:\Software\Installer.exe'} {
                return @{
                    VersionInfo = @{
                        FileVersion = "2.2.1";
                        CompanyName = "Wazuh"
                    }
                }
            }
            # Mock Get-ItemProperty for the Get() Method
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
            }
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return {$true}
            }
            $myObject.Ensure = "Present"
            $results = $myObject.Test()
            $results | Should be $false
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 2 -Exactly -Scope it
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }
    }

    Context 'Testing the Set() Method' {
        #Instantiate Object
        $myObject = [WazuhAgentInstall]::new()
        $myObject.InstallerPath = "C:\Software\Installer.exe"
        It 'Should execute the installer if Ensure = Present' {
            $myObject.Ensure = 'Present'
            # Mock Test-Path for ValidateInstallerPath()
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return $true
            }
            Mock Start-Process  -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$FilePath -eq "C:\Software\Installer.exe"} {
                return { }
            }
            $results = $myObject.Set()
            $results | should be $null
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
            Assert-MockCalled Start-Process -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

        It 'Should Execute Uninstall if Ensure = Absent' {
            $myObject.Ensure = 'Absent'
            # Mock Get-ItemProperty for GetInstallInformation() Method
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Software\UnInstall.exe' }
            }
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\UnInstall.exe"} {
                return $true
            }
            #Mock Start-Process for WazuhInstaller() Method
            Mock Start-Process  -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$FilePath -eq "C:\Software\UnInstall.exe"} {
                return { }
            }
            $results = $myObject.Set()
            $results | should be $null
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
            Assert-MockCalled Start-Process -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }
    }

    Context 'Testing the ValidateInstallerPath() Method' {
        #Instantiate Object
        $myObject = [WazuhAgentInstall]::new()
        $myObject.InstallerPath = "C:\Software\Installer.exe"
        It 'Should return TRUE if InstallerPath is valid' {
            $myObject.Ensure = 'Present'
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return $true
            }
            $results = $myObject.ValidateInstallerPath($myObject.InstallerPath)
            $results | should be $true
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

        It 'Should throw exception for invalid Path' {
            $myObject.Ensure = 'Present'
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return $false
            }
            {$myObject.ValidateInstallerPath("C:\Software\Installer.exe")} | should throw "FileNotFoundException"
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }
    }

    Context 'Testing the VersionUpgrade() Method' {
        #Instantiate Object
        $myObject = [WazuhAgentInstall]::new()
        $myObject.InstallerPath = "C:\Software\Installer.exe"
        It 'Should return FALSE if the Current Version Matches the Provided Installer' {
            $myObject.Ensure = 'Present'
            # Mock Test-Path for ValidateInstallerPath()
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return $true
            }
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'C:\Software\Installer.exe'} {
                return @{
                    VersionInfo = @{
                        FileVersion = "2.1.1";
                        CompanyName = "Wazuh"
                    }
                }
            }
            $result = $myObject.VersionUpgrade("2.1.1")
            $result | Should be $false
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

        It 'Should return TRUE if the Current Version does NOT MATCH Provided Installer' {
            $myObject.Ensure = 'Present'
            # Mock Test-Path for ValidateInstallerPath()
            Mock Test-Path -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq "C:\Software\Installer.exe"} {
                return $true
            }
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'C:\Software\Installer.exe'} {
                return @{
                    VersionInfo = @{
                        FileVersion = "3.0.0";
                        CompanyName = "Wazuh"
                    }
                }
            }
            $result = $myObject.VersionUpgrade("2.1.1")
            $result | Should be $true
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

    }

    Context 'Testing the WazuhInstaller() Method' {
        #Instantiate Object
        $myObject = [WazuhAgentInstall]::new()
        $myObject.InstallerPath = "C:\Software\Installer.exe"
        It 'Should return NULL on successful installation' {
            $myObject.Ensure = 'Present'
            #Mock Start-Process for WazuhInstaller() Method
            Mock Start-Process  -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$FilePath -eq "C:\Software\Installer.exe"} {
                return { }
            }
            $myObject.WazuhInstaller($myObject.InstallerPath) | Should be $null
            Assert-MockCalled Start-Process -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

        It 'Should THROW exception on error of installation' {
            {$myObject.WazuhInstaller("C:\Software\Nothing.exe")} | Should throw
        }
    }

    Context 'GetInstallerInformation() Method' {
        $myObject = [WazuhAgentInstall]::new()
        It 'Should return NULL if there is no Wazuh Entry' {
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return { }
            }
            $myObject.GetInstallInformation() | Should be $null
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }

        It 'Should return NOT NULL if Wazuh Entry found in Registry' {
            Mock Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -ParameterFilter {$Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'} {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
            }
            $myObject.GetInstallInformation() | Should not be $null
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Exactly -Scope it
        }
    }
}

