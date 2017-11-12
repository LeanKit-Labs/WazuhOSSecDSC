using module ..\WazuhOSSecDSC.psm1

Describe 'Testing the Class based DSC resource WazuhAgentRegister' {

    $myObject = [WazuhAgentRegister]::new()
    $myObject.AgentName = 'WazuhAgent'
    $myObject.WazuhServerApiFqdn = 'wazuh.test.api.com'
    $secpasswd = ConvertTo-SecureString "PlainTextPassword" -AsPlainText -Force
    $myObject.Credential = New-Object System.Management.Automation.PSCredential ("username", $secpasswd)
    $myObject.UseSelfSignedCerts = $True

    <# Context 'Testing the Get() Method' {

        Mock Resolve-DnsName -ModuleName 'WazuhOssecDSC' {
            return @{
                IP4Address = '10.10.0.1'
            }
        }

        It 'Should return AgentRegistered $true' {

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 1
                    }
                }
            }

            $myObject.Ensure = 'Absent'

            $results = $myObject.get()
            $results.AgentRegistered | Should be $true

            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
        }

        It 'Should return AgentRegistered $false' {

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 0
                    }
                }
            }

            $myObject.Ensure = 'Absent'

            $results = $myObject.get()
            $results.AgentRegistered | Should be $false

            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
        }

        It 'Should return valid object parameters' {

            $myObject.Ensure = 'Present'

            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe' }
            }

            $results = $myObject.Get()
            $results.AgentPath | Should be 'C:\Program Files (x86)\ossec-agent'
            $results.AgentConfigFile | should be 'C:\Program Files (x86)\ossec-agent\ossec.conf'
            $results.WazuhServerApiIP | Should be '10.10.0.1'

            $results.AgentName | Should be 'WazuhAgent'
            $results.BaseUrl | Should be 'https://wazuh.test.api.com:55000'

            Assert-MockCalled Resolve-DnsName -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
        }

        It 'Should return AgentRegistered $true' {

            $myObject.Ensure = 'Present'
            $myObject.ApiPollingInterval = 10

            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe' }
            }

            Mock Test-Path -ModuleName 'WazuhOssecDSC' {
                return $true
            }

            Mock Get-Content -ModuleName 'WazuhOssecDSC' {
                return (Get-Date).DateTime
            }

            $results = $myObject.Get()

            $results.AgentRegistered | Should be $true

            Assert-MockCalled Resolve-DnsName -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 2 -Scope it -Exactly
        }

        It 'Should return AgentRegistered $false' {

            $myObject.Ensure = 'Present'
            $myObject.ApiPollingInterval = 10

            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe' }
            }

            Mock Test-Path -ModuleName 'WazuhOssecDSC' {
                return $true
            }

            Mock Get-Content -ModuleName 'WazuhOssecDSC' {
                return (Get-Date).AddMinutes(-20).DateTime
            }

            $results = $myObject.Get()

            $results.AgentRegistered | Should be $false

            Assert-MockCalled Resolve-DnsName -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 2 -Scope it -Exactly
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-Content -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
        }

        It 'Return type of the Get() Method should be "WazuhAgentRegister"' {
            ($myObject.Get()).Gettype() | Should be 'WazuhAgentRegister'
        }

        It 'test polling log' {

        }
    }

    Context 'Testing the Test() Method' {

        Mock Resolve-DnsName -ModuleName 'WazuhOssecDSC' {
            return @{
                IP4Address = '10.10.0.1'
            }
        }

        Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
            return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe' }
        }

        It 'Should return $True if Ensure is Present and $this is Present' {
            $myObject.Ensure = 'Present'

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 1
                        items = @{
                            id = '123';
                            status = 'Active'
                        }
                    }
                }
            }

            Mock Test-Path -ModuleName 'WazuhOssecDSC' {
                return $true
            }

            Mock Get-Content -ModuleName 'WazuhOssecDSC' {
                return '123'
            }

            $myObject.test() | Should be $True

            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 2 -Scope it -Exactly
            Assert-MockCalled Get-Content -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
        }

        It 'Should return $False if Ensure is Present and $this is Absent' {
            $myObject.Ensure = 'Present'

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 1
                    }
                }
            }

            $myObject.test() | Should be $False

            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
        }

        It 'Should return $True if Ensure is Absent and $this is Absent' {
            $myObject.Ensure = 'Absent'

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 0
                    }
                }
            }

            $myObject.test() | Should be $True

            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
        }

        It 'Should return $False if Ensure is Absent and $this is Present' {
            $myObject.Ensure = 'Absent'

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 1
                    }
                }
            }

            $myObject.test() | Should be $False

            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
        }
    } #>

    Context 'Testing the Set() Method' {

        It 'Should Register the Agent if Ensure is Present' {

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 0;
                    data = '123'
                    }
                }

            Mock Invoke-Expression -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock Stop-Service -ModuleName 'WazuhOssecDSC' {

            }

            Mock Get-Service -ModuleName 'WazuhOssecDSC' {
                return @{
                    status = "Stopped"
                }
            }

            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe' }
            }

            Mock Get-Content -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock Out-File -ModuleName 'WazuhOssecDSC' {
                return {  }
            }
            # Need to Mock Get-ItemProperty that is called in GetInstallInformation

            # Need to Mock Get-Content called in UpdateConfigFile (just make $_InstalledAgentVersion -ge 2.1.0)

            { $myObject.set() } | Should not throw

        }

        <# It 'Should Delete the Agent if Agent already exists or Ensure is Absent' {

            $myObject.Ensure = 'Absent'

            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 1
                    }
                }
            }


        } #>

    }

    <# Context 'Testing the AgentRegisterNew() Method' {

    }

    Context 'Testing the AgentRegisterDelete() Method' {

    }

    Context 'Testing the GetAgentKey() Method' {

    }

    Context 'Testing the ImportAgentKey() Method' {

    }

    Context 'Testing the IgnoreSelfSignedCerts() Method' {

    }

    Context 'Testing the WazuhApiRequest() Method' {

    }

    Context 'Testing the GetAgentInfo() Method' {

    }

    Context 'Testing the AgentControl() Method' {

    }

    Context 'Testing the UpdateConfigFile() Method' {

    }

    Context 'Testing the InitializePolling() Method' {

    }

    Context 'Testing the GetWazuhServeIP() Method' {

        It 'Should return IP address on success' {

            Mock Resolve-DnsName -ModuleName 'WazuhOssecDSC' {
                return @{
                    IP4Address = '10.10.0.1'
                }
            }

            $myObject.GetWazuhServeIP() | Should be '10.10.0.1'

            Assert-MockCalled Resolve-DnsName -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly

        }

        It 'Should Throw if IP address is not returned' {

            Mock Resolve-DnsName -ModuleName 'WazuhOssecDSC' {
                return @{  }
            }

            { $myObject.GetWazuhServeIP() } | Should throw "Error: Unable to obtain Wazuh Server IP"

            Assert-MockCalled Resolve-DnsName -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly

        }
    }

    Context 'Testing the GetAgentPath() Method' {

        $myObject = New-Object -TypeName WazuhAgentRegister

        It 'Should return a string (AgentPath) on success' {

            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ UninstallString = "`"C:\Program Files (x86)\ossec-agent\uninstall.exe`"" ; DisplayName = 'Wazuh Agent 2.1.1'}
            }

            $result = $myObject.GetAgentPath()
            $result | Should be "C:\Program Files (x86)\ossec-agent"
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly
        }

        It 'Should throw an error if installation path does not exist' {
            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ }
            }

            { $myObject.GetAgentPath() } | Should throw "Error: Unable to locate the Agent installation path"
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly

        }
    }

    Context 'Testing the RegistrationStatus() Method' {

        Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
            return {  }
        }

        Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
            return @{
                data = @{
                    totalItems = 1
                    items = @{
                        id = '123'
                    }
                }
            }
        }

        It 'Should return a hashtable' {

            Mock $myObject.GetAgentInfo() -ModuleName 'WazuhOssecDSC' {
                New-MockObject -Type 'System.Object'
            }

            $_RegistrationStatus | Should beoftype System.Object

            Assert-MockCalled $myObject.GetAgentInfo() -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly
        }

    }

    Context 'Testing the GetInstallInformation() Method' {

        It "should return DisplayName and DisplayVersion" {

            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; DisplayVersion = "2.1.1" }
            }

            $result = $myObject.GetInstallInformation()

            $result.DisplayName | Should be 'Wazuh Agent 2.1.1'
            $result.DisplayVersion | Should be "2.1.1"

            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope It -Exactly
        }

        It "Should return null if not installed" {

            Mock Get-ItemProperty { } -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' }

            $result = $myObject.GetInstallInformation()
            $result | Should be $null
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
        }
    } #>
}
