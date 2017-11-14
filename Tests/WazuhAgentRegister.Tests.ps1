using module ..\WazuhOSSecDSC.psm1

Describe 'Testing the Class based DSC resource WazuhAgentRegister' {

    $myObject = [WazuhAgentRegister]::new()
    $myObject.AgentName = 'WazuhAgent'
    $myObject.WazuhServerApiFqdn = 'wazuh.test.api.com'
    $secpasswd = ConvertTo-SecureString "PlainTextPassword" -AsPlainText -Force
    $myObject.Credential = New-Object System.Management.Automation.PSCredential ("username", $secpasswd)
    $myObject.UseSelfSignedCerts = $True
    $myObject.AgentConfigFile = "ossec.conf"
    Context 'Testing the Get() Method' {
        Mock Resolve-DnsName -ModuleName 'WazuhOssecDSC' {
            return @{
                IP4Address = '10.10.0.1'
            }
        }

        It 'Return type of the Get() Method should be "WazuhAgentRegister"' {
            $myObject.Ensure = 'Absent'
            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe' }
            }

            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    data = @{
                        totalItems = 0
                    }
                }
            }

            ($myObject.Get()).Gettype() | Should be 'WazuhAgentRegister'
        }

        It 'Should return AgentRegistered $true Ensure = Absent and found on Server' {

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

        It 'Should return AgentRegistered $false Ensure = Absent and NOT found on Server' {

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

            Mock Out-File -ModuleName 'WazuhOssecDSC' {

            }

            $results = $myObject.Get()

            $results.AgentRegistered | Should be $false

            Assert-MockCalled Resolve-DnsName -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 2 -Scope it -Exactly
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-Content -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Out-File -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
        }

        It 'Should remove the Polling Log file if ApiPollingInterval = 0' {
            $myObject.ApiPollingInterval = 0
            Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
                return @{ DisplayName = 'Wazuh Agent 2.1.1'; UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe' }
            }

            Mock Test-Path -ModuleName 'WazuhOssecDSC' {
                return $true
            }
            Mock Remove-Item -ModuleName 'WazuhOssecDSC' {

            }
            $myObject.Get()
            Assert-MockCalled Resolve-DnsName -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Get-ItemProperty -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Test-Path -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly
            Assert-MockCalled Remove-Item -ModuleName 'WazuhOSSecDSC' -Times 1 -Scope it -Exactly

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
    }

    Context 'Testing the Set() Method' {
        Mock Resolve-DnsName -ModuleName 'WazuhOssecDSC' {
            return @{
                IP4Address = '10.10.0.1'
            }
        }
        Mock Get-ItemProperty -ModuleName 'WazuhOssecDSC' -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' } {
            return @{ DisplayName = 'Wazuh Agent 2.1.1';
                    UninstallString = 'C:\Program Files (x86)\ossec-agent\uninstall.exe';
                    DisplayVersion = '2.1.1' }
        }

        It 'Should Register the Agent if Ensure is Present' {
            $myObject.Ensure = 'Present'
            $Script:GetServiceCounter = 1
            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 0;
                    data  = '123'
                }
            }
            Mock Invoke-Expression -ModuleName 'WazuhOssecDSC' {
                return {  }
            }
            # Thank you Dexter Posh
            # www.dexterposh.com/2016/05/powershell-pester-counter-based-mocking.html
            Mock Get-Service -ModuleName 'WazuhOssecDSC' {
                if ($Script:GetServiceCounter -lt 1)
                {
                    $Script:GetServiceCounter++
                    @{Status = 'Stopped'}
                }
                else
                {
                    @{Status = 'Running'}
                }
            }
            Mock Get-Content -ModuleName 'WazuhOssecDSC' {
                return {  }
            }
            Mock Out-File -ModuleName 'WazuhOssecDSC' {
                return {  }
            }
            # Need to set this here because for some reason the Config File path was real nasty
            $myObject.AgentConfigFile = 'ossec.conf'
            { $myObject.set() } | Should not throw
            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 3 -Scope It -Exactly
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 3 -Scope It -Exactly
            Assert-MockCalled Invoke-Expression -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled Get-Service -ModuleName 'WazuhOssecDSC' -Times 2 -Scope It -Exactly
            Assert-MockCalled Get-Content -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
            Assert-MockCalled Out-File -ModuleName 'WazuhOssecDSC' -Times 1 -Scope It -Exactly
        }

        It 'Should Delete the Agent if Agent already exists or Ensure is Absent' {
            $myObject.Ensure = 'Absent'
            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return {  }
            }
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 0;
                    data = @{
                        message = 'Error'
                    }
                }
            }
            { $myObject.set() } | Should not throw

        }
    }

    Context 'Testing the AgentRegisterNew() Method' {

        It 'Should Return Agent ID when error response = 0 from API' {
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 0;
                    data  = '123'
                }
            }

            $results = $myObject.AgentRegisterNew()
            $results | Should be '123'
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly
        }

        It 'Should throw an Exception when error response NOT 0 from API' {
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 1
                }
            }
            { $myObject.AgentRegisterNew() } | Should throw
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly
        }
    }

    Context 'Testing the AgentRegisterDelete() Method' {
        It 'Should NOT throw Exception when response = 0 from API' {
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 0
                }
            }
            #$results = $myObject.AgentRegisterDelete('123')
            { $myObject.AgentRegisterDelete('123') } | Should not throw
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly
        }

        It 'Should throw Exception when response != 0 from API' {
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 1;
                    data  = @{
                        message = 'Pester Error'
                    }
                }
            }
            #$results = $myObject.AgentRegisterDelete('123')
            { $myObject.AgentRegisterDelete('123') } | Should throw
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly
        }

    }

    Context 'Testing the GetAgentKey() Method' {
        It 'Should return the Agent Key XyXyXyXy when error reponse = 0 from API' {
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 0;
                    data  = 'XyXyXyXy'
                }
            }
            $results = $myObject.GetAgentKey('123')
            $results | Should be 'XyXyXyXy'
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly

        }

        It 'Should return throw and Exception when error reponse != 0 from API' {
            Mock ConvertFrom-Json -ModuleName 'WazuhOssecDSC' {
                return @{
                    error = 1;
                    data  = 'XyXyXyXy'
                }
            }
            { $myObject.GetAgentKey('123') } | Should throw
            #$results = $myObject.GetAgentKey('123')
            #$results | Should be 'XyXyXyXy'
            Assert-MockCalled ConvertFrom-Json -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly

        }

    }

    <# Context 'Testing the ImportAgentKey() Method' {

    }

    Context 'Testing the IgnoreSelfSignedCerts() Method' {

    } #>

    Context 'Testing the WazuhApiRequest() Method' {
        It 'Should return a string response from the API' {
            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                return "Good Response"
            }
            $results = $myObject.WazuhApiRequest('Get', '/Agents', 'Param')
            $results | Should be "Good Response"
            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly
        }
        # Having trouble getting invoke-webrequest to throw an error
        It 'Should Throw an exception if API response fails' {
            $myObject.BaseUrl = 'http://notvalid'
            Mock Invoke-WebRequest -ModuleName 'WazuhOssecDSC' {
                { throw [System.Web.HttpException] }
            }
            $results = $myObject.WazuhApiRequest('Get', '/Agents', 'Params')
            { $myObject.WazuhApiRequest('Get', '/Agents', 'Param') } | Should throw
            #$results = $myObject.WazuhApiRequest('Get', '/Agents', 'Param')
            #$results | Should be 'System Exception'
            Assert-MockCalled Invoke-WebRequest -ModuleName 'WazuhOssecDSC' -Times 1 -Scope it -Exactly

        }

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
    }
}
