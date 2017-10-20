enum Ensure
{
    Present
    Absent
}

enum AgentStatus
{
    Start
    Stop
}

[DSCResource()]
# DSC Resource to Install/Un-install the Wazuh OSSec Agent
class WazuhAgentInstall
{
    [DscProperty(Key)]
    [String]$InstallerPath

    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(NotConfigurable)]
    [string]$ExeVersion

    [DscProperty(NotConfigurable)]
    [string]$Installed

    [DscProperty(NotConfigurable)]
    [string]$InstalledVersion

    # Get Method should return only the properties of the resource at the time it is run.
    [WazuhAgentInstall] Get()
    {
        $_WazuhPackage = Get-Package -Name "*Wazuh*" -ProviderName Programs -ErrorAction SilentlyContinue
        if ((Get-Service -Name "*OSSec*") -and ($_WazuhPackage.Status -eq "Installed"))
        {
            Write-Verbose "Ossec Service Installed"
            $this.Installed = 'Present'
            $this.InstalledVersion = $_WazuhPackage.Version
            Write-Verbose "Current installed version: $($this.InstalledVersion)"
        }
        else
        {
            Write-Verbose "OSSec Agent is not installed"
            $this.Installed = 'Absent'
        }
        return $this
    }

    [bool] Test()
    {
        $Get = $this.Get()

        if ($this.Ensure -eq $Get.Installed)
        {
            if (($this.Ensure -eq [Ensure]::Present) -and ($this.VersionUpgrade($Get.InstalledVersion)))
            {
                return $false
            }
            return $true
        }
        return $false
    }

    [void] Set()
    {
        if ($this.Ensure -eq [Ensure]::Present)
        {
            Write-Verbose -Message "Installing/Updating OSSEC Agent"
            if ($this.ValidateInstallerPath())
            {
                Write-Verbose "Starting Wazuh OSSEC Installer"
                $this.WazuhInstaller($this.InstallerPath)
            }
        }
        elseif ($this.Ensure -eq [Ensure]::Absent)
        {
            try
            {
                Write-Verbose "Uninstalling Wazuh OSSec Agent"
                $UninstallString = ((Get-Package -Name "*Wazuh*" -ProviderName Programs -ErrorAction Stop).Meta.Attributes.Get_Item("UninstallString")).trim([char]"`"")
                $this.WazuhInstaller($UninstallString)
            }
            catch [System.Exception]
            {
                Write-Verbose "$($_.Exception.Message)"
            }
        }
    }

    #region Helper Methods
    [bool] ValidateInstallerPath()
    {
        #Determine if the Installer Path is valid and if so get the FilVersion Attribute for Test() Method
        if (Test-Path -Path $this.InstallerPath -PathType Leaf)
        {
            return $true
        }
        else
        {
            Write-Verbose "File not found: $($this.InstallerPath)"
            throw [System.IO.FileNotFoundException]
        }
    }

    #Compare the installed version vs the one supplied to determine if this is an upgrade
    [bool] VersionUpgrade($CurrentVersion)
    {
        $this.ValidateInstallerPath()
        $_InstallerInfo = Get-ItemProperty -Path $this.InstallerPath
        if (($CurrentVersion -eq $_InstallerInfo.VersionInfo.Fileversion) -and ($_InstallerInfo.VersionInfo.CompanyName -like "*Wazuh*"))
        {
            return $false
        }
        else
        {
            Write-Verbose "New Version detected: $($_InstallerInfo.VersionInfo.Fileversion)"
            return $true
        }
    }

    [void] WazuhInstaller([string] $AgentExePath)
    {
        try
        {
            Start-Process -NoNewWindow -ErrorAction stop -Filepath $AgentExePath -ArgumentList '/S'
            Write-Verbose "Agent installation/removal complete."
        }
        catch
        {
            throw $_.Exception
        }
    }

    #endregion
}

[DSCResource()]
# DSC Resource to register the Wazuh OSSec Agent
class WazuhAgentRegister
{
    #region header
    # Vast portions of this resource were taken/inspired by the script provided by Wazuh, Inc.
    ###
    #  Powershell script for registering agents automatically with the API
    #  Copyright (C) 2017 Wazuh, Inc. All rights reserved.
    #  Wazuh.com
    #
    #  This program is a free software; you can redistribute it
    #  and/or modify it under the terms of the GNU General Public
    #  License (version 2) as published by the FSF - Free Software
    #  Foundation.
    ###

    ###
    # Source:
    # https://raw.githubusercontent.com/wazuh/wazuh-api/2.0/examples/api-register-agent.ps1
    ###
    #endregion
    [DscProperty(Key)]
    [String]$AgentName

    [DscProperty(Mandatory)]
    [String]$WazuhServerApiFqdn

    [DscProperty()]
    [string]$WazuhServerApiPort = "55000"

    [DscProperty(Mandatory)]
    [bool]$UseSelfSignedCerts = $false

    [DscProperty()]
    [int16]$ApiPollingInterval = 0

    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(NotConfigurable)]
    [String]$AgentPath

    [DscProperty(NotConfigurable)]
    [String]$BaseUrl

    [DscProperty(NotConfigurable)]
    [String]$AgentConfigFile = "ossec.conf"

    [DscProperty(NotConfigurable)]
    [String]$WazuhServerApiIP

    [DscProperty(NotConfigurable)]
    [bool]$AgentRegistered

    [DscProperty(NotConfigurable)]
    [AgentStatus]$AgentStatus

    [WazuhAgentRegister] Get()
    {
        #Set Certificate policy to ignore Self Signed Certs, False by default.
        if ($this.UseSelfSignedCerts)
        {
            Write-Verbose "Allowing Self Signed Certs"
            $this.IgnoreSelfSignedCerts()
        }
        Write-Verbose "Agent Name: $($this.AgentName)"
        $this.BaseUrl = "https://" + $this.WazuhServerApiFqdn + ":" + $this.WazuhServerApiPort
        Write-Verbose "Base URL: $($this.BaseUrl)"
        $this.AgentPath = $this.GetAgentPath()
        Write-Verbose "Agent Path: $($This.AgentPath)"
        $this.AgentConfigFile = $this.AgentPath + "\" + $this.AgentConfigFile
        Write-Verbose "OSSec Agent Config: $($This.AgentConfigFile)"
        $this.WazuhServerApiIP = $this.GetWazuhServeIP()
        Write-Verbose "Wazuh Server IP: $($This.WazuhServerApiIP)"

        # This block uses the ApiPollingInterval value to determine if it should poll for Agent Registration.
        #   We put this in to alleviate unnecessary API calls to the server. Other wise every time DSC ran this would make a call
        #   to the API to verify the Agent was registered. Most of which would return back $true.
        #   If no ApiPollingInterval is set it wll poll each time
        if (($this.ApiPollingInterval -eq 0) -or (($this.InitializePolling()) -and ($this.ApiPollingInterval -ne 0)))
        {
            #If PollingInterval is 0 cleanup the polling file so we don't have any lingering data lying around should the interval change later
            if (($this.ApiPollingInterval -eq 0) -and (Test-Path ($this.AgentPath + "\DSC_Polling.log") -PathType Leaf))
            {
                Remove-Item -Path ($this.AgentPath + "\DSC_Polling.log") -Force
            }
            $AgentPollResult = $this.GetAgentInfo()
            #If Total Items greater than or equal to 1 the agent should be registered
            if (($agentPollResult | ConvertFrom-Json).data.totalitems -ge 1)
            {
                $this.AgentRegistered = $true
            }
            else
            {
                $this.AgentRegistered = $false
            }
        }
        else
        {
            #No need to poll for agent status so assume Registered with the server
            $this.AgentRegistered = $true
        }
        return $this
    }

    [bool] Test()
    {
        $this.Get()
        if (!($this.AgentRegistered))
        {
            return $false
        }
        return $true
    }

    [void] Set()
    {
        # Register the Agent, Get the Key from Wazuh Server, Import the Key, update ossec.conf, and restart the Agent service
        $AgentRegisterResponse = $this.AgentRegisterNew()
        $AgentKeyResponse = $this.GetAgentKey($AgentRegisterResponse)
        $this.ImportAgentKey($AgentKeyResponse)
        $this.AgentControl([AgentStatus]::Stop)
        $this.UpdateConfigFile()
        $this.AgentControl([AgentStatus]::Start)
    }

    #region Helper Methods
    [string] AgentRegisterNew()
    {
        $Params = @{name = $this.AgentName}
        Write-Verbose "Registering Agent with server: $($This.AgentName)"
        $ApiResponse = $this.WazuhApiRequest("POST", "/agents", $Params) | ConvertFrom-Json
        If ($ApiResponse.error -ne '0')
        {
            throw "ERROR: $($ApiResponse.message)"
        }
        else
        {
            $AgentId = $ApiResponse.data
            Write-Verbose "Agent Registerd: (Agent - $($this.AgentName)) / (ID - $($AgentId))"
            return $AgentId
        }
    }

    [string] GetAgentKey($AgentId)
    {
        # Getting agent key from manager
        Write-Verbose "Retrieving Agent Key from server"
        #$response = req -method "GET" -resource "/agents/$($agent_id)/key" | ConvertFrom-Json
        #ToDo: I think converFrom-Json on the call lilke above so we don't have to below.
        $_ApiResponse = $this.WazuhApiRequest("Get", "/agents/$($AgentId)/key") | ConvertFrom-Json
        If ($_ApiResponse.error -ne '0')
        {
            throw "ERROR: $($_ApiResponse.message)"
        }
        else
        {
            $AgentKey = $_ApiResponse.data
            Write-Verbose "Key for agent '$($AgentId)' received."
        }
        return $AgentKey
    }

    [void]ImportAgentKey($AgentKey)
    {
        Write-Verbose "Importing authentication key"
        Write-Output "y" | & "$($this.GetAgentPath())\manage_agents.exe" "-i $($AgentKey)" "y`r`n"
    }

    # If UseSelfSignedCerts=$true modify Certificate Policy to allow
    [void]IgnoreSelfSignedCerts()
    {
        add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class PolicyCert : ICertificatePolicy {
        public PolicyCert() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = new-object PolicyCert
    }

    [string]WazuhApiRequest($Method, $Resource, $Params)
    {
        $_UserName = ($this.Credential).GetNetworkCredential().UserName
        $_PassWord = ($this.Credential).GetNetworkCredential().Password
        $_Base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $_UserName, $_PassWord)))
        $this.BaseUrl = "https://" + $this.WazuhServerApiFqdn + ":" + $this.WazuhServerApiPort
        $_Url = $this.BaseUrl + $Resource;

        try
        {
            return Invoke-WebRequest -Headers @{Authorization = ("Basic {0}" -f $_Base64AuthInfo)} -Method $Method -Uri $_Url -Body $Params -UseBasicParsing
        }
        catch
        {
            return $_.Exception
        }
    }

    [string]WazuhApiRequest($Method, $Resource)
    {
        $_UserName = ($this.Credential).GetNetworkCredential().UserName
        $_PassWord = ($this.Credential).GetNetworkCredential().Password
        $_Base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $_UserName, $_PassWord)))
        $this.BaseUrl = "https://" + $this.WazuhServerApiFqdn + ":" + $this.WazuhServerApiPort
        $_Url = $this.BaseUrl + $Resource;

        try
        {
            return Invoke-WebRequest -Headers @{Authorization = ("Basic {0}" -f $_Base64AuthInfo)} -Method $Method -Uri $_Url -UseBasicParsing
        }
        catch
        {
            return $_.Exception
        }
    }

    [string]GetAgentInfo()
    {
        $_QueryParameter = @{search = $This.AgentName}
        return $this.WazuhApiRequest("GET", "/agents", $_QueryParameter)
    }

    [void]AgentControl([AgentStatus]$AgentStatus)
    {
        $_ServiceName = "OssecSvc"

        switch ($AgentStatus)
        {
            'Stop'
            {
                try
                {
                    if ((Get-Service -Name "$_ServiceName").status -ne "Stopped")
                    {
                        Write-Verbose "Stopping Agent"
                        Stop-Service -Name $_ServiceName
                        Start-Sleep -Seconds 2
                        if ((Get-Service -Name $_ServiceName).Status -eq "Stopped")
                        {
                            Write-Verbose "Agent Stopped"
                        }
                        else
                        {
                            throw "Error: Agent did not stop"
                        }
                    }
                    Write-Verbose "Agent Stopped"
                }
                catch
                {
                    throw "Error: Could not stop Agent"
                }
            }
            'Start'
            {
                try
                {
                    if ((Get-Service -Name "$_ServiceName").status -ne "Running")
                    {
                        Write-Verbose "Starting Agent"
                        Start-Service -Name $_ServiceName
                        Start-Sleep -Seconds 2
                        if ((Get-Service -Name $_ServiceName).Status -eq "Running")
                        {
                            Write-Verbose "Agent Started"
                        }
                        else
                        {
                            throw "Error: Agent did not start"
                        }
                    }
                    Write-Verbose "Agent is running"
                }
                catch
                {
                    throw "Error: Could not start Agent"
                }
            }
            Default
            {}
        }
    }

    [void]UpdateConfigFile()
    {
        # Check installed version because the default Config file changed starting with v2.1.0
        # Do a String replpace for newer version vs the Add-Content
        $_AgentConfigFilePath = $this.GetAgentPath() + "\" + $this.AgentConfigFile
        $_InstalledAgentVersion = (Get-Package -Name "*Wazuh*" -ProviderName Programs).Version
        $_WazuhServerIP = $this.GetWazuhServeIP()
        Write-Verbose "Updating Configuration File: $_AgentConfigFilePath with Server IP: $_WazuhServerIP"
        if ($_InstalledAgentVersion -ge "2.1.0")
        {
            try
            {
                (Get-Content $_AgentConfigFilePath) -replace "0.0.0.0", $_WazuhServerIP | Out-File $_AgentConfigFilePath -Encoding ascii
            }
            catch
            {
                throw "ERROR: Could not write config file: $_AgentConfigFilePath"
            }
        }
        else
        {
            try
            {
                Add-Content $_AgentConfigFilePath "`n<ossec_config>   <client>      <server-ip>$($_WazuhServerIP)</server-ip>   </client> </ossec_config>"
            }
            catch
            {
                throw "ERROR: Could not write config file: $_AgentConfigFilePath"
            }
        }
    }

    [bool] InitializePolling()
    {
        $_PollingLogFile = ($this.GetAgentPath()) + "\DSC_Polling.log"
        if (!(Test-Path -Path $_PollingLogFile))
        {
            #Polling file does not exist so lets create and write Date-Time, Return true
            Write-Verbose "Writing out DSC_Polling.log file"
            (Get-Date).DateTime | Out-File -FilePath $_PollingLogFile -NoNewline
            Return $true
        }
        else
        {
            Write-Verbose "Checking timespan from last Poll"
            #File exists so lets do some Date Maths
            [datetime] $_LastPollTime = Get-Content $_PollingLogFile
            if (($_interval = New-TimeSpan -Start $_LastPollTime).TotalMinutes -ge $($this.ApiPollingInterval))
            {
                Write-Verbose "Polling interval of `"$([int]$($_interval).TotalMinutes)`" minutes exceeds defined value of $($this.ApiPollingInterval) minutes - Calling API"
                #Update the DSC_Polling.log file with a new time stamp
                (Get-Date).DateTime | Out-File -FilePath $_PollingLogFile -NoNewline -Force
                Return $true
            }
            else
            {
                Write-Verbose "Polling Interval within defined value of $($this.ApiPollingInterval) - Bypassing API"
                return $false
            }
        }
    }

    #The following two methods are used in various other methods so we broke them out to reduce code and make it simpler...we hope.
    [string]GetWazuhServeIP()
    {
        Write-Verbose "Resolving Wazuh Server IP Address"
        if ($_WazuhServerIP = (Resolve-DnsName -Name $($this.WazuhServerApiFqdn) -Verbose:$false).IP4Address)
        {
            return $_WazuhServerIP
        }
        else
        {
            throw "Error: Unable to obtain Wazuh Server IP"
        }
    }

    [string]GetAgentPath()
    {
        if ($_AgentPath = (Get-Package -Name "*wazuh*").Meta.Attributes.Get_Item("UninstallString").trim([char]"`"") | Split-Path )
        {
            return $_AgentPath
        }
        else
        {
            throw "Error: Unable to locate the Agent installation path"
        }
    }

    #endregion
}