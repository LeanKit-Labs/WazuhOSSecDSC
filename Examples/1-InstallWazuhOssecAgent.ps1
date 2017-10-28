<#
    .EXAMPLE

    This example shows how to use the File resouce to download the MSI installer to the local Node
    and then uses the two WazuhOSSec resources to install and register the agent with the manager.

    [File]OSSecDownload
    Downlods the MSI installer from a UNC path to the local server

    [WazuhAgentInstall]OSSecAgentInstall
    Installs the Wazuh OSSec Agent from the local path on the server

    [WazuhAgentRegister]OSSecAgentRegister
    Registers the Agent with the Manager server
    Uses self signed Certs
    Sets a polling interval to 120 minutes

#>

Configuration Example

{
    param
    (
        [Parameter()]
        [System.String[]]
        $NodeName = 'localhost',

        # Username and Password for Wazuh Manager API Access
        [Parameter()]
        [pscredential]
        $MyCreds
    )

    Import-DscResource -ModuleName WazuhOSSecDSC

    Node $NodeName
    {
        File OSSecDownload
        {
            SourcePath      = "\\Server\Software\Wazuh\wazuh-agent-2.1.1-1.msi"
            DestinationPath = "C:\Software\Wazuh\wazuh-agent-2.1.1-1.msi"
            Type            = 'File'
            Ensure          = 'Present'
        }

        WazuhAgentInstall OSSecAgentInstall
        {
            InstallerPath = "C:\Software\Wazuh\wazuh-agent-2.1.1-1.msi"
            Ensure        = 'Present'
            DependsOn     = '[File]OSSecDownload'
        }

        WazuhAgentRegister OSSecAgentRegister
        {
            AgentName          = $NodeName
            WazuhServerApiFqdn = "yourserver.yorudomain.com"
            WazuhServerApiPort = 55000 # Defaults to 55000 so not needed unless running not default
            UseSelfSignedCerts = $true # Defaults to False so if using Self Signed Cert on Manager set to True
            ApiPollingInterval = 120 # The DSC Resource will poll every two hours.  Used to minimize impact to manager server in large environments
            Credential         = $MyCreds
            Ensure             = 'Present'
            DependsOn          = "[WazuhAgentInstall]OSSecAgentInstall"
        }
    }
}