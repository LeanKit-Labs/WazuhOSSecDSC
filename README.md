# WazuhOSSecDSC
Powershell DSC Class based resource for installing and configuring the Wazuh Agent

The **WazuhOSSecDSC** resources allow you to install and register the Wazuh Ossec Agent with the defined Wazuh Server.


## Description
The **WazuhOSSecDSC** module contains the **WazuhAgentInstall** and **WazuhAgentRegister** DSC Resources.  These resources were built using PowerShell Classes and as such will require Powershell 5.0+.  These DSC resources allow you to install the Wazuh agent and register it with the Wazuh server.

## Resources
* **WazuhAgentInstall** Installs or Upgrades the Wazuh Agent from a path you provide.
* **WazuhAgentRegister** Registers or Deletes an agent on the Wazuh Manager.

### **WazuhAgentInstall**
* **InstallerPath** - Path to the Wazuh Agent installer on the local server.
* **Ensure** - Install or uninstall the agent. (Present/Absent).

### **WazuhAgentRegister**
* **AgentName** - The name you want to register for the Agent.
* **WazuhServerApiFqdn** - The FQDN of the Wazuh Server. i.e. wazuh.domain.com
* **WazuhServerApiPort** - The port the Wazuh server is listening on.  Defaults to 55000
* **UseSelfSignedCerts** - Determines whether to use a self signed cert with the Wazuh server.  Default is false.
* **ApiPollingInterval** - Used to determine a polling interval for checking if the agent is registered.  Default is 0 for no interval meaning the resource will poll the server everytime DSC is run.  Specified in minutes.
* **Credential** - PSCredential object passed into the rersource for authenticating to the Wazuh server
* **Ensure** - Registers or Deletes the agent on the Wazuh Manager. (Present/Absent)

## Versions

### 1.0.0
* Initial commit of DSC resource
