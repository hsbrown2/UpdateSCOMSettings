[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$True)]
    $ScomServer
)
  
    Import-Module OperationsManager
    New-SCOMManagementGroupConnection -ComputerName $ScomServer
   
    $gateways = Get-SCOMGatewayManagementServer | Select-Object DisplayName, IPAddress
    $gatelist = $gateways.DisplayName

    $managementservers = Get-SCOMManagementServer | Select-Object DisplayName,IPAddress | Where-Object {$_.DisplayName -notin $gatelist} | Sort-Object DisplayName
    foreach($managementserver in $managementservers){
        
        $thems = $managementserver.DisplayName
        Write-Host "Executing commands on $thems"
    
        Invoke-Command -ComputerName $thems -ScriptBlock {

            $key = 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup'
            $InstallDirectory = (Get-ItemProperty -Path $key -Name InstallDirectory).InstallDirectory
            $path = $InstallDirectory+"ConfigService.config"
            $xml = [xml](Get-Content "$path")
    
            #The first three settings modified are referenced here:
            #https://support.microsoft.com/en-us/help/3092452/configuration-isn-t-updated-and-event-id-29181-is-logged-in-system-cen
            #this was added improve snapshot synchronization above the defaults
            $SnapshotSyncManagedEntityBatchSize = $xml.Config.Component.Instance.Category.Setting | Where-Object {$_.Name -eq "SnapshotSyncManagedEntityBatchSize"}
            $SnapshotSyncManagedEntityBatchSize.Value = "10000"
    
            $SnapshotSyncRelationshipBatchSize = $xml.Config.Component.Instance.Category.Setting | Where-Object {$_.Name -eq "SnapshotSyncRelationshipBatchSize"}
            $SnapshotSyncRelationshipBatchSize.Value = "10000"
    
            $SnapshotSyncTypedManagedEntityBatchSize = $xml.Config.Component.Instance.Category.Setting | Where-Object {$_.Name -eq "SnapshotSyncTypedManagedEntityBatchSize"}
            $SnapshotSyncTypedManagedEntityBatchSize.Value = "20000"
    
            #The next two settings are referenced here:
            #https://blogs.technet.microsoft.com/momteam/2013/01/29/support-tip-config-service-deltasynchronization-process-fails-with-timeout-exception/
            #These settings improve the delta sync by increasing the job timeouts
            #The first setting is found twice in the configservice.config file, so here we want to ensure we only update the one we want each time
            foreach ($node in $xml.SelectNodes('//Category[@Name="Cmdb"]//OperationTimeout')) {
     
                $node.DefaultTimeoutSeconds = "300"
            }
    
            foreach ($node in $xml.SelectNodes('//Category[@Name="ConfigStore"]//OperationTimeout')) {
     
                $node.DefaultTimeoutSeconds = "300"
            }

            $GetEntityChangeDeltaList = $xml.Config.Component.Instance.Category.Setting.OperationTimeout.Operation | Where-Object {$_.Name -eq "GetEntityChangeDeltaList"}
            $GetEntityChangeDeltaList.TimeoutSeconds = "300"
    
            #Save the changes to the xml config file
            $xml.Save($path)

            #The below configurations are all referenced here (same for 2012 R2 and 2016):
            #https://kevinholman.com/2017/03/08/recommended-registry-tweaks-for-scom-2016-management-servers/
            #***NOTE*** Although this article discusses NOT adding the PoolManager keys, in our environment this was neccessary
            #***IMPORTANT*** The PoolManager keys ONLY must also be added to all gateway servers in the Management Group. This is done with a separate script.
            #***NOTE*** Bulk Insert Command Timeout Seconds is found here: https://support.microsoft.com/en-us/help/3029227/data-warehouse-logging-improvements-in-opsmgr-2012-r2-ur5-that-help-tr

            #Persistence Checkpoint Depth Maximum
            #Description:  Management Servers that host a large amount of agentless objects, which results in the MS running a large number of workflows: 
            #(network/URL/Linux/3rd party/VEEAM)  This is an ESE DB setting which controls how often ESE writes to disk.  
            #A larger value will decrease disk IO caused by the SCOM healthservice but increase ESE recovery time in the case of a healthservice crash.
 
            #State Queue Items
            #Description:  This sets the maximum size of healthservice internal state queue.  
            #It should be equal or larger than the number of monitor based workflows running in a healthservice.  
            #Too small of a value, or too many workflows will cause state change loss.

            $Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HealthService\Parameters"
            If (-Not(Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey}
            Set-ItemProperty -path "Registry::$Key" -Name "Persistence Checkpoint Depth Maximum" -Type "DWORD" -Value "104857600"
            Set-ItemProperty -path "Registry::$Key" -Name "State Queue Items" -Type "DWORD" -Value "20480"

            #PoolLeaseRequestPeriodSeconds 
            #PoolNetworkLatencySeconds
            #Both of these have been changed under the advisement of Microsoft
            #causing resource pools to lose quorum often
            #By increasing the length of the lease and the network timeout, we were able to overcome these issues
            $Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\PoolManager"
            If (-Not(Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey}
            Set-ItemProperty -path "Registry::$Key" -Name "PoolLeaseRequestPeriodSeconds" -Type "DWORD" -Value "600"
            Set-ItemProperty -path "Registry::$Key" -Name "PoolNetworkLatencySeconds" -Type "DWORD" -Value "120"

            #GroupCalcPollingIntervalMilliseconds
            #Description:  This setting will slow down how often group calculation runs to find changes in group memberships.  
            #Group calculation can be very expensive, especially with a large number of groups, large agent count, or complex group membership expressions.  
            #Slowing this down will help keep groupcalc from consuming all the healthservice and database I/O. 900000 is every 15 minutes.
            $Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0"
            If (-Not(Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey}
            Set-ItemProperty -path "Registry::$Key" -Name "GroupCalcPollingIntervalMilliseconds" -Type "DWORD" -Value "900000"

            #Bulk Insert Command Timeout Seconds 
            #SQL time-outs may occur for various reasons. In some cases, increasing the value of the time-out interval may be helpful in reducing or eliminating time-out events.

            #Command Timeout Seconds
            #Description:  This helps with dataset maintenance as the default timeout of 10 minutes is often too short.  
            #Setting this to a longer value helps reduce the 31552 events you might see with standard database maintenance.  
            #This is a very common issue.   http://blogs.technet.com/b/kevinholman/archive/2010/08/30/the-31552-event-or-why-is-my-data-warehouse-server-consuming-so-much-cpu.aspx  
            #This should be adjusted to however long it takes aggregations or other maintenance to run in your environment.  
            #We need this to complete in less than one hour, so if it takes more than 30 minutes to complete, you really need to investigate why it is so slow, 
            #either from too much data or SQL performance issues.
    
            #Deployment Command Timeout Seconds
            #Description:  This helps with deployment of heavy handed scripts that are applied during version upgrades and cumulative updates.  
            #Customers often see blocking on the DW database for creating indexes, and this causes the script not to be able to deployed in the default of 3 hours.  
            #Setting this value to allow for one full day to deploy the script resolves most customer issues.  
            #Setting this to a longer value helps reduce the 31552 events you might see with standard database maintenance after a version upgrade or UR deployment.  
            #This is a very common issue in large environments are very large warehouse databases.

            $Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Data Warehouse"
            If (-Not(Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey}
            Set-ItemProperty -path "Registry::$Key" -Name "Bulk Insert Command Timeout Seconds" -Type "DWORD" -Value "90"
            Set-ItemProperty -path "Registry::$Key" -Name "Command Timeout Seconds" -Type "DWORD" -Value "1200"
            Set-ItemProperty -path "Registry::$Key" -Name "Deployment Command Timeout Seconds" -Type "DWORD" -Value "86400"

            #DALInitiateClearPool DALInitiateClearPoolSeconds
            #This setting configures the SDK service to attempt a reconnection to SQL server upon disconnection, 
            #on a regular basis.  Without these settings, an extended SQL outage can cause a management server to 
            #never reconnect back to SQL when SQL comes back online after an outage.   
            #Per:  http://support.microsoft.com/kb/2913046/en-us  All management servers in a management group should get the registry change.
            $Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\DAL"
            If (-Not(Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey}
            Set-ItemProperty -path "Registry::$Key" -Name "DALInitiateClearPool" -Type "DWORD" -Value "1"
            Set-ItemProperty -path "Registry::$Key" -Name "DALInitiateClearPoolSeconds" -Type "DWORD" -Value "60"


            #AsyncProcessLimit
            #This key increases the number of asynchronous process that can be run as 5 is too low.
            #This impacts largely PowerShell sessions on Management Servers. The default limit is 5, but modern machines
            #can handle many more. 20 seems to be the "sweet spot".
            $Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Modules\Global\Command Executer"
            If (-Not(Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey}
            Set-ItemProperty -path "Registry::$Key" -Name "AsyncProcessLimit" -Type "DWORD" -Value "20"

            #Add the necessary registry ACL to ensure that access to the database key is audited
            $key = "HKLM:\SOFTWARE\Microsoft\System Center\2010\Common\MOMBins"
            $RegKey_ACL = Get-Acl $key
            $AccessRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone","SetValue,CreateSubKey,Delete,QueryValues","none","none","Success,Failure")
            $RegKey_ACL.AddAuditRule($AccessRule)
            $RegKey_ACL | Set-Acl $key

            Restart-Service OMSDK,HealthService,cshost
        }

        Start-Sleep 5
    }