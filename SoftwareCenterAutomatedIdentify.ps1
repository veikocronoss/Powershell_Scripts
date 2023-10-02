#region~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~OVERVIEW~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<#
-NAME
    SoftwareCenterPush
-DESCRIPTION
    This Script runs after 10 days of new Software Center updates. This forces the software if it has not been
        Installed. If it still fails, it "will" automate a ticket/email to Helpdesk for reports/Metrics.
-AUTHOR
    Daniel Gaudette
#>
#endregion
#region~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Add-type for Window Focus~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WinAp {
      [DllImport("user32.dll")]
      [return: MarshalAs(UnmanagedType.Bool)]
      public static extern bool SetForegroundWindow(IntPtr hWnd);

      [DllImport("user32.dll")]
      [return: MarshalAs(UnmanagedType.Bool)]
      public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }
"@
#endregion
#region~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~GLOBAL DECLARATIONS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#Pulls WMI Object of Software Center

#Loads the Baseline SDC to reference for install
$baseline = Import-Csv -Path "\\path\to\baseline\SDCBaseline.csv" -Delimiter ","

#Creates a table to be utilized later in the script.
$Errored = New-Object System.Data.DataTable "Errored"
$col = New-Object System.Data.DataColumn Software,([String])
$Errored.Columns.Add($col)

#Gathers critical data to be used for emails
#variables in this will vary based on your Active Directory configration
$IPAddress = [System.Net.DNS]::GetHostByName($env:COMPUTERNAME).addresslist.IPaddresstostring
$ou = [ADSI]"LDAP://OU=container2,OU=container1,DC=domain1,DC=domain2,DC=domain3,DC=domain4"
$ouSeach = New-Object System.DirectoryServices.DirectorySearcher($ou)
$ouSeach.Filter = "(&(objectclass=user)(samaccountname=$env:USERNAME))"
$ouSeach.FindAll() | %{ $user = $_.properties.displayname }

#Creates empty arrays to be used later in the script
$arrMem = @()

#endregion
#region~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~FUNCTIONS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#This function does the installation of the software identified in the WMI Software Center
function TriggerAppInstall(){
    
    #Identifies the parameters required to install the software.
    Param(
        [String][Parameter(Mandatory = $true, Position = 1)]$CompName,
        [String][Parameter(Mandatory = $true, Position = 2)]$appName,
        [ValidateSet("Install","Uninstall","Repair")]
        [String][Parameter(Mandatory = $true, Position = 3)]$method
    )

    #Identifies the specific application to be installed.
    $Application = (Get-CimInstance -ClassName CCM_Application -Namespace 'root/ccm/clientsdk' -ComputerName $CompName -ErrorAction Stop | Where-Object {$_.Name -like $appName})
        
    #Creates the arguements to be used to force the install.
    $args = @{
        EnforcePreference = [UInt32] 0
        Id = "$($Application.Id)"
        IsMachineTarget = $Application.IsMachineTarget
        IsRebootIfNeeded = $false
        Priority = 'High'
        Revision = "$($Application.Revision)"
    }

    #Starts the process to install the application identified earlier. The 'Out-Null' portion is to not require the powershell window to be open.
    Invoke-CimMethod -Namespace 'root/ccm/ClientSDK' -ClassName CCM_Application -ComputerName $CompName -MethodName $method -Arguments $args -ErrorAction Stop | Out-Null
}

#This function is to validate the buffer time needed from when the Software Center gets updated to when this script runs.
Function GetDate($Apptime){

    #Converts the date from WMI language to System language
    $date = [Management.ManagementDateTimeConverter]::ToDateTime($Apptime)
    
    #If the date is 10 days or more, the rest of the script will run. If not, it will not run.
    if($date.Date.AddDays(-10)){
        return $true
    }else{
        return $false
    }
}

#This function will check the date, then force the trigger to happen.
Function PushInstall($AppName, $AppStart, $appMethod){
    if(GetDate -Apptime $AppStart){ TriggerAppInstall -CompName $env:COMPUTERNAME -appName $AppName -method $appMethod }
}

#This function checks the error that was returned after install.
Function ErrorCheck($AppError){
    
    #If the error code returns "ERROR", it will load the table that was initialized. If not, it will continue on.
    if($AppError -like "3"){
        $nRow = $Errored.NewRow()
        $nRow.Software = $app.FullName
        $Errored.Rows.Add($nRow) 
    }
}

#This function re-attempts installs that may have failed.
Function RetryInstall(){
    
    #Creates an array to be loaded so the table can be cleared and re-used.
    $arrErr = @()

    #Loads the array, before clearing the table.
    ForEach($item in $Errored){ $arrErr += $item.Software }

    #Clears the table, and re-creates it to be used throughout the script. Attempting to use an Array in this manner will cause issues.
    $Errored = $null
    $Errored = New-Object System.Data.DataTable "Errored"
    $col = New-Object System.Data.DataColumn Software,([String])
    $Errored.Columns.Add($col)

    #Cycles through the WMI Software Center to capture the Start time, and the error code it receieved, even after re-attempts
    ForEach($obj in $AppWMI){
        
        #Cycles through the Array of software that has already failed.
        ForEach($App in $arrErr){
            
            #If the software in the array does not match, it will continue, otherwise, it will run the PushInstall function and retrieve the error code.
            if(!($app -eq $obj.FullName)){
                Continue
            }else{
                PushInstall -AppName $app -AppStart $obj.StartTime -appMethod "Install"
                ErrorCheck -AppError $obj.ErrorCode
            }
        }
    }
}

#This function is the initial runthrough of all the WMI software center to make the initial attempt to install what is provided.
Function CheckAllApps(){

    #Cycles through the WMI Software Center to capture the Start time, and the error code it receieved
    ForEach($app in $AppWMI){

        #Cycles through the Array of software to be referenced for the baseline.
        ForEach($item in $arrMem){

            #HBSS repair actions to aid  with Identifying Rogue Agents, or removing Rogue Agents
            #This section can be removed if your organization is not utilizing Trellix/McAfee
            if($app.FullName -match "HBSS"){
                PushInstall -AppName $app.FullName -AppStart $app.StartTime -appMethod "Repair"
                break
            
            #If the software doesn't match, it moves to the next item
            }elseif(!($app.FullName -match $item)){ 
                Continue 

            #NIPR Certs is in part of the WMI and Registry, but is not shown as "CrossCert". This part specifically targets the CrossCert installation
            #This section can be removed if your organization is not using "NIPR CERTS"
            }elseif(($item -like "NIPR Certs") -and ($app.InstallState -like "NotInstalled")){
                PushInstall -AppName $app.FullName -AppStart $app.StartTime -appMethod "Install"
                ErrorCheck -AppError $app.ErrorCode 

            #This will install the software that was referenced, as long as it has not been installed previously.
            }elseif($app.InstallState -like "NotInstalled"){ 
                PushInstall -AppName $app.FullName -AppStart $app.StartTime -appMethod "Install"
                ErrorCheck -AppError $app.ErrorCode
            }
        }
    }
}

Function SendErrorMail(){
    if($WMIErrored){
        $body = "Office,`r`n`r`n" + `
            "THIS IS A SYSTEM GENERATED EMAIL ON BEHALF OF "  + $user + ".`r`n`r`n"` + `
            "The computer having issues is "+ $env:COMPUTERNAME + " and they have the IP address of " + $IPAddress + " `r`n`r`n" + `
            "The issue with this machine is that the CCM agent is malfunctioning, as the WMI object could not be retrieved. `r`n`r`n" + `
            "Please make a ticket for this as the issue needs to be resolved.`r`n`r`n" + `
            "DO NOT RESPOND TO THIS EMAIL! Make a ticket so the issue can be tracked by the organization."
             
    }else{
        $body = "Office,`r`n`r`n" + `
            "THIS IS A SYSTEM GENERATED EMAIL ON BEHALF OF "  + $user + ".`r`n`r`n"` + `
            "The computer having issues is "+ $env:COMPUTERNAME + " and they have the IP address of " + $IPAddress + " `r`n`r`n" + `
            "The following issues were found with the system: `r`n`r`n" 
        ForEach($software in $Errored){
            $body += $software.Software + "`r`n"
        }    
        $body += "`r`nPlease make a ticket for this as the issue needs to be resolved.`r`n`r`n" + `
            "DO NOT RESPOND TO THIS EMAIL! Make a ticket so the issue can be tracked by the organization."

    }

    #This will open Microsoft Outlook, and create a Mail Item. This will also send on their behalf to the dedicated email indicated.
    #This can be good for pre-emptive maintenance, given that your organization is on top of their Vulnerability management.
    $outlook = New-Object -ComObject Outlook.Application
    $mail = $outlook.CreateItem(0)
    $mail.To = #Insert a dedicated email address you would like this sent to"
    $mail.Subject = "SYSTEM GENERATED - Errors on Login"
    $mail.Body = $body
    $mail.Display()
    $p = Get-Process -Name "OUTLOOK"
    if (($p -eq $null) -and ($adm -ne "")) {
        Start-Process "$proc" -Verb runAs
    } elseif (($p -eq $null) -and ($adm -eq "")) {
        Start-Process "$proc"
    } else {
        $h = $p.MainWindowHandle
        [void] [WinAp]::SetForegroundWindow($h)
    }
    [System.Windows.Forms.SendKeys]::SendWait("%S")
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) | Out-Null
}
#endregion
#region~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~INSTALLATION AND REPORTING~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#Loads the Memory Array for the SDC software to be referenced.
ForEach($SDC in $baseline){ $arrMem += $SDC.Software }
Try{
    $AppWMI = Get-WmiObject -Namespace "root/ccm/clientsdk" -Class CCM_Application
}Catch{
    $WMIErrored = $true
}
if($WMIErrored){
    SendErrorMail
}else{
    #This part calls the check, and installation functions earlier declared. It will run 3 times before stopping.
    for($i = 0; $i -lt 3; $i++){
    
        #This is the first runthrough, so after this runs, it will not need to go through the whole reference again.
        if($i -eq 0){ CheckAllApps }

        #This part forces a wait time to allow the installation to occur.
        Start-Sleep -Seconds 600

        #If the table is empty, it will force the loop to end. This is intended for full success of installations.
        if($Errored -eq $null){
            $i = 3
    
        #If the table is not empty, it will re-attempt to install what had specifically failed.
        }else{
            RetryInstall
        }
        if($i -eq 2){
            SendErrorMail
        }
    }
}

#endregion