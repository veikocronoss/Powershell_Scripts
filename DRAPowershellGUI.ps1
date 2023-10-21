<#
  NAME: 
  - NetIQ Domain Resource Administrator(DRA) PowerShell Graphical User Interface (GUI) Shared Drive Utility
  PURPOSE:
  - To Utilize the DRA Powershell Utilities provided by the NetIQ DRA Rest Product for ease of use on System Administrators.
  AUTHOR: 
  - Daniel Gaudette
#>

#region Required Assemblies
<#
    This section of code is the assemblies needed by this script in order to function properly.
    It also allows the PowerShell console window to be hidden.
#>
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'

[Console.Window]::ShowWindow([Console.Window]::GetConsoleWindow(), 0)
#endregion

#region Elevated Permissions Check
# This section checks to see if you are running in elevated permissions. If not, it will attempt to force you to elevated permissions to run.
Param([switch]$Elevated)
Function Check-Admin {
        $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
        $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}
        if ((Check-Admin) -eq $false){
            if ($elevated)
            {# could not elevate, quit
            }
        else {Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList ('-noprofile -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))}
        exit}
#endregion


#region Logic

# This function refreshes the ListView that was populated with the user's security groups.
# It does the refresh by doing a new LDAP query to pull the updated information.
Function Refresh(){

    # First Clears the ListView to make sure there are no remnant values
    $lvExSecGrp.Items.Clear()

    # Loads the $user variable with the $txtUser from the main form. This is the user the administrator would be working with at the time.
    $user = $txtUser.Text.ToString()

    # This LDAP Query has been modified due to the sensitive nature of the original network Enclave. Modify this to your own domain.
    # This LDAP query also allows for speedy checks versus using the actual Domain Resource Administrator.
    $ou              = [ADSI]"LDAP://OU=Container3,OU=Container2,OU=Container1,DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ouPerson        = New-Object System.DirectoryServices.DirectorySearcher($ou)
    $ouPerson.Filter = "(&(objectClass=person)(displayName=$user))"

    # This Cycles through each record found, and then loads the ListView
    $ouPerson.FindAll() | %{

        # This grabs the member_of property of Active Directory
        $usergroups = $_.properties.memberof

        # Cycles through each group
        ForEach($grp in $usergroups){

            # Removes the Common Name (CN) from the group name
            $grp = $grp.ToString().Replace("CN=","")

            # Removes everything after the group name, given there is no additional commas in the group name.
            $grp = $grp.ToString().Substring(0,$grp.IndexOfAny(","))

            # Creates a new ListView Item to load the groups into the ListView
            $lvItem = New-Object System.Windows.Forms.ListViewItem($grp,0)

            # Adds the ListView Item to the ListView
            $lvExSecGrp.Items.Add($lvItem)
        }
    }
}


# As the Function name Indicates, This is the Remove Group Function.
# $user and $group are the forced parameters.
Function RemoveGroup($user,$group){

    # These two lines change one of the text boxes on the main form as a way to update status during different functions.
    $txtStatus.Text = ""
    $txtStatus.Text = "Removing user from group. Please wait..."

    # Allows for the Textbox to show the update.
    Start-Sleep -Milliseconds 5

    # This LDAP Query has been modified due to the sensitive nature of the original network Enclave. Modify this to your own domain.
    # This LDAP query also allows for speedy checks versus using the actual Domain Resource Administrator.
    # The use of 2 LDAPs allow for different OU/DC values to occur.
    $ou              = [ADSI]"LDAP://OU=Container3,OU=Container2,OU=Container1,DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ou2             = [ADSI]"LDAP://DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ouPerson        = New-Object System.DirectoryServices.DirectorySearcher($ou)
    $ouPerson.Filter = "(&(objectClass=person)(displayName=$user))"
    $ouGroup         = New-Object System.DirectoryServices.DirectorySearcher($ou2)
    $ouGroup.Filter  = "(&(objectClass=group)(cn=$group))"

    # Cycle through the first filter, and grab the required field for the Remove function to occur.
    $ouPerson.FindAll() | %{ [String]$name = $_.properties.name  }

    # Cycle through the second filter and grab the required field for the Remove function to occur.
    $ouGroup.FindAll() | % { [String]$gName = $_.properties.name }

    # DRA Server values have been changed due to sensitive network enclave names
    # Test to see if the first DRA server is awake/online. If not, fail over to the next one.
    If(Test-Connection -ComputerName "DRA-SRV-1.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -ErrorAction SilentlyContinue -Count 1){

        # NetIQ's function to Remove Security Groups from Members.
        Remove-DRAGroupMembers -Users $name -Identifier $gName -DRAHostServer "DRA-SRV-1.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRAHostPort "(DRAHostPort)" -DRARestServer "DRA-SRV-1.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRARestPort "(DRARestPort)" -Domain "DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -Force

        # Small processing timne before notifying the administrator of success
        Start-sleep -Milliseconds 5

        # Notification to administrator of success
        [System.Windows.Forms.MessageBox]::Show("$user as been removed from $group at DRA-SRV-1","Group Removed","Ok","Information")

    }Else{
        # NetIQ's function to Remove Security Groups from Members.
        Remove-DRAGroupMembers -Users $name -Identifier $gName -DRAHostServer "DRA-SRV-2.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRAHostPort "(DRAHostPort)" -DRARestServer "DRA-SRV-2.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRARestPort "(DRARestPort)" -Domain "DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -Force

        # Small processing timne before notifying the administrator of success
        Start-sleep -Milliseconds 5

        # Notification to administrator of success
        [System.Windows.Forms.MessageBox]::Show("$user as been removed from $group at DRA-SRV-2","Group Removed","Ok","Information")
    }

    # Allows for processing time before updating Form
    Start-Sleep -Seconds 1

    # Clears old values in preparation to load the new ones.
    $lvExSecGrp.Items.Clear()

    $ouPerson.FindAll() | %{

        # This grabs the member_of property of Active Directory
        $usergroups = $_.properties.memberof

        # Cycles through each group
        ForEach($grp in $usergroups){

            # Removes the Common Name (CN) from the group name
            $grp = $grp.ToString().Replace("CN=","")

            # Removes everything after the group name, given there is no additional commas in the group name.
            $grp = $grp.ToString().Substring(0,$grp.IndexOfAny(","))

            # Creates a new ListView Item to load the groups into the ListView
            $lvItem = New-Object System.Windows.Forms.ListViewItem($grp,0)

            # Adds the ListView Item to the ListView
            $lvExSecGrp.Items.Add($lvItem)
        }
    }

    # Updates the status on the main form
    $txtStatus.Text = ""
    $txtStatus.Text = "Waiting for Administrator Input."

    #Refreshes the main form.
    $frmMain.Refresh()

} 

# As the Function name Indicates, This is the Add Group Function.
# $user and $group are the forced parameters.
Function AddGroup($user,$group){

    # These two lines change one of the text boxes on the main form as a way to update status during different functions.
    $txtStatus.Text = ""
    $txtStatus.Text = "Adding user to group. Please wait..."

    # Allows for the Textbox to show the update.
    Start-Sleep -Milliseconds 5
    
    # This LDAP Query has been modified due to the sensitive nature of the original network Enclave. Modify this to your own domain.
    # This LDAP query also allows for speedy checks versus using the actual Domain Resource Administrator.
    # The use of 2 LDAPs allow for different OU/DC values to occur.
    $ou              = [ADSI]"LDAP://OU=Container3,OU=Container2,OU=Container1,DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ou2             = [ADSI]"LDAP://DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ouPerson        = New-Object System.DirectoryServices.DirectorySearcher($ou)
    $ouPerson.Filter = "(&(objectClass=person)(displayName=$user))"
    $ouGroup         = New-Object System.DirectoryServices.DirectorySearcher($ou2)
    $ouGroup.Filter  = "(&(objectClass=group)(cn=$group))"

    # Cycle through the first filter, and grab the required field for the Remove function to occur.
    $ouPerson.FindAll() | %{ [String]$name = $_.properties.name  }

    # Cycle through the second filter and grab the required field for the Remove function to occur.
    $ouGroup.FindAll() | % { [String]$gName = $_.properties.name }

    # DRA Server values have been changed due to sensitive network enclave names
    # Test to see if the first DRA server is awake/online. If not, fail over to the next one.
    If(Test-Connection -ComputerName "DRA-SRV-1.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -ErrorAction SilentlyContinue -Count 1){

        # NetIQ's function to Add Security Groups to Members.
        Add-DRAGroupMembers -Users $name -Identifier $gName -DRAHostServer "DRA-SRV-1.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRAHostPort "(DRAHostPort)" -DRARestServer "DRA-SRV-1.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRARestPort "(DRARestPort)" -Domain "DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -Force

        # Small processing timne before notifying the administrator of success
        Start-sleep -Milliseconds 5

        # Notification to administrator of success
        [System.Windows.Forms.MessageBox]::Show("$user as been added to $group at DRA-SRV-1","Group Removed","Ok","Information")

    }Else{
        # NetIQ's function to Add Security Groups from Members.
        Add-DRAGroupMembers -Users $name -Identifier $gName -DRAHostServer "DRA-SRV-2.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRAHostPort "(DRAHostPort)" -DRARestServer "DRA-SRV-2.DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -DRARestPort "(DRARestPort)" -Domain "DOMAIN_IDENTITY.SUBDOMAIN.DOMAIN1.DOMAIN2" -Force

        # Small processing timne before notifying the administrator of success
        Start-sleep -Milliseconds 5

        # Notification to administrator of success
        [System.Windows.Forms.MessageBox]::Show("$user as been added to $group at DRA-SRV-2","Group Removed","Ok","Information")
    }

    # Allows for processing time.
    Start-Sleep -Seconds 1

    # Updates the status on the main form.
    $txtStatus.Text = ""
    $txtStatus.Text = "Waiting for Administrator Input."

    # Refreshes the main form.
    $frmMain.Refresh()
}

# This function takes Administrator input of groups, Searches for them, and then sends the request to add the user to the group.
Function SearchInputGroup(){

    # Updates the Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Checking for Group provided by Administrator"

    # Administrator input through Visual Basic Input Box
    $grpName = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the group you would like to add the user to", "Add User to Non-Selected Group")

    #LDAP Query, as indicated before.
    $ou              = [ADSI]"LDAP://DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ouGroup         = New-Object System.DirectoryServices.DirectorySearcher($ou)
    $ouGroup.Filter  = "(&(objectClass=group)(cn=$grpName))"

    # Cycle through the records for the appropriate group.
    $ouGroup.FindAll() | %{

        # Forces Property into a string
        $gName = $_.properties.name

        # If string comes back null, throw an error
        if($gname -like $null){

            # Update Status
            $txtStatus.Text = ""
            $txtStatus.Text = "Group invalid, Administrator needs to submit new group"

            # Prompt Administrator with Messagebox that group is not valid.
            [System.Windows.Forms.MessageBox]::Show("$grpName is not a valid group","Error","Ok","Error")
            
        }else{

            # Update Status
            $txtStatus.Text = ""
            $txtStatus.Text = "Group provided by Administrator has been validated"

            # Allow for Processing Time
            Start-Sleep -Milliseconds 10

            # Send request to have group added to user.
            AddGroup -user $txtUser.Text.ToString() -group $gName
        }
    }
}

# This function confirms the group that the administrator found through Shared Drive groups.
Function ConfirmGroup($group){

    # Update Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Confirming group with Administrator"

    # Confirm with Administrator that this is the group they want to add to.
    $msgconf = $group + "`r`n`r`n Is this the correct security group you are attempting to add to?"
    $msg = [System.Windows.Forms.MessageBox]::Show($msgconf,"Confirm Security Group","YesNo","Information")

    # Check Confirmation with message box. No "else" statement required.
    If($msg -eq "Yes"){

        # Since confirmed, update combo box with selected group.
        $cmbFPGroup.SelectedText = $group

        # Close file path search form.
        $frmFilepath.Close()

        # Update Status
        $txtStatus.Text = ""
        $txtStatus.Text = "Waiting for Administrator Input"
    }
}

# This function searches for the file path, grabs the groups associated with the file path, and finds them in Active Directory.
Function SearchFilePath($filepath){

    # Update Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Searching for filepath"

    # Fresh LDAP Query. Missing filter, as the filter will be loaded later.    
    $ou              = [ADSI]"LDAP://DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ouGroup         = New-Object System.DirectoryServices.DirectorySearcher($ou)

    # Confirm the file path exists.
    If(Test-Path -Path $filepath -ErrorAction SilentlyContinue){

        # Load the reference location with the file path searched.
        $txtFilepath.Text = $filepath

        # Update Status
        $txtStatus.Text = ""
        $txtStatus.Text = "Filepath input, validating path"

        # Confirm file path is a directory. Script intended to give access to Security groups for file paths, not specific files.
        if((Get-Item $filepath -ErrorAction SilentlyContinue) -is [System.IO.DirectoryInfo]){

            # Update Status
            $txtStatus.Text = ""
            $txtStatus.Text = "Path Validated, Getting groups from path"

            # Cycle through each group indicated in the Access list on the File path
            ForEach($item in (Get-ACL $filepath).Access){

                # Force Group name into String value
                [String]$grpName = $item.IdentityReference

                # Confirm the group is part of the domain, and not a local security group. If local, skip that group.
                If(!($grpName.ToUpper() -match "DOMAIN_IDENTITY")){Continue}

                # Remove domain identity for LDAP search
                $grpName = $grpName.ToString().Replace("DOMAIN_IDENTITY\","")

                # Load Group permissions on the file path
                [String]$grpRights = $item.FileSystemRights

                # Load LDAP filter
                $ouGroup.Filter = "(&(objectClass=group)(cn=$grpName))"

                # Cycle through LDAP Records
                $ouGroup.FindAll() | %{

                    # Create ListView item to load Listview for file path security group search
                    $lvFPItem = New-Object System.Windows.Forms.ListViewItem($grpName,0)

                    # While loading the Listview, load the reference combo box for later use if needed.
                    $cmbFPGroup.Items.Add($grpName)

                    # Add SubItem of permissions in folder to ListView item
                    $lvFPItem.SubItems.Add($grpRights)

                    # Add Listview Item to Listview
                    $lvFPInfoBox.Items.Add($lvFPItem)

                    # Resize to Group Name
                    $lvFPInfoBox.AutoResizeColumns("ColumnContent")
                }
            }     
        }

    # File Path was incorrect, or Administrator did not have enough permissions
    }Else{

        # Notification to administrator
        [System.Windows.Forms.MessageBox]::Show("Either you do not have permissions, or that is not a valid path. `r`n`r`n Please check that you are running this script as an administrator or check that the filepath exists.","Error accessing path","OK","Error")
        
        # Update Status
        $txtStatus.Text = ""
        $txtStatus.Text = "File path invalid"
    }
}

# This function confirms the user that will be selected for groups to be added to.
Function ConfirmChoice($user){

    # Update Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Confirming with Administrator for correct User"

    # Confirmation of selected user
    $message = $user + "`r`n Is this the correct user?"
    $confmsgbox = [System.Windows.Forms.MessageBox]::Show($message,'Confirm User','YesNo','Information')

    # Validate Confirmation
    If($confmsgbox -eq "Yes"){

        # Load LDAP with selected user information
        $ou              = [ADSI]"LDAP://OU=Container3,OU=Container2,OU=Container1,DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
        $ouPerson        = New-Object System.DirectoryServices.DirectorySearcher($ou)
        $ouPerson.Filter = "(&(objectClass=person)(displayName=$user))"

        # Cycle through records to grab User groups
        $ouPerson.FindAll() | %{
    
            # This grabs the member_of property of Active Directory
            $usergroups = $_.properties.memberof
    
            # Cycles through each group
            ForEach($grp in $usergroups){
    
                # Removes the Common Name (CN) from the group name
                $grp = $grp.ToString().Replace("CN=","")
    
                # Removes everything after the group name, given there is no additional commas in the group name.
                $grp = $grp.ToString().Substring(0,$grp.IndexOfAny(","))
    
                # Creates a new ListView Item to load the groups into the ListView
                $lvItem = New-Object System.Windows.Forms.ListViewItem($grp,0)
    
                # Adds the ListView Item to the ListView
                $lvExSecGrp.Items.Add($lvItem)
            }
        }

        # Load Reference field on Main form
        $txtUser.Text = $user

        # Update Status
        $txtStatus.Text = ""
        $txtStatus.Text = "Waiting for Administrator Input"

        # Close user Search Form
        [void]$frmUser.Close()
    }
}

# This function Searches LDAP by first and last name, and loads the User Search Form with the results.
Function SearchName($first,$last){

    # Clear old results out of the field.
    $lvInfoBox.Items.Clear()

    # Update Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Searching for User"

    # LDAP Search for user by First and Last name
    $ou              = [ADSI]"LDAP://OU=Container3,OU=Container2,OU=Container1,DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ouPerson        = New-Object System.DirectoryServices.DirectorySearcher($ou)
    $ouPerson.Filter = "(&(objectClass=person)(givenname=$first)(sn=$last))"
    
    # Cycles through records for all matches
    $ouPerson.FindAll() | %{

        # Forces values into a string
        [String]$name = $_.properties.displayname

        # Creates a ListView item per record
        $lvItem = New-Object System.Windows.Forms.ListViewItem($name,0)

        # Adds Listview Item to Listview
        $lvInfoBox.Items.Add($lvItem)
    }  
}

# This function searches LDAP for user by Employee ID number, and loads the results.
Function SearchEDI($user){

    # Clear out old values
    $lvInfoBox.Items.Clear()

    # Update Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Searching for User"

    # LDAP Search for user by Employee ID
    $ou              = [ADSI]"LDAP://OU=Container3,OU=Container2,OU=Container1,DC=Subdomain2,DC=Subdomain1,DC=Domain1,DC=Domain2"
    $ouPerson        = New-Object System.DirectoryServices.DirectorySearcher($ou)
    $ouPerson.Filter = "(&(objectClass=person)(employeeID=$user))"
    
    # Cycle through records and load the list view
    $ouPerson.FindAll() | %{

        # Force value into string
        [String]$name = $_.properties.displayname

        # Creates a Listview Item for each record found
        $lvItem = New-Object System.Windows.Forms.ListViewItem($name,0)

        #Loads Listview Item into Listview
        $lvInfoBox.Items.Add($lvItem)
    }   
}

#endregion

#region FilePath Search Form
# This form is used for searching for the file path, and the security groups associated with them. 

# File Path form Variable
$frmFilepath                = New-Object System.Windows.Forms.Form
$frmFilepath.ClientSize     = New-Object System.Drawing.Point(1020,650)
$frmFilepath.MinimumSize    = $frmFilepath.ClientSize
$frmFilepath.MaximumSize    = $frmFilepath.ClientSize
$frmFilepath.Text           = "DRAPowerShell v2 Utility Filepath Selection"
$frmFilepath.TopMost        = $false
$frmFilepath.AutoScale      = $false

# Label Variable associated with File Path Search
$lblFPtxt                   = New-Object System.Windows.Forms.Label
$lblFPtxt.Font              = New-Object System.Drawing.Font('Arial',16)
$lblFPtxt.Location          = New-Object System.Drawing.Point(10,10)
$lblFPtxt.Text              = "Enter Filepath:"
$lblFPtxt.AutoSize          = $true

# Textbox variable associated with File Path Search
$txtFPSearch                = New-Object System.Windows.Forms.TextBox
$txtFPSearch.Font           = New-Object System.Drawing.Font('Arial',13)
$txtFPSearch.Location       = New-Object System.Drawing.Point(10,40)
$txtFPSearch.Width          = 980
$txtFPSearch.Height         = 30
$txtFPSearch.AutoSize       = $false

# This adds an Enter button event
$txtFPSearch.Add_Keydown({

    # Will only accept "Enter". No other Key will force an event.
    if($_.KeyCode -eq 'Enter'){

        # If Search is null, Error out.
        if($txtFPSearch.Text.ToString() -like $null){

            # Error Notification
            [System.Windows.MessageBox]::Show("Please Enter the filepath you would like to search.", 'Error input', 'Ok','Error')   

        # Search Not Null
        }else{

            # Force Search Box text into value
            $FPsearch = $txtFPSearch.Text.ToString()

            # Call function which searches for the file path
            SearchFilePath -filepath $FPsearch             
        }
    }
})

#Button Variable associated with File Path Search
$btnSearchFP                = New-Object System.Windows.Forms.Button
$btnSearchFP.Font           = New-Object System.Drawing.Font('Arial',14)
$btnSearchFP.Location       = New-Object System.Drawing.Point(10,80)
$btnSearchFP.Text           = "Search for Filepath groups"
$btnSearchFP.AutoSize       = $true
$btnSearchFP.BackColor      = [System.Drawing.ColorTranslator]::FromHtml("#417505")

# Click event on Search Button
$btnSearchFP.Add_Click({

    # If Search is null, Error out.
    if($txtFPSearch.Text.ToString() -like $null){

        # Error Notification
        [System.Windows.MessageBox]::Show("Please Enter the filepath you would like to search.", 'Error input', 'Ok','Error')   

    # Search Not null
    }else{

        # Force Search box text into value
        $FPsearch = $txtFPSearch.Text.ToString()

        # Call function which searches for the file path
        SearchFilePath -filepath $FPsearch             
    }
})

#Label Variable associated with the Security Group List View
$lblSecGrpLv                = New-Object System.Windows.Forms.Label
$lblSecGrpLv.Font           = New-Object System.Drawing.Font('Arial',16)
$lblSecGrpLv.Location       = New-Object System.Drawing.Point(10,150)
$lblSecGrpLv.Text           = "File path Domain Security Groups"
$lblSecGrpLv.AutoSize       = $true

#Security Group List View Variable
$lvFPInfoBox                  = New-Object System.Windows.Forms.ListView
$lvFPInfoBox.Location         = New-Object System.Drawing.Point(10,190)
$lvFPInfoBox.Size             = New-Object System.Drawing.Size(980,400)
$lvFPInfoBox.Font             = New-Object System.Drawing.Font('Arial',16)
$lvFPInfoBox.View             = "Details"
$lvFPInfoBox.AutoSize         = $false
$lvFPInfoBox.FullRowSelect    = $true
$lvFPInfoBox.GridLines        = $true
$lvFPInfoBox.MultiSelect      = $false
$lvFPInfoBox.Scrollable       = $true

# Add Columns to the ListView
$lvFPInfoBox.Columns.Add("Security Groups",-2,"Left")
$lvFPInfoBox.Columns.Add("Rights",-2,"Left")

# Add Double Click to List view items
$lvFPInfoBox.Add_MouseDoubleClick({

    # Force Selected item into value
    $selected = $lvFPInfoBox.SelectedItems[0].Text

    # Call function which confirms selection
    ConfirmGroup -group $selected
})

# Load controls into the form for later use.
$frmFilepath.Controls.AddRange(@($lblFPtxt,$txtFPSearch,$btnSearchFP,$lblSecGrpLv, $lvFPInfoBox))

#endregion

#region User Search Form
# This form is used for searching the user needed.

# User Search Form Variable
$frmUser                    = New-Object system.Windows.Forms.Form
$frmUser.ClientSize         = New-Object System.Drawing.Point(1020,650)
$frmUser.MinimumSize        = $frmUser.ClientSize
$frmUser.MaximumSize        = $frmUser.ClientSize
$frmUser.text               = "DRAPowerShell v2 Utility User Selection"
$frmUser.TopMost            = $false
$frmUser.AutoScale          = $false

# Label Variable associated with EDI Number textbox
$lblEDI                     = New-Object System.Windows.Forms.Label
$lblEDI.Font                = New-Object System.Drawing.Font('Arial Bold',16)
$lblEDI.Location            = New-Object System.Drawing.Point(10,10)
$lblEDI.AutoSize            = $true
$lblEDI.Text                = "User EDI Number:"

# EDI Textbox variable
$txtEDI                     = New-Object System.Windows.Forms.TextBox
$txtEDI.Font                = New-Object System.Drawing.Font('Arial',14)
$txtEDI.Location            = New-Object System.Drawing.Point(10,40)
$txtEDI.AutoSize            = $false
$txtEDI.Width               = 300
$txtEDI.Height              = 35

# Adds an "Enter" event to the EDI Textbox
$txtEDI.Add_KeyDown({

    # Will only accept Enter to start the event
    if($_.KeyCode -eq 'Enter'){

        #Clears the values of Listview before checking for someone new
        $lvInfoBox.Items.Clear()

        # Checks to see if EDI is null by mistake
        if($txtEDI.Text.ToString() -like $null){

            # Error Notification
            [System.Windows.MessageBox]::Show("Please Enter the user's EDI before hitting enter.", 'Error input', 'Ok','Error')   

        # EDI Text box not null
        }else{

            # Forces EDI Text Box into Value
            $userEDI = $txtEDI.Text.ToString()

            # Calls EDI Search Function
            SearchEDI -user $userEDI             
        }
    }
})

# Label Variable associated with First Name Text Box
$lblFirstName               = New-Object System.Windows.Forms.Label
$lblFirstName.Font          = New-Object System.Drawing.Font('Arial Bold',16)
$lblFirstName.Location      = New-Object System.Drawing.Point(330,10)
$lblFirstName.Text          = "First Name:"
$lblFirstName.AutoSize      = $true

# First Name Textbox Variable
$txtFirstName               = New-Object System.Windows.Forms.TextBox
$txtFirstName.Font          = New-Object System.Drawing.Font('Arial',14)
$txtFirstName.Location      = New-Object System.Drawing.Point(330,40)
$txtFirstName.AutoSize      = $false
$txtFirstName.Width         = 300
$txtFirstName.Height        = 35

# Adds enter Event to First Name Textbox
$txtFirstName.Add_KeyDown({

    # Will only accept Enter for event
    if($_.KeyCode -eq 'Enter'){

        # Clears old results before searching for new ones
        $lvInfoBox.Items.Clear()

        # Errors if First or Last Name text boxes are null
        if(($txtFirstName.Text.ToString() -like $null) -or ($txtLastName.Text.ToString() -like $null)){

            # Error Notification
            [System.Windows.MessageBox]::Show("Please Enter the user's First and Last Name before hitting enter.", 'Error input', 'Ok','Error')

        # First and Last name not null
        }else{

            # Forces First and Last name into Values
            $userFirst = $txtFirstName.Text.ToString()
            $userLast = $txtLastName.Text.ToString()

            # Calls Name search function
            SearchName -first $userFirst -last $userLast          
        }
    }
})

# Label Variable associated with Last name Text box
$lblLastName                = New-Object System.Windows.Forms.Label
$lblLastName.Font           = New-Object System.Drawing.Font('Arial Bold',16)
$lblLastName.Location       = New-Object System.Drawing.Point(655,10)
$lblLastName.Text           = "Last Name:"
$lblLastName.AutoSize       = $true

# Last Name Text Box Variable
$txtLastName                = New-Object System.Windows.Forms.TextBox
$txtLastName.Font           = New-Object System.Drawing.Font('Arial',14)
$txtLastName.Location       = New-Object System.Drawing.Point(655,40)
$txtLastName.AutoSize       = $false
$txtLastName.Width          = 300
$txtLastName.Height         = 35

# Adds Enter Event to Last Name Textbox
$txtLastName.Add_KeyDown({

    # Will only accept Enter for event
    if($_.KeyCode -eq 'Enter'){

        # Clears old results before searching for new ones
        $lvInfoBox.Items.Clear()

        # Errors if First or Last Name text boxes are null
        if(($txtFirstName.Text.ToString() -like $null) -or ($txtLastName.Text.ToString() -like $null)){

            # Error Notification
            [System.Windows.MessageBox]::Show("Please Enter the user's First and Last Name before hitting enter.", 'Error input', 'Ok','Error')

        # First and Last name not null
        }else{

            # Forces First and Last name into Values
            $userFirst = $txtFirstName.Text.ToString()
            $userLast = $txtLastName.Text.ToString()

            # Calls Name search function
            SearchName -first $userFirst -last $userLast          
        }
    }
})

# Button for Searching for User
$btnOUSearch                = New-Object System.Windows.Forms.Button
$btnOUSearch.Font           = New-Object System.Drawing.Font('Arial',14)
$btnOUSearch.Location       = New-Object System.Drawing.Point(655,90)
$btnOUSearch.Text           = "Search"
$btnOUSearch.Width          = 150
$btnOUSearch.Height         = 35
$btnOUSearch.BackColor      = [System.Drawing.ColorTranslator]::FromHtml("#417505")

# Adds Click Event
$btnOUSearch.Add_Click({

    # Clears old results
    $lvInfoBox.Items.Clear()

    # Checks for all Null values
    if(($txtFirstName.Text.ToString() -like $null) -and ($txtLastName.Text.ToString() -like $null) -and ($txtEDI.Text.ToString() -like $null)){

        # Error Notification
        [System.Windows.MessageBox]::Show("Please a value before hitting Search.", 'Error input', 'Ok','Error')

    # If EDI Not Null    
    }elseif(!($txtEDI.Text.ToString() -like $null)){

        # Force EDI to value
        $userEDI = $txtEDI.Text.ToString()

        # Call EDI search function
        SearchEDI -user $userEDI 

    # If EDI and Either first or last name null
    }elseif(($txtFirstName.Text.ToString() -like $null) -or ($txtLastName.Text.ToString() -like $null)){

        # Error Notification
        [System.Windows.MessageBox]::Show("Please Enter the user's First and Last Name before hitting Search.", 'Error input', 'Ok','Error') 

    # First and Last name not null, EDI Null
    }else{

        #Force First and Last name text boxes to values
        $userFirst = $txtFirstName.Text.ToString()
        $userLast = $txtLastName.Text.ToString()

        # Call Search Name function
        SearchName -first $userFirst -last $userLast
    }
})

# Label variable associated with Results ListView
$lblInfo                    = New-Object System.Windows.Forms.Label
$lblInfo.Font               = New-Object System.Drawing.Font('Arial Bold',16)
$lblInfo.Location           = New-Object System.Drawing.Point(10,140)
$lblInfo.Text               = "Matching Users"
$lblInfo.AutoSize           = $true

# Results ListView
$lvInfoBox                  = New-Object System.Windows.Forms.ListView
$lvInfoBox.Location         = New-Object System.Drawing.Point(10,170)
$lvInfoBox.Size             = New-Object System.Drawing.Size(980,400)
$lvInfoBox.Font             = New-Object System.Drawing.Font('Arial',16)
$lvInfoBox.View             = "Details"
$lvInfoBox.AutoSize         = $false
$lvInfoBox.FullRowSelect    = $true
$lvInfoBox.GridLines        = $true
$lvInfoBox.MultiSelect      = $false
$lvInfoBox.Scrollable       = $true

# Add Column to Results ListView
$lvInfoBox.Columns.Add("User Name",-2,"Left")

# Add Double Click event for Confirmation
$lvInfoBox.Add_MouseDoubleClick({

    # Force Selection to value
    $selected = $lvInfoBox.SelectedItems[0].Text

    # Call Confirmation function for user
    ConfirmChoice -user $selected
})


# Load controls for User Search Form
$frmUser.controls.AddRange(@($lblEDI,$txtEDI,$lblFirstName,$txtFirstName,$lblLastName,$txtLastName,$btnOUSearch,$lblInfo,$lvInfoBox))

#endregion

#region Main Form
# This is the Main operating Form. This form allows you to call the other Search Forms, as well as the Addition and removal of security groups.

# Main Form Variable
$frmMain                    = New-Object System.Windows.Forms.Form
$frmMain.ClientSize         = New-Object System.Drawing.Point(1200,600)
$frmMain.MinimumSize        = $frmMain.ClientSize
$frmMain.MaximumSize        = $frmMain.ClientSize
$frmMain.text               = "DRAPowerShell v2 Utility"
$frmMain.TopMost            = $false
$frmMain.AutoScale          = $false

# Label Variable associated with UserName Textbox
$lblUser                    = New-Object System.Windows.Forms.Label
$lblUser.Font               = New-Object System.Drawing.Font('Arial',16)
$lblUser.Location           = New-Object System.Drawing.Point(10,10)
$lblUser.Text               = "User Name"
$lblUser.AutoSize           = $true

# Username Textbox Variable
$txtUser                    = New-Object System.Windows.Forms.TextBox
$txtUser.Font               = New-Object System.Drawing.Font('Arial',13)
$txtUser.Location           = New-Object System.Drawing.Point(10,40)
$txtUser.Text               = "Click Search For User to fill this field"
$txtUser.AutoSize           = $True
$txtUser.Width              = 700
$txtUser.Height             = 30
$txtUser.ReadOnly           = $true

# Button for user search
$btnSearchUser              = New-Object System.Windows.Forms.Button
$btnSearchUser.Font         = New-Object System.Drawing.Font('Arial',14)
$btnSearchUser.Location     = New-Object System.Drawing.Point(10,75)
$btnSearchUser.Text         = "Search for User"
$btnSearchUser.AutoSize     = $true
$btnSearchUser.BackColor    = [System.Drawing.ColorTranslator]::FromHtml("#417505")

# Click Event added
$btnSearchUser.Add_Click({

    # Clear User Search form before Loading
    $txtUser.Text = ""
    $lvInfoBox.Items.Clear()
    $lvExSecGrp.Items.Clear()
    $txtUser.Text = ""
    $txtEDI.Text = ""
    $txtFirstName.Text = ""
    $txtLastName.Text = ""

    # Update Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Searching for User"

    # Open User Search Form
    [void]$frmUser.ShowDialog()
})

# ListView of User Security groups
$lvExSecGrp                 = New-Object System.Windows.Forms.ListView
$lvExSecGrp.Font            = New-Object System.Drawing.Font('Arial',14)
$lvExSecGrp.Location        = New-Object System.Drawing.Point(750,10)
$lvExSecGrp.Size            = New-Object System.Drawing.Size(420,530)
$lvExSecGrp.View            = "Details"
$lvExSecGrp.AutoSize        = $false
$lvExSecGrp.GridLines       = $true
$lvExSecGrp.Scrollable      = $true
$lvExSecGrp.FullRowSelect   = $true
$lvExSecGrp.MultiSelect     = $false

# Add Column to Listview
$lvExSecGrp.Columns.Add("Existing User Security Groups",-2,"Left")

# Button for Refreshing User Security Group Data
$btnRefresh                 = New-Object System.Windows.Forms.Button
$btnRefresh.Font            = New-Object System.Drawing.Font('Arial',14)
$btnRefresh.Location        = New-Object System.Drawing.Point(300,75)
$btnRefresh.Text            = "Refresh User"
$btnRefresh.AutoSize        = $true

# Click Event added
$btnRefresh.Add_Click({

    # Check for Null Value
    If($txtUser.Text.ToString() -like $null){

        #Error Notification
        [System.Windows.Forms.MessageBox]::Show("The required fields are empty for this button use","Error","Ok","Error")

    # Check for Default data values
    }ElseIf($txtUser.Text.ToString() -match "Click Search For User to fill this field"){

        # Error Notification
        [System.Windows.Forms.MessageBox]::Show("The required fields are incorrect for this button use","Error","Ok","Error")

    #Not Null or Default
    }Else{

        #Call Refresh Function
        Refresh
    }
})

# User Clear Button
$btnUserClear               = New-Object System.Windows.Forms.Button
$btnUserClear.Font          = New-Object System.Drawing.Font('Arial',14)
$btnUserClear.Location      = New-Object System.Drawing.Point(603,75)
$btnUserClear.Text          = "Clear User"
$btnUserClear.AutoSize      = $true
$btnUserClear.BackColor     = [System.Drawing.ColorTranslator]::FromHtml("#FF0000")

# Adds Click event
$btnUserClear.Add_Click({

    # Sets UserName TextBox back to default
    $txtUser.Text = "Click Search For User to fill this field"

    # Clears Security Group ListView
    $lvExSecGrp.Items.Clear()  
})

# Label Variable associated with FilePath Textbox
$lblFilePath                = New-Object System.Windows.Forms.Label
$lblFilePath.Font           = New-Object System.Drawing.Font('Arial',16)
$lblFilePath.Location       = New-Object System.Drawing.Point(10,150)
$lblFilePath.Text           = "File Path"
$lblFilePath.AutoSize       = $true

# File path Textbox variable
$txtFilepath                = New-Object System.Windows.Forms.TextBox
$txtFilepath.Font           = New-Object System.Drawing.Font('Arial',13)
$txtFilepath.Location       = New-Object System.Drawing.Point(10,180)
$txtFilepath.Width          = 700
$txtFilepath.Height         = 30
$txtFilepath.ReadOnly       = $true
$txtFilepath.ScrollBars     = "Horizontal"
$txtFilepath.Text           = "Click Search for Filepath Group to fill this field"

# File Path search button
$btnFPSearch                = New-Object System.Windows.Forms.Button
$btnFPSearch.Font           = New-Object System.Drawing.Font('Arial',14)
$btnFPSearch.Location       = New-Object System.Drawing.Point(10,215)
$btnFPSearch.Text           = "Search for Filepath Group"
$btnFPSearch.AutoSize       = $true
$btnFPSearch.BackColor      = [System.Drawing.ColorTranslator]::FromHtml("#417505")

# Click Event added
$btnFPSearch.Add_Click({

    #Clears Values from File Path Search Form
    $txtFPSearch.Text = ""
    $txtFilepath.Text = ""
    $lvFPInfoBox.Items.Clear()
    $cmbFPGroup.Text = ""
    $cmbFPGroup.Items.Clear()

    # Update Status
    $txtStatus.Text = ""
    $txtStatus.Text = "Searching for Filepath"

    # Show File path Search Form
    [void]$frmFilepath.ShowDialog()
})

# Clear File path values button
$btnFPClear                 = New-Object System.Windows.Forms.Button
$btnFPClear.Font            = New-Object System.Drawing.Font('Arial',14)
$btnFPClear.Location        = New-Object System.Drawing.Point(567,215)
$btnFPClear.Text            = "Clear File Path"
$btnFPClear.AutoSize        = $true
$btnFPClear.BackColor       = [System.Drawing.ColorTranslator]::FromHtml("#FF0000")

# Click Event added
$btnFPClear.Add_Click({

    # Set File path text box to default value
    $txtFilepath.Text = "Click Search for Filepath Group to fill this field"

    # Clear combo box, and set back to default value
    $cmbFPGroup.Items.Clear()
    $cmbFPGroup.Text = "Select the Security group from the File Path"
})

# Label variable associated with File path security group combo box
$lblFPcmb                   = New-Object System.Windows.Forms.Label
$lblFPcmb.Font              = New-Object System.Drawing.Font('Arial',16)
$lblFPcmb.Location          = New-Object System.Drawing.Point(10,260)
$lblFPcmb.Text              = "File Path Groups"
$lblFPcmb.AutoSize          = $true

# File path security group combo box
$cmbFPGroup                 = New-Object System.Windows.Forms.ComboBox
$cmbFPGroup.Font            = New-Object System.Drawing.Font('Arial',13)
$cmbFPGroup.Location        = New-Object System.Drawing.Point(10,290)
$cmbFPGroup.Width           = 700
$cmbFPGroup.Height          = 30
$cmbFPGroup.DropDownHeight  = 300
$cmbFPGroup.DropDownWidth   = 680
$cmbFPGroup.Text            = "Select the Security group from the File Path"

# Button to add users to groups indicated in File Path Security group combo box
$btnAddSUGrp                = New-Object System.Windows.Forms.Button
$btnAddSUGrp.Font           = New-Object System.Drawing.Font('Arial',14)
$btnAddSUGrp.Location       = New-Object System.Drawing.Point(10,350)
$btnAddSUGrp.Text           = "Add User to Selected Group"
$btnAddSUGrp.AutoSize       = $true
$btnAddSUGrp.BackColor      = [System.Drawing.ColorTranslator]::FromHtml("#417505")

# Click Event Added
$btnAddSUGrp.Add_Click({

    # Checks for Null Values
    If(($txtUser.Text.ToString() -like $null) -or ($txtFilepath.Text.ToString() -like $null) -or ($cmbFPGroup.Text.ToString() -like $null)){

        # Error Notification
        [System.Windows.Forms.MessageBox]::Show("The required fields are empty for this button use","Error","Ok","Error")

    # Checks for Default Values
    }ElseIf(($txtUser.Text.ToString() -match "Click Search For User to fill this field") -or ($txtFilePath.Text.ToString() -match "Click Search for Filepath Group to fill this field") -or ($cmbFPGroup.Text.ToString() -match "Select the Security group from the File Path")){
        
        # Error Notification
        [System.Windows.Forms.MessageBox]::Show("The required fields are incorrect for this button use","Error","Ok","Error")

    # Not Null, Not Default
    }Else{

        # Calls the add group function
        AddGroup -user $txtUser.Text.ToString() -group $cmbFPGroup.Text.ToString()
    }
})

# Button to add administrator defined group to user
$btnAddIUGrp                = New-Object System.Windows.Forms.Button
$btnAddIUGrp.Font           = New-Object System.Drawing.Font('Arial',14)
$btnAddIUGrp.Location       = New-Object System.Drawing.Point(10,390)
$btnAddIUGrp.Text           = "Add User to a Non-selected Group"
$btnAddIUGrp.AutoSize       = $true
$btnAddIUGrp.BackColor      = [System.Drawing.ColorTranslator]::FromHtml("#417505")

# Click event added
$btnAddIUGrp.Add_Click({

    # Check for null value
    If($txtUser.Text.ToString() -like $null){

        # Error Notification
        [System.Windows.Forms.MessageBox]::Show("Either the user is missing, or a group has not been selected","Error","Ok","Error")

    # Check for Default Value
    }ElseIf($txtUser.Text.ToString() -like "Click Search For User to fill this field"){

        # Error Notification
        [System.Windows.Forms.MessageBox]::Show("Either the user is incorrect, or a group has not been selected","Error","Ok","Error")

    # Not Null, Not Default
    }Else{

        # Call Search Input Function
        SearchInputGroup
    }
})

# Button for removing users from group
$btnRmUGrp                  = New-Object System.Windows.Forms.Button
$btnRmUGrp.Font             = New-Object System.Drawing.Font('Arial',14)
$btnRmUGrp.Location         = New-Object System.Drawing.Point(400,350)
$btnRmUGrp.Text             = "Remove User from Selected Group"
$btnRmUGrp.AutoSize         = $true
$btnRmUGrp.BackColor        = [System.Drawing.ColorTranslator]::FromHtml("#FF0000")

# Click event added
$btnRmUGrp.Add_Click({

    # Check for Null Values
    If(($txtUser.Text.ToString() -like $null) -or ($lvExSecGrp.SelectedItems[0].Text -like $null)){

        # Error Notification
        [System.Windows.Forms.MessageBox]::Show("Either the user is missing, or a group has not been selected","Error","Ok","Error")

    # Check for Default Values
    }ElseIf(($txtUser.Text.ToString() -like "Click Search For User to fill this field") -or ($lvExSecGrp.SelectedItems[0].Text -like $null)){

        # Error Notification
        [System.Windows.Forms.MessageBox]::Show("Either the user is incorrect, or a group has not been selected","Error","Ok","Error")

    # Not Null, Not Default
    }Else{

        #Calls Remove Group Function
        RemoveGroup -user $txtUser.Text.ToString() -group $lvExSecGrp.SelectedItems[0].Text.ToString()
    }
})

# Label Variable associated with Status Update Textbox
$lblStatus                  = New-Object System.Windows.Forms.Label
$lblStatus.Font             = New-Object System.Drawing.Font('Arial',16)
$lblStatus.Location         = New-Object System.Drawing.Point(10, 440)
$lblStatus.Text             = "Status Update"
$lblStatus.AutoSize         = $true

# Status Update Textbox variable
$txtStatus                  = New-Object System.Windows.Forms.TextBox
$txtStatus.Font             = New-Object System.Drawing.Font('Arial',14)
$txtStatus.Location         = New-Object System.Drawing.Point(10,470)
$txtStatus.Width            = 700
$txtStatus.Height           = 80
$txtStatus.ReadOnly         = $true
$txtStatus.Text             = "Waiting for Admin Input"

# Load controls into the form for later use.
$frmMain.controls.AddRange(@($lblUser,$txtUser,$btnSearchUser,$lvExSecGrp,$btnUserClear,$lblFilePath,$txtFilepath,$btnFPSearch,$btnFPClear,$lblFPcmb,$cmbFPGroup,$btnAddSUGrp,$btnAddIUGrp,$btnRmUGrp,$lblStatus,$txtStatus, $btnRefresh))

#endregion

# Show main form
[void]$frmMain.ShowDialog()

