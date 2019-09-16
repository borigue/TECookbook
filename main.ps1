<#
  .SYNOPSIS
    A set of commandlets that allows for easy management of objects in Tripwire Enterprise
  .DESCRIPTION
    A set of commandlets that allows for easy management of objects in Tripwire Enterprise
  .EXAMPLE
    N/A
  .NOTES
    Initial release version
#>
#Requires -Version 3.0
<#
=========================================
CHANGELOG:
=========================================
2019-FEB-19 - Boris Guiffot - Initial release version
#>
# ---------------------------------------------------------------------------------------------
# Title:     TE Object Management
# Author:    Boris Guiffot
# Version:   0.1
# ---------------------------------------------------------------------------------------------
#
# THIS SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED  
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR  
# FITNESS FOR A PARTICULAR PURPOSE, AND/OR NONINFRINGEMENT. 
#   
# The script is provided AS IS without warranty of any kind.
# ---------------------------------------------------------------------------------------------
# TE server hostname 
#$teserver = "tripwireServer.server01.net"
param([string] $inputfile = "-inputfile")
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::tls12
# General Setup
[CmdletBinding()]

$DebugPreference = "Continue"
#$VerbosePreference = "Continue"
$ErrorActionPreference = "Continue"
################ ********************* ####################
# Credentials
################ ********************* ####################

$teserver=""
$twPass=""
$twUser=""

. .\Constants-Oracle.ps1


################ ********************* ####################
# Turn off SSL validation.  (NOT RECOMMENDED!):
################ ********************* ####################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
Write-host "SSL validation disabled!!" -ForegroundColor Yellow
################ ********************* ####################
# Prompt for credentials if not passed
################ ********************* ####################
If (!$twPass)
    {
    # Prompt for credentials:
    $Creds = Get-Credential
    }
else
    {
    # Encode credentials
    $securePasssword = ConvertTo-SecureString $twPass -AsPlainText -Force 
    $Creds = New-Object System.Management.Automation.PSCredential($twUser,$securePasssword)
    }
 
Write-host "Using https://$teserver/api/v1/"
$Uri = "https://$teserver/api/v1/"

################ ********************* ####################
# Connect to the Tripwire Enterprise server
################ ********************* ####################
# Connect to the server and pull down the CSRF token for future POST/PUT/DELETE operations:
$CSRF = Invoke-RestMethod -Uri ($Uri+'csrf-token') -Method Get -Credential $Creds -ContentType 'application/json' -Headers $headers -SessionVariable ActiveSessionVariable
# Build the header for later use
$headers = @{};
$headers.Add($CSRF.tokenName, $CSRF.tokenValue)
# X-Requested-With is required
$headers.Add("X-Requested-With", "XMLHttpRequest")
# $headers.Add("User-Agent", "PowerShell Script")
$headers | Out-String -stream | Write-Debug
If (!$headers.CSRFToken) {
Write-host "Error contacting API - please check the URL and credentials provided" 
exit}

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Get-TimeStamp {return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)}
function Get-TE-AVAPI-Login{
    param($sslIgnore,$teserver,$tepass,$teuser)
    Write-host "Setting values for asset view logins"
    $securePasssword = ConvertTo-SecureString $tepass -AsPlainText -Force 
    $TECreds = New-Object System.Management.Automation.PSCredential($teuser,$securePasssword)
    $TEAVURI = "https://$teserver/assetview/api/"
    Set-Variable -Name "TECreds" -Value $TECreds -Scope Global
    Set-Variable -Name "TEAVURI" -Value $TEAVUri -Scope Global
    Write-host "Get-TE-AVAPI-Login completed"
}
################# ********************* ###################
# Get a list of tagset
################ ********************* ####################
function Get-TE-AVAPI-Tagset-ID{
    param($tagsetname)
    $tagsets = Get-TE-AVAPI-Tagsets -aslist $true
    $tagset = $tagsets | Where-Object {$_.name -eq $tagsetname}
    return $tagset.id
}
# Get-TE-AVAPI-Tagset-iD -tagsetname "Test"
################ ********************* ####################
# Get a list of tags
################ ********************* ####################
function Get-TE-AVAPI-Tags{
    param($asxml,$aslist)
    $tags= Invoke-RestMethod -uri ($TEAVURI+'tags') -Credential $TECreds
    if($aslist -eq $true){$tags.tags.tag}else{return $tags}
}
# Get-TE-AVAPI-Tags -aslist $true
################ ********************* ####################
# Get id of a single of tag
################ ********************* ####################
function Get-TE-AVAPI-Tag-ID{
    param($tagname)
    $tags = Get-TE-AVAPI-Tags -aslist $true
    $tag = $tags | Where-Object {$_.name -eq $tagname}
    return $tag.id
}
# Get-TE-AVAPI-Tag-ID -tagname "Windows"
################ ********************* ####################
# Get an asset's ID
################ ********************* ####################
function Get-TE-AVAPI-Node-ID{
    param($nodename)
    Write-Debug "Connecting to $TEAVURI"
    $assets = Invoke-RestMethod -uri ($TEAVURI+'assets') -Credential $TECreds
    $id = $assets.assets.'computing-device' | Where-Object {$_.hostname -eq $nodename} | Select-Object synthetic-id
    $id = $id.'synthetic-id'[0].id
    Write-debug "Asset view asset id = $id"
    return $id
}
# Get-TE-AVAPI-Node-ID -nodename "mynodename"
################ ********************* ####################
# Get an asset's tags
################ ********************* ####################
function Get-TE-AVAPI-Node-Tags{
    param($nodename,$asxml,$aslist)
    Write-Debug "Connecting to $TEAVURI"
    $assets = Invoke-RestMethod -uri ($TEAVURI+'assets') -Credential $TECreds
    $id = $assets.assets.'computing-device' | Where-Object {$_.hostname -eq $nodename} | Select-Object synthetic-id
    $id = $id.'synthetic-id'[0].id
    Write-debug "Asset view asset id = $id"
    $tags = Invoke-RestMethod -uri ($TEAVURI+"assets/$id/tags") -Credential $creds
    if($aslist -eq $true){$tags.tags.tag}else{return $tags}
}
# Get-TE-AVAPI-Node-Tags -nodename "NODENAME" -aslist $true
################ ********************* ####################
# Apply a tag
################ ********************* ####################
function Update-TE-AVAPI-Node-Tag{
    param($nodename,$tagname)
    $uri = "https://localhost/assetview/api/tags"
    $assetid =  Get-TE-AVAPI-Node-ID -nodename $nodename
    $tagid = Get-TE-AVAPI-Tag-ID -tagname $tagname
    # Write the tag
    $assets = Invoke-RestMethod -uri ($TEAVURI+"assets/$assetid/tags/$tagid") -Credential $creds -Method post -body $body -ContentType "application/xml" 
}
################ ********************* ####################
# Get Node Data
################ ********************* ####################
function Get-AllNodes{
    $Nodes = Invoke-RestMethod -Uri ($Uri+"nodes") -Method Get -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
    # Iterate through all nodes found, and output real-time setting:
    return $Nodes
}
# Get-AllNodes
################ ********************* ####################
# Get Alls Data
################ ********************* ####################
function Get-AllNodesWithOldVersion{
    Param($version)
    $Nodes = Invoke-RestMethod -Uri ($Uri+"nodes") -Method Get -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
    # Filter to node version
    $nodes = $nodes | Where-Object {$_.agentVersion -like $version}
    return $Nodes
}
# Get-AllNodesWithOldVersion -versions '8.1*'
################ ********************* ####################
# Get Node (Filtered) Data
################ ********************* ####################
function Get-Node{
    param($FilteredNodeName)
    $Nodes = Invoke-RestMethod -Uri ($Uri+"nodes?name=$FilteredNodeName") -Method Get -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
	return $nodes
}
# Get-Node -FilteredNodeName "192.168.15.129"


################ ********************* ####################
# Get Node Group Data
################ ********************* ####################
function Get-AllNodeGroups{
    $NodeGroups = Invoke-RestMethod -Uri ($Uri+"nodegroups") -Method Get -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
    return $NodeGroups
}
# Get-AllNodeGroups


################ ********************* ####################
# Get Node Group (filtered) Data
################ ********************* ####################
function Get-NodeGroups{
    param($FilteredGroupName)
    $NodeGroups = Invoke-RestMethod -Uri ($Uri+"nodegroups?name=$FilteredGroupName") -Method Get -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
    return $NodeGroups
}
# Get-NodeGroups -FilteredGroupName "Windows"


################ ********************* ####################
# Get Parent node groups for a node
################ ********************* ####################
function Get-ParentGroupsForNode{
    param($FilteredNodeName)
    $node = Get-Node -FilteredNodeName $FilteredNodeName
    $id = $node.id
    Write-host "Getting data for "$id "," $FilteredNodeName
    $parents = Invoke-RestMethod -Uri ($Uri+"nodes/$id/parentGroups") -Method Get -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
    $parents | ForEach-Object{
    # Get bottom object to find the "closest" tag
    $count = $_.path.name.Count - 1
    $parentgroupnames += $_.path.name[$count] + ","}
    return $parentgroupnames
}
# Get-ParentGroupsForNode  -FilteredNodeName 'uk2upvapmur005.mfil.local'


################ ********************* ####################
# Get Node Group Child Nodes 
################ ********************* ####################
function Get-NodeGroupChildren{
   param ($NodeGroupID)
    $NodeGroupMembers = Invoke-RestMethod -Uri ($Uri+"nodegroups/$NodeGroupID/descendantNodes") -Method Get -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
    return $NodeGroupMembers
}


################ ********************* ####################
# Create New-OracleDBNode 
################ ********************* ####################

function New-OracleDBNode{
    param ($oracleLoginAs, 
            $oracleSecurity, 
            $auditenabled, 
            $node,  
            $delegateagent,
            $dbuser,
            $dbpass,
            $port
    )
    
    if($oracleLoginAs -notin "DEFAULT","SYSDBA"){Write-debug "Oracle login must be DEFAULT or SYSDBA" -ForegroundColor Red}
    if($oracleSecurity -notin "NONE","SSL","ANONYMOUS_ENCRYPT"){Write-debug "Oracle security must be NONE, SSL or ANONYMOUS_ENCRYPT" -ForegroundColor Red}

     $delegate = Get-Node -FilteredNodeName $delegateagent
     $delegatenode = $delegate.id
	Write-host "delegatenode: " $delegatenode

	if ($delegatenode.count -eq 0)  {
     $count = $delegatenode.length
     $message = "Could not find delegate agent in Line $linecount,$delegateagent ($count node(s) found)"
	 Add-Content "$logFile"  "$(Get-TimeStamp) $message"
	 write-host  "$(Get-TimeStamp)  $message" -ForegroundColor Red
     Write-Error  "$message"
	}

    if ($delegatenode.count -gt 1)  {
     $count = $delegatenode.length
     $message = "There are more than one nodes associated with the node. That could need to some issues $delegateagent ($count node(s) found)"
	 Add-Content "$logFile"  "$(Get-TimeStamp) $message"
	 write-host  "$(Get-TimeStamp) $message" -ForegroundColor Red
     write-Error  "$message"
	}

    if ($delegate.commonAgentUuid -ne $null)  {
     $message = "There is a Axon UID "+ $delegate.commonAgentUuid +" associated with your delegate node, please ensure you use a Java node instead"
	 Add-Content "$logFile"  "$(Get-TimeStamp) $message"
	 write-host  "$(Get-TimeStamp) $message" -ForegroundColor Red
     write-Error  "$message"
	}

    $linecount=1


    $nodetype = "Oracle Database Server"
    Write-host "node type:" $nodetype
    $CurrentDate = Get-Date


    $currentnode = Get-Node -FilteredNodeName $node

    if ($currentnode  -ne $null)  {
     $description = "Oracle Database: Auto-Updated ($CurrentDate)"
     $json = @"
     { "name": "$node","type": "$nodetype","auditEnabled": "true","delegate": "$delegatenode", "description": "$description","dsUseSsl": false,"isDisabled": false,"oracleIsService": true,"oracleLoginAs": "$oracleLoginAs","oracleSecurityType": "$oracleSecurity","password": "$dbpass","port": $port,"user": "$dbuser"
    }
"@
    Write-debug $json
    Write-host  "Json: " $json


    $message = "The node $node already exists. That could need to some issues"
	 Add-Content "$logFile"  "$(Get-TimeStamp) $message"
      write-host  "$(Get-TimeStamp) $message" -ForegroundColor Red
	Write-Error  "$message"



    try{
        Write-host ($Uri+"nodes")
       # $nodeUpdate = Invoke-RestMethod -uri ($Uri+"nodes") -Body $json -Method Post -ContentType "application/json" -Headers $headers -WebSession $ActiveSessionVariable
      #   Write-host "nodeUpdate: "$nodecreate
         Write-host "node: "$currentnode
     

     if ($currentnode.Count -gt 1) {
$nodeid = $currentnode.Get(0).id
}else {
$nodeid = $currentnode.id}


       Write-host "nodeid: "$nodeid
       $nodeupdate = Invoke-RestMethod -uri ($Uri+"nodes"+"/$nodeid") -Body $json -Method PUT -ContentType "application/json" -Headers $headers -WebSession $ActiveSessionVariable
        Write-host "nodeupdate: "$nodeupdate
       # return $nodecreate
        $message = "Successfully updated node $node"
       Write-Host  $message 
        Add-Content "$logFile" "$(Get-TimeStamp) $message"
        }
    catch{
        Write-Host "Error updating Oracle Node:" $_.Exception.message
    }
	
    } else {

    $description = "Oracle Database: Auto-Created ($CurrentDate)"
    $json = @"
{ "name": "$node","type": "$nodetype","auditEnabled": "true","delegate": "$delegatenode", "description": "$description","dsUseSsl": false,"isDisabled": false,"oracleIsService": true,"oracleLoginAs": "$oracleLoginAs","oracleSecurityType": "$oracleSecurity","password": "$dbpass","port": $port,"user": "$dbuser"
}
"@
Write-debug $json
Write-host  "Json: " $json


    try{
        Write-host ($Uri+"nodes")
        $nodecreate = Invoke-RestMethod -uri ($Uri+"nodes") -Body $json -Method Post -ContentType "application/json" -Headers $headers -WebSession $ActiveSessionVariable
         Write-host "nodeCreate: "$nodecreate
         $message = "Successfully added node $node"
         Write-Host  $message
        Add-Content "$logFile" "$(Get-TimeStamp) $message"
        }
    catch{
        Write-Host "Error creating Oracle Node:" $_.Exception.message
    }
}

}

################ ********************* ####################
# Set Node Tags
################ ********************* ####################

function SetNode-Tags{
    param ($node,
            $tags
    )

    try{

        write-host $teserver -ForegroundColor Green
        Get-TE-AVAPI-Login -teserver $teserver -teuser $twuser -tepass $twpass
        Write-Host $TEAVURI
        Write-Host $node -ForegroundColor Yellow

        $in_Tags.Split(",") | ForEach {
        $tag = $_.Trim()
        Write-host "Adding tag : "$tag 
        Update-TE-AVAPI-Node-Tag -nodename $node -tagname $tag
 }
       
        }
    catch{
        Write-Host "Error adding tags: $_.Exception.Message "
    }
}

################ ********************* ####################
# MAIN 
################ ********************* ####################	
# CHRIS TEST++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
$inputfile =  ".\InputList-Oracle.txt"
# CHRIS TEST++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


if (!(Test-Path $inputfile)) {
write-host "File " $inputfile " not found"
exit
}

$csv = Import-CSV $inputfile -Delimiter ';'
$csv | %{

  $linecount++
  $in_Hostname=$_.'Hostname'.Trim()
  $in_database=$_.'database'
  $in_Delegator=,$_.'Delegator'
  $in_ApplicationOwner=$_.'ApplicationOwner'
  $in_uid=$_.'uid'
  $in_pwd=$_.'pwd'
  #$in_Tags=$_.'Tags'.Trim()


  $node = "$in_Hostname"+":$in_database"

  Add-Content "$logFile" "$(Get-TimeStamp) Creating node: $node"
  New-OracleDBNode -oracleLoginAs "DEFAULT" -oracleSecurity "NONE" -auditenabled "true" -node $node -delegateagent "$in_Delegator" -dbuser $_.'uid' -dbpass $_.'pwd' -port 1521

  #SetNode-Tags -node $in_Hostname -tags $in_Tags
  }
