# Script: detect-horizontal-user-brute-froce-attack.ps1
# Author: Richard Hatch, 2014 - RGH@Portcullis-Security.com

# Number of failed logons within the defined time span
# Total events -gt this value will trick the response action
$threshold = 4

#The email server to use when sending alerts
$EmailServer = "127.0.0.1"

#The email address to send from
$mail_domainSrc = "alerts@mydomain.com"

#clean-up any data from a previous run
Remove-Variable events

#get the events from the local system. RUN ON DC (or central log server)
$events = get-winevent -EA silentlycontinue -filterhashtable @{LogName='Security';id=4771; `
starttime=(Get-Date).AddHours(-1);endtime=(Get-Date)  }

# Copy the following line for each required ID value (and update the ID param!)

# $events += get-winevent -EA silentlycontinue -filterhashtable @{LogName='Security'; `
#id=4771;starttime=(Get-Date).AddHours(-1);endtime=(Get-Date)  }

#declare our data hash
$scares = @{}


#process each event 
ForEach ($evt in $events)
{
	#convert the event data to xml so we can get items
	$evtxml = [xml]$evt.ToXML()

	$curTargetUserName = ""
	$curServiceName = ""
	$curIPAddress = ""
	$curEventTime = $evtxml.Event.System.TimeCreated.SystemTime

	#need to loop through each 'data' properties
	for ($i=0; $i -lt $evtxml.Event.EventData.childNodes.count; $i++)
	{
		if ($evtxml.Event.EventData.Data[$i].name -eq "IpAddress")
		{
			$curIPAddress = $evtxml.Event.EventData.Data[$i].'#text'
		}
	} #end for ($i=0; $i -lt $evtxml.Event.EventData.count; $i++)

	#If we have never seen this IP failing to logon create a new entry
	#
	#Without this check the code attempts to repeatedly create the 
	#same hash entry, causing an error.
	if (!($scares.ContainsKey($curIPAddress)))
	{
		$scares.Add($curIPAddress, 0); #init to 0
	}
	
	#count this failed logon attempt
	$scares["$curIPAddress"] += 1

} #end ForEach ($evt in $events)

$scares.GetEnumerator() | % {
	if ( $($_.value) -gt $threshold )
	{
		$attackerIP = $($_.key)
		$attackerFailedTimes = $($_.value)
		
		Write-Host "[!] IP: $($_.key) failed to login $($_.value) times in the last hour"
		
		#$mail_domainSrc = [string]([adsi]'').distinguishedName
		$mail_subject = "ALERT ${mail_domainSrc}: Host $($_.key) may be attacking ActiveDirectory user accounts"
		$mail_body = " 
		ALERT! A possible brute-force password guessing attack detected within the last hour
		from the host with the IP $attackerIP. Failed logon count was $attackerFailedTimes
		
		$mail_domainSrc
		"

		Send-MailMessage -To ITSecurity@mydomain.com -From $mail_domainSrc `
			-Subject $mail_subject -Body $mail_body -SmtpServer $EmailServer `
			-Priority High
		

	} #end if ( $($_.value) -gt $threshold )
} #end $scares.GetEnumerator() | % {
