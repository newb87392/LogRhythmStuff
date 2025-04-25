# PowerShell Script to identify LogRhythm System Monitors that are active
# but have log sources with missing or outdated log messages

# Using default parameters (looks for files in current directory, 7-day threshold)
#.\Analyze-LogRhythmSources.ps1

# With custom file paths
#.\Analyze-LogRhythmSources.ps1 -AgentPropertiesFile "C:\path\to\LogRhythm_AgentPropertiesExport.csv" -LogSourcePropertiesFile "C:\path\to\LogRhythm_LogSourcePropertiesExport.csv"

# With custom threshold (e.g., 14 days)
#.\Analyze-LogRhythmSources.ps1 -DaysThreshold 14


param (
    [Parameter(Mandatory=$false)]
    [string]$AgentPropertiesFile = ".\LogRhythm_AgentPropertiesExport.csv",
    
    [Parameter(Mandatory=$false)]
    [string]$LogSourcePropertiesFile = ".\LogRhythm_LogSourcePropertiesExport.csv",
    
    [Parameter(Mandatory=$false)]
    [int]$DaysThreshold = 1  # Define how many days without logs is concerning
)

# Function to convert string date to DateTime object, handling various formats
function ConvertTo-DateTime {
    param([string]$dateString)
    
    if ([string]::IsNullOrEmpty($dateString)) {
        return $null
    }
    
    try {
        # Try to parse the date string
        return [DateTime]::Parse($dateString)
    }
    catch {
        try {
            # If standard parsing fails, try custom format
            if ($dateString -match '(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2})') {
                return [DateTime]::ParseExact($matches[1], "M/d/yyyy h:mm:ss", $null)
            }
            elseif ($dateString -match '(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}\s+[AP]M)') {
                return [DateTime]::ParseExact($matches[1], "M/d/yyyy h:mm tt", $null)
            }
        }
        catch {
            Write-Warning "Could not parse date: $dateString"
            return $null
        }
        
        Write-Warning "Could not parse date: $dateString"
        return $null
    }
}

Write-Host "Starting LogRhythm System Monitor and Log Source analysis..." -ForegroundColor Cyan

# Check if files exist
if (-not (Test-Path $AgentPropertiesFile)) {
    Write-Error "Agent properties file not found: $AgentPropertiesFile"
    exit 1
}

if (-not (Test-Path $LogSourcePropertiesFile)) {
    Write-Error "Log source properties file not found: $LogSourcePropertiesFile"
    exit 1
}

# Import CSV files
try {
    $agents = Import-Csv $AgentPropertiesFile
    $logSources = Import-Csv $LogSourcePropertiesFile
    
    Write-Host "Successfully imported data:" -ForegroundColor Green
    Write-Host "  - Agents: $($agents.Count)" -ForegroundColor Green
    Write-Host "  - Log Sources: $($logSources.Count)" -ForegroundColor Green
}
catch {
    Write-Error "Error importing CSV files: $_"
    exit 1
}

# Get current date for comparison
$currentDate = Get-Date

# Initialize results collection
$results = @()

# Process each system monitor (we'll filter for active ones later)
foreach ($agent in $agents) {
    
    # Parse the LastHeartbeat date
    $lastHeartbeatDate = ConvertTo-DateTime $agent.LastHeartbeat
    
    # Only consider agents with heartbeats in the last day
    $isAgentActive = $false
    if ($lastHeartbeatDate -ne $null) {
        $agentDaysInactive = ($currentDate - $lastHeartbeatDate).Days
        $isAgentActive = ($agentDaysInactive -le 1)
    }
    
    # Skip agents that aren't considered active by our new definition
    if (-not $isAgentActive) {
        continue
    }
    
    # Find all log sources for this System Monitor
    $monitorName = $agent.SystemMonitorName
    $hostName = $agent.HostName
    
    # Find log sources for this host
    $agentSources = $logSources | Where-Object { 
        ($_.Collection -eq $hostName) -or 
        ($_."Collection Host" -like "*Host: $hostName*") -or
        ($_."Log Host" -eq $hostName)
    }
    
    # Check each log source for this agent
    foreach ($source in $agentSources) {
        # Skip if the Log Source Type contains "LogRhythm " 
        if ($source."Log Source Type" -like "*LogRhythm *") {
            continue
        }
        
        # Skip if there's no Last Log Message date
        if ([string]::IsNullOrEmpty($source."Last Log Message")) {
            continue
        }
        
        # Parse the last log message date
        $lastLogDate = ConvertTo-DateTime $source."Last Log Message"
        
        # Skip if we couldn't parse the date
        if ($null -eq $lastLogDate) {
            continue
        }
        
        $daysWithoutLogs = ($currentDate - $lastLogDate).Days
        
        # Include issues where logs are older than threshold
        if ($daysWithoutLogs -gt $DaysThreshold) {
            $results += [PSCustomObject]@{
                Entity = $agent."Host Entity"
                HostName = $hostName
                SystemMonitorName = $monitorName
                LastHeartbeat = $agent.LastHeartbeat
                LogSourceName = $source."Log Source Name"
                LogSourceType = $source."Log Source Type"
                LastLogMessage = $source."Last Log Message"
                DaysWithoutLogs = $daysWithoutLogs
            }
        }
    }
}

# Display and export results
if ($results.Count -eq 0) {
    Write-Host "No issues found. All log sources from active agents are reporting logs within $DaysThreshold days." -ForegroundColor Green
} else {
    Write-Host "Found $($results.Count) log sources from active agents with outdated logs (more than $DaysThreshold days old):" -ForegroundColor Yellow
    
    # Group results by host for better readability
    $groupedResults = $results | Group-Object -Property SystemMonitorName
    
    foreach ($group in $groupedResults) {
        Write-Host "`nSystem Monitor: $($group.Name)" -ForegroundColor Yellow
        $agent = $agents | Where-Object { $_.SystemMonitorName -eq $group.Name } | Select-Object -First 1
        Write-Host "  Last Heartbeat: $($agent.LastHeartbeat)" -ForegroundColor Cyan
        
        foreach ($item in $group.Group) {
            Write-Host "  • $($item.LogSourceType): $($item.LogSourceName)" -ForegroundColor Yellow
            Write-Host "    Last Message: $($item.LastLogMessage) ($($item.DaysWithoutLogs) days ago)" -ForegroundColor White
        }
    }
    
    # Export to CSV
    #$outputFile = "LogRhythm_OutdatedLogSources_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    #$results | Export-Csv -Path $outputFile -NoTypeInformation
    #Write-Host "`nExported results to: $outputFile" -ForegroundColor Green
}

Write-Host "`nScript completed." -ForegroundColor Green