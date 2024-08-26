
<#
.SYNOPSIS
Scan filesystem partitions if files with .LNK extension exist of malicious content. 
When malicious content exist move .LNK file from original location to a containment location.


.DESCRIPTION
This script provides the following activities:

- Checking: all .LNK file Target path and argument fields
- Move .LNK file with suspicouse content in Target path and argument fields away from original location
- Save processed and moved file detailes to a .csv file 

This script will create a LNKProcessing directory with timestamp in either users temp directory or Windows temp directory depending on the context the scrip runs(System or user).
    - .LNK files detected to be malicious are moved to BadLnkFiles subdirectory of LNKProcessing.
    -  LNKRepairLog.csv containing: processed and moved files to a .csv file is stored in the LNKProcessing folder
    -  LNKProcessingLog.txt containing: scrip logging is stored in the LNKProcessing folder


.EXAMPLE
    
    PS> .\LnkFileRemediation.ps1
#>

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('LogContent')]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = 'C:\Logs\PowerShellLog.log',
       
        [Parameter(Mandatory = $false)]
        [ValidateSet('Error', 'Warn', 'Info')]
        [string]$Level = 'Info',
       
        [Parameter(Mandatory = $false)]
        [switch]$NoClobber
    )

    begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'SilentlyContinue'
    } process {
       
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
        }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $null = New-Item $Path -Force -ItemType File
        }

        else {
            # Nothing to see here yet.
        }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
            }
        }
       
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append -Encoding utf8
    } end {

    }
}

function Invoke-RemoveLnkFile {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $LNKFileToRemove
    )
  
    if (Test-Path $LNKFileToRemove) {
        $FileNameOnly = Split-Path -Path $LNKFileToRemove -Leaf

        if (-Not (Get-ChildItem $BadLnkFolder -Filter $FileNameOnly)) {
            Write-Host "[>] Moving $LNKFileToRemove bad lnk file to $BadLnkFolder" -ForegroundColor Magenta
            Write-Log -Message "Moving $LNKFileToRemove bad lnk file to $BadLnkFolder" -Path $LogPath -Level Info

            Move-Item -Path $LNKFileToRemove -Destination $BadLnkFolder

            Write-Host "[>] $LNKFileToRemove is removed from orginal location" -ForegroundColor Magenta
            Write-Log -Message "$LNKFileToRemove is removed from orginal location" -Path $LogPath -Level Info

            $MovedToLocationFileName = $BadLnkFolder + '\' + $FileNameOnly 
            return $MovedToLocationFileName
        } else {
            $Random = (Get-Random).ToString()
            $RandomizedFileName = $Random + '-' + $FileNameOnly 

            Write-Host "[>] Moving $LNKFileToRemove bad lnk file to $BadLnkFolder" -ForegroundColor Magenta
            Write-Log -Message "Moving $LNKFileToRemove bad lnk file to $BadLnkFolder" -Path $LogPath -Level Info
            $MovedToLocationFileNameRandomized = $BadLnkFolder + '\' + $RandomizedFileName
            Move-Item -Path $LNKFileToRemove -Destination $MovedToLocationFileNameRandomized 
            Write-Host "[>] FIleName already exist new file name in $BadLnkFolder is $MovedToLocationFileNameRandomized" -ForegroundColor Magenta
            Write-Host "[>] $LNKFileToRemove is removed from orginal location" -ForegroundColor Magenta
            Write-Log -Message "$LNKFileToRemove is removed from orginal location" -Path $LogPath -Level Info
        
            return $MovedToLocationFileNameRandomized 
        }
    } else {
        Write-Host "[>] Removal .LNK failled - File $LNKFileToRemove does not exist!" -ForegroundColor Yellow
        Write-Host '----------------------------------' -ForegroundColor Yellow
        Write-Log -Message "Removal .LNK failled - File $LNKFileToRemove does not exist!" -Path $LogPath -Level Error
    }
}  

function Invoke-SystemInkCheck {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Object[]]$LNKFile
    )

    $LegitLNKsSystemTools = @(
        [PSCustomObject]@{
            Lnk = 'Command Prompt.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'computer.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Control Panel.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'File Explorer.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Run.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Command Prompt.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Search.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Windows PowerShell (x86).lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Windows PowerShell.lnk'
        }
    )

    $LegitLNKsPS = @(
        [PSCustomObject]@{
            Lnk = 'Windows PowerShell (x86).lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Windows PowerShell.lnk'
        },
        [PSCustomObject]@{
            Lnk = 'Command Prompt.lnk'
        }
    )
    
    $Split = $LNKFile.FullName -split '\\'
    $AppData = 'AppData'
    $AllUsers = 'All Users'
    $ProgramData = 'ProgramData' #Win8
    $ContainsAppData = $Split | Where-Object { $_ -eq $AppData -or $_ -eq $AllUsers -or $_ -eq $ProgramData }

    if ($ContainsAppData) {
        $ContainsWinX = $Split | Where-Object { $_ -eq 'WinX' }
       
        if (($ContainsWinX) -and ($LNKFile.Arguments -eq '')) {
            Write-Log -Message 'AppData/WinX: Folder, Native system path with .LNK files, without lnk arguments--' -Path $LogPath -Level Info
            return $true
        } else {
            $SplitStart = $LNKFile.FullName -split 'Start Menu'          
            $SplitStartForward = $SplitStart -split '\\'

            if ($SplitStartForward | Where-Object { $_ -eq 'System Tools' -or $_ -eq 'Programs' }) {
                foreach ($LnkSTitem in $LegitLNKsSystemTools) {
                    if (($SplitStartForward | Where-Object { ($_ -eq $LnkSTitem.lnk -and $LNKFile.Arguments -eq '') -or ($_ -eq $LnkSTitem.lnk -and $LNKFile.Arguments -like '-sta*') })) {
                        Write-Log -Message 'AppData or All Users/Start Menu/System Tools or program: Folder contains a known .LNK files without lnk arguments--' -Path $LogPath -Level Info
                        
                        return $true
                    }
                }
            }
            if ($SplitStartForward | Where-Object { $_ -eq 'Windows PowerShell' -and $LNKFile.Arguments -eq '' }) {
                foreach ($LnkPSItem in $LegitLNKsPS) {
                    if ($SplitStartForward | Where-Object { $_ -eq $LnkPSItem.lnk }) {
                        Write-Log -Message 'AppData or All Users/Start Menu/Windows PowerShell: Folder contains a known .LNK file without lnk arguments--' -Path $LogPath -Level Info
                        return $true
                    }
                }
            }
        }
    }

    Write-Log -Message 'Not a System .lnk file' -Path $LogPath -Level Info
    Write-Log -Message 'Not a System .lnk file' -Path $LogPath -Level Info
    return $false
}

function Get-LnkDetails {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $FileToProcess,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $ProcessingFolder
    )

    $ExtenstionCheck = Get-ChildItem $FileToProcess -Force -EA Silent | Select-Object Extension -ErrorAction Ignore 

    #Cyrillic chars in filename and alternative .lnk extensions .lnkxxx
    if(($FileToProcess -match '(\w+[\u0400-\u052F]+)|([\u0400-\u052F]+\w+)') -or ($ExtenstionCheck.Extension -ne '.lnk')){
        
        Write-Log -Message 'LNK File alternative processing' -Path $LogPath -Level Info
        Write-Host "[>] LNK File alternative processing" -ForegroundColor DarkGray
        $RandomNum = Get-Random -Maximum 10000
        $ShortCutProcessingUnicodeName = "LnkFileRemProc$RandomNum.lnk"
        $LnkFileProcessing = "$ProcessingFolder\$ShortCutProcessingUnicodeName"

        Write-Log -Message 'LNK File alternative processing' -Path $LogPath -Level Info
        Copy-Item $FileToProcess -Destination $LnkFileProcessing -Force -EA Silent
        $Shell = New-Object -ComObject WScript.Shell
        $ShortCutDetails = $Shell.CreateShortcut($LnkFileProcessing) 
        $ShortCutDetailsUnicoded = New-Object PSObject -Property @{
            'Fullname'    = $FileToProcess
            'TargetPath'   = $ShortCutDetails.TargetPath
            'Arguments' = $ShortCutDetails.Arguments
            'IconLocation'    = $ShortCutDetails.IconLocation
            'Encoded'   = $true         
        }
        
        Write-Log -Message 'Remove temp processing data' -Path $LogPath -Level Info
        Write-Host "[>] Processing Remove temp processing data" -ForegroundColor DarkGray
        Remove-Item -Path $LnkFileProcessing -Force -ErrorAction SilentlyContinue
        return $ShortCutDetailsUnicoded 

    }

    $Shell = New-Object -ComObject WScript.Shell
    $ShortCutDetails = $Shell.CreateShortcut($FileToProcess) 
    return $ShortCutDetails 
}

#Windows 7 not supported
$OSversion = (Get-WmiObject -Class Win32_Operatingsystem).Version
if ($OSversion -like '6.1*') {
    Write-Host 'Windows 7 not supported - Exiting'
    Start-Sleep -Seconds 2
    Exit
}

$DesktopPath = [Environment]::GetFolderPath("Desktop")

$ProcFolder = (Get-Date -Format 'yyyyMMdd_HHmm') + '_LNKProcessing'
$ProcessingFolder = Join-Path -Path $DesktopPath -ChildPath $ProcFolder
if (-Not (Test-Path -Path $ProcessingFolder)) {
    New-Item -Path $ProcessingFolder -ItemType 'Directory' | Out-Null
    New-Item -Path $ProcessingFolder -Name 'BadLnkFiles' -ItemType 'Directory' | Out-Null
    
}
$BadLnkFolder = $ProcessingFolder + '\BadLnkFiles' 

#Setup log files
$LogPath = "$ProcessingFolder\$(Get-Date -Format yyyyMMdd_HHmm)_LNKProcessingLog.txt"
$FileLog = "$ProcessingFolder\$(Get-Date -Format yyyyMMdd_HHmm)_LNKRepairLog.csv"

Write-Log -Message 'Initiated .Lnk validation' -Path $LogPath -Level Info

#Initiate table values csv output
Add-Content -Path $FileLog -Value '"Lnk File name","Lnk file path","Lnk target field","Lnk arguments field","Lnk Icon Location","Malicious","MatchOnExtension","MatchOnArguments","LnkMmaliciousMovedToLocation"' -Encoding utf8

#Interation disks
$Disks = Get-PSDrive -PSProvider FileSystem | Where-Object Used -GT 0
$DriveLetters = $Disks.Root

#Enumeration .LNK files local disk
Write-Host '[>] Starting enumeration of .LNK files from local disks' -ForegroundColor DarkCyan
$FilesToProcess = foreach ($DriveLetter in $DriveLetters) {
    Write-Log -Message "Scanning $DriveLetter for .LNK files" -Path $LogPath -Level Info
    Write-Host "[>] Scanning $DriveLetter for .LNK files" -ForegroundColor DarkGray
    #Regex - last .lnk occurens in file name
    Get-Item -Path "$($DriveLetter)*" -Exclude 'Windows', 'Program Files', 'Program Files (x86)' -Force -EA Silent | Get-ChildItem -Recurse -ErrorAction Ignore -Force | Where-Object { $_.extension -match '(\.lnk(?=[^.]*$))' } -ErrorAction Ignore
}

if ($FilesToProcess) {
    foreach ($File in $FilesToProcess) {
        #Checking if file is in badlnkFiles folder if so skip checking - this to prevent re-detection second run
        $FIleProcessingPathCheck = $File.FullName -split '\\'
        if (-not(($FIleProcessingPathCheck | Where-Object { $_ -Like '*_LNKProcessing' }) -and ($FIleProcessingPathCheck | Where-Object { $_ -eq 'BadLnkFiles' }))) {

            Write-Log -Message 'Processing LNK File' -Path $LogPath -Level Info
      
            $MaliciousLNK = $False
            $MatchOnArguments = $False
            $MatchOnExtension = $False
            $extension = $null
            $FileName = $null

            $ShortCut = Get-LnkDetails -FileToProcess $File.FullName -ProcessingFolder $ProcessingFolder

            if ($ShortCut.TargetPath) {
                $extension = Split-Path $ShortCut.TargetPath -Leaf 
            } else {
                Write-Log -Message 'Empty target path in .INK' -Path $LogPath -Level Info
            }
 
            $FileName = Split-Path -Path $ShortCut.Fullname -Leaf

            Write-Host "[>] Processing $($ShortCut.Fullname)" -ForegroundColor DarkGray
            Write-Log -Message "Processing $($ShortCut.Fullname)" -Path $LogPath -Level Info
            #Matching extensions
            if (($extension -contains 'cmd.exe') -or ($extension -contains 'powershell.exe') -or ($extension -contains 'mshta.exe') -or ($extension -contains 'rundll32.exe') -or ($extension -contains 'wscript.exe')) {
                $MaliciousLNK = $true
                $MatchOnExtension = $true
                Write-Host '----------------------------------' -ForegroundColor Yellow
                Write-Host '[>] Match on extension found!' -ForegroundColor Yellow
                Write-Host "[>] Found $($ShortCut.Fullname) match on extension  $MatchOnExtension!" -ForegroundColor Yellow
                Write-Host "[>] Found $extension used in .LNK TargetPath" -ForegroundColor Yellow
                Write-Host '----------------------------------' -ForegroundColor Yellow
                Write-Log -Message "Match on extension found!: $($ShortCut.Fullname) contains $extension used in .LNK TargetPath" -Path $LogPath -Level Info
            } 
            #Matching arguments
            if ($ShortCut.Arguments -match '(https?:\/\/|w{3}?.)') {
                $maliciousLNK = $true
                $MatchOnArguments = $true
                Write-Host '----------------------------------' -ForegroundColor Yellow
                Write-Host '[>] Match on argument found!' -ForegroundColor Yellow
                Write-Host "[>] Found $($ShortCut.Fullname) match on arguments $MatchOnArguments!" -ForegroundColor Yellow
                Write-Host "[>] Found $($ShortCut.Arguments) used in .LNK argument field" -ForegroundColor Yellow
                Write-Log -Message "Match on argument found!: $($ShortCut.Fullname) contains $($ShortCut.Arguments)  used in .LNK argument field" -Path $LogPath -Level Info
                Write-Host '----------------------------------' -ForegroundColor Yellow
            }

            $LnkFileDetails = New-Object PSObject -Property @{
                'LnkFileName'                 = $FileName
                'LnkTargetPath'               = $Shortcut.TargetPath
                'LnkArguments'                = $ShortCut.Arguments
                'LnkIconLocation'             = $ShortCut.IconLocation
                'LnkFullname'                 = $ShortCut.Fullname
                'MatchOnExtension'            = $MatchOnExtension
                'MatchOnArguments'            = $MatchOnArguments
                'MaliciousLNK'                = $maliciousLNK
                'LnkmaliciousMovedToLocation' = ''
            }

            if ($LnkFileDetails.MaliciousLNK) {
                Write-Host '----------------------------------' -ForegroundColor Green
                Write-Host '[>] Processing Removal' -ForegroundColor Green

                $SystemFile = Invoke-SystemInkCheck($ShortCut)
                if ($SystemFile) {
                    Write-Log -Message "Skipping removal - SystemFile $($LnkFileDetails.LnkFullname)" -Path $LogPath -Level Info
                    Write-Host "[>] Skipping  removal - SystemFile $($LnkFileDetails.LnkFullname)" -ForegroundColor Green
                
                    $LnkFileDetails.LnkmaliciousMovedToLocation = 'Move skipped due to System file'
                    $LnkFileDetails.maliciousLNK = $False
                    $LnkFileDetails.MatchOnArguments = $False
                    Write-Host '----------------------------------' -ForegroundColor Green
                } else {               
                    Write-Log -Message "Start removal of $($LnkFileDetails.LnkFullname)" -Path $LogPath -Level Info
                    Write-Host "[>] Start removal of $($LnkFileDetails.LnkFullname)" -ForegroundColor Green
              
                    $NewInkLocation = Invoke-RemoveLnkFile($LnkFileDetails.LnkFullname)
                    $LnkFileDetails.LnkmaliciousMovedToLocation = ($NewInkLocation)
                    Write-Host '----------------------------------' -ForegroundColor Green
                }
           
            }

            Write-Log -Message 'Add data to CSV' -Path $LogPath -Level Info     
            Add-Content -Path $FileLog "`"$($LnkFileDetails.LnkFileName)`",`"$($LnkFileDetails.LnkFullname)`",`"$($LnkFileDetails.LnkTargetPath)`",`"$($LnkFileDetails.LnkArguments)`",`"$($LnkFileDetails.LnkIconLocation)`",`"$($LnkFileDetails.MaliciousLNK)`",`"$($LnkFileDetails.MatchOnExtension)`",`"$($LnkFileDetails.MatchOnArguments)`",`"$($LnkFileDetails.LnkmaliciousMovedToLocation)`"" -Encoding utf8  
        } else {
            Write-Log -Message "Skipping file $($File.FullName) file is in processing folder - $BadLnkFolder" -Path $LogPath -Level Info
            Write-Host "[>] Skipping file $($File.FullName) file is in processing folder - $BadLnkFolder" -ForegroundColor Green    
        }
    }       
} else {
    Write-Log -Message 'No .LNK files to process' -Path $LogPath -Level Info
    Write-Host '[>] No .LNK files to process)' -ForegroundColor DarkGray
    exit
}

Write-Log -Message 'Ready processing closing script' -Path $LogPath -Level Info
Write-Host '[>] Ready processing closing script ' -ForegroundColor DarkGray
