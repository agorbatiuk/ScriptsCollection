<#
#>

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = 'C:\Logs\PowerShellLog.log',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warn", "Info")]
        [string]$Level = "Info",
        
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
        } elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $null = New-Item $Path -Force -ItemType File
        } else {
            # Nothing to see here yet.
        }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

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

Function UnzipDocx($FileNameDocx) {

    $FileDestinationProcessing = $ProcessingFolder + "\" + $FileNameDocx

    if (-not (Test-Path -Path $FileDestinationProcessing -PathType Leaf)) {
        Write-Host "[>] Processing to move to folder: $FileDestinationProcessing" -ForegroundColor DarkGray
        Copy-Item $FileItem -Destination $FileDestinationProcessing
    }

    #Rename files to .zip to be able to extract
    Write-Host "[>] Renaming .docx to zip" -ForegroundColor DarkGray
    $NewFileNamezipped = "$FileBaseName.zip"
    $NewProcessintLocationZip = $ProcessingFolder + "\" + $NewFileNamezipped
    $NewProcessintLocationOriginal = $ProcessingFolder + "\" + $FileName

    if (-not (Test-Path -Path $NewProcessintLocationZip -PathType Leaf)) {
        Rename-Item -Path $NewProcessintLocationOriginal -NewName $NewProcessintLocationZip
        Write-Log -Message "file - $NewProcessintLocationOr in xml files of docx file" -Path $LogPath -Level Info
    }
    
    #Extract ZIP files
    $ExtractLocationZipProcessing = $ProcessingFolder + "\" + $FileBaseName

    if (-not (Test-Path -Path $ExtractLocationZipProcessing)) {
        Write-Host "[>] Extracting zip" -ForegroundColor DarkGray
        Expand-Archive $NewProcessintLocationZip -DestinationPath $ExtractLocationZipProcessing
    }
    Remove-Item $NewProcessintLocationZip -Force
    return $ExtractLocationZipProcessing
}

Function Invoke-ResetTemplate {
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $FileItem,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $ProcessingFolder,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $BadFiles,
        [Parameter(Mandatory = $true, Position = 3)]
        [string] $FixedFiles
    )
    Write-Log -Message "Processing: $FileItem" -Path $LogPath -Level Info
    Write-Host "[>] Processing: $FileItem" -ForegroundColor Cyan
    $FolderofFile = Split-Path -Path $FileItem
    $FileName = Split-Path -Path $FileItem -Leaf
    $FileBaseName = (Get-Item $FileItem).BaseName
    $FileExtension = (Split-Path -Path $FileItem -Leaf).Split(".")[-1]
    $ReplaceOriginalFiles = $true

    Write-Host "[>] Starting reset for: $FileItem" -ForegroundColor DarkGray
    if ($FileExtension -eq "docx") {
        $ExtractLocationZipProcessing = UnzipDocx($FileName)
        Write-Host "[>] Starting template reset for file: $FileItem" -ForegroundColor DarkCyan
        #Check for presence of template
        if (Test-Path "$ExtractLocationZipProcessing\word\_rels\settings.xml.rels") {
            $xml = New-Object XML
            $xml.Load("$ExtractLocationZipProcessing\word\_rels\settings.xml.rels")
            $xmlData = $xml.Relationships.ChildNodes
            #Check if template is remote
            if ($xmlData.Target -match '(http[s]?|[s]?ftp[s]?(:\/\/))' -or $xmlData.Target -match '(^(\\))') {
                $RemoteTemplate = $xmlData.Target
                Write-Log -Message "XML state before: $($xmlData.Target)" -Path $LogPath -Level Info
                #Change XML File
                $xmlData.SetAttribute("Target", "");
                Write-Log -Message "XML state after : $($xmlData.Target)" -Path $LogPath -Level Info
                $xml.Save("$ExtractLocationZipProcessing\word\_rels\settings.xml.rels")
                #Re-zip and change back to .docx
                $NewFileNamezipped = "$FileBaseName.zip"
                $FileFiledPathZip = $FixedFiles + "\" + $NewFileNamezipped
                Compress-Archive -Path "$ExtractLocationZipProcessing\*" -DestinationPath $FileFiledPathZip -Force
                Rename-Item -Path "$FileFiledPathZip" -NewName "$FileBaseName.docx"
                $DocxFixedLocation = $FixedFiles + "\" + "$FileBaseName.docx"
                #Print results
                Write-Host "[>] Reset Results:" -ForegroundColor DarkGreen
                Write-Host "    [>] Injected template removed from file" -ForegroundColor DarkGreen
                Write-Host "    [>] Malicious file copied to: $OriginalFolder" -ForegroundColor DarkGreen
                Write-Host "    [>] Cleaned file saved to: $DocxFixedLocation" -ForegroundColor DarkGreen
            } else {
                $RemoteTemplate = $xmlData.Target
                $Cleaned = $false
                $BackupFile = $null
            }
        } else {
            $RemoteTemplate = $false
            $Cleaned = $false
            $BackupFile = $null
        }
        #If remote template found, replace original file with clean version
        if ($ReplaceOriginalFiles -and $RemoteTemplate) {
            try {
                Write-Host "[>] Replacing malicious file with cleaned version" -ForegroundColor DarkGray
                #Backup original file, check if duplicate file name and rename when required
                if (-Not (Get-ChildItem $BadFiles -Filter $FileName)) {
                    Move-Item -Path $FileItem -Destination $BadFiles
                    $BackupFile = Join-Path -Path $BadFiles -ChildPath $FileName
                } else {
                    $chars = 48..57; $chars += 65..90; $chars += 97..122
                    $id = '' ; 0..7 | ForEach-Object { $id = $id + [char](Get-Random $chars) }
                    $FileNameNew = ($FileBaseName + '_' + $id + '.' + $FileExtension)
                    $BackupFile = Join-Path -Path $BadFiles -ChildPath $FileNameNew
                    Move-Item -Path $FileItem -Destination $BackupFile
                }
                #Move fixed file to original location
                Move-Item -Path $DocxFixedLocation -Destination $FolderofFile

                Write-Host "[>] File successfully cleaned: $FileItem" -ForegroundColor Green
                $Cleaned = $true
            } catch {
                Write-Log -Message "Failed to move or replace $FileItem!" -Path $LogPath -Level Error
            }
        } 
        #Clean up extract directory
        $null = Remove-Item $ExtractLocationZipProcessing -Force -Recurse
        Write-Log -Message "Finished template reset for docx file" -Path $LogPath -Level Info
    } elseif ($FileExtension -eq "doc") {
        Write-Host "[>] Resetting default templates (doc)" -ForegroundColor DarkGray
        $FileDestinationProcessing = Join-Path -Path $ProcessingFolder -ChildPath "FixedFiles\$FileName"
        Copy-Item $FileItem -Destination $FileDestinationProcessing
        $Word = New-Object -ComObject Word.Application
        #Disabling Macros
        Write-Host "[>] Disabling Office Macros" -ForegroundColor DarkGray
        $Word.AutomationSecurity = "msoAutomationSecurityForceDisable"
        $Document = $Word.documents.open($FileDestinationProcessing)
        #Check XML Templates
        Write-Host "[>] Checking for remote templates in XML data" -ForegroundColor DarkGray
        [xml]$Data = $document.AttachedTemplate.Parent.ActiveDocument.WordOpenXML
        $XMLTargetData = $Data.package.part.xmlData.Relationships.Relationship
        $i = 0
        $RemoteTemplate = $null
        foreach ($target in $XMLTargetData) {
            if (
                $target.type -notmatch 'hyperlink$' -and
                ($target.target -match '(http[s]?|[s]?ftp[s]?(:\/\/))' -or $target.target -match '(^(\\))')
            ) {
                Write-Host "[>] HTTP or SMB Targets found!" -ForegroundColor Yellow
                if ($i -eq 0) {
                    Write-Host "[*] Remote endpoints found in XML:" -ForegroundColor Yellow
                    Write-Host "----------------------------------" -ForegroundColor Yellow
                }
                $i++
                Write-Host "Target:" $target.target -ForegroundColor Yellow
                Write-Host "Injected in:" $target.type -ForegroundColor Yellow
                Write-Host "----------------------------------" -ForegroundColor Yellow
                #Write findings to log
                Write-Log -Message "Remote Template Found: $($target.target -replace 'http','hxxp')" -Path $LogPath -Level Info
                Write-Log -Message "Remote Template Type: $($target.type)" -Path $LogPath -Level Info

                $RemoteTemplate = $target.target
            }
        }

        #Set Attached Template (overrides any existing template)
        if ($RemoteTemplate) {
            $NewTemplate = "$env:APPDATA\Microsoft\Templates\Normal.dotm"
            $Document.AttachedTemplate = $NewTemplate
            Write-Log -Message "Template set to $env:APPDATA\Microsoft\Templates\Normal.dotm" -Path $LogPath -Level Info            
            Write-Host "[>] Templates reset to normal.dotm" -ForegroundColor DarkGray
            Write-Host "[>] Closing Word Document" -ForegroundColor DarkGray
            $Document.Close()
        }
        else {
            $Cleaned = $false
            Write-Host "[>] No HTTP or SMB Targets found" -ForegroundColor DarkGray
            Write-Log -Message "No HTTP or SMB Targets found in doc file" -Path $LogPath -Level Info
        }
        Write-Log -Message "File with reset template saved to: $FileDestinationProcessing" -Path $LogPath -Level Info
        #Close Word Process
        $Word.Quit()
        Write-Log -Message "Word Process Closed" -Path $LogPath -Level Info
        
        if ($ReplaceOriginalFiles -and $RemoteTemplate) {
            try {
                Write-Host "[>] Replacing malicious file with cleaned version" -ForegroundColor DarkGray
                #Backup original file, check if duplicate file name and rename when required
                if (-Not (Get-ChildItem $BadFiles -Filter $FileName)) {
                    Move-Item -Path $FileItem -Destination $BadFiles
                    $BackupFile = Join-Path -Path $BadFiles -ChildPath $FileName
                }
                else {
                    $chars = 48..57; $chars += 65..90; $chars += 97..122
                    $id = '' ; 0..7 | ForEach-Object { $id = $id + [char](Get-Random $chars) }
                    $FileNameNew = ($FileBaseName + '_' + $id + '.' + $FileExtension)
                    $BackupFile = Join-Path -Path $BadFiles -ChildPath $FileNameNew
                    Move-Item -Path $FileItem -Destination $BackupFile
                }
                Move-Item $FileDestinationProcessing -Destination $FolderofFile
                $Cleaned = $true
                Write-Host "[>] File successfully cleaned: $FileItem" -ForegroundColor Green
            }
            catch {
                Write-Log -Message "Failed to move or replace $FileItem!" -Path $LogPath -Level Error
            }
        }
    }
    #Output Results
    [PSCustomObject]@{
        'OriginalFile'   = $FileItem
        'RemoteTemplate' = $RemoteTemplate -replace 'http', 'hxxp'
        'Cleaned'        = $Cleaned
        'BackupFile'     = $BackupFile
    }
}

$DesktopPath = [Environment]::GetFolderPath("Desktop")

#Setup Log Files
Write-Log -Message "Start Folder creation" -Path $ProcessingLog -Level Info
$ProcFolder = (Get-Date -Format 'yyyyMMdd_HHmm') + '_WordDocCleanup'
$ProcessingFolder = Join-Path -Path $DesktopPath -ChildPath $ProcFolder
if (-Not (Test-Path -Path $ProcessingFolder)) {
    New-Item -Path $ProcessingFolder -ItemType "Directory" | Out-Null
    Write-Log -Message "Folder created: $ProcessingFolder" -Path $ProcessingLog -Level Info
}

$ProcessingLog = "$ProcessingFolder\$(Get-Date -Format yyyyMMdd_HHmm)_TemplateInjectionProcessingLog.txt"
$LogPath = "$ProcessingFolder\$(Get-Date -Format yyyyMMdd_HHmm)_TemplateInjectionRepairLog.txt"
$FileLog = "$ProcessingFolder\$(Get-Date -Format yyyyMMdd_HHmm)_TemplateInjectionRepairLog.csv"

Add-Content -Path $FileLog -Value 'OriginalFile,RemoteTemplate,Cleaned,BackupPath' -Encoding utf8
Write-Log -Message "Initiated TemplateInjectionProcessing" -Path $ProcessingLog -Level Info

#Check if script has run previously, if more than 5 do not continue
$NumberOfWordDocFolder = Get-ChildItem -path $DesktopPath -Recurse | Where-Object { $_.FullName -like "*WordDocCleanup" }
if ($NumberOfWordDocFolder.count -gt 5) {
    Write-Log -Message "Run the cleanup more then 5 times" -Path $ProcessingLog -Level Info
    Write-Host "[>] Run the cleanup more then 5 times" -ForegroundColor DarkGray
    exit
}

$BadFiles = Join-Path -Path $ProcessingFolder -ChildPath 'BadFiles'
if (-Not (Test-Path -Path $BadFiles)) {
    $null = New-Item -Path $ProcessingFolder -Name "BadFiles" -ItemType "Directory" 
    Write-Log -Message "Folder created: $BadFiles" -Path $ProcessingLog -Level Info
}

$FixedFiles = "$ProcessingFolder" + "\FixedFiles"
if (-Not (Test-Path -Path $FixedFiles)) {
    $null = New-Item -Path $ProcessingFolder -Name "FixedFiles" -ItemType "Directory" 
    Write-Log -Message "folder $ProcessingFolder\FixedFiles created" -Path $ProcessingLog -Level Info
}
Write-Log -Message "CleanupScript run:" $NumberOfWordDocFolder.count -Path $ProcessingLog -Level Info
$Disks = Get-PSDrive -PSProvider FileSystem | Where-Object Used -gt 0
$DriveLetters = $Disks.Root

Write-Host "[>] Starting enumeration of Word files from local disks" -ForegroundColor DarkCyan
$FilesToProcess = foreach ($DriveLetter in $DriveLetters) {
    Write-Log -Message "Scanning $DriveLetter for files" -Path $LogPath -Level Info
    Write-Host "[>] Scanning $DriveLetter for files" -ForegroundColor DarkGray
    Get-ChildItem "$($DriveLetter)*" -Directory |
        Where-Object Name -notmatch 'Windows|Program Files|Program Files (x86)' |
        Get-ChildItem -Recurse -Filter '*.doc' -ErrorAction Ignore
}

if ($FilesToProcess) {
    foreach ($File in $FilesToProcess) {
        $params = @{
            'FileItem'         = $File.FullName
            'ProcessingFolder' = $ProcessingFolder
            'BadFiles'         = $BadFiles
            'FixedFiles'       = $FixedFiles
        }
        $Results = Invoke-ResetTemplate @params
        Add-Content -Path $FileLog "`"$($Results.OriginalFile)`",`"$($Results.RemoteTemplate)`",`"$($Results.Cleaned)`",`"$($Results.BackupFile)`"" -Encoding utf8
    }
} else {
    Write-Log -Message "No Word files found to process." -Path $LogPath -Level Info
}
Write-Log -Message "Script Finished!" -Path $ProcessingLog -Level Info