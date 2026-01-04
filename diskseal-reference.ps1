<#
.SYNOPSIS
  elbcloud DiskSeal – Final v1.14 (NO console output, RecoveryPassword only, no secret persistence)

  - Auswahl: Volume (mit Laufwerksbuchstaben) ODER Disk (RAW/ohne Buchstaben)
  - Disk-Preparation (DESTRUKTIV): init/partition/NTFS (wenn Disk gewählt)
  - Wenn Volume bereits BitLocker "ON": NTFS Quick-Format (RESET) und dann normal fortfahren
  - BitLocker Enable (Full-Disk Only) via RecoveryPasswordProtector (kein .bek)
  - JSON-Protokoll + Hash nach C:\elbcloud\diskseal\logs\disk-encryption
  - Audit-Report: HTML + Hash in ZIP nach C:\elbcloud\diskseal\reports\disk-encryption
  - VERPFLICHTEND: Nach 100% Verschlüsselung -> NTFS Quick-Format (für direkte Nutzbarkeit)

.REQUIREMENTS
  - Run as Administrator
  - BitLocker available
  - Out-GridView available (Windows PowerShell 5.1)

.SAFETY
  - System/Boot/OS disks excluded (best effort)
  - Destruktive Schritte erfordern Tipp-Bestätigung:
      - FORMAT X
      - INIT DISK N
      - RESET X
      - POSTFORMAT X
  - Bei Leer-/Falscheingabe wird NICHT abgebrochen, sondern erneut abgefragt.
  - Abbruch erfolgt nur über den Abbrechen-Button im Dialog.
#>

[CmdletBinding()]
param(
  [Parameter()]
  [string]$LogRoot = "C:\elbcloud\diskseal\logs\disk-encryption",

  [Parameter()]
  [string]$ReportsRoot = "C:\elbcloud\diskseal\reports\disk-encryption",

  [Parameter()]
  [ValidateSet("XtsAes128","XtsAes256")]
  [string]$EncryptionMethod = "XtsAes256",

  # Max wait time for "wait until fully encrypted" in minutes (mandatory post-format depends on this)
  [Parameter()]
  [ValidateRange(1, 43200)]
  [int]$MaxWaitMinutes = 720
)

# --- Quiet host: no console output/noise ---
$VerbosePreference      = "SilentlyContinue"
$InformationPreference  = "SilentlyContinue"
$WarningPreference      = "SilentlyContinue"
$ProgressPreference     = "SilentlyContinue"
$ErrorActionPreference  = "Stop"

# ----------------- Global State -----------------
$script:DiskWasPreparedByTool = $false
$script:PreparedDiskNumber = $null
$script:finalSuccess = $false
$script:finalSuccessMessage = ""
$script:lastProtocolPath = $null
$script:lastZipPath = $null
$script:lastMountPoint = $null

# ----------------- Helpers -----------------

function Assert-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw "Bitte PowerShell als Administrator starten." }
}

function Ensure-Folder([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Assert-OutGridView {
  if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
    throw "Out-GridView nicht verfügbar. Bitte in Windows PowerShell 5.1 ausführen."
  }
}

function Wait-VolumeReady {
  param(
    [Parameter(Mandatory)][string]$MountPoint,
    [int]$Retries = 30,
    [int]$DelaySeconds = 1
  )
  $dl = $MountPoint.TrimEnd(':')
  for ($i=0; $i -lt $Retries; $i++) {
    try {
      $v = Get-Volume -DriveLetter $dl -ErrorAction Stop
      if ($v -and $v.FileSystemType -and $v.DriveLetter) { return $v }
    } catch { }
    Start-Sleep -Seconds $DelaySeconds
  }
  throw "Volume $MountPoint nicht bereit (Get-Volume stabilisiert sich nicht)."
}

function Show-SuccessDialog {
  param(
    [Parameter(Mandatory)][string]$MountPoint,
    [Parameter(Mandatory)][string]$ProtocolPath,
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$Message
  )
  Add-Type -AssemblyName System.Windows.Forms
  $text = @"
$Message

Target: $MountPoint

JSON Protocol:
$ProtocolPath

Report ZIP:
$ZipPath

Hinweis:
Es wird kein Recovery Secret gespeichert oder angezeigt (RecoveryPasswordProtector).
"@
  [System.Windows.Forms.MessageBox]::Show($text, "elbcloud DiskSeal – Erfolg", "OK", "Information") | Out-Null
}

function Show-ErrorDialog {
  param([Parameter(Mandatory)][string]$Message)
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.MessageBox]::Show($Message, "elbcloud DiskSeal – Fehler", "OK", "Error") | Out-Null
}

function Get-SystemEvidence {
  $os   = Get-CimInstance Win32_OperatingSystem
  $bios = Get-CimInstance Win32_BIOS
  $cs   = Get-CimInstance Win32_ComputerSystem

  [pscustomobject]@{
    Hostname     = $env:COMPUTERNAME
    OS           = "$($os.Caption) ($($os.Version))"
    Manufacturer = $cs.Manufacturer
    Model        = $cs.Model
    BIOSSerial   = $bios.SerialNumber
  }
}

function Get-VolumeMap {
  param([string]$MountPoint)

  $driveLetter = $MountPoint.TrimEnd(':')
  $vol  = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
  $part = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
  $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop

  [pscustomobject]@{
    Volume = $vol
    Partition = $part
    Disk = $disk
  }
}

function Get-DiskIdentityEvidence {
  param([int]$DiskNumber)

  $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
  $w32  = Get-CimInstance Win32_DiskDrive | Where-Object { $_.Index -eq $DiskNumber } | Select-Object -First 1

  $phys = $null
  try { $phys = Get-PhysicalDisk | Where-Object { $_.FriendlyName -eq $disk.FriendlyName } | Select-Object -First 1 } catch { }

  [pscustomobject]@{
    DiskNumber            = $disk.Number
    DiskFriendlyName      = $disk.FriendlyName
    DiskSizeBytes         = $disk.Size
    DiskBusType           = $disk.BusType
    DiskPartitionStyle    = $disk.PartitionStyle
    DiskOperationalStatus = $disk.OperationalStatus
    DiskIsBoot            = $disk.IsBoot
    DiskIsSystem          = $disk.IsSystem
    DiskIsReadOnly        = $disk.IsReadOnly

    GetDisk_UniqueId      = $disk.UniqueId
    GetDisk_SerialNumber  = $disk.SerialNumber

    Win32_Model           = $w32.Model
    Win32_SerialNumber    = $w32.SerialNumber
    Win32_PNPDeviceId     = $w32.PNPDeviceID

    PhysicalDisk_Serial   = $phys.SerialNumber
    PhysicalDisk_UniqueId = $phys.UniqueId
    PhysicalDisk_MediaType= $phys.MediaType
    PhysicalDisk_CanPool  = $phys.CanPool
  }
}

function Get-VolumeEvidence {
  param([string]$MountPoint)

  $m = Get-VolumeMap -MountPoint $MountPoint
  $vol  = $m.Volume
  $part = $m.Partition
  $disk = $m.Disk

  [pscustomobject]@{
    MountPoint        = $MountPoint
    DriveLetter       = $vol.DriveLetter
    FileSystemLabel   = $vol.FileSystemLabel
    FileSystemType    = $vol.FileSystemType
    HealthStatus      = $vol.HealthStatus
    OperationalStatus = $vol.OperationalStatus
    SizeRemaining     = $vol.SizeRemaining
    Size              = $vol.Size

    DiskNumber        = $disk.Number
    PartitionNumber   = $part.PartitionNumber

    DiskIdentity      = (Get-DiskIdentityEvidence -DiskNumber $disk.Number)
  }
}

function Write-ProtocolJson($Protocol, [string]$Path) {
  Ensure-Folder (Split-Path -Parent $Path)
  $Protocol | ConvertTo-Json -Depth 60 | Set-Content -Path $Path -Encoding UTF8
  $hash = Get-FileHash -Path $Path -Algorithm SHA256
  Set-Content -Path ($Path + ".sha256") -Value $hash.Hash -Encoding ASCII
}

function Write-HashFile {
  param([Parameter(Mandatory)][string]$FilePath)
  $h = Get-FileHash -Path $FilePath -Algorithm SHA256
  Set-Content -Path ($FilePath + ".sha256") -Value $h.Hash -Encoding ASCII
}

function New-AuditHtmlReport {
  param(
    [Parameter(Mandatory)]$Protocol,
    [Parameter(Mandatory)][string]$JsonPath,
    [Parameter(Mandatory)][string]$HtmlPath
  )

  Ensure-Folder (Split-Path -Parent $HtmlPath)

  $jsonHash = (Get-FileHash -Path $JsonPath -Algorithm SHA256).Hash
  $di = $Protocol.Target.Evidence.DiskIdentity
  $statusClass = if ($Protocol.Result.Status -eq "Success") { "ok" } else { "fail" }

  $targetType = $Protocol.Target.TargetType
  $targetId   = $Protocol.Target.TargetId

  $html = @"
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>elbcloud DiskSeal – Audit Report</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; font-size: 12px; margin: 28px; }
  h1 { font-size: 20px; margin: 0 0 6px 0; }
  h2 { font-size: 14px; margin: 18px 0 6px 0; }
  .meta { color: #444; margin-bottom: 14px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
  th { background: #f3f3f3; text-align: left; width: 32%; }
  .ok { color: #0b6; font-weight: 700; }
  .fail { color: #b00; font-weight: 700; }
  .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
  .footer { margin-top: 18px; font-size: 10px; color: #666; }
</style>
</head>
<body>

<h1>elbcloud DiskSeal – Audit Report</h1>
<div class="meta">
  <div><b>Report-ID:</b> <span class="mono">$($Protocol.ReportId)</span></div>
  <div><b>Ticket-ID:</b> <span class="mono">$($Protocol.TicketId)</span></div>
  <div><b>Operator:</b> $($Protocol.Operator)</div>
  <div><b>Status:</b> <span class="$statusClass">$($Protocol.Result.Status)</span></div>
</div>

<h2>Zeiten</h2>
<table>
  <tr><th>Start (Local)</th><td class="mono">$($Protocol.StartLocal)</td></tr>
  <tr><th>Start (UTC)</th><td class="mono">$($Protocol.StartUtc)</td></tr>
  <tr><th>Ende (Local)</th><td class="mono">$($Protocol.EndLocal)</td></tr>
  <tr><th>Ende (UTC)</th><td class="mono">$($Protocol.EndUtc)</td></tr>
  <tr><th>Dauer (Sekunden)</th><td class="mono">$($Protocol.DurationSeconds)</td></tr>
</table>

<h2>System</h2>
<table>
  <tr><th>Hostname</th><td class="mono">$($Protocol.System.Hostname)</td></tr>
  <tr><th>OS</th><td>$($Protocol.System.OS)</td></tr>
  <tr><th>Hersteller / Modell</th><td>$($Protocol.System.Manufacturer) / $($Protocol.System.Model)</td></tr>
  <tr><th>BIOS Serial</th><td class="mono">$($Protocol.System.BIOSSerial)</td></tr>
</table>

<h2>Target</h2>
<table>
  <tr><th>Target Type</th><td class="mono">$targetType</td></tr>
  <tr><th>Target ID</th><td class="mono">$targetId</td></tr>
  <tr><th>MountPoint</th><td class="mono">$($Protocol.Target.MountPoint)</td></tr>
  <tr><th>Dateisystem</th><td class="mono">$($Protocol.Target.Evidence.FileSystemType)</td></tr>
  <tr><th>Label</th><td class="mono">$($Protocol.Target.Evidence.FileSystemLabel)</td></tr>
  <tr><th>DiskNumber / Partition</th><td class="mono">$($Protocol.Target.Evidence.DiskNumber) / $($Protocol.Target.Evidence.PartitionNumber)</td></tr>
  <tr><th>Bus / Größe (Bytes)</th><td class="mono">$($di.DiskBusType) / $($di.DiskSizeBytes)</td></tr>
  <tr><th>Modell (Win32)</th><td class="mono">$($di.Win32_Model)</td></tr>
  <tr><th>Seriennummern (best effort)</th>
      <td class="mono">
        Get-Disk Serial: $($di.GetDisk_SerialNumber)<br>
        Win32 Serial: $($di.Win32_SerialNumber)<br>
        PhysicalDisk Serial: $($di.PhysicalDisk_Serial)
      </td></tr>
  <tr><th>Unique IDs</th>
      <td class="mono">
        Get-Disk UniqueId: $($di.GetDisk_UniqueId)<br>
        PhysicalDisk UniqueId: $($di.PhysicalDisk_UniqueId)
      </td></tr>
  <tr><th>PNP Device ID</th><td class="mono">$($di.Win32_PNPDeviceId)</td></tr>
</table>

<h2>Verschlüsselung</h2>
<table>
  <tr><th>Scope</th><td class="mono">$($Protocol.Encryption.Scope)</td></tr>
  <tr><th>Method</th><td class="mono">$($Protocol.Encryption.Method)</td></tr>
  <tr><th>Recovery Password ProtectorId</th><td class="mono">$($Protocol.RecoveryPassword.ProtectorId)</td></tr>
  <tr><th>Secret gespeichert/angezeigt</th><td class="mono">Persisted=$($Protocol.RecoveryPassword.Persisted) / Displayed=$($Protocol.RecoveryPassword.WasDisplayedToOperator)</td></tr>
</table>

<h2>Post-Process</h2>
<table>
  <tr><th>Post-Format (NTFS Quick Format)</th><td class="mono">$($Protocol.PostProcess.PostFormatMandatory)</td></tr>
  <tr><th>Post-Format Ergebnis</th><td class="mono">$($Protocol.PostProcess.PostFormatResult)</td></tr>
</table>

<h2>Ergebnis</h2>
<table>
  <tr><th>Message</th><td>$($Protocol.Result.Message)</td></tr>
  <tr><th>Error</th><td class="mono">$(if($Protocol.Result.Error){$Protocol.Result.Error.ExceptionType + " – " + $Protocol.Result.Error.Message}else{'-'})</td></tr>
</table>

<h2>Integrität</h2>
<table>
  <tr><th>JSON-Protokoll</th><td class="mono">$JsonPath</td></tr>
  <tr><th>SHA256(JSON)</th><td class="mono">$jsonHash</td></tr>
</table>

<div class="footer">
  Tool: elbcloud DiskSeal v$($Protocol.Tool.Version) • Report-ID <span class="mono">$($Protocol.ReportId)</span>
</div>

</body>
</html>
"@

  Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}

function New-ReportZip {
  param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$HtmlPath
  )

  Ensure-Folder (Split-Path -Parent $ZipPath)

  $hashPath = "$HtmlPath.sha256"
  if (-not (Test-Path $HtmlPath)) { throw "HTML report not found: $HtmlPath" }
  if (-not (Test-Path $hashPath)) { throw "HTML hash not found: $hashPath" }

  $tempZipDir = Join-Path $env:TEMP ("DiskSealZip-" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $tempZipDir | Out-Null

  Copy-Item $HtmlPath (Join-Path $tempZipDir "report.html") -Force
  Copy-Item $hashPath (Join-Path $tempZipDir "report.html.sha256") -Force

  @"
elbcloud DiskSeal – Audit Report

Inhalt:
- report.html        : Audit-Report (menschenlesbar)
- report.html.sha256 : SHA-256 Hash zur Integritätsprüfung

Verifikation:
certutil -hashfile report.html SHA256
Vergleiche Ausgabe mit report.html.sha256

Hinweis:
Die Integrität des JSON-Protokolls ist im report.html dokumentiert (SHA256(JSON)).
"@ | Set-Content (Join-Path $tempZipDir "README.txt") -Encoding UTF8

  Compress-Archive -Path (Join-Path $tempZipDir "*") -DestinationPath $ZipPath -Force
  Remove-Item $tempZipDir -Recurse -Force
}

# ----------------- Confirmation GUI (FIXED) -----------------

function Show-ConfirmTextDialog {
  param(
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$Message
  )

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $form = New-Object System.Windows.Forms.Form
  $form.Text = $Title
  $form.Size = New-Object System.Drawing.Size(640, 320)
  $form.StartPosition = "CenterScreen"
  $form.FormBorderStyle = "FixedDialog"
  $form.MaximizeBox = $false
  $form.MinimizeBox = $false
  $form.Topmost = $true

  $font = New-Object System.Drawing.Font("Segoe UI", 10)

  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Location = New-Object System.Drawing.Point(16, 16)
  $lbl.Size = New-Object System.Drawing.Size(600, 180)
  $lbl.Font = $font
  $lbl.Text = $Message

  $txt = New-Object System.Windows.Forms.TextBox
  $txt.Location = New-Object System.Drawing.Point(16, 205)
  $txt.Size = New-Object System.Drawing.Size(600, 25)
  $txt.Font = $font

  $btnOk = New-Object System.Windows.Forms.Button
  $btnOk.Text = "OK"
  $btnOk.Location = New-Object System.Drawing.Point(430, 240)
  $btnOk.Size = New-Object System.Drawing.Size(90, 32)
  $btnOk.Font = $font
  $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK

  $btnCancel = New-Object System.Windows.Forms.Button
  $btnCancel.Text = "Abbrechen"
  $btnCancel.Location = New-Object System.Drawing.Point(526, 240)
  $btnCancel.Size = New-Object System.Drawing.Size(90, 32)
  $btnCancel.Font = $font
  $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

  $form.Controls.AddRange(@($lbl, $txt, $btnOk, $btnCancel))
  $form.AcceptButton = $btnOk
  $form.CancelButton = $btnCancel

  $dialog = $form.ShowDialog()

  if ($dialog -eq [System.Windows.Forms.DialogResult]::Cancel) {
    return [pscustomobject]@{ Canceled = $true; Text = $null }
  }

  return [pscustomobject]@{ Canceled = $false; Text = $txt.Text }
}

function Confirm-DestructiveAction {
  param(
    [Parameter(Mandatory)][ValidateSet("FORMAT","INIT","RESET","POSTFORMAT")][string]$Mode,
    [Parameter(Mandatory)][string]$TargetLabel
  )

  Add-Type -AssemblyName System.Windows.Forms

  switch ($Mode) {
    "FORMAT" {
      $expected = "FORMAT $TargetLabel"
      $msg = "ACHTUNG: Schnellformatierung nach NTFS löscht ALLE Daten auf $TargetLabel.`n`n" +
             "Zum Bestätigen bitte exakt eintippen:`n$expected`n`n" +
             "Abbrechen = keine Aktion."
    }
    "INIT" {
      $expected = "INIT DISK $TargetLabel"
      $msg = "ACHTUNG: Datenträger (Disk $TargetLabel) wird vorbereitet:`n" +
             "- (falls RAW) GPT initialisieren`n" +
             "- ALLE Partitionen entfernen`n" +
             "- 1 Partition erstellen (Max) + Laufwerksbuchstabe`n" +
             "- Schnellformat NTFS`n`n" +
             "DESTRUKTIV: Vorhandene Daten/Partitionen gehen verloren.`n`n" +
             "Zum Bestätigen bitte exakt eintippen:`n$expected"
    }
    "RESET" {
      $expected = "RESET $TargetLabel"
      $msg = "HINWEIS: $TargetLabel ist bereits BitLocker-verschlüsselt.`n" +
             "DiskSeal setzt das Volume durch NTFS-Quick-Format zurück und startet dann den Prozess neu.`n`n" +
             "ACHTUNG: Alle Daten auf $TargetLabel gehen verloren.`n`n" +
             "Zum Bestätigen bitte exakt eintippen:`n$expected"
    }
    "POSTFORMAT" {
      $expected = "POSTFORMAT $TargetLabel"
      $msg = "VERPFLICHTEND: Nach vollständiger Verschlüsselung wird $TargetLabel schnell nach NTFS formatiert, " +
             "damit das Medium direkt wieder nutzbar ist.`n`n" +
             "Zum Bestätigen bitte exakt eintippen:`n$expected"
    }
  }

  while ($true) {
    $dlg = Show-ConfirmTextDialog -Title "elbcloud DiskSeal – Bestätigung" -Message $msg
    if ($dlg.Canceled) { return $false }

    $typed = ""
    if ($null -ne $dlg.Text) { $typed = $dlg.Text.Trim() }

    if ([string]::IsNullOrWhiteSpace($typed)) {
      [System.Windows.Forms.MessageBox]::Show(
        "Eingabe ist leer. Bitte den Bestätigungstext exakt eingeben.",
        "elbcloud DiskSeal – Hinweis",
        "OK",
        "Warning"
      ) | Out-Null
      continue
    }

    if ($typed -eq $expected) { return $true }

    [System.Windows.Forms.MessageBox]::Show(
      "Eingabe stimmt nicht überein.`n`nErwartet:`n$expected`n`nEingegeben:`n$typed`n`nBitte erneut versuchen.",
      "elbcloud DiskSeal – Vertippt",
      "OK",
      "Warning"
    ) | Out-Null
  }
}

# ----------------- File system / disk handling -----------------

function Ensure-SupportedFileSystemOrFormat {
  param([string]$MountPoint)

  if ($script:DiskWasPreparedByTool) {
    $null = Wait-VolumeReady -MountPoint $MountPoint
    return "NTFS"
  }

  $supported = @("NTFS","FAT16","FAT32","exFAT")
  $v = Wait-VolumeReady -MountPoint $MountPoint
  $fs = $v.FileSystemType
  if ($supported -contains $fs) { return $fs }

  if (-not (Confirm-DestructiveAction -Mode "FORMAT" -TargetLabel $MountPoint.TrimEnd(':'))) {
    throw "Formatting canceled by operator. Aborting."
  }

  Format-Volume -DriveLetter $MountPoint.TrimEnd(':') -FileSystem NTFS -NewFileSystemLabel "DISKSEAL" -Confirm:$false -Force | Out-Null
  $null = Wait-VolumeReady -MountPoint $MountPoint
  return "NTFS"
}

function Get-EligibleVolumeRows {
  $osDrive = ($env:SystemDrive).TrimEnd('\')

  $vols = Get-BitLockerVolume | Where-Object {
    $_.MountPoint -and $_.MountPoint -match "^[A-Z]:$"
  } | Where-Object {
    $_.MountPoint -ne $osDrive -and
    -not $_.VolumeType.ToString().Contains("OperatingSystem") -and
    -not $_.VolumeType.ToString().Contains("System") -and
    -not $_.VolumeType.ToString().Contains("Boot")
  }

  foreach ($v in $vols) {
    $fs = $null; $diskNo = $null; $label = $null
    try {
      $vol = Get-Volume -DriveLetter $v.MountPoint.TrimEnd(':')
      $fs = $vol.FileSystemType
      $label = $vol.FileSystemLabel
      $diskNo = (Get-Partition -DriveLetter $v.MountPoint.TrimEnd(':') | Select-Object -First 1).DiskNumber
    } catch { }

    [pscustomobject]@{
      Type             = "Volume"
      TargetId         = $v.MountPoint
      MountPoint       = $v.MountPoint
      DiskNumber       = $diskNo
      PartitionStyle   = $null
      OperationalStatus= $null
      IsReadOnly       = $null
      FileSystem       = $fs
      Label            = $label
      VolumeStatus     = $v.VolumeStatus
      ProtectionStatus = $v.ProtectionStatus
      SizeGB           = [math]::Round(($v.CapacityGB), 2)
      FriendlyName     = $null
      BusType          = $null
    }
  }
}

function Get-EligibleNonSystemDiskRows {
  $disks = Get-Disk | Where-Object {
    -not $_.IsSystem -and -not $_.IsBoot -and
    $_.OperationalStatus -ne "No Media"
  }

  foreach ($d in $disks) {
    $parts = @()
    try { $parts = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue } catch { }

    $hasDriveLetter = $false
    foreach ($p in $parts) { if ($p.DriveLetter) { $hasDriveLetter = $true; break } }

    $isCandidate =
      ($d.PartitionStyle -eq "RAW") -or
      (($d.PartitionStyle -ne "RAW") -and -not $hasDriveLetter) -or
      ($d.OperationalStatus -eq "Offline") -or
      ($d.IsReadOnly -eq $true)

    if (-not $isCandidate) { continue }

    [pscustomobject]@{
      Type             = "Disk"
      TargetId         = "$($d.Number)"
      MountPoint       = $null
      DiskNumber       = $d.Number
      PartitionStyle   = $d.PartitionStyle
      OperationalStatus= $d.OperationalStatus
      IsReadOnly       = $d.IsReadOnly
      FileSystem       = if ($d.PartitionStyle -eq "RAW") { "RAW" } else { "" }
      Label            = $null
      VolumeStatus     = "N/A"
      ProtectionStatus = "N/A"
      SizeGB           = [math]::Round(($d.Size/1GB), 2)
      FriendlyName     = $d.FriendlyName
      BusType          = $d.BusType
    }
  }
}

function Prepare-DiskToNtfsVolume {
  param([Parameter(Mandatory)][int]$DiskNumber)

  $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop

  if ($disk.IsSystem -or $disk.IsBoot) { throw "Refusing to touch system/boot disk: $DiskNumber" }
  if ($disk.OperationalStatus -eq "Offline") { throw "Disk $DiskNumber is Offline. Bring it Online first." }
  if ($disk.IsReadOnly) { throw "Disk $DiskNumber is ReadOnly. Remove ReadOnly first." }

  if ($disk.PartitionStyle -eq "RAW") {
    Initialize-Disk -Number $DiskNumber -PartitionStyle GPT -ErrorAction Stop | Out-Null
  }

  $parts = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue
  foreach ($p in $parts) {
    try { Remove-Partition -DiskNumber $DiskNumber -PartitionNumber $p.PartitionNumber -Confirm:$false -ErrorAction Stop | Out-Null } catch { }
  }

  $part = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
  Format-Volume -Partition $part -FileSystem NTFS -NewFileSystemLabel "DISKSEAL" -Confirm:$false -Force | Out-Null

  $mount = ($part.DriveLetter + ":")
  $null = Wait-VolumeReady -MountPoint $mount

  $script:DiskWasPreparedByTool = $true
  $script:PreparedDiskNumber = $DiskNumber

  return $mount
}

function Wait-ForBitLockerFullyEncrypted {
  param(
    [Parameter(Mandatory)][string]$MountPoint,
    [int]$MaxMinutes = 720
  )

  $deadline = (Get-Date).AddMinutes($MaxMinutes)
  while ((Get-Date) -lt $deadline) {
    $b = Get-BitLockerVolume -MountPoint $MountPoint
    if ($b.VolumeStatus -eq "FullyEncrypted" -or ($b.EncryptionPercentage -ge 100)) {
      return $true
    }
    Start-Sleep -Seconds 10
  }
  return $false
}

# ----------------- Input GUI -----------------

function Show-DiskSealInputDialog {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "elbcloud DiskSeal – Eingaben"
  $form.Size = New-Object System.Drawing.Size(720, 360)
  $form.StartPosition = "CenterScreen"
  $form.FormBorderStyle = "FixedDialog"
  $form.MaximizeBox = $false
  $form.MinimizeBox = $false
  $form.Topmost = $true

  $font = New-Object System.Drawing.Font("Segoe UI", 10)

  $lblTicket = New-Object System.Windows.Forms.Label
  $lblTicket.Text = "Ticket-ID:"
  $lblTicket.Location = New-Object System.Drawing.Point(20, 20)
  $lblTicket.Size = New-Object System.Drawing.Size(120, 25)
  $lblTicket.Font = $font

  $txtTicket = New-Object System.Windows.Forms.TextBox
  $txtTicket.Location = New-Object System.Drawing.Point(160, 20)
  $txtTicket.Size = New-Object System.Drawing.Size(520, 25)
  $txtTicket.Font = $font

  $lblOperator = New-Object System.Windows.Forms.Label
  $lblOperator.Text = "Operator (Vorname Nachname):"
  $lblOperator.Location = New-Object System.Drawing.Point(20, 60)
  $lblOperator.Size = New-Object System.Drawing.Size(340, 25)
  $lblOperator.Font = $font

  $txtOperator = New-Object System.Windows.Forms.TextBox
  $txtOperator.Location = New-Object System.Drawing.Point(20, 90)
  $txtOperator.Size = New-Object System.Drawing.Size(660, 25)
  $txtOperator.Font = $font

  $grpScope = New-Object System.Windows.Forms.GroupBox
  $grpScope.Text = "Verschlüsselungsmodus"
  $grpScope.Location = New-Object System.Drawing.Point(20, 130)
  $grpScope.Size = New-Object System.Drawing.Size(660, 85)
  $grpScope.Font = $font

  $rbFull = New-Object System.Windows.Forms.RadioButton
  $rbFull.Text = "Full (kompletter Datenträger – erforderlich, um auch Alt-Daten abzudecken)"
  $rbFull.Location = New-Object System.Drawing.Point(15, 35)
  $rbFull.Size = New-Object System.Drawing.Size(630, 25)
  $rbFull.Font = $font
  $rbFull.Checked = $true
  $rbFull.Enabled = $false

  $grpScope.Controls.AddRange(@($rbFull))

  $chkAllowDiskPrep = New-Object System.Windows.Forms.CheckBox
  $chkAllowDiskPrep.Text = "Disk-Preparation erlauben (RAW/ohne Buchstaben → INIT + NTFS, DESTRUKTIV!)"
  $chkAllowDiskPrep.Location = New-Object System.Drawing.Point(20, 225)
  $chkAllowDiskPrep.Size = New-Object System.Drawing.Size(660, 25)
  $chkAllowDiskPrep.Font = $font
  $chkAllowDiskPrep.Checked = $true

  $lblMandatory = New-Object System.Windows.Forms.Label
  $lblMandatory.Text = "Hinweis: Nach 100% Verschlüsselung wird verpflichtend ein NTFS-Quick-Format ausgeführt (für direkte Nutzbarkeit)."
  $lblMandatory.Location = New-Object System.Drawing.Point(20, 255)
  $lblMandatory.Size = New-Object System.Drawing.Size(660, 40)
  $lblMandatory.Font = New-Object System.Drawing.Font("Segoe UI", 9)
  $lblMandatory.ForeColor = [System.Drawing.Color]::FromArgb(80,80,80)

  $btnOk = New-Object System.Windows.Forms.Button
  $btnOk.Text = "Weiter"
  $btnOk.Location = New-Object System.Drawing.Point(500, 300)
  $btnOk.Size = New-Object System.Drawing.Size(85, 32)
  $btnOk.Font = $font

  $btnCancel = New-Object System.Windows.Forms.Button
  $btnCancel.Text = "Abbrechen"
  $btnCancel.Location = New-Object System.Drawing.Point(595, 300)
  $btnCancel.Size = New-Object System.Drawing.Size(85, 32)
  $btnCancel.Font = $font

  $form.Controls.AddRange(@(
    $lblTicket, $txtTicket,
    $lblOperator, $txtOperator,
    $grpScope, $chkAllowDiskPrep,
    $lblMandatory,
    $btnOk, $btnCancel
  ))
  $form.AcceptButton = $btnOk
  $form.CancelButton = $btnCancel

  $script:result = $null

  $btnOk.Add_Click({
    $ticket = $txtTicket.Text.Trim()
    $op = $txtOperator.Text.Trim()

    if ([string]::IsNullOrWhiteSpace($ticket)) {
      [System.Windows.Forms.MessageBox]::Show("Bitte Ticket-ID angeben.", "DiskSeal", "OK", "Warning") | Out-Null
      return
    }

    $tokens = $op -split "\s+" | Where-Object { $_ -ne "" }
    if ($tokens.Count -lt 2) {
      [System.Windows.Forms.MessageBox]::Show("Bitte Operator als 'Vorname Nachname' angeben.", "DiskSeal", "OK", "Warning") | Out-Null
      return
    }

    $script:result = [pscustomobject]@{
      TicketId = $ticket
      OperatorName = $op
      EncryptionScope = "Full"
      AllowDiskPreparation = [bool]$chkAllowDiskPrep.Checked
    }

    $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Close()
  })

  $btnCancel.Add_Click({
    $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Close()
  })

  $dialog = $form.ShowDialog()
  if ($dialog -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
  return $script:result
}

# ----------------- Main -----------------

Assert-Admin
Assert-OutGridView
Ensure-Folder $LogRoot
Ensure-Folder $ReportsRoot

$input = Show-DiskSealInputDialog
if (-not $input) { return }

$ticketId        = $input.TicketId
$operatorName    = $input.OperatorName
$encryptionScope = $input.EncryptionScope
$allowDiskPrep   = $input.AllowDiskPreparation

# Build selection list
$rows = @()
$rows += Get-EligibleVolumeRows
if ($allowDiskPrep) { $rows += Get-EligibleNonSystemDiskRows }

if (-not $rows -or $rows.Count -eq 0) {
  Show-ErrorDialog -Message "Keine geeigneten Volumes/Disks gefunden."
  return
}

$selected = $rows | Out-GridView -Title "elbcloud DiskSeal – Auswahl: Volume (X:) oder Disk (RAW/ohne Buchstaben)" -PassThru
if (-not $selected) { return }

$targetType = $selected.Type
$targetId   = $selected.TargetId
$mount      = $null

try {
  if ($targetType -eq "Volume") {
    $mount = $selected.MountPoint
  }
  elseif ($targetType -eq "Disk") {
    if (-not (Confirm-DestructiveAction -Mode "INIT" -TargetLabel $selected.DiskNumber)) { return }
    $mount = Prepare-DiskToNtfsVolume -DiskNumber $selected.DiskNumber
  }
  else {
    throw "Unknown selection type."
  }

  if (-not $mount) { return }

  # Extra OS drive exclusion
  if ($mount -eq ($env:SystemDrive).TrimEnd('\')) { throw "Selected target resolves to OS drive. Aborting." }

  $script:lastMountPoint = $mount

  $start    = Get-Date
  $stamp    = $start.ToString("yyyyMMdd-HHmmss")
  $computer = $env:COMPUTERNAME
  $reportId = [guid]::NewGuid().ToString()

  $protocolPath = Join-Path $LogRoot "DISKSEAL-ENCRYPT-$computer-$($mount.Replace(':',''))-$ticketId-$stamp.json"
  $reportBase   = "DISKSEAL-REPORT-$computer-$($mount.Replace(':',''))-$ticketId-$stamp"
  $htmlPath     = Join-Path $LogRoot ($reportBase + ".html")   # temp; will be zipped
  $zipPath      = Join-Path $ReportsRoot ($reportBase + ".zip")

  $script:lastProtocolPath = $protocolPath
  $script:lastZipPath = $zipPath

  $protocol = @{
    Tool = @{
      Name    = "elbcloud DiskSeal"
      Version = "1.14"
      Purpose = "BitLocker encryption (RecoveryPasswordProtector, no secret persistence) + audit report + mandatory post-format for usability"
    }
    ReportId     = $reportId
    TicketId     = $ticketId
    Operator     = $operatorName
    Encryption   = @{
      Scope  = $encryptionScope
      Method = $EncryptionMethod
    }
    Target       = @{
      TargetType = $targetType
      TargetId   = $targetId
      MountPoint = $mount
      Evidence   = $null
    }
    PostProcess  = @{
      PostFormatMandatory = $true
      PostFormatResult    = "NotStarted"
    }
    RecoveryPassword = @{
      ProtectorId            = $null
      WasDisplayedToOperator = $false
      Persisted              = $false
    }
    StartLocal   = $start.ToString("o")
    StartUtc     = $start.ToUniversalTime().ToString("o")
    System       = (Get-SystemEvidence)
    Result       = @{
      Status  = "Started"
      Message = ""
      Error   = $null
    }
  }

  # Pre-log
  $protocol.Target.Evidence = Get-VolumeEvidence -MountPoint $mount
  Write-ProtocolJson -Protocol $protocol -Path $protocolPath

  # Ensure supported FS; will not prompt if tool prepared the disk
  $fsFinal = Ensure-SupportedFileSystemOrFormat -MountPoint $mount
  $protocol.Target.Evidence = Get-VolumeEvidence -MountPoint $mount
  $protocol.Target.Evidence | Add-Member -NotePropertyName FileSystemFinal -NotePropertyValue $fsFinal -Force
  Write-ProtocolJson -Protocol $protocol -Path $protocolPath

  # --- BitLocker enable or reset+enable ---
  $current = Get-BitLockerVolume -MountPoint $mount

  if ($current.ProtectionStatus -eq "On") {
    if (-not (Confirm-DestructiveAction -Mode "RESET" -TargetLabel $mount.TrimEnd(':'))) { return }

    $protocol.Result.Message = "BitLocker war bereits aktiv – Volume wurde per NTFS-Quick-Format zurückgesetzt, Prozess wird neu gestartet."
    Write-ProtocolJson -Protocol $protocol -Path $protocolPath

    Format-Volume -DriveLetter $mount.TrimEnd(':') -FileSystem NTFS -NewFileSystemLabel "DISKSEAL" -Confirm:$false -Force | Out-Null
    $null = Wait-VolumeReady -MountPoint $mount

    $current = Get-BitLockerVolume -MountPoint $mount
  }

  $usedSpaceOnly = ($encryptionScope -eq "UsedSpaceOnly")

  if ($usedSpaceOnly) {
    $null = Enable-BitLocker -MountPoint $mount `
      -EncryptionMethod $EncryptionMethod `
      -UsedSpaceOnly `
      -RecoveryPasswordProtector `
      -SkipHardwareTest `
      -ErrorAction Stop
  } else {
    $null = Enable-BitLocker -MountPoint $mount `
      -EncryptionMethod $EncryptionMethod `
      -RecoveryPasswordProtector `
      -SkipHardwareTest `
      -ErrorAction Stop
  }

  # Capture protector info (best effort) – DO NOT persist secret
  $after = Get-BitLockerVolume -MountPoint $mount
  $rp = $after.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -First 1
  if ($rp) { $protocol.RecoveryPassword.ProtectorId = $rp.KeyProtectorId }
  $protocol.RecoveryPassword.WasDisplayedToOperator = $false
  $protocol.RecoveryPassword.Persisted = $false

  # --- Mandatory post-format confirmation (before waiting) ---
  if (-not (Confirm-DestructiveAction -Mode "POSTFORMAT" -TargetLabel $mount.TrimEnd(':'))) {
    $protocol.PostProcess.PostFormatResult = "CanceledByOperator"
    throw "Mandatory post-format canceled by operator."
  }

  $protocol.PostProcess.PostFormatResult = "WaitingForEncryption"
  Write-ProtocolJson -Protocol $protocol -Path $protocolPath

  $ok = Wait-ForBitLockerFullyEncrypted -MountPoint $mount -MaxMinutes $MaxWaitMinutes
  if (-not $ok) {
    $protocol.PostProcess.PostFormatResult = "TimeoutWaitingForEncryption"
    throw "Timeout waiting for full encryption ($MaxWaitMinutes minutes)."
  }

  $protocol.PostProcess.PostFormatResult = "Formatting"
  Write-ProtocolJson -Protocol $protocol -Path $protocolPath

  # Quick format NTFS for direct usability
  Format-Volume -DriveLetter $mount.TrimEnd(':') -FileSystem NTFS -NewFileSystemLabel "DISKSEAL" -Confirm:$false -Force | Out-Null
  $null = Wait-VolumeReady -MountPoint $mount
  $protocol.PostProcess.PostFormatResult = "Success"

  $protocol.Result.Status  = "Success"
  $protocol.Result.Message = "DiskSeal abgeschlossen: BitLocker-Verschlüsselung (RecoveryPasswordProtector, kein Secret gespeichert/angezeigt) und NTFS Quick-Format nach 100% Verschlüsselung ausgeführt."
  $script:finalSuccess = $true
  $script:finalSuccessMessage = $protocol.Result.Message

  $end = Get-Date
  $protocol["EndLocal"] = $end.ToString("o")
  $protocol["EndUtc"]   = $end.ToUniversalTime().ToString("o")
  $protocol["DurationSeconds"] = [math]::Round(($end - $start).TotalSeconds, 2)
  try { $protocol.Target.Evidence = Get-VolumeEvidence -MountPoint $mount } catch { }

  # Final JSON + hash
  Write-ProtocolJson -Protocol $protocol -Path $protocolPath

  # HTML + hash + ZIP
  New-AuditHtmlReport -Protocol $protocol -JsonPath $protocolPath -HtmlPath $htmlPath
  Write-HashFile -FilePath $htmlPath
  New-ReportZip -ZipPath $zipPath -HtmlPath $htmlPath

  # cleanup standalone html/hash (already inside ZIP)
  try {
    Remove-Item $htmlPath -Force -ErrorAction SilentlyContinue
    Remove-Item ($htmlPath + ".sha256") -Force -ErrorAction SilentlyContinue
  } catch { }

  if ($script:finalSuccess) {
    Show-SuccessDialog -MountPoint $mount -ProtocolPath $protocolPath -ZipPath $zipPath -Message $script:finalSuccessMessage
  }
}
catch {
  $msg = $_.Exception.Message
  try { Show-ErrorDialog -Message ("DiskSeal Fehler:`n`n" + $msg) } catch { }
  return
}
