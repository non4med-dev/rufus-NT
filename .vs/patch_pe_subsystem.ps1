# VS2022 cannot link directly for the Windows NT 4.0 subsystem, sooo...
# Hold my beer son

param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][int]$Major,
    [Parameter(Mandatory = $true)][int]$Minor
)

$bytes = [System.IO.File]::ReadAllBytes($Path)
if (($bytes.Length -lt 0x100) -or ($bytes[0] -ne 0x4D) -or ($bytes[1] -ne 0x5A)) {
    throw "Target is not a valid DOS/PE image: $Path"
}

$peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
if (($peOffset -lt 0) -or (($peOffset + 0x58) -gt $bytes.Length) -or
    ($bytes[$peOffset] -ne 0x50) -or ($bytes[$peOffset + 1] -ne 0x45) -or
    ($bytes[$peOffset + 2] -ne 0) -or ($bytes[$peOffset + 3] -ne 0)) {
    throw "Target contains an invalid PE header: $Path"
}

$optionalHeader = $peOffset + 24
$magic = [System.BitConverter]::ToUInt16($bytes, $optionalHeader)
if (($magic -ne 0x10B) -and ($magic -ne 0x20B)) {
    throw "Target contains an unsupported PE optional header: $Path"
}

$Major = 4
$Minor = 0

# PE32 and PE32+ use the same offsets for these fields
[System.Array]::Copy([System.BitConverter]::GetBytes([UInt16]$Major), 0, $bytes, $optionalHeader + 40, 2)
[System.Array]::Copy([System.BitConverter]::GetBytes([UInt16]$Minor), 0, $bytes, $optionalHeader + 42, 2)
[System.Array]::Copy([System.BitConverter]::GetBytes([UInt16]$Major), 0, $bytes, $optionalHeader + 48, 2)
[System.Array]::Copy([System.BitConverter]::GetBytes([UInt16]$Minor), 0, $bytes, $optionalHeader + 50, 2)
[System.IO.File]::WriteAllBytes($Path, $bytes)
Write-Host "PE operating-system and subsystem versions set to $Major.$Minor for $Path"
