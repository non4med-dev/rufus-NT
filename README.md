# Rufus-NT
### The Reliable USB Formatting Utility, for anything NT (with USB support)

![Rufus-NT-Banner](https://raw.githubusercontent.com/non4med-dev/Rufus-NT/master/res/banner.png)

The original project can be found [under this link.](https://github.com/pbatard/rufus)

## Features
  
- Everything that [Rufus](https://github.com/pbatard/rufus/tree/v4.7) already has to offer<br>
  ... but on Windows versions no one sane would ever consider

| Windows Version | Formatting / Partitioning | Windows To Go | Disk Cloning | Networking | Localization |
| --- | --- | --- | --- | --- | --- |
| Windows 7      | Fully supported | Fully supported | VHD Only    | Fully supported | Fully supported |
| Windows Vista  | Fully supported | Fully supported | VHD Only    | Disabled        | Fully supported |
| Windows XP     | Fully supported | Fully supported | VHD Only    | Disabled        | No Arabic       |
| Windows 2000   | Fully supported | Fully supported | VHD Only    | Disabled        | No Arabic       |
| Windows NT 4.0 | Fully supported | Supported (?)   | Unsupported | Disabled        | Limited         |

- Specific fixes and optimizations for all systems
- Fido ISO downloading restored to Windows 7<br>
-> [Powershell 7.2](https://github.com/PowerShell/PowerShell/releases/tag/v7.2.24) is required<br>
- Fixes for VPNs, outdated drivers, unupdated systems
- GRUB and Syslinux embedded for offline use
- GPT partitioning for Windows NT4, XP and 2000
- Native, optimized, fully functional UI even on older systems
- Increased performance over last-supported versions (~15% on average)
- Actively maintained, selectively updated from upstream

## Documentation

Rufus-NT can be built as either `rufusnt.exe` or `rufusnt-noembed.exe` with the difference being not including /res/embed.<br>
That saves about 900kb after compression.<br>

Rufus-NT includes `wimgapi.dll` (6.1.7601.24546) and `bcdboot.exe` (6.2.8102) patched with the api-shim `ntapi.dll`.<br>

If you'd like to recreate the patches, understand how they work and what they do, look [here](https://github.com/non4med-dev/rufus-nt/docs/bcdboot-wimgapi-ntapi.md)<br>
Prerequisites are either python3 or a PE editor.<br>

Most changes up to Update 5 weren't properly documented, explained nor audited.<br>
I've tried my best at explaining everything in [this audit here](https://github.com/non4med-dev/rufus-nt/docs/code-audit-update5.md)

## Compilation

Use Visual Studio 2022 and then invoke the `.sln` <br>

UPX 3.91 with `--lzma --best` compression is recommended 

#### Visual Studio

Rufus is an OSI compliant Open Source project. You are entitled to
download and use the *freely available* [Visual Studio Community Edition](https://www.visualstudio.com/vs/community/)
to build, run or develop for Rufus. As per the Visual Studio Community Edition license,
this applies regardless of whether you are an individual or a corporate user.

Rufus is 100% [Free Software](https://www.gnu.org/philosophy/free-sw) ([GPL v3](https://www.gnu.org/licenses/gpl-3.0))
All credits for the original project go to [Pete Batard](https://github.com/pbatard) and all other contributors.
Rufus-Legacy is an unofficial fork and is not affiliated with, endorsed by, or otherwise associated with the upstream Rufus project.
