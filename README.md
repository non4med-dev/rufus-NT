# Rufus-NT
### The Reliable USB Formatting Utility, for anything NT (with USB support)

![Rufus-NT-Banner](https://raw.githubusercontent.com/non4med-dev/Rufus-NT/master/res/banner.png)

The original project can be found [under this link.](https://github.com/pbatard/rufus)

## Introduction

Rufus-NT is a fork of Rufus designed to run natively on every NT-based Windows system with USB support.<br>
The main targets are Windows NT 4.0 - Windows 7, and each have their own set of fixes.<br>

## Features
  
- **Everything** that Rufus already has to offer<br>
- ISO downloading fully functional on Windows 7 again
- Fixes for VPNs, outdated drivers, unupdated systems
- GRUB and Syslinux embedded for offline systems
- Experimental GPT partitioning (for pre-Vista systems)
- Lots of custom dialogs, translations, UI optimizations
- Improved error messages to understand whats going on
- Drag-and-drop installation of diskcopy.dll (MS-DOS)
- Increased performance over last-supported versions<br>
  (buffer optimizations, simpler write mechanisms, wimlib)
- Written with security and transparency in mind as well
- Actively maintained with upstream commits,<br>
  selectively ones that actually benefit older systems

## Compilation

Use Visual Studio 2022 and then invoke the `.sln` <br>

rufusnt.sln builds the regular build<br>
rufusnt_noembed.sln builds without /res/embed<br>

UPX 3.91 with `--lzma --best` compression is recommended 

<details>
<summary><strong>Documentation</strong></summary>
<br>

Building without /res/embed saves ~900kb space after UPX and is only recommended for Windows 7+

Rufus-NT includes `wimgapi.dll` (6.1.7601.24546) and `bcdboot.exe` (6.2.8102) patched with an API shim `ntapi.dll` to maintain a fallback to wimlib and to provide Windows To Go creation functionality on pre-XP systems<br>

Prerequisites for patching are either python3 (for automated) or a PE editor (for manual).<br>

You can read more about them specifically [here](https://github.com/non4med-dev/rufus-NT/blob/master/docs/bcdboot-wimgapi-ntapi.md)<br>

If you'd like to understand the changes done in Rufus-NT in more detail, take a look at [this audit here](https://github.com/non4med-dev/rufus-NT/blob/master/docs/code-audit.md)

Certain parts of this project (i.e. API-shims, patcher.py, localization) were AI assisted. It isn't slop though, don't worry. Anyone is free to read the code and suggest fixes, changes or different ways of handling things.

</details>

#### Visual Studio

Rufus is an OSI compliant Open Source project. You are entitled to
download and use the *freely available* [Visual Studio Community Edition](https://www.visualstudio.com/vs/community/)
to build, run or develop for Rufus. As per the Visual Studio Community Edition license,
this applies regardless of whether you are an individual or a corporate user.

Rufus is 100% [Free Software](https://www.gnu.org/philosophy/free-sw) ([GPL v3](https://www.gnu.org/licenses/gpl-3.0))
All credits for the original project go to [Pete Batard](https://github.com/pbatard) and all other contributors.
Rufus-Legacy is an unofficial fork and is not affiliated with, endorsed by, or otherwise associated with the upstream Rufus project.
