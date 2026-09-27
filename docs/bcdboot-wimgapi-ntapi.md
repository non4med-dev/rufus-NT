# Reproducing bcdboot.exe, wimgapi.dll and ntapi.dll

| File | Tested versions | Original SHA-256 | Patched SHA-256 |
| --- | --- | --- | --- |
| `bcdboot.exe` | 6.2.8102.0     (x86) | `415ca8c856a2336f6fad3a84f44d9e25cc593aafcbea4d5e70478480836ac148` | `c668dabb7c89a43cf47935c48b17319cae6e8f927508d0422b411a8dfa82fa41` |
| `wimgapi.dll` | 6.1.7601.24546 (x86) | `bdc0da45afc830fdebda4475e988bd511c0e1ca8d35563f0f6e189f0374db1a9` | `5cf9fd71c88e200244cd35566c819e915a61e1d53e9326cc602cc67f2c0ef6de` |
| `wimgapi.dll` | 6.1.7601.17514 (x86) | `01d5535cb22991309fedaba85f1a55e6605d0f1cfb3d0b464d32e1ff31b4ba32` | `87bbd01704e5eb9f36f1c1887819c8d088c8188682e107a6d5d122b1b1a82ed3` |
| `ntapi.dll`   | /res/wintogo/ntapi | n/a                                                          | `86507bee2a263fd27037a5dd069072c943f79786a1baad6fb394fabadbd57418` |

## Automated

1. Obtain bcdboot.exe from Windows 8 DP, I used [this one here](https://archive.org/details/Windows8DeveloperPreview32bit)
   and wimgapi.dll from either SP1 RTM or ESU updated Windows 7 (anything in-between should be patched manually)
2. Open the command prompt in rufus-nt\docs\
3. Insert the paths and run:

   ```text
   python patcher.py --bcdboot X:\path\to\original\bcdboot.exe --wimgapi X:\path\to\original\wimgapi.dll --output-dir X:\save\patched\files\here
   ```

4. Build `ntapi.dll` from an **x86 Native Tools Command Prompt for Visual Studio 2022**:

   ```text
   cd "res\wintogo\ntapi"
   build.cmd
   ```

5. Copy the built ntapi.dll beside `bcdboot.exe` (and `wimgapi.dll`)

6. Verify all three SHA-256 values

   ```text
   python patcher.py --verify-only --output-dir X:\patched\files\directory
   ```

## What is changed in `bcdboot.exe`

The source is x86 `bcdboot.exe` from Windows 8 DP 6.2.8102.0

1. The `KERNEL32.dll`, `NTDLL.dll` and `ADVAPI32.dll` imports are redirected to `NTAPI.dll`.
2. `TimeDateStamp` and `ForwarderChain` are cleared in every import descriptor.
3. Every Import Address Table is restored from its Original First Thunk table, including the terminating null entry.
4. The PE Bound Import data-directory entry is cleared.
5. The PE checksum is recomputed. The expected checksum field is `0x0002F7BF`.

## What is changed in `wimgapi.dll`

The only thing changed are the import discriptors:<br>
from `KERNEL32.dll` to `NTAPI.dll`<br>
from `ADVAPI32.dll` to `NTAPI.dll`<br>
It must be done with a hex editor as CFF_Explorer won't change everything

## What is `ntapi.dll`

ntapi.dll is a simple API shim made specifically for these two files.<br>
It includes extra APIs from a previous experiment in which I tried to patch Windows 8.1's wimgapi.dll,<br>
which turned out to be a total flop; it was utterly slow and unstable.

Every already-existing import gets redirected, every missing one gets a good-enough-ish implementation. 

The reason for it being an API shim and not some crazy reverse-engineering project is
that Microsoft's binaries are closed-source, and I don't want any legal trouble.

## Manual reproduction, for review only

The automated script is the authoritative method. To independently reproduce
the work in a PE editor:

1. Verify the SHA-256 hashes of both files
2. For `bcdboot.exe`, replace the three import DLL names listed above.
3. For every `IMAGE_IMPORT_DESCRIPTOR`, zero `TimeDateStamp` and `ForwarderChain`.
4. Copy every 32-bit thunk value from `OriginalFirstThunk` to `FirstThunk`, up to and including its zero terminator.
5. Redirect the corresponding bound-import name strings and zero the Bound Import data-directory RVA and size.
6. Recompute the PE checksum and confirm the final SHA-256.
7. For `wimgapi.dll`, rename only the `KERNEL32.dll` and `ADVAPI32.dll` import
   strings in a hex editor, preserve the existing checksum field, and confirm the final hash.
