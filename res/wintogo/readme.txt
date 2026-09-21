ntapi is an api shim, thats about it, it redirects native APIs to existing ones,
and implements good enough-ish workarounds for missing ones

it was created SPECIFICALLY for bcdboot and wimgapi,
originally for Windows 8.1's wimgapi which turned out to be a flop
and therefore, do not expect it to work with anything else

bcdboot had its import table changed to ntapi, and:
had this done for every import descriptor:

descriptor->TimeDateStamp = 0;

descriptor->ForwarderChain = 0;
had its PE bound import directory disabled:
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:

VirtualAddress = 0

Size = 0

and had:

INT / OriginalFirstThunk:
    RtlInitUnicodeString

IAT / FirstThunk:
    6A242548

changed to:

INT:
    IMAGE_IMPORT_BY_NAME -> "RtlInitUnicodeString"

IAT:
    IMAGE_IMPORT_BY_NAME -> "RtlInitUnicodeString"


if youre trying to recreate it, dont. but good luck anyways. whoever you are, youre gonna need it.

wimgapi was much simpler; 
all that had to be done was to change the import descriptors through a hex editor
cff explorer wasn't changing everything