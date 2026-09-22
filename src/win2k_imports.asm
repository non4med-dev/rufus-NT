.386
.model flat
option casemap:none

EXTERN _W2K_DecodePointer@4:PROC
EXTERN _W2K_EncodePointer@4:PROC
EXTERN _W2K_GetModuleHandleExA@12:PROC
EXTERN _W2K_GetModuleHandleExW@12:PROC
EXTERN _W2K_InitializeSListHead@4:PROC
EXTERN _W2K_HeapQueryInformation@20:PROC
EXTERN _W2K_InterlockedFlushSList@4:PROC
EXTERN _W2K_InterlockedPushEntrySList@8:PROC

_DATA SEGMENT
PUBLIC __imp__DecodePointer@4
PUBLIC __imp__EncodePointer@4
PUBLIC __imp__GetModuleHandleExA@12
PUBLIC __imp__GetModuleHandleExW@12
PUBLIC __imp__InitializeSListHead@4
PUBLIC __imp__HeapQueryInformation@20
PUBLIC __imp__InterlockedFlushSList@4
PUBLIC __imp__InterlockedPushEntrySList@8

__imp__DecodePointer@4 DD OFFSET _W2K_DecodePointer@4
__imp__EncodePointer@4 DD OFFSET _W2K_EncodePointer@4
__imp__GetModuleHandleExA@12 DD OFFSET _W2K_GetModuleHandleExA@12
__imp__GetModuleHandleExW@12 DD OFFSET _W2K_GetModuleHandleExW@12
__imp__InitializeSListHead@4 DD OFFSET _W2K_InitializeSListHead@4
__imp__HeapQueryInformation@20 DD OFFSET _W2K_HeapQueryInformation@20
__imp__InterlockedFlushSList@4 DD OFFSET _W2K_InterlockedFlushSList@4
__imp__InterlockedPushEntrySList@8 DD OFFSET _W2K_InterlockedPushEntrySList@8
_DATA ENDS

END
