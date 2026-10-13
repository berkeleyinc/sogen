// Stub implementations for oledlg.dll (the OLE common dialogs): they report success without
// showing anything, which is enough for applications that only need the imports to resolve.
#include <stdint.h>

__stdcall uintptr_t OleUIAddVerbMenuA(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7, uintptr_t a8)  // ordinal 1
{
    (void)(a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8);
    return 0;
}

__stdcall uintptr_t OleUICanConvertOrActivateAs(uintptr_t a0, uintptr_t a1, uintptr_t a2)  // ordinal 2
{
    (void)(a0 + a1 + a2);
    return 0;
}

__stdcall uintptr_t OleUIInsertObjectA(uintptr_t a0)  // ordinal 3
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIPasteSpecialA(uintptr_t a0)  // ordinal 4
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIEditLinksA(uintptr_t a0)  // ordinal 5
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIChangeIconA(uintptr_t a0)  // ordinal 6
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIConvertA(uintptr_t a0)  // ordinal 7
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIBusyA(uintptr_t a0)  // ordinal 8
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIUpdateLinksA(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3)  // ordinal 9
{
    (void)(a0 + a1 + a2 + a3);
    return 0;
}

__cdecl uintptr_t OleUIPromptUserA(uintptr_t a0, uintptr_t a1)  // ordinal 10
{
    (void)(a0 + a1);
    return 0;
}

__stdcall uintptr_t OleUIObjectPropertiesA(uintptr_t a0)  // ordinal 11
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIChangeSourceA(uintptr_t a0)  // ordinal 12
{
    (void)(a0);
    return 0;
}

__cdecl uintptr_t OleUIPromptUserW(uintptr_t a0, uintptr_t a1)  // ordinal 13
{
    (void)(a0 + a1);
    return 0;
}

__stdcall uintptr_t OleUIAddVerbMenuW(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7, uintptr_t a8)  // ordinal 14
{
    (void)(a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8);
    return 0;
}

__stdcall uintptr_t OleUIBusyW(uintptr_t a0)  // ordinal 15
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIChangeIconW(uintptr_t a0)  // ordinal 16
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIChangeSourceW(uintptr_t a0)  // ordinal 17
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIConvertW(uintptr_t a0)  // ordinal 18
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIEditLinksW(uintptr_t a0)  // ordinal 19
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIInsertObjectW(uintptr_t a0)  // ordinal 20
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIObjectPropertiesW(uintptr_t a0)  // ordinal 21
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIPasteSpecialW(uintptr_t a0)  // ordinal 22
{
    (void)(a0);
    return 0;
}

__stdcall uintptr_t OleUIUpdateLinksW(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3)  // ordinal 23
{
    (void)(a0 + a1 + a2 + a3);
    return 0;
}

