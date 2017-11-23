/**********************************************************************
 *
 * StackWalker.cpp
 *
 *
 * History:
 *  2005-07-27   v1    - First public release on http://www.codeproject.com/
 *                       http://www.codeproject.com/threads/StackWalker.asp
 *  2005-07-28   v2    - Changed the params of the constructor and ShowCallstack
 *                       (to simplify the usage)
 *  2005-08-01   v3    - Changed to use 'CONTEXT_FULL' instead of CONTEXT_ALL
 *                       (should also be enough)
 *                     - Changed to compile correctly with the PSDK of VC7.0
 *                       (GetFileVersionInfoSizeA and GetFileVersionInfoA is wrongly defined:
 *                        it uses LPSTR instead of LPCSTR as first paremeter)
 *                     - Added declarations to support VC5/6 without using 'dbghelp.h'
 *                     - Added a 'pUserData' member to the ShowCallstack function and the
 *                       PReadProcessMemoryRoutine declaration (to pass some user-defined data,
 *                       which can be used in the readMemoryFunction-callback)
 *  2005-08-02   v4    - OnSymInit now also outputs the OS-Version by default
 *                     - Added example for doing an exception-callstack-walking in main.cpp
 *                       (thanks to owillebo: http://www.codeproject.com/script/profile/whos_who.asp?id=536268)
 *  2005-08-05   v5    - Removed most Lint (http://www.gimpel.com/) errors... thanks to Okko Willeboordse!
 *
 **********************************************************************/
#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#pragma comment(lib, "version.lib")  // for "VerQueryValue"
#include <boost\algorithm\string.hpp>
#include <boost\format.hpp>

#include "StackWalker.h"
using namespace std;



// If VC7 and later, then use the shipped 'dbghelp.h'-file
#if _MSC_VER >= 1300
#include <dbghelp.h>
#include "StackWalkerInternal.hpp"
#else
// inline the important dbghelp.h-declarations...
typedef enum
{
    SymNone = 0,
    SymCoff,
    SymCv,
    SymPdb,
    SymExport,
    SymDeferred,
    SymSym,
    SymDia,
    SymVirtual,
    NumSymTypes
} SYM_TYPE;
typedef struct _IMAGEHLP_LINE64
{
    DWORD   SizeOfStruct;           // set to sizeof(IMAGEHLP_LINE64)
    PVOID   Key;                    // internal
    DWORD   LineNumber;             // line number in file
    PCHAR   FileName;               // full filename
    DWORD64 Address;                // first instruction of line
} IMAGEHLP_LINE64, * PIMAGEHLP_LINE64;
typedef struct _IMAGEHLP_MODULE64
{
    DWORD       SizeOfStruct;           // set to sizeof(IMAGEHLP_MODULE64)
    DWORD64     BaseOfImage;            // base load address of module
    DWORD       ImageSize;              // virtual size of the loaded module
    DWORD       TimeDateStamp;          // date/time stamp from pe header
    DWORD       CheckSum;               // checksum from the pe header
    DWORD       NumSyms;                // number of symbols in the symbol table
    SYM_TYPE    SymType;                // type of symbols loaded
    CHAR        ModuleName[32];         // module name
    CHAR        ImageName[256];         // image name
    CHAR        LoadedImageName[256];   // symbol file name
} IMAGEHLP_MODULE64, * PIMAGEHLP_MODULE64;
typedef struct _IMAGEHLP_SYMBOL64
{
    DWORD   SizeOfStruct;           // set to sizeof(IMAGEHLP_SYMBOL64)
    DWORD64 Address;                // virtual address including dll base address
    DWORD   Size;                   // estimated size of symbol, can be zero
    DWORD   Flags;                  // info about the symbols, see the SYMF defines
    DWORD   MaxNameLength;          // maximum size of symbol name in 'Name'
    CHAR    Name[1];                // symbol name (null terminated string)
} IMAGEHLP_SYMBOL64, * PIMAGEHLP_SYMBOL64;
typedef enum
{
    AddrMode1616,
    AddrMode1632,
    AddrModeReal,
    AddrModeFlat
} ADDRESS_MODE;
typedef struct _tagADDRESS64
{
    DWORD64         Offset;
    WORD            Segment;
    ADDRESS_MODE    Mode;
} ADDRESS64, * LPADDRESS64;
typedef struct _KDHELP64
{
    DWORD64 Thread;
    DWORD   ThCallbackStack;
    DWORD   ThCallbackBStore;
    DWORD   NextCallback;
    DWORD   FramePointer;
    DWORD64 KiCallUserMode;
    DWORD64 KeUserCallbackDispatcher;
    DWORD64 SystemRangeStart;
    DWORD64 Reserved[8];
} KDHELP64, * PKDHELP64;
typedef struct _tagSTACKFRAME64
{
    ADDRESS64   AddrPC;               // program counter
    ADDRESS64   AddrReturn;           // return address
    ADDRESS64   AddrFrame;            // frame pointer
    ADDRESS64   AddrStack;            // stack pointer
    ADDRESS64   AddrBStore;           // backing store pointer
    PVOID       FuncTableEntry;       // pointer to pdata/fpo or NULL
    DWORD64     Params[4];            // possible arguments to the function
    BOOL        Far;                  // WOW far call
    BOOL        Virtual;              // is this a virtual frame?
    DWORD64     Reserved[3];
    KDHELP64    KdHelp;
} STACKFRAME64, * LPSTACKFRAME64;
typedef
BOOL
(
__stdcall *PREAD_PROCESS_MEMORY_ROUTINE64)(
    HANDLE      hProcess,
    DWORD64     qwBaseAddress,
    PVOID       lpBuffer,
    DWORD       nSize,
    LPDWORD     lpNumberOfBytesRead);
typedef
PVOID
(
__stdcall *PFUNCTION_TABLE_ACCESS_ROUTINE64)(
    HANDLE  hProcess,
    DWORD64 AddrBase);
typedef
DWORD64
(
__stdcall *PGET_MODULE_BASE_ROUTINE64)(
    HANDLE  hProcess,
    DWORD64 Address);
typedef
DWORD64
(
__stdcall *PTRANSLATE_ADDRESS_ROUTINE64)(
    HANDLE    hProcess,
    HANDLE    hThread,
    LPADDRESS64 lpaddr);
#define SYMOPT_CASE_INSENSITIVE         0x00000001
#define SYMOPT_UNDNAME                  0x00000002
#define SYMOPT_DEFERRED_LOADS           0x00000004
#define SYMOPT_NO_CPP                   0x00000008
#define SYMOPT_LOAD_LINES               0x00000010
#define SYMOPT_OMAP_FIND_NEAREST        0x00000020
#define SYMOPT_LOAD_ANYTHING            0x00000040
#define SYMOPT_IGNORE_CVREC             0x00000080
#define SYMOPT_NO_UNQUALIFIED_LOADS     0x00000100
#define SYMOPT_FAIL_CRITICAL_ERRORS     0x00000200
#define SYMOPT_EXACT_SYMBOLS            0x00000400
#define SYMOPT_ALLOW_ABSOLUTE_SYMBOLS   0x00000800
#define SYMOPT_IGNORE_NT_SYMPATH        0x00001000
#define SYMOPT_INCLUDE_32BIT_MODULES    0x00002000
#define SYMOPT_PUBLICS_ONLY             0x00004000
#define SYMOPT_NO_PUBLICS               0x00008000
#define SYMOPT_AUTO_PUBLICS             0x00010000
#define SYMOPT_NO_IMAGE_SEARCH          0x00020000
#define SYMOPT_SECURE                   0x00040000
#define SYMOPT_DEBUG                    0x80000000
#define UNDNAME_COMPLETE                 (0x0000)  // Enable full undecoration
#define UNDNAME_NAME_ONLY                (0x1000)  // Crack only the name for primary declaration;
#endif  // _MSC_VER < 1300

// Some missing defines (for VC5/6):
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif


// secure-CRT_functions are only available starting with VC8
#if _MSC_VER < 1400
#define strcpy_s strcpy
#define strcat_s(dst, len, src) strcat(dst, src)
#define _snprintf_s _snprintf
#define _tcscat_s _tcscat
#endif

// Normally it should be enough to use 'CONTEXT_FULL' (better would be 'CONTEXT_ALL')
#define USED_CONTEXT_FLAGS CONTEXT_FULL


// #############################################################
StackWalker::StackWalker(
    DWORD dwProcessId,
    HANDLE hProcess)
{
    this->m_options = OptionsAll;
    this->m_modulesLoaded = FALSE;
    this->m_hProcess = hProcess;
    this->m_sw = new StackWalkerInternal(this, this->m_hProcess);
    this->m_dwProcessId = dwProcessId;
    this->m_szSymPath = NULL;
}
StackWalker::StackWalker(
    int options,
    LPCSTR szSymPath,
    DWORD dwProcessId,
    HANDLE hProcess)
{
    this->m_options = options;
    this->m_modulesLoaded = FALSE;
    this->m_hProcess = hProcess;
    this->m_sw = new StackWalkerInternal(this, this->m_hProcess);
    this->m_dwProcessId = dwProcessId;
    if (szSymPath != NULL)
    {
        this->m_szSymPath = _strdup(szSymPath);
        this->m_options |= SymBuildPath;
    }
    else
        this->m_szSymPath = NULL;
}

StackWalker::~StackWalker()
{
    if (m_szSymPath != NULL)
        free(m_szSymPath);
    m_szSymPath = NULL;
    if (this->m_sw != NULL)
        delete this->m_sw;
    this->m_sw = NULL;
}

BOOL StackWalker::LoadModules()
{
    if (this->m_sw == NULL)
    {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    if (m_modulesLoaded != FALSE)
        return TRUE;
    // Build the sym-path:
    PCHAR   szSymPath = NULL;
    if ((this->m_options & SymBuildPath) != 0)
    {
        const size_t    nSymPathLen = 4096;
        szSymPath = (char*)malloc(nSymPathLen);
        if (szSymPath == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        szSymPath[0] = 0;
        // Now first add the (optional) provided sympath:
        if (this->m_szSymPath != NULL)
        {
            strcat_s(szSymPath, nSymPathLen, this->m_szSymPath);
            strcat_s(szSymPath, nSymPathLen, ";");
        }
        strcat_s(szSymPath, nSymPathLen, ".;");
        const size_t    nTempLen = 1024;
        char            szTemp[nTempLen];
        // Now add the current directory:
        if (GetCurrentDirectoryA(nTempLen, szTemp) > 0)
        {
            szTemp[nTempLen - 1] = 0;
            strcat_s(szSymPath, nSymPathLen, szTemp);
            strcat_s(szSymPath, nSymPathLen, ";");
        }
        // Now add the path for the main-module:
        if (GetModuleFileNameA(NULL, szTemp, nTempLen) > 0)
        {
            
            szTemp[nTempLen - 1] = 0;
            for (char* p = (szTemp + strlen(szTemp) - 1); p >= szTemp; --p)
            {
                // locate the rightmost path separator
                if ((*p == '\\') || (*p == '/') || (*p == ':'))
                {
                    *p = 0;
                    break;
                }
            }  // for (search for path separator...)
            if (strlen(szTemp) > 0)
            {
                //if (!boost::icontains(szSymPath, szTemp))
                {
                    strcat_s(szSymPath, nSymPathLen, szTemp);
                    strcat_s(szSymPath, nSymPathLen, "\\Symbol");
                    strcat_s(szSymPath, nSymPathLen, ";");
                }
                
            }
        }
        if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", szTemp, nTempLen) > 0)
        {
            szTemp[nTempLen - 1] = 0;
            strcat_s(szSymPath, nSymPathLen, szTemp);
            strcat_s(szSymPath, nSymPathLen, ";");
        }
        if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", szTemp, nTempLen) > 0)
        {
            szTemp[nTempLen - 1] = 0;
            strcat_s(szSymPath, nSymPathLen, szTemp);
            strcat_s(szSymPath, nSymPathLen, ";");
        }
        if (GetEnvironmentVariableA("SYSTEMROOT", szTemp, nTempLen) > 0)
        {
            szTemp[nTempLen - 1] = 0;
            strcat_s(szSymPath, nSymPathLen, szTemp);
            strcat_s(szSymPath, nSymPathLen, ";");
            // also add the "system32"-directory:
            strcat_s(szTemp, nTempLen, "\\system32");
            strcat_s(szSymPath, nSymPathLen, szTemp);
            strcat_s(szSymPath, nSymPathLen, ";");
        }
        if ((this->m_options & SymBuildPath) != 0)
        {
            if (GetEnvironmentVariableA("SYSTEMDRIVE", szTemp, nTempLen) > 0)
            {
                szTemp[nTempLen - 1] = 0;
                strcat_s(szSymPath, nSymPathLen, "SRV*");
                strcat_s(szSymPath, nSymPathLen, szTemp);
                strcat_s(szSymPath, nSymPathLen, "\\mss");
                strcat_s(szSymPath, nSymPathLen, "*http://msdl.microsoft.com/download/symbols;");
            }
            else
                strcat_s(szSymPath, nSymPathLen, "SRV*C:\\mss*http://msdl.microsoft.com/download/symbols;");
        }
    }
    // First Init the whole stuff...
    BOOL    bRet = this->m_sw->Init(szSymPath);
    if (szSymPath != NULL)
        free(szSymPath);
    szSymPath = NULL;
    if (bRet == FALSE)
    {
        this->OnDbgHelpErr("Error while initializing dbghelp.dll", 0, 0);
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    bRet = this->m_sw->LoadModules(this->m_hProcess, this->m_dwProcessId);
    if (bRet != FALSE)
        m_modulesLoaded = TRUE;
    return bRet;
}


// The following is used to pass the "userData"-Pointer to the user-provided readMemoryFunction
// This has to be done due to a problem with the "hProcess"-parameter in x64...
// Because this class is in no case multi-threading-enabled (because of the limitations
// of dbghelp.dll) it is "safe" to use a static-variable
static StackWalker::PReadProcessMemoryRoutine   s_readMemoryFunction = NULL;
static LPVOID                                   s_readMemoryFunction_UserData = NULL;

BOOL StackWalker::ShowCallstack(
    HANDLE hThread,
    const CONTEXT* context,
    PReadProcessMemoryRoutine readMemoryFunction,
    LPVOID pUserData)
{
    CONTEXT c;
    CallstackEntry                              csEntry;
    IMAGEHLP_SYMBOL64*                          pSym = NULL;
    StackWalkerInternal::IMAGEHLP_MODULE64_V2   Module;
    IMAGEHLP_LINE64                             Line;
    int                                         frameNum;
    if (m_modulesLoaded == FALSE)
        this->LoadModules();  // ignore the result...
    if (this->m_sw->m_hDbhHelp == NULL)
    {
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    s_readMemoryFunction = readMemoryFunction;
    s_readMemoryFunction_UserData = pUserData;
    if (context == NULL)
    {
        // If no context is provided, capture the context
        if (hThread == GetCurrentThread())
        {
            GET_CURRENT_CONTEXT(c, USED_CONTEXT_FLAGS);
        }
        else
        {
            SuspendThread(hThread);
            memset(&c, 0, sizeof(CONTEXT));
            c.ContextFlags = USED_CONTEXT_FLAGS;
            if (GetThreadContext(hThread, &c) == FALSE)
            {
                ResumeThread(hThread);
                return FALSE;
            }
        }
    }
    else
        c = *context;

    //////////////////////////////////////////////////////////////////////////
    outStream << endl << endl;

    // init STACKFRAME for first call
    STACKFRAME64    s; // in/out stackframe
    memset(&s, 0, sizeof(s));
    DWORD   imageType;
#ifdef _M_IX86
    // normally, call ImageNtHeader() and use machine info from PE header
    imageType = IMAGE_FILE_MACHINE_I386;
    s.AddrPC.Offset = c.Eip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.Ebp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.Esp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
    imageType = IMAGE_FILE_MACHINE_AMD64;
    s.AddrPC.Offset = c.Rip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.Rsp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.Rsp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
    imageType = IMAGE_FILE_MACHINE_IA64;
    s.AddrPC.Offset = c.StIIP;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.IntSp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrBStore.Offset = c.RsBSP;
    s.AddrBStore.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.IntSp;
    s.AddrStack.Mode = AddrModeFlat;
#else
#error "Platform not supported!"
#endif
    pSym = (IMAGEHLP_SYMBOL64 *)malloc(sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
    if (!pSym)
        goto cleanup;  // not enough memory...
    memset(pSym, 0, sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
    pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    pSym->MaxNameLength = STACKWALK_MAX_NAMELEN;
    memset(&Line, 0, sizeof(Line));
    Line.SizeOfStruct = sizeof(Line);
    memset(&Module, 0, sizeof(Module));
    Module.SizeOfStruct = sizeof(Module);
    for (frameNum = 0; ; ++frameNum)
    {
        // get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
        // if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
        // assume that either you are done, or that the stack is so hosed that the next
        // deeper frame could not be found.
        // CONTEXT need not to be suplied if imageTyp is IMAGE_FILE_MACHINE_I386!
        if (!this->m_sw->pStackWalk64(imageType, this->m_hProcess, hThread, &s, &c, myReadProcMem, this->m_sw->pSymFunctionTableAccess64, this->m_sw->pSymGetModuleBase64, NULL))
        {
            this->OnDbgHelpErr("StackWalk64", GetLastError(), s.AddrPC.Offset);
            break;
        }
        csEntry.offset = s.AddrPC.Offset;
        csEntry.name[0] = 0;
        csEntry.undName[0] = 0;
        csEntry.undFullName[0] = 0;
        csEntry.offsetFromSmybol = 0;
        csEntry.offsetFromLine = 0;
        csEntry.lineFileName[0] = 0;
        csEntry.lineNumber = 0;
        csEntry.loadedImageName[0] = 0;
        csEntry.moduleName[0] = 0;
        if (s.AddrPC.Offset == s.AddrReturn.Offset)
        {
            this->OnDbgHelpErr("StackWalk64-Endless-Callstack!", 0, s.AddrPC.Offset);
            break;
        }
        if (s.AddrPC.Offset != 0)
        {
            // we seem to have a valid PC
            // show procedure info (SymGetSymFromAddr64())
            if (this->m_sw->pSymGetSymFromAddr64(this->m_hProcess, s.AddrPC.Offset, &(csEntry.offsetFromSmybol), pSym) != FALSE)
            {
                // TODO: Mache dies sicher...!
                strcpy_s(csEntry.name, pSym->Name);
                // UnDecorateSymbolName()
                this->m_sw->pUnDecorateSymbolName(pSym->Name, csEntry.undName, STACKWALK_MAX_NAMELEN, UNDNAME_NAME_ONLY);
                this->m_sw->pUnDecorateSymbolName(pSym->Name, csEntry.undFullName, STACKWALK_MAX_NAMELEN, UNDNAME_COMPLETE);
            }
            else
            {
                this->OnDbgHelpErr("SymGetSymFromAddr64", GetLastError(), s.AddrPC.Offset);
            }
            // show line number info, NT5.0-method (SymGetLineFromAddr64())
            if (this->m_sw->pSymGetLineFromAddr64 != NULL)
            {
                // yes, we have SymGetLineFromAddr64()
                if (this->m_sw->pSymGetLineFromAddr64(this->m_hProcess, s.AddrPC.Offset, &(csEntry.offsetFromLine), &Line) != FALSE)
                {
                    csEntry.lineNumber = Line.LineNumber;
                    // TODO: Mache dies sicher...!
                    strcpy_s(csEntry.lineFileName, Line.FileName);
                }
                else
                {
                    this->OnDbgHelpErr("SymGetLineFromAddr64", GetLastError(), s.AddrPC.Offset);
                }
            } // yes, we have SymGetLineFromAddr64()
            // show module info (SymGetModuleInfo64())
            if (this->m_sw->GetModuleInfo(this->m_hProcess, s.AddrPC.Offset, &Module) != FALSE)
            {
                // got module info OK
                switch (Module.SymType)
                {
                case SymNone:
                    csEntry.symTypeString = "-nosymbols-";
                    break;
                case SymCoff:
                    csEntry.symTypeString = "COFF";
                    break;
                case SymCv:
                    csEntry.symTypeString = "CV";
                    break;
                case SymPdb:
                    csEntry.symTypeString = "PDB";
                    break;
                case SymExport:
                    csEntry.symTypeString = "-exported-";
                    break;
                case SymDeferred:
                    csEntry.symTypeString = "-deferred-";
                    break;
                case SymSym:
                    csEntry.symTypeString = "SYM";
                    break;
#if API_VERSION_NUMBER >= 9
                case SymDia:
                    csEntry.symTypeString = "DIA";
                    break;
#endif
                case 8:
                    //SymVirtual:
                    csEntry.symTypeString = "Virtual";
                    break;
                default:
                    //_snprintf( ty, sizeof ty, "symtype=%ld", (long) Module.SymType );
                    csEntry.symTypeString = NULL;
                    break;
                }
                // TODO: Mache dies sicher...!
                strcpy_s(csEntry.moduleName, Module.ModuleName);
                csEntry.baseOfImage = Module.BaseOfImage;
                strcpy_s(csEntry.loadedImageName, Module.LoadedImageName);
            } // got module info OK
            else
            {
                this->OnDbgHelpErr("SymGetModuleInfo64", GetLastError(), s.AddrPC.Offset);
            }
        } // we seem to have a valid PC
        CallstackEntryType  et = nextEntry;
        if (frameNum == 0)
            et = firstEntry;
        this->OnCallstackEntry(et, csEntry);
        if (s.AddrReturn.Offset == 0)
        {
            this->OnCallstackEntry(lastEntry, csEntry);
            SetLastError(ERROR_SUCCESS);
            break;
        }
    } // for ( frameNum )
    cleanup:
    if (pSym)
        free(pSym);
    if (context == NULL)
        ResumeThread(hThread);

    outStream << std::endl;
    return TRUE;
}

BOOL StackWalker::DumpCrash(
    PEXCEPTION_POINTERS pExceptionInfo,
    std::string strCrashpath)
{
    HANDLE  hFile = ::CreateFile(strCrashpath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        _MINIDUMP_EXCEPTION_INFORMATION exInfo;

        exInfo.ThreadId = ::GetCurrentThreadId();
        exInfo.ExceptionPointers = pExceptionInfo;
        exInfo.ClientPointers = TRUE;

        BOOL result = this->m_sw->pMiniDumpWriteDump(
            ::GetCurrentProcess(),
            ::GetCurrentProcessId(),
            hFile,
            MiniDumpWithDataSegs,
            &exInfo,
            0,
            0);

        ::CloseHandle(hFile);
    }
    return TRUE;
}

BOOL __stdcall StackWalker::myReadProcMem(
    HANDLE      hProcess,
    DWORD64     qwBaseAddress,
    PVOID       lpBuffer,
    DWORD       nSize,
    LPDWORD     lpNumberOfBytesRead)
{
    if (s_readMemoryFunction == NULL)
    {
        SIZE_T  st;
        BOOL    bRet = ReadProcessMemory(hProcess, (LPVOID)qwBaseAddress, lpBuffer, nSize, &st);
        *lpNumberOfBytesRead = (DWORD)st;
        //printf("ReadMemory: hProcess: %p, baseAddr: %p, buffer: %p, size: %d, read: %d, result: %d\n", hProcess, (LPVOID) qwBaseAddress, lpBuffer, nSize, (DWORD) st, (DWORD) bRet);
        return bRet;
    }
    else
    {
        return s_readMemoryFunction(hProcess, qwBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead, s_readMemoryFunction_UserData);
    }
}

void StackWalker::OnLoadModule(
    LPCSTR img,
    LPCSTR mod,
    DWORD64 baseAddr,
    DWORD size,
    DWORD result,
    LPCSTR symType,
    LPCSTR pdbName,
    ULONGLONG fileVersion)
{
	CHAR    buffer[STACKWALK_MAX_NAMELEN] = { 0 };
    if (fileVersion == 0)
        _snprintf_s(buffer, STACKWALK_MAX_NAMELEN
        , "%s:%s (%p), size: %d (result: %d), "//"SymType: '%s', PDB: '%s'"
        , img
        , mod
        , (LPVOID)baseAddr
        , size
        , result
        //, symType
        //, pdbName
        );
    else
    {
        DWORD   v4 = (DWORD)fileVersion & 0xFFFF;
        DWORD   v3 = (DWORD)(fileVersion >> 16) & 0xFFFF;
        DWORD   v2 = (DWORD)(fileVersion >> 32) & 0xFFFF;
        DWORD   v1 = (DWORD)(fileVersion >> 48) & 0xFFFF;
        _snprintf_s(buffer, STACKWALK_MAX_NAMELEN, 
        "%s:%s (%p), size: %d (result: %d), "
        //"SymType: '%s', PDB: '%s', "
        "fileVersion: %d.%d.%d.%d", 
            img, 
            mod, 
            (LPVOID)baseAddr, 
            size, 
            result, 
            //symType, 
            //pdbName, 
            v1, v2, v3, v4);
    }
    OnOutput(buffer);
}

void StackWalker::OnCallstackEntry(
    CallstackEntryType eType,
    CallstackEntry& entry)
{
    CHAR    buffer[STACKWALK_MAX_NAMELEN] = { 0 };
    if ((eType != lastEntry) && (entry.offset != 0))
    {
        if (entry.name[0] == 0)
            strcpy_s(entry.name, "(function-name not available)");
        if (entry.undName[0] != 0)
            strcpy_s(entry.name, entry.undName);
        if (entry.undFullName[0] != 0)
            strcpy_s(entry.name, entry.undFullName);
        if (entry.lineFileName[0] == 0)
        {
            strcpy_s(entry.lineFileName, "(filename not available)");
            if (entry.moduleName[0] == 0)
                strcpy_s(entry.moduleName, "(module-name not available)");
            _snprintf_s(buffer, STACKWALK_MAX_NAMELEN, "%p (%s): %s: %s", (LPVOID)entry.offset, entry.moduleName, entry.lineFileName, entry.name);
        }
        else
            _snprintf_s(buffer, STACKWALK_MAX_NAMELEN, "%s (%d): %s", entry.lineFileName, entry.lineNumber, entry.name);
        OnOutput(buffer);
    }
}

void StackWalker::OnDbgHelpErr(
    LPCSTR szFuncName,
    DWORD gle,
    DWORD64 addr)
{
    CHAR    buffer[STACKWALK_MAX_NAMELEN] = { 0 };
    _snprintf_s(buffer, STACKWALK_MAX_NAMELEN, "ERROR: %s, GetLastError: %d (Address: %p)", szFuncName, gle, (LPVOID)addr);
    OnOutput(buffer);
}

void StackWalker::OnSymInit(
    LPCSTR szSearchPath,
    DWORD symOptions,
    LPCSTR szUserName)
{
    TCHAR szGetComputerName[256] = { 0 };
    DWORD szSize;
    GetComputerName(szGetComputerName, &szSize);
    boost::format message("SymInit: "
        "\n\tSymbol-SearchPath: '%s', "
        "\n\tsymOptions: %d, "
        "\n\tUserName: '%s'"
        "\n\tComputerName: '%s'"
        );
    message % szSearchPath % symOptions % szUserName % szGetComputerName;

    OnOutput(message.str().c_str());;
    // Also display the OS-version
#if _MSC_VER <= 1200
    OSVERSIONINFOA  ver;
    ZeroMemory(&ver, sizeof(OSVERSIONINFOA));
    ver.dwOSVersionInfoSize = sizeof(ver);
    if (GetVersionExA(&ver) != FALSE)
    {
        _snprintf_s(buffer, STACKWALK_MAX_NAMELEN, "OS-Version: %d.%d.%d (%s)", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion);
        OnOutput(buffer);
    }
#else
    OSVERSIONINFOEXA    ver;
    ZeroMemory(&ver, sizeof(OSVERSIONINFOEXA));
    ver.dwOSVersionInfoSize = sizeof(ver);
    if (GetVersionExA((OSVERSIONINFOA *)&ver) != FALSE)
    {
        TCHAR buffer[256] = { 0 };
        _snprintf_s(buffer, 
            STACKWALK_MAX_NAMELEN, 
            "OS-Version: %d.%d.%d (%s) 0x%x-0x%x", 
            ver.dwMajorVersion, 
            ver.dwMinorVersion, 
            ver.dwBuildNumber, 
            ver.szCSDVersion, 
            ver.wSuiteMask, 
            ver.wProductType);
        OnOutput(buffer);
        OnOutput("\n");
        OnOutput("\n");
    }
#endif
}

void StackWalker::OnOutput(LPCSTR buffer)
{
    using namespace std;
    OutputDebugStringA(buffer);
    outStream << buffer << endl;
}
