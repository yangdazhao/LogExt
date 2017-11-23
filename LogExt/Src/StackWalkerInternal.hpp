#pragma once

class StackWalker;

class StackWalkerInternal
{
public:
    StackWalkerInternal(
        StackWalker* parent,
        HANDLE hProcess)
        : pStackWalk64(NULL)
        , pSymFunctionTableAccess64(NULL)
        , pSymGetLineFromAddr64(NULL)
        , pSymGetModuleBase64(NULL)
        , pSymGetModuleInfo64(NULL)
        , pSymGetOptions(NULL)
        , pSymGetSymFromAddr64(NULL)
        , pSymInitialize(NULL)
        , pSymLoadModule64(NULL)
        , pSymSetOptions(NULL)
        , pUnDecorateSymbolName(NULL)
        , pSymGetSearchPath(NULL)
        , m_hDbhHelp(NULL)
    {
        m_parent = parent;
        pSymCleanup = NULL;
        m_hProcess = hProcess;
        m_szSymPath = NULL;
    }
    ~StackWalkerInternal()
    {
        if (pSymCleanup != NULL)
            pSymCleanup(m_hProcess);  // SymCleanup
        if (m_hDbhHelp != NULL)
            FreeLibrary(m_hDbhHelp);
        m_hDbhHelp = NULL;
        m_parent = NULL;
        if (m_szSymPath != NULL)
            free(m_szSymPath);
        m_szSymPath = NULL;
    }
    BOOL Init(
        LPCSTR szSymPath)
    {
        if (m_parent == NULL)
            return FALSE;
        // Dynamically load the Entry-Points for dbghelp.dll:
        // First try to load the newsest one from
        TCHAR   szTemp[4096] = { 0 };
        // But before wqe do this, we first check if the ".local" file exists
        if (::GetModuleFileName(NULL, szTemp, 4096) > 0)
        {
            _tcscat_s(szTemp, _T(".local"));
            if (GetFileAttributes(szTemp) == INVALID_FILE_ATTRIBUTES)
            {
                // ".local" file does not exist, so we can try to load the dbghelp.dll from the "Debugging Tools for Windows"
                if (GetEnvironmentVariable(_T("ProgramFiles"), szTemp, 4096) > 0)
                {
                    _tcscat_s(szTemp, _T("\\Debugging Tools for Windows\\dbghelp.dll"));
                    // now check if the file exists:
                    if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
                    {
                        m_hDbhHelp = LoadLibrary(szTemp);
                    }
                }
                // Still not found? Then try to load the 64-Bit version:
                if ((m_hDbhHelp == NULL) && (GetEnvironmentVariable(_T("ProgramFiles"), szTemp, 4096) > 0))
                {
                    _tcscat_s(szTemp, _T("\\Debugging Tools for Windows 64-Bit\\dbghelp.dll"));
                    if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
                    {
                        m_hDbhHelp = LoadLibrary(szTemp);
                    }
                }
            }
        }
        if (m_hDbhHelp == NULL)  // if not already loaded, try to load a default-one
            m_hDbhHelp = LoadLibrary(_T("dbghelp.dll"));
        if (m_hDbhHelp == NULL)
            return FALSE;
        pSymInitialize = (tSI)GetProcAddress(m_hDbhHelp, "SymInitialize");
        pSymCleanup = (tSC)GetProcAddress(m_hDbhHelp, "SymCleanup");
        pStackWalk64 = (tSW)GetProcAddress(m_hDbhHelp, "StackWalk64");
        pSymGetOptions = (tSGO)GetProcAddress(m_hDbhHelp, "SymGetOptions");
        pSymSetOptions = (tSSO)GetProcAddress(m_hDbhHelp, "SymSetOptions");
        pSymFunctionTableAccess64 = (tSFTA)GetProcAddress(m_hDbhHelp, "SymFunctionTableAccess64");
        pSymGetLineFromAddr64 = (tSGLFA)GetProcAddress(m_hDbhHelp, "SymGetLineFromAddr64");
        pSymGetModuleBase64 = (tSGMB)GetProcAddress(m_hDbhHelp, "SymGetModuleBase64");
        pSymGetModuleInfo64 = (tSGMI)GetProcAddress(m_hDbhHelp, "SymGetModuleInfo64");
        //pSGMI_V3 = (tSGMI_V3) GetProcAddress(m_hDbhHelp, "SymGetModuleInfo64" );
        pSymGetSymFromAddr64 = (tSGSFA)GetProcAddress(m_hDbhHelp, "SymGetSymFromAddr64");
        pUnDecorateSymbolName = (tUDSN)GetProcAddress(m_hDbhHelp, "UnDecorateSymbolName");
        pSymLoadModule64 = (tSLM)GetProcAddress(m_hDbhHelp, "SymLoadModule64");
        pSymGetSearchPath = (tSGSP)GetProcAddress(m_hDbhHelp, "SymGetSearchPath");
        pMiniDumpWriteDump = (tMDWD)GetProcAddress(m_hDbhHelp, "MiniDumpWriteDump");

        
        if (pSymCleanup == NULL || pSymFunctionTableAccess64 == NULL || pSymGetModuleBase64 == NULL || pSymGetModuleInfo64 == NULL || pSymGetOptions == NULL || pSymGetSymFromAddr64 == NULL || pSymInitialize == NULL || pSymSetOptions == NULL || pStackWalk64 == NULL || pUnDecorateSymbolName == NULL || pSymLoadModule64 == NULL)
        {
            FreeLibrary(m_hDbhHelp);
            m_hDbhHelp = NULL;
            pSymCleanup = NULL;
            return FALSE;
        }
        // SymInitialize
        if (szSymPath != NULL)
            m_szSymPath = _strdup(szSymPath);
        if (this->pSymInitialize(m_hProcess, m_szSymPath, FALSE) == FALSE)
            this->m_parent->OnDbgHelpErr("SymInitialize", GetLastError(), 0);
        DWORD           symOptions = this->pSymGetOptions();  // SymGetOptions
        symOptions |=   SYMOPT_LOAD_LINES;
        symOptions |=   SYMOPT_FAIL_CRITICAL_ERRORS;
        //symOptions |= SYMOPT_NO_PROMPTS;
        // SymSetOptions
        symOptions = this->pSymSetOptions(symOptions);
        char    buf[StackWalker::STACKWALK_MAX_NAMELEN] = { 0 };
        if (this->pSymGetSearchPath != NULL)
        {
            if (this->pSymGetSearchPath(m_hProcess, buf, StackWalker::STACKWALK_MAX_NAMELEN) == FALSE)
                this->m_parent->OnDbgHelpErr("SymGetSearchPath", GetLastError(), 0);
        }
        char    szUserName[1024] = { 0  };
        DWORD   dwSize = 1024;
        GetUserNameA(szUserName, &dwSize);
        this->m_parent->OnSymInit(buf, symOptions, szUserName);
        return TRUE;
    }

    StackWalker*                    m_parent;

    HMODULE     m_hDbhHelp;
    HANDLE      m_hProcess;
    LPSTR       m_szSymPath;

    typedef struct
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
    } IMAGEHLP_MODULE64_V2;


    // SymCleanup()
    typedef BOOL (__stdcall *tSC)(IN HANDLE hProcess);
    tSC     pSymCleanup;

    // SymFunctionTableAccess64()
    typedef PVOID (__stdcall *tSFTA)(HANDLE hProcess,DWORD64 AddrBase);
    tSFTA   pSymFunctionTableAccess64;

    // SymGetLineFromAddr64()
    typedef BOOL (__stdcall *tSGLFA)(HANDLE,DWORD64,PDWORD,PIMAGEHLP_LINE64);
    tSGLFA  pSymGetLineFromAddr64;

    // SymGetModuleBase64()
    typedef DWORD64 (__stdcall *tSGMB)(HANDLE,DWORD64);
    tSGMB   pSymGetModuleBase64;

    // SymGetModuleInfo64()
    typedef BOOL (__stdcall *tSGMI)(HANDLE ,DWORD64 ,IMAGEHLP_MODULE64_V2* );
    tSGMI   pSymGetModuleInfo64;

    //  // SymGetModuleInfo64()
    //  typedef BOOL (__stdcall *tSGMI_V3)( IN HANDLE hProcess, IN DWORD64 dwAddr, OUT IMAGEHLP_MODULE64_V3 *ModuleInfo );
    //  tSGMI_V3 pSGMI_V3;

    // SymGetOptions()
    typedef DWORD (__stdcall *tSGO)();
    tSGO    pSymGetOptions;

    // SymGetSymFromAddr64()
    typedef BOOL (__stdcall *tSGSFA)(HANDLE ,DWORD64 ,PDWORD64 ,PIMAGEHLP_SYMBOL64 );
    tSGSFA  pSymGetSymFromAddr64;

    // SymInitialize()
    typedef BOOL (__stdcall *tSI)(HANDLE ,PSTR ,BOOL );
    tSI     pSymInitialize;

    // SymLoadModule64()
    typedef DWORD64 (__stdcall *tSLM)(HANDLE ,HANDLE , PSTR ,PSTR ,DWORD64 ,DWORD );
    tSLM    pSymLoadModule64;

    // SymSetOptions()
    typedef DWORD (__stdcall *tSSO)(DWORD );
    tSSO    pSymSetOptions;

    // StackWalk64()
    typedef BOOL (__stdcall *tSW)(DWORD ,HANDLE ,HANDLE ,LPSTACKFRAME64 ,PVOID ,PREAD_PROCESS_MEMORY_ROUTINE64 ,PFUNCTION_TABLE_ACCESS_ROUTINE64 ,PGET_MODULE_BASE_ROUTINE64 ,PTRANSLATE_ADDRESS_ROUTINE64 );
    tSW     pStackWalk64;

    // UnDecorateSymbolName()
    typedef DWORD (__stdcall WINAPI *tUDSN)(PCSTR ,PSTR ,DWORD ,DWORD );
    tUDSN   pUnDecorateSymbolName;

    typedef BOOL (__stdcall WINAPI *tSGSP)(HANDLE ,PSTR ,DWORD );
    tSGSP   pSymGetSearchPath;

    typedef BOOL(__stdcall WINAPI *tMDWD)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
    tMDWD   pMiniDumpWriteDump;

private:
    // **************************************** ToolHelp32 ************************
#define MAX_MODULE_NAME32 255
#define TH32CS_SNAPMODULE   0x00000008
#pragma pack( push, 8 )
    typedef struct tagMODULEENTRY32
    {
        DWORD   dwSize;
        DWORD   th32ModuleID;       // This module
        DWORD   th32ProcessID;      // owning process
        DWORD   GlblcntUsage;       // Global usage count on the module
        DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
        BYTE*   modBaseAddr;        // Base address of module in th32ProcessID's context
        DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
        HMODULE hModule;            // The hModule of this module in th32ProcessID's context
        char    szModule[MAX_MODULE_NAME32 + 1];
        char    szExePath[MAX_PATH];
    } MODULEENTRY32;
    typedef MODULEENTRY32*  PMODULEENTRY32;
    typedef MODULEENTRY32*  LPMODULEENTRY32;
#pragma pack( pop )

    BOOL GetModuleListTH32(
        HANDLE hProcess,
        DWORD pid)
    {
        // CreateToolhelp32Snapshot()
        typedef HANDLE (__stdcall *tCT32S)(DWORD ,DWORD );
        // Module32First()
        typedef BOOL (__stdcall *tM32F)(HANDLE ,LPMODULEENTRY32 );
        // Module32Next()
        typedef BOOL (__stdcall *tM32N)(HANDLE ,LPMODULEENTRY32 );
        // try both dlls...
        const TCHAR*    dllname[] =
        {
            _T("kernel32.dll"), _T("tlhelp32.dll")
        };
        HINSTANCE       hToolhelp = NULL;
        tCT32S          pCreateToolhelp32Snapshot = NULL;
        tM32F           pModule32First = NULL;
        tM32N           pModule32Next = NULL;
        HANDLE          hSnap;
        MODULEENTRY32   me;
        me.dwSize = sizeof(me);
        BOOL    keepGoing;
        size_t  i;
        for (i = 0; i < (sizeof(dllname) / sizeof(dllname[0])); i++)
        {
            hToolhelp = LoadLibrary(dllname[i]);
            if (hToolhelp == NULL)
                continue;
            pCreateToolhelp32Snapshot = (tCT32S)GetProcAddress(hToolhelp, "CreateToolhelp32Snapshot");
            pModule32First = (tM32F)GetProcAddress(hToolhelp, "Module32First");
            pModule32Next = (tM32N)GetProcAddress(hToolhelp, "Module32Next");
            if ((pCreateToolhelp32Snapshot != NULL) && (pModule32First != NULL) && (pModule32Next != NULL))
                break; // found the functions!
            FreeLibrary(hToolhelp);
            hToolhelp = NULL;
        }
        if (hToolhelp == NULL)
            return FALSE;
        hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (hSnap == (HANDLE) - 1)
            return FALSE;
        keepGoing = !!pModule32First(hSnap, &me);
        int cnt = 0;
        while (keepGoing)
        {
            this->LoadModule(hProcess, me.szExePath, me.szModule, (DWORD64)me.modBaseAddr, me.modBaseSize);
            cnt++;
            keepGoing = !!pModule32Next(hSnap, &me);
        }
        CloseHandle(hSnap);
        FreeLibrary(hToolhelp);
        if (cnt <= 0)
            return FALSE;
        return TRUE;
    }  // GetModuleListTH32

    // **************************************** PSAPI ************************
    typedef struct _MODULEINFO
    {
        LPVOID  lpBaseOfDll;
        DWORD   SizeOfImage;
        LPVOID  EntryPoint;
    } MODULEINFO, * LPMODULEINFO;

    BOOL GetModuleListPSAPI(
        HANDLE hProcess)
    {
        // EnumProcessModules()
        typedef BOOL (__stdcall *tEPM)(HANDLE , HMODULE* ,DWORD ,LPDWORD );
        // GetModuleFileNameEx()
        typedef DWORD (__stdcall *tGMFNE)(HANDLE ,HMODULE ,LPSTR ,DWORD );
        // GetModuleBaseName()
        typedef DWORD (__stdcall *tGMBN)(HANDLE ,HMODULE ,LPSTR ,DWORD );
        // GetModuleInformation()
        typedef BOOL (__stdcall *tGMI)(HANDLE ,HMODULE ,LPMODULEINFO ,DWORD );

        HINSTANCE       hPsapi;
        tEPM            pEnumProcessModules;
        tGMFNE          pGetModuleFileNameExA;
        tGMBN           pGetModuleBaseNameA;
        tGMI            pGetModuleInformation;
        DWORD           i;
        //ModuleEntry e;
        DWORD           cbNeeded;
        MODULEINFO      mi;
        HMODULE*        hMods = 0;
        char*           tt = NULL;
        char*           tt2 = NULL;
        const SIZE_T    TTBUFLEN = 8096;
        int             cnt = 0;
        hPsapi = LoadLibrary(_T("psapi.dll"));
        if (hPsapi == NULL)
            return FALSE;
        pEnumProcessModules = (tEPM)GetProcAddress(hPsapi, "EnumProcessModules");
        pGetModuleFileNameExA = (tGMFNE)GetProcAddress(hPsapi, "GetModuleFileNameExA");
        pGetModuleBaseNameA = (tGMFNE)GetProcAddress(hPsapi, "GetModuleBaseNameA");
        pGetModuleInformation = (tGMI)GetProcAddress(hPsapi, "GetModuleInformation");
        if ((pEnumProcessModules == NULL) || (pGetModuleFileNameExA == NULL) || (pGetModuleBaseNameA == NULL) || (pGetModuleInformation == NULL))
        {
            // we couldn't find all functions
            FreeLibrary(hPsapi);
            return FALSE;
        }
        hMods = (HMODULE *)malloc(sizeof(HMODULE) * (TTBUFLEN / sizeof HMODULE));
        tt = (char*)malloc(sizeof(char) * TTBUFLEN);
        tt2 = (char*)malloc(sizeof(char) * TTBUFLEN);
        if ((hMods == NULL) || (tt == NULL) || (tt2 == NULL))
            goto cleanup;
        if (!pEnumProcessModules(hProcess, hMods, TTBUFLEN, &cbNeeded))
        {
            goto cleanup;
        }
        if (cbNeeded > TTBUFLEN)
        {
            goto cleanup;
        }
        for (i = 0; i < cbNeeded / sizeof hMods[0]; i++)
        {
            // base address, size
            pGetModuleInformation(hProcess, hMods[i], &mi, sizeof mi);
            // image file name
            tt[0] = 0;
            pGetModuleFileNameExA(hProcess, hMods[i], tt, TTBUFLEN);
            // module name
            tt2[0] = 0;
            pGetModuleBaseNameA(hProcess, hMods[i], tt2, TTBUFLEN);
            DWORD   dwRes = this->LoadModule(hProcess, tt, tt2, (DWORD64)mi.lpBaseOfDll, mi.SizeOfImage);
            if (dwRes != ERROR_SUCCESS)
                this->m_parent->OnDbgHelpErr("LoadModule", dwRes, 0);
            cnt++;
        }
        cleanup:
        if (hPsapi != NULL)
            FreeLibrary(hPsapi);
        if (tt2 != NULL)
            free(tt2);
        if (tt != NULL)
            free(tt);
        if (hMods != NULL)
            free(hMods);
        return cnt != 0;
    }  // GetModuleListPSAPI

    DWORD LoadModule(
        HANDLE hProcess,
        LPCSTR img,
        LPCSTR mod,
        DWORD64 baseAddr,
        DWORD size)
    {
        CHAR*   szImg = _strdup(img);
        CHAR*   szMod = _strdup(mod);
        DWORD   result = ERROR_SUCCESS;
        if ((szImg == NULL) || (szMod == NULL))
            result = ERROR_NOT_ENOUGH_MEMORY;
        else
        {
            if (pSymLoadModule64(hProcess, 0, szImg, szMod, baseAddr, size) == 0)
                result = GetLastError();
        }
        ULONGLONG   fileVersion = 0;
        if ((m_parent != NULL) && (szImg != NULL))
        {
            // try to retrive the file-version:
            if ((this->m_parent->m_options & StackWalker::RetrieveFileVersion) != 0)
            {
                VS_FIXEDFILEINFO*   fInfo = NULL;
                DWORD               dwHandle;
                DWORD               dwSize = GetFileVersionInfoSizeA(szImg, &dwHandle);
                if (dwSize > 0)
                {
                    LPVOID  vData = malloc(dwSize);
                    if (vData != NULL)
                    {
                        if (GetFileVersionInfoA(szImg, dwHandle, dwSize, vData) != 0)
                        {
                            UINT    len;
                            TCHAR   szSubBlock[] = _T("\\");
                            if (VerQueryValue(vData, szSubBlock, (LPVOID *)&fInfo, &len) == 0)
                                fInfo = NULL;
                            else
                            {
                                fileVersion = ((ULONGLONG)fInfo->dwFileVersionLS) + ((ULONGLONG)fInfo->dwFileVersionMS << 32);
                            }
                        }
                        free(vData);
                    }
                }
            }
            // Retrive some additional-infos about the module
            IMAGEHLP_MODULE64_V2    Module;
            const char*             szSymType = "-unknown-";
            if (this->GetModuleInfo(hProcess, baseAddr, &Module) != FALSE)
            {
                switch (Module.SymType)
                {
                case SymNone:
                    szSymType = "-nosymbols-";
                    break;
                case SymCoff:
                    szSymType = "COFF";
                    break;
                case SymCv:
                    szSymType = "CV";
                    break;
                case SymPdb:
                    szSymType = "PDB";
                    break;
                case SymExport:
                    szSymType = "-exported-";
                    break;
                case SymDeferred:
                    szSymType = "-deferred-";
                    break;
                case SymSym:
                    szSymType = "SYM";
                    break;
                case 8:
                    //SymVirtual:
                    szSymType = "Virtual";
                    break;
                case 9:
                    // SymDia:
                    szSymType = "DIA";
                    break;
                }
            }
            this->m_parent->OnLoadModule(img, mod, baseAddr, size, result, szSymType, Module.LoadedImageName, fileVersion);
        }
        if (szImg != NULL)
            free(szImg);
        if (szMod != NULL)
            free(szMod);
        return result;
    }
public:
    BOOL LoadModules(
        HANDLE hProcess,
        DWORD dwProcessId)
    {
        // first try toolhelp32
        if (GetModuleListTH32(hProcess, dwProcessId))
            return true;
        // then try psapi
        return GetModuleListPSAPI(hProcess);
    }


    BOOL GetModuleInfo(
        HANDLE hProcess,
        DWORD64 baseAddr,
        IMAGEHLP_MODULE64_V2* pModuleInfo)
    {
        if (this->pSymGetModuleInfo64 == NULL)
        {
            SetLastError(ERROR_DLL_INIT_FAILED);
            return FALSE;
        }
        // First try to use the larger ModuleInfo-Structure
        //    memset(pModuleInfo, 0, sizeof(IMAGEHLP_MODULE64_V3));
        //    pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V3);
        //    if (this->pSGMI_V3 != NULL)
        //    {
        //      if (this->pSGMI_V3(hProcess, baseAddr, pModuleInfo) != FALSE)
        //        return TRUE;
        //      // check if the parameter was wrong (size is bad...)
        //      if (GetLastError() != ERROR_INVALID_PARAMETER)
        //        return FALSE;
        //    }
        // could not retrive the bigger structure, try with the smaller one (as defined in VC7.1)...
        pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V2);
        void*   pData = malloc(4096); // reserve enough memory, so the bug in v6.3.5.1 does not lead to memory-overwrites...
        if (pData == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        memcpy(pData, pModuleInfo, sizeof(IMAGEHLP_MODULE64_V2));
        if (this->pSymGetModuleInfo64(hProcess, baseAddr, (IMAGEHLP_MODULE64_V2 *)pData) != FALSE)
        {
            // only copy as much memory as is reserved...
            memcpy(pModuleInfo, pData, sizeof(IMAGEHLP_MODULE64_V2));
            pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V2);
            free(pData);
            return TRUE;
        }
        free(pData);
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
};

