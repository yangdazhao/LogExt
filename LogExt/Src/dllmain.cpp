// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <boost/date_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <fstream>
#include <WinUser.h>
#include "resource.h"
#include "StackWalker.h"

#include <shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

using namespace boost;
using namespace std;

using namespace boost::posix_time;

namespace fs = boost::filesystem;

#define BUFSIZE 1024

BOOL IsCUI = FALSE;
BOOL CheckCUI();

// 此函数一旦成功调用，之后对 SetUnhandledExceptionFilter 的调用将无效
void DisableSetUnhandledExceptionFilter()
{
	void* addr = (void*)GetProcAddress(LoadLibrary("kernel32.dll"),"SetUnhandledExceptionFilter");

	if (addr)
	{
		unsigned char code[16];
		int size = 0;
		//xor eax,eax;
		code[size++] = 0x33;
		code[size++] = 0xC0;
		//ret 4
		code[size++] = 0xC2;
		code[size++] = 0x04;
		code[size++] = 0x00;

		DWORD dwOldFlag, dwTempFlag;
		//VirtualProtect(addr, size, PAGE_READWRITE, &dwOldFlag);
		VirtualProtectEx(GetCurrentProcess(), addr, size, PAGE_EXECUTE_READWRITE, &dwOldFlag);
		WriteProcessMemory(GetCurrentProcess(), addr, code, size, NULL);
		//VirtualProtect(addr, size, dwOldFlag, &dwTempFlag);
		VirtualProtectEx(GetCurrentProcess(), addr, size, dwOldFlag, &dwTempFlag);
	}
}

LONG WINAPI ExpFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
	MessageBox(NULL, "ExpFilter", "ExpFilter", MB_OK);
	std::stringstream strContent;
#if 0
	OutputDebugString("收集注册表项:");
	for (auto iter = gVecRegContent.begin(); iter != gVecRegContent.end(); iter++)
	{
		std::string strRet = GetRegContent(std::get<0>(*iter), std::get<1>(*iter), std::get<2>(*iter));
		strContent << std::get<2>(*iter) << ":";
		if (strRet.empty())
		{
			strContent << "空" << "\n";
		}
		else
		{
			strContent << strRet << "\n";
		}
	}
#endif

	using namespace boost;
	LONG retValue = EXCEPTION_CONTINUE_SEARCH;
	PEXCEPTION_RECORD pExceptionRecord = pExceptionInfo->ExceptionRecord;
	while (pExceptionRecord)
	{
		format fm("exceptCode is: %08X, ExceptionAddress is %08X,NumberParameters is %d;");
		fm % pExceptionRecord->ExceptionCode % pExceptionRecord->ExceptionAddress  % pExceptionRecord->NumberParameters;
		strContent << fm.str().c_str() << endl;
		pExceptionRecord = pExceptionRecord->ExceptionRecord;
	}

	//////////////////////////////////////////////////////////////////////////
	// dumps/InterfaceService_20161101_095501_Crash.dmp
	try
	{
		TCHAR szLogPath[256] = { 0 };
		::GetModuleFileName(NULL, szLogPath, 256);

		fs::path dumpPath(szLogPath);
		dumpPath.remove_filename();
		dumpPath.append("dumps");
		if (!fs::exists(dumpPath))
		{
			fs::create_directory(dumpPath);
		}

		::PathRemoveExtension(szLogPath);
		std::string DumpName(::PathFindFileName(szLogPath));
		ptime now = second_clock::local_time();
		DumpName.append("_");
		DumpName.append(to_iso_string(now));
		DumpName.append("_Crash");
		dumpPath.append(DumpName);
		dumpPath.replace_extension(".dmp");

		StackWalker sw;
		sw.ShowCallstack(GetCurrentThread(), pExceptionInfo->ContextRecord);
		sw.DumpCrash(pExceptionInfo, dumpPath.string());
		strContent << sw.outStream.str();

#if 0
		CSMTPImpl smtp(strContent.str());
		smtp.SetDstMail(gStrDstMail);
		smtp.SetSubject(::PathFindFileName(szLogPath));

		if (bfs::exists(dumpPath))
		{
			::OutputDebugString(dumpPath.string().c_str());
			smtp.AddAttachment(dumpPath.string());
		}


		fs::path dirPath(szLogPath);
		dirPath.remove_filename();
		OutputDebugString("收集文件:");
		for (auto iter = gVecFiles.begin(); iter != gVecFiles.end(); iter++)
		{
			fs::path temp = dirPath;
			temp.append(*iter);
			if (fs::exists(temp))
			{
				::OutputDebugString(temp.string().c_str());
				smtp.AddAttachment(temp.string());
			}
		}
		smtp.svc();
#endif
	}
	catch (...)
	{
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD  ul_reason_for_call, LPVOID)
{
	fs::path currentPath(fs::current_path());
	std::string strConfigFile;
	std::string strLogPath;
	TCHAR szModuleFileName[BUFSIZE] = { 0 };
	TCHAR szCurrentDir[BUFSIZE] = { 0 };
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		::SetUnhandledExceptionFilter(ExpFilter);
		DisableSetUnhandledExceptionFilter();
		setlocale(LC_ALL, "chs");
		IsCUI = CheckCUI();
		::GetModuleFileName(module, szModuleFileName, 1024);
		::PathRemoveExtension(szModuleFileName);
		::SetCurrentDirectory(szModuleFileName);
		strConfigFile.assign(szModuleFileName);
		strConfigFile = strConfigFile.substr(0, strConfigFile.find_last_of('\\'));
		strLogPath.assign(strConfigFile.c_str());

		strLogPath.append("/Log");
		if (!fs::exists(strLogPath))
		{
#ifdef _WINDOWS
			::OutputDebugString(strLogPath.c_str());
#else
			::OutputDebugString(strLogPath.c_str());
#endif
			fs::create_directory(strLogPath);
		}
		currentPath.append("Log");
		if (!fs::exists(currentPath))
		{
			fs::create_directory(currentPath);
		}

		strConfigFile.append("/log4cpp.conf");
		fs::path _path(strConfigFile);
		bool IsExist = filesystem::exists(_path);
		if (!IsExist)
		{
			HRSRC hRsrc = ::FindResource(module, MAKEINTRESOURCE(IDR_CONF), "conf"); // type
			if (!hRsrc)
				return FALSE;           // load resource into memory
			DWORD len = ::SizeofResource(module, hRsrc);
			BYTE* lpRsrc = (BYTE*)::LoadResource(module, hRsrc);
			if (!lpRsrc)
				return FALSE;

			ofstream _ofs(_path.string());
			_ofs << lpRsrc;
			_ofs.flush();
			_ofs.close();
		}

		try {
			///< 加载Log4cpp的配置文件
			log4cpp::PropertyConfigurator::configure(strConfigFile.c_str());
		}
		catch (log4cpp::ConfigureFailure& f) {
			OutputDebugString("日志配置读取错误");
			OutputDebugString(f.what());
		}

		if (!IsExist)
		{
			fs::remove(_path);
		}
		}
	break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		log4cpp::Category::shutdown();
		break;
	}
	return TRUE;
	}

BOOL CheckCUI() {
	BOOL Result = FALSE;
	do
	{
		TCHAR szBuffer[MAX_PATH] = { 0 };
		if (FAILED(::GetModuleFileName(NULL, szBuffer, MAX_PATH)))
		{
			break;
		}

		HANDLE hFile = ::CreateFile(szBuffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
		IMAGE_DOS_HEADER image_dos_header;
		IMAGE_FILE_HEADER image_file_header;
		IMAGE_OPTIONAL_HEADER image_optional_header;
		DWORD dwOutLength;
		::ReadFile(hFile, &image_dos_header, sizeof(image_dos_header), &dwOutLength, NULL);
		// GOTO IMAGE_NT_SIGNATURE
		::SetFilePointer(hFile, image_dos_header.e_lfanew + sizeof(DWORD), NULL, FILE_BEGIN);
		// GOTO IMAGE_FILE_HEADER
		::ReadFile(hFile, &image_file_header, sizeof(image_file_header), &dwOutLength, NULL);
		::ReadFile(hFile, &image_optional_header, sizeof(image_optional_header), &dwOutLength, NULL);
		Result = (image_optional_header.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);
		::CloseHandle(hFile);
	} while (FALSE);
	return Result;
}