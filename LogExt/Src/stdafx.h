// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifdef WIN32
#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define _CRT_SECURE_NO_WARNINGS
// Windows Header Files:

#include <windows.h>
#endif // WIN32

#ifdef _WINDOWS
#pragma warning ( push )
#pragma warning (disable:4996)
#pragma warning (disable:4512)
#endif
#include <log4cpp/Appender.hh>
#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/RemoteSyslogAppender.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/SimpleLayout.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/Priority.hh>
#include <log4cpp/PropertyConfigurator.hh>
#ifdef _WINDOWS
#pragma warning ( pop )
#endif

extern BOOL IsCUI;

#pragma comment(lib,"Ws2_32.lib")
#ifdef _DEBUG
#pragma comment(lib,"log4cppLIB141d.lib")
#else
#pragma comment(lib,"log4cppLIB141.lib")
#endif

//#include "vld.h"