#ifndef LOGEXT_H_B537CD55_499A_455F_BE68_DFFF90B65768_
#define LOGEXT_H_B537CD55_499A_455F_BE68_DFFF90B65768_
#include <string>

#define _STR(A)     #A
#define MacroStr(B) _STR(B)

//#define EXTLIB( A ) #A MacroStr(_MSC_PLATFORM_TOOLSET) DEBUGSTR ".lib"
#define EXTLIB( A ) #A ".lib"

#ifdef LOGEXT_EXPORTS
#define LogExt_API __declspec(dllexport)
#else
#define  LogExt_API __declspec(dllimport)
#pragma comment(lib, EXTLIB(LogExt) )
#endif

#define	YZF_DEBUG	 7
#define	YZF_INFO	 6
#define	YZF_NOTICE	 5
#define	YZF_WARN	 4
#define	YZF_ERR		 3

extern "C" int LogExt_API Logging(
    int Log_Level,
    const char* stringFormat, ...);

extern "C" int LogExt_API Logging_Bin(
    int Log_Level,
    const unsigned char* BinData,
    int nLength);

extern "C" bool LogExt_API AddAppender(
    const char* szAppenderType,
    const char* szConversionPattern,
    int iPriority);

#ifdef LOG_ERR
#undef LOG_ERR
#endif//LOG_ERR
#define LOG_ERR( message, ... )     { Logging(YZF_ERR,	message, __VA_ARGS__ ); }

#ifdef LOG_WARN
#undef LOG_WARN
#endif // LOG_ERR
#define LOG_WARN( message, ... )    { Logging(YZF_WARN,	message, ##__VA_ARGS__ ); }

#ifdef LOG_NOTICE
#undef LOG_NOTICE
#endif // LOG_ERR
#define LOG_NOTICE( message, ... )	{ Logging(YZF_NOTICE,	message, __VA_ARGS__ ); }

#ifdef LOG_INFO
#undef LOG_INFO
#endif//LOG_INFO
#define LOG_INFO( message, ... )    { Logging(YZF_INFO,	message, __VA_ARGS__ ); }

#ifdef LOG_DEBUG
#undef LOG_DEBUG
#endif//LOG_DEBUG
#define LOG_DEBUG( message, ... )   { Logging(YZF_DEBUG,message, __VA_ARGS__ ); }

#ifdef _DEBUG
#define LOG_DEBUG_EX LOG_DEBUG
#else
#define LOG_DEBUG_EX
#endif//DEBUG

#ifdef LOG_FUNC_ERR
#undef LOG_FUNC_ERR
#endif//LOG_FUNC_ERR
#define LOG_FUNC_ERR( format, ... )     { Logging(YZF_ERR,	 "file:[%s];line:[%d];function:[%s]; #"##format, __FILE__, __LINE__,__FUNCTION__,  __VA_ARGS__ ); }

#ifdef LOG_FUNC_WARN
#undef LOG_FUNC_WARN
#endif//LOG_FUNC_WARN
#define LOG_FUNC_WARN( format, ... )    { Logging(YZF_WARN,	 "file:[%s];line:[%d];function:[%s]; #"##format, __FILE__, __LINE__,__FUNCTION__,  __VA_ARGS__ ); }

#ifdef LOG_FUNC_INFO
#undef LOG_FUNC_INFO
#endif//LOG_FUNC_INFO
#define LOG_FUNC_INFO( format, ... )    { Logging(YZF_INFO,	 "file:[%s];line:[%d];function:[%s]; #"##format, __FILE__, __LINE__,__FUNCTION__,  __VA_ARGS__ ); }

#ifdef LOG_FUNC_DEBUG
#undef LOG_FUNC_DEBUG
#endif//LOG_FUNC_DEBUG
#define LOG_FUNC_DEBUG( format, ... )   { Logging(YZF_DEBUG, "file:[%s];line:[%d];function:[%s]; #"##format, __FILE__, __LINE__,__FUNCTION__,  __VA_ARGS__ ); }

class TraceObject {
public:
    explicit TraceObject(const char* text)
        : m_name(text)
    {
        LOG_DEBUG("%s Enter..", m_name.c_str());
    }

    ~TraceObject()
    {
        LOG_DEBUG("%s Leave..", m_name.c_str());
    }

protected:
    std::string m_name;
};

//#include <Windows.h>
#ifdef _WINDOWS_
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

class TraceObject_Time {
public:
    explicit TraceObject_Time(const char* text)
        : m_name(text)
        , m_dwStart(::GetTickCount())
    {
        LOG_DEBUG("%s Enter..", m_name.c_str());
    }

    ~TraceObject_Time()
    {
        LOG_DEBUG("%s Consumption time:%d ms Leave..", m_name.c_str(), ::GetTickCount() - m_dwStart);
    }

protected:
    std::string m_name;
    DWORD       m_dwStart;
};

#pragma warning (push)
#pragma warning (disable : 4996)

class TraceObject_TimeEx {
public:
    explicit TraceObject_TimeEx(const char* text)
        : m_name(text)
        , m_dwStart(::GetTickCount())
        , m_szBuffer(NULL)
    {
    }

    void Print(const char* stringFormat, ...)
    {
        if (NULL == stringFormat)
        {
            return;
        }
        va_list arglist;
        va_start(arglist, stringFormat);
        char *pBuffer(NULL);
        int len = _vscprintf(stringFormat, arglist) + 1;
        m_szBuffer = (char*)malloc(len * sizeof(char));
        memset(m_szBuffer, 0, len * sizeof(char));
        vsprintf_s(m_szBuffer, len, stringFormat, arglist);
        va_end(arglist);
        LOG_DEBUG("%s {%s} Enter..", m_name.c_str(), m_szBuffer);
    }

    ~TraceObject_TimeEx()
    {
        LOG_DEBUG("%s {%s} Consumption time:%d ms Leave..", m_name.c_str(), m_szBuffer, ::GetTickCount() - m_dwStart);
        if (m_szBuffer)
        {
            free(m_szBuffer);
        }
    }

protected:
    char *       m_szBuffer;
    std::string m_name;
    DWORD       m_dwStart;
};

#define TRACE_TIME( ) TraceObject_Time _traceObj(__FUNCTION__);
#define TRACE_TIMEEx( ... ) TraceObject_TimeEx _traceObj(__FUNCTION__);_traceObj.Print(##__VA_ARGS__);
#define DECLARE_TRACE_OBJECT_TIMEEx TRACE_TIMEEx
#define DECLARE_TRACE_OBJECT_TIME TRACE_TIME
#pragma warning (pop)
#else
#define DECLARE_TRACE_OBJECT_TIME()
//#define TRACE_TIME( )
//#define TRACE_TIMEEx( ... )
#endif // _DEBUG

#define DECLARE_TRACE_OBJECT()      TraceObject _traceObj(__FUNCTION__);
#define FUNCTION_ENTER() LOG_DEBUG("%s Enter.", __FUNCTION__);

#endif // LOGEXT_H_B537CD55_499A_455F_BE68_DFFF90B65768_