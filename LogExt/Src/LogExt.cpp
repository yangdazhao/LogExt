// LogExt.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "LogExt.h"
#include <boost\algorithm\string.hpp>

log4cpp::Category &RootCategory = log4cpp::Category::getRoot();

// SS-FORMAT-OFF
static const char* s_hexTable[256] =
{
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10", "11",
    "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", "20", "21", "22", "23",
    "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", "30", "31", "32", "33", "34", "35",
    "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
    "5A", "5B", "5C", "5D", "5E", "5F", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B",
    "6C", "6D", "6E", "6F", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D",
    "7E", "7F", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F", "A0", "A1",
    "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2", "B3",
    "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", "C0", "C1", "C2", "C3", "C4", "C5",
    "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
    "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9",
    "EA", "EB", "EC", "ED", "EE", "EF", "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB",
    "FC", "FD", "FE", "FF"
};
// SS-FORMAT-ON

int LogExt_API Logging(
    int Log_Level,
    const char* stringFormat,
    ...)
{
    try {
        char LogBuffer[1024] = { 0 };
        va_list arglist;
        va_start(arglist, stringFormat);

        bool bMalloc(false);
        char *pBuffer(NULL);
        int len = vsnprintf(NULL, 0, stringFormat, arglist) + 1;

        if (len > 1024)
        {
            bMalloc = true;
            pBuffer = (char*)malloc(len * sizeof(char));
            memset(pBuffer, 0, len * sizeof(char));
        }
        else
        {
            pBuffer = LogBuffer;
            len = 1024;
        }
        vsnprintf(pBuffer, len, stringFormat, arglist);
        va_end(arglist);
        unsigned short dwColor = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;

        switch (Log_Level)
        {
        case L_DEBUG:
            RootCategory.debug("%s", pBuffer);
            break;
        case L_INFO:
            RootCategory.info("%s", pBuffer);
            dwColor = FOREGROUND_GREEN;
            break;
        case L_NOTICE:
            RootCategory.notice("%s", pBuffer);
            dwColor = FOREGROUND_GREEN;
            break;
        case L_WARN:
            RootCategory.warn("%s", pBuffer);
            dwColor = FOREGROUND_RED;
            break;
        case L_ERR:
            RootCategory.error("%s", pBuffer);
            dwColor = FOREGROUND_RED;
            break;
        default:
            break;
        }
        if (IsCUI)
        {
            HANDLE hStdhandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
            ::SetConsoleTextAttribute(hStdhandle, dwColor | FOREGROUND_INTENSITY);
            printf("%s\n", pBuffer);
            ::SetConsoleTextAttribute(hStdhandle, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
        }

        if (bMalloc)
        {
            free(pBuffer);
            pBuffer = NULL;
        }   
	}
    catch (...)
    {
        RootCategory.error("%s", "Function:Logging");
    }
    return 0;
}

extern "C" int LogExt_API Logging_Bin(
    int Log_Level,
    const unsigned char* BinData,
    int nLength)
{
    std::string LogBuffer;
    for (int iIndex = 0; iIndex < nLength; iIndex++)
    {
        if (iIndex % 16 == 0)
        {
            LogBuffer.append("\n");
        }
        else
        {
            LogBuffer.append(" ");
        }
        LogBuffer.append(s_hexTable[(int)BinData[iIndex]]);
    }

    unsigned short dwColor = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;

    switch (Log_Level)
    {
    case L_DEBUG:
        RootCategory.debug(LogBuffer);
        break;
    case L_INFO:
        RootCategory.info(LogBuffer);
        dwColor = FOREGROUND_GREEN;
        break;
    case L_NOTICE:
        RootCategory.notice(LogBuffer);
        dwColor = FOREGROUND_GREEN;
        break;
    case L_WARN:
        RootCategory.warn(LogBuffer);
        dwColor = FOREGROUND_RED;
        break;
    case L_ERR:
        RootCategory.error(LogBuffer);
        dwColor = FOREGROUND_RED;
        break;
    default:
        break;
    }

    if (IsCUI)
    {
        HANDLE hStdhandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        ::SetConsoleTextAttribute(hStdhandle, dwColor | FOREGROUND_INTENSITY);
        printf("%s", LogBuffer.c_str());
        ::SetConsoleTextAttribute(hStdhandle, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
    }

    return 0;
}

//[YDZ][IS][%d{%H:%M:%S.%l}][%p][%t] - %m%n
bool AddAppender(
    const char* szAppenderType,
    const char* szConversionPattern,
    int iPriority)
{
#pragma region Remote
	RootCategory.removeAppender(RootCategory.getAppender("Remote"));
    if (RootCategory.getAppender("Remote"))
    {
        RootCategory.addAppender(RootCategory.getAppender("Remote"));
    }
	RootCategory.removeAppender(RootCategory.getAppender("Remote"));
#pragma endregion Remote

#pragma region RemoteSyslogAppender
    RootCategory.removeAppender(RootCategory.getAppender("RemoteSyslogAppender"));
    if (RootCategory.getAppender("RemoteSyslogAppender"))
    {
        RootCategory.addAppender(RootCategory.getAppender("RemoteSyslogAppender"));
    }
    RootCategory.removeAppender(RootCategory.getAppender("RemoteSyslogAppender"));
#pragma endregion Kiwi


    log4cpp::Appender * pDstAppender = NULL;
    if (boost::iequals("RemoteSyslogAppender", szAppenderType))
    {
        std::string strName("Kiwi Syslog");
        std::string strRelayer("222.128.63.84");
        pDstAppender = new log4cpp::RemoteSyslogAppender(
            szAppenderType,
            strName,
            strRelayer,
			LOG_USER,
			514);
    }

    if (NULL == pDstAppender)
    {
        return false;
    }

    if (pDstAppender)
    {
        log4cpp::PatternLayout* pLayout = new log4cpp::PatternLayout();
        pLayout->setConversionPattern(szConversionPattern);
        pDstAppender->setThreshold(iPriority* 100);
        pDstAppender->setLayout(pLayout);
        RootCategory.addAppender(pDstAppender);
    }
    return true;
}