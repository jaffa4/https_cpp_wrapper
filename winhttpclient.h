/**
 *  Copyright 2008-2010 Cheng Shi.  All rights reserved.
 *  Email: shicheng107@hotmail.com
 
    punlished: http://www.codeproject.com/Articles/66625/A-Fully-Featured-Windows-HTTP-Wrapper-in-C
    license: The Code Project Open License (CPOL)
    modified by jaffa4 to make it work in Ultimate ++ Framework
 */

#ifndef WINHTTPCLIENT_H
#define WINHTTPCLIENT_H

#pragma comment(lib, "Winhttp.lib")

//#include "plugin\\pcre\\RegExp.h"

#include <plugin/pcre/Pcre.h>
//#include "StringProcess.h"
 //#include <comutil.h>
 //#include "Windows.h"
 
 #include "Winnls.h"
 
 #include <Core/Core.h>


using namespace Upp;
 
 
 
#include <windows.h>
#include <Winhttp.h>
#include <string>
using namespace std;

typedef bool (*PROGRESSPROC)(double);

static const unsigned int INT_RETRYTIMES = 3;
static wchar_t *SZ_AGENT = L"WinHttpClient";
static const int INT_BUFFERSIZE = 10240;    // Initial 10 KB temporary buffer, double if it is not enough.

class WinHttpClient
{
public:
    inline WinHttpClient(const WString &url, PROGRESSPROC progressProc = NULL);
    inline ~WinHttpClient(void);

    // It is a synchronized method and may take a long time to finish.
    inline bool SendHttpRequest(const WString &httpVerb = L"GET", bool disableAutoRedirect = false);
    inline WString GetResponseHeader(void);
    inline WString GetResponseContent(void);
    inline WString GetResponseCharset(void);
    inline WString GetResponseStatusCode(void);
    inline WString GetResponseLocation(void);
    inline WString GetRequestHost(void);
    inline const BYTE *GetRawResponseContent(void);
    inline unsigned int GetRawResponseContentLength(void);
    inline unsigned int GetRawResponseReceivedContentLength(void);
    inline bool SaveResponseToFile(const WString &filePath);
    inline WString GetResponseCookies(void);
    inline bool SetAdditionalRequestCookies(const WString &cookies);
    inline bool SetAdditionalDataToSend(BYTE *data, unsigned int dataSize);
    inline bool UpdateUrl(const WString &url);
    inline bool ResetAdditionalDataToSend(void);
    inline bool SetAdditionalRequestHeaders(const WString &additionalRequestHeaders);
    inline bool SetRequireValidSslCertificates(bool require);
    inline bool SetProxy(const WString &proxy);
    inline DWORD GetLastError(void);
    inline bool SetUserAgent(const WString &userAgent);
    inline bool SetForceCharset(const WString &charset);
    inline bool SetProxyUsername(const WString &username);
    inline bool SetProxyPassword(const WString &password);
    inline bool SetTimeouts(unsigned int resolveTimeout = 0,
                            unsigned int connectTimeout = 60000,
                            unsigned int sendTimeout = 30000,
                            unsigned int receiveTimeout = 30000);

private:
    inline WinHttpClient(const WinHttpClient &other);
    inline WinHttpClient &operator =(const WinHttpClient &other);
    inline bool SetProgress(unsigned int byteCountReceived);

    HINTERNET m_sessionHandle;
    bool m_requireValidSsl;
    WString m_requestURL;
    WString m_requestHost;
    WString m_responseHeader;
    WString m_responseContent;
    WString m_responseCharset;
    BYTE *m_pResponse;
    unsigned int m_responseByteCountReceived;   // Up to 4GB.
    PROGRESSPROC m_pfProcessProc;
    unsigned int m_responseByteCount;
    WString m_responseCookies;
    WString m_additionalRequestCookies;
    BYTE *m_pDataToSend;
    unsigned int m_dataToSendSize;
    WString m_additionalRequestHeaders;
    WString m_proxy;
    DWORD m_dwLastError;
    WString m_statusCode;
    WString m_userAgent;
    bool m_bForceCharset;
    WString m_proxyUsername;
    WString m_proxyPassword;
    WString m_location;
    unsigned int m_resolveTimeout;
    unsigned int m_connectTimeout;
    unsigned int m_sendTimeout;
    unsigned int m_receiveTimeout;
};

WinHttpClient::WinHttpClient(const WString &url, PROGRESSPROC progressProc)
    : m_requestURL(url),
      m_sessionHandle(NULL),
      m_requireValidSsl(false),
      m_responseHeader(L""),
      m_responseContent(L""),
      m_responseCharset(L""),
      m_requestHost(L""),
      m_pResponse(NULL),
      m_responseByteCountReceived(0),
      m_pfProcessProc(progressProc),
      m_responseByteCount(0),
      m_responseCookies(L""),
      m_additionalRequestCookies(L""),
      m_pDataToSend(NULL),
      m_dataToSendSize(0),
      m_proxy(L""),
      m_dwLastError(0),
      m_statusCode(L""),
      m_userAgent(SZ_AGENT),
      m_bForceCharset(false),
      m_proxyUsername(L""),
      m_proxyPassword(L""),
      m_location(L""),
      m_resolveTimeout(0),
      m_connectTimeout(60000),
      m_sendTimeout(30000),
      m_receiveTimeout(30000)
{
}

WinHttpClient::~WinHttpClient(void)
{
    if (m_pResponse != NULL)
    {
        delete[] m_pResponse;
    }
    if (m_pDataToSend != NULL)
    {
        delete[] m_pDataToSend;
    }

    if (m_sessionHandle != NULL)
    {
        ::WinHttpCloseHandle(m_sessionHandle);
    }
}

bool WinHttpClient::SendHttpRequest(const WString &httpVerb, bool disableAutoRedirect)
{
    if (m_requestURL.GetLength() <= 0)
    {
        m_dwLastError = ERROR_PATH_NOT_FOUND;
        return false;
    }
    // Make verb uppercase.
    WString verb = httpVerb;
    if (_wcsicmp(verb.Begin(), L"GET") == 0)
    {
        verb = L"GET";
    }
    else if (_wcsicmp(verb.Begin(), L"POST") == 0)
    {
        verb = L"POST";
    }
    else
    {
        m_dwLastError = ERROR_INVALID_PARAMETER;
        return false;
    }
    bool bRetVal = true;

    if (m_sessionHandle == NULL)
    {
        m_sessionHandle = ::WinHttpOpen(m_userAgent.Begin(),  
                                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME, 
                                        WINHTTP_NO_PROXY_BYPASS,
                                        0);
        if (m_sessionHandle == NULL)
        {
            m_dwLastError = ::GetLastError();
            return false;
        }
    }

    ::WinHttpSetTimeouts(m_sessionHandle,
                         m_resolveTimeout,
                         m_connectTimeout,
                         m_sendTimeout,
                         m_receiveTimeout);

    wchar_t szHostName[MAX_PATH] = L"";
    wchar_t szURLPath[MAX_PATH * 5] = L"";
    URL_COMPONENTS urlComp;
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = szHostName;
    urlComp.dwHostNameLength = MAX_PATH;
    urlComp.lpszUrlPath = szURLPath;
    urlComp.dwUrlPathLength = MAX_PATH * 5;
    urlComp.dwSchemeLength = 1; // None zero

    if (::WinHttpCrackUrl(m_requestURL.Begin(), m_requestURL.GetLength(), 0, &urlComp))
    {
        m_requestHost = szHostName;
        HINTERNET hConnect = NULL;
        hConnect = ::WinHttpConnect(m_sessionHandle, szHostName, urlComp.nPort, 0);
        if (hConnect != NULL)
        {
            DWORD dwOpenRequestFlag = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
            HINTERNET hRequest = NULL;
            hRequest = ::WinHttpOpenRequest(hConnect,
                                            verb.Begin(),
                                            urlComp.lpszUrlPath,
                                            NULL,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            dwOpenRequestFlag);
            if (hRequest != NULL)
            {
                // If HTTPS, then client is very susceptable to invalid certificates
                // Easiest to accept anything for now
                if (!m_requireValidSsl && urlComp.nScheme == INTERNET_SCHEME_HTTPS)
                {
                    DWORD options = SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                                    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                                    | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
                    ::WinHttpSetOption(hRequest,
                                       WINHTTP_OPTION_SECURITY_FLAGS,
                                       (LPVOID)&options,
                                       sizeof(DWORD));
                }

                bool bGetReponseSucceed = false;
                unsigned int iRetryTimes = 0;

                // Retry for several times if fails.
                while (!bGetReponseSucceed && iRetryTimes++ < INT_RETRYTIMES)
                {
                    if (m_additionalRequestHeaders.GetLength() > 0)
                    {
                        if (!::WinHttpAddRequestHeaders(hRequest, m_additionalRequestHeaders.Begin(), m_additionalRequestHeaders.GetLength(), WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON))
                        {
                            m_dwLastError = ::GetLastError();
                        }
                    }
                    if (m_additionalRequestCookies.GetLength() > 0)
                    {
                        WString cookies = L"Cookie: ";
                        cookies += m_additionalRequestCookies;
                        if (!::WinHttpAddRequestHeaders(hRequest, cookies.Begin(), cookies.GetLength(), WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON))
                        {
                            m_dwLastError = ::GetLastError();
                        }
                    }
                    if (m_proxy.GetLength() > 0)
                    {
                        WINHTTP_PROXY_INFO proxyInfo;
                        memset(&proxyInfo, 0, sizeof(proxyInfo));
                        proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                        wchar_t szProxy[MAX_PATH] = L"";
                        wcscpy_s(szProxy, MAX_PATH, m_proxy.Begin());
                        proxyInfo.lpszProxy = szProxy;

                        if (!::WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo)))
                        {
                            m_dwLastError = ::GetLastError();
                        }

                        if (m_proxyUsername.GetLength() > 0)
                        {
                            if (!::WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY_USERNAME, (LPVOID)m_proxyUsername.Begin(), m_proxyUsername.GetLength() * sizeof(wchar_t)))
                            {
                                m_dwLastError = ::GetLastError();
                            }
                            if (m_proxyPassword.GetLength() > 0)
                            {
                                if (!::WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY_PASSWORD, (LPVOID)m_proxyPassword.Begin(), m_proxyPassword.GetLength() * sizeof(wchar_t)))
                                {
                                    m_dwLastError = ::GetLastError();
                                }
                            }
                        }
                    }

                    if (disableAutoRedirect)
                    {
                        DWORD dwDisableFeature = WINHTTP_DISABLE_REDIRECTS;
                        if (!::WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &dwDisableFeature, sizeof(dwDisableFeature)))
                        {
                            m_dwLastError = ::GetLastError();
                        }
                    }
                    bool bSendRequestSucceed = false;
                    if (::WinHttpSendRequest(hRequest,
                                             WINHTTP_NO_ADDITIONAL_HEADERS,
                                             0,
                                             WINHTTP_NO_REQUEST_DATA,
                                             0,
                                             0,
                                             NULL))
                    {
                        bSendRequestSucceed = true;
                    }
                    else
                    {
                        // Query the proxy information from IE setting and set the proxy if any.
                        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
                        memset(&proxyConfig, 0, sizeof(proxyConfig));
                        if (::WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig))
                        {
                            if (proxyConfig.lpszAutoConfigUrl != NULL)
                            {
                                WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions;
                                memset(&autoProxyOptions, 0, sizeof(autoProxyOptions));
                                autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL;
                                autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP;
                                autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;
                                autoProxyOptions.fAutoLogonIfChallenged = TRUE;
                                autoProxyOptions.dwReserved = 0;
                                autoProxyOptions.lpvReserved = NULL;

                                WINHTTP_PROXY_INFO proxyInfo;
                                memset(&proxyInfo, 0, sizeof(proxyInfo));

                                if (::WinHttpGetProxyForUrl(m_sessionHandle, m_requestURL.Begin(), &autoProxyOptions, &proxyInfo))
                                {
                                    if (::WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo)))
                                    {
                                        if (::WinHttpSendRequest(hRequest,
                                                                 WINHTTP_NO_ADDITIONAL_HEADERS,
                                                                 0,
                                                                 WINHTTP_NO_REQUEST_DATA,
                                                                 0,
                                                                 0,
                                                                 NULL))
                                        {
                                            bSendRequestSucceed = true;
                                        }
                                    }
                                    if (proxyInfo.lpszProxy != NULL)
                                    {
                                        ::GlobalFree(proxyInfo.lpszProxy);
                                    }
                                    if (proxyInfo.lpszProxyBypass != NULL)
                                    {
                                        ::GlobalFree(proxyInfo.lpszProxyBypass);
                                    }
                                }
                                else
                                {
                                    m_dwLastError = ::GetLastError();
                                }
                            }
                            else if (proxyConfig.lpszProxy != NULL)
                            {
                                WINHTTP_PROXY_INFO proxyInfo;
                                memset(&proxyInfo, 0, sizeof(proxyInfo));
                                proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                                wchar_t szProxy[MAX_PATH] = L"";
                                wcscpy_s(szProxy, MAX_PATH, proxyConfig.lpszProxy);
                                proxyInfo.lpszProxy = szProxy;

                                if (proxyConfig.lpszProxyBypass != NULL)
                                {
                                    wchar_t szProxyBypass[MAX_PATH] = L"";
                                    wcscpy_s(szProxyBypass, MAX_PATH, proxyConfig.lpszProxyBypass);
                                    proxyInfo.lpszProxyBypass = szProxyBypass;
                                }

                                if (!::WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo)))
                                {
                                    m_dwLastError = ::GetLastError();
                                }
                            }

                            if (proxyConfig.lpszAutoConfigUrl != NULL)
                            {
                                ::GlobalFree(proxyConfig.lpszAutoConfigUrl);
                            }
                            if (proxyConfig.lpszProxy != NULL)
                            {
                                ::GlobalFree(proxyConfig.lpszProxy);
                            }
                            if (proxyConfig.lpszProxyBypass != NULL)
                            {
                                ::GlobalFree(proxyConfig.lpszProxyBypass);
                            }
                        }
                        else
                        {
                            m_dwLastError = ::GetLastError();
                        }
                    }
                    if (bSendRequestSucceed)
                    {
                        if (m_pDataToSend != NULL)
                        {
                            DWORD dwWritten = 0;
                            if (!::WinHttpWriteData(hRequest,
                                                    m_pDataToSend,
                                                    m_dataToSendSize,
                                                    &dwWritten))
                            {
                                m_dwLastError = ::GetLastError();
                            }
                        }
                        if (::WinHttpReceiveResponse(hRequest, NULL))
                        {
                            DWORD dwSize = 0;
                            BOOL bResult = FALSE;
                            bResult = ::WinHttpQueryHeaders(hRequest,
                                                            WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                                            WINHTTP_HEADER_NAME_BY_INDEX,
                                                            NULL,
                                                            &dwSize,
                                                            WINHTTP_NO_HEADER_INDEX);
                            if (bResult || (!bResult && (::GetLastError() == ERROR_INSUFFICIENT_BUFFER)))
                            {
                                wchar_t *szHeader = new wchar_t[dwSize];
                                if (szHeader != NULL)
                                {
                                    memset(szHeader, 0, dwSize* sizeof(wchar_t));
                                    if (::WinHttpQueryHeaders(hRequest,
                                                              WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                                              WINHTTP_HEADER_NAME_BY_INDEX,
                                                              szHeader,
                                                              &dwSize,
                                                              WINHTTP_NO_HEADER_INDEX))
                                    {
                                        m_responseHeader=szHeader;
                                      
                                        String regExp = "";
                                        if (!m_bForceCharset)
                                        {
                                            regExp = "charset={[A-Za-z0-9\\-_]+}";
                                            RegExp r(regExp,RegExp::UTF8|RegExp::CASELESS);
                                            if (r.Match(m_responseHeader.ToString()))
                                            {
                                                m_responseCharset = r[0].ToWString();
                                            }
                                        }
                                        regExp = "Content-Length: {[0-9]+}";
                                        RegExp r2(regExp,RegExp::UTF8|RegExp::CASELESS);
                                        if (r2.Match(m_responseHeader.ToString()))
                                        {
                                            m_responseByteCount =  ScanInt64(r2[0]);
                                        }
                                        regExp = "Location: {[0-9]+}";
                                        RegExp r3(regExp,RegExp::UTF8|RegExp::CASELESS);
                                        if (r3.Match(m_responseHeader.ToString()))
                                        {
                                            m_location = r3[0].ToWString();
                                        }
                                        regExp = "Set-Cookie:\\b*{.+?}\\n";
                                        RegExp r4(regExp,RegExp::UTF8|RegExp::CASELESS);
                                        bool first = true;
                                        while (r4.GlobalMatch(m_responseHeader.ToString()))
                                        {
                                            //for (int i = 0; i < r4.GetCount(); i++)
                                           // {
                                                m_responseCookies +=  r4[0].ToWString();
                                                if (first)
                                                    first = false;
                                                else
                                                    m_responseCookies += L"; ";
                                               /* if (i != r4.GetCount() - 1)
                                                {
                                                    m_responseCookies += L"; ";
                                                }*/
                                         //   }
                                           
                                        }
                                         m_responseCookies = TrimRight(m_responseCookies);// L" ");
                                            if (m_responseCookies.GetLength() > 0 && m_responseCookies[m_responseCookies.GetLength() - 1] != L';')
                                            {
                                                m_responseCookies += L";";
                                            }
                                    }
                                    delete[] szHeader;
                                }
                            }
                            
                            dwSize = 0;
                            bResult = ::WinHttpQueryHeaders(hRequest,
                                                            WINHTTP_QUERY_STATUS_CODE,
                                                            WINHTTP_HEADER_NAME_BY_INDEX,
                                                            NULL,
                                                            &dwSize,
                                                            WINHTTP_NO_HEADER_INDEX);
                            if (bResult || (!bResult && (::GetLastError() == ERROR_INSUFFICIENT_BUFFER)))
                            {
                                wchar_t *szStatusCode = new wchar_t[dwSize];
                                if (szStatusCode != NULL)
                                {
                                    memset(szStatusCode, 0, dwSize* sizeof(wchar_t));
                                    if (::WinHttpQueryHeaders(hRequest,
                                                              WINHTTP_QUERY_STATUS_CODE,
                                                              WINHTTP_HEADER_NAME_BY_INDEX,
                                                              szStatusCode,
                                                              &dwSize,
                                                              WINHTTP_NO_HEADER_INDEX))
                                    {
                                        m_statusCode = szStatusCode;
                                    }
                                    delete[] szStatusCode;
                                }
                            }

                            unsigned int iMaxBufferSize = INT_BUFFERSIZE;
                            unsigned int iCurrentBufferSize = 0;
                            if (m_pResponse != NULL)
                            {
                                delete[] m_pResponse;
                                m_pResponse = NULL;
                            }
                            m_pResponse = new BYTE[iMaxBufferSize];
                            if (m_pResponse == NULL)
                            {
                                bRetVal = false;
                                break;
                            }
                            memset(m_pResponse, 0, iMaxBufferSize);
                            do
                            {
                                dwSize = 0;
                                if (::WinHttpQueryDataAvailable(hRequest, &dwSize))
                                {
                                    SetProgress(iCurrentBufferSize);
                                    BYTE *pResponse = new BYTE[dwSize + 1];
                                    if (pResponse != NULL)
                                    {
                                        memset(pResponse, 0, (dwSize + 1)*sizeof(BYTE));
                                        DWORD dwRead = 0;
                                        if (::WinHttpReadData(hRequest,
                                                              pResponse,
                                                              dwSize,
                                                              &dwRead))
                                        {
                                            if (dwRead + iCurrentBufferSize > iMaxBufferSize)
                                            {
                                                BYTE *pOldBuffer = m_pResponse;
                                                m_pResponse = new BYTE[iMaxBufferSize * 2];
                                                if (m_pResponse == NULL)
                                                {
                                                    m_pResponse = pOldBuffer;
                                                    bRetVal = false;
                                                    break;
                                                }
                                                iMaxBufferSize *= 2;
                                                memset(m_pResponse, 0, iMaxBufferSize);
                                                memcpy(m_pResponse, pOldBuffer, iCurrentBufferSize);
                                                delete[] pOldBuffer;
                                            }
                                            memcpy(m_pResponse + iCurrentBufferSize, pResponse, dwRead);
                                            iCurrentBufferSize += dwRead;
                                        }
                                        delete[] pResponse;
                                    }
                                }
                                else
                                {
                                    m_dwLastError = ::GetLastError();
                                }
                            }
                            while (dwSize > 0);
                            SetProgress(iCurrentBufferSize);
                            m_responseByteCountReceived = iCurrentBufferSize;

                            UINT codePage = CP_ACP;
                            DWORD dwFlag = MB_PRECOMPOSED;
                            if (_wcsnicmp(m_responseCharset.Begin(), L"utf-8", 5) == 0)
                            {
                                codePage = CP_UTF8;
                                dwFlag = 0;
                            }
                            int iLength = ::MultiByteToWideChar(codePage,
                                                                dwFlag, 
                                                                (LPCSTR)m_pResponse, 
                                                                m_responseByteCountReceived + 1, 
                                                                NULL, 
                                                                0);
                            if (iLength <= 0)
                            {
                                // Use CP_ACP if UTF-8 fail
                                codePage = CP_ACP;
                                dwFlag = MB_PRECOMPOSED;
                                iLength = ::MultiByteToWideChar(codePage,
                                                                dwFlag, 
                                                                (LPCSTR)m_pResponse, 
                                                                m_responseByteCountReceived + 1, 
                                                                NULL, 
                                                                0);
                            }
                            if (iLength > 0)
                            {
                                wchar_t *wideChar = new wchar_t[iLength];
                                if (wideChar != NULL)
                                {
                                    memset(wideChar, 0, iLength * sizeof(wchar_t));
                                    iLength = ::MultiByteToWideChar(codePage,
                                                                    dwFlag, 
                                                                    (LPCSTR)m_pResponse, 
                                                                    m_responseByteCountReceived + 1, 
                                                                    wideChar, 
                                                                    iLength);
                                    if (iLength > 0)
                                    {
                                        m_responseContent = wideChar;
                                    }
                                    delete[] wideChar;
                                }
                            }
                            bGetReponseSucceed = true;

                            // If the resposne html web page size is less than 200, retry.
                            if (verb == L"GET" && !disableAutoRedirect)
                            {
                                String regExp = "{<html>}";
                                String content = FromUnicode(m_responseContent,CHARSET_UTF8);
                                RegExp r(regExp,RegExp::UTF8|RegExp::CASELESS);
                                if (r.Match(content))
                                {
                                    regExp = "{</html>}";
                                    RegExp r2(regExp,RegExp::UTF8|RegExp::CASELESS);
                                    if (!r2.Match(content))
                                    {
                                        m_dwLastError = ERROR_INVALID_DATA;
                                        bGetReponseSucceed = false;
                                    }
                                }
                            }
                        }
                        else
                        {
                            m_dwLastError = ::GetLastError();
                        }
                    }
                } // while
                if (!bGetReponseSucceed)
                {
                    bRetVal = false;
                }

                ::WinHttpCloseHandle(hRequest);
            }
            ::WinHttpCloseHandle(hConnect);
        }

    }

    return bRetVal;
}

WString WinHttpClient::GetResponseHeader(void)
{
    return m_responseHeader;
}

WString WinHttpClient::GetResponseContent(void)
{
    return m_responseContent;
}

WString WinHttpClient::GetResponseCharset(void)
{
    return m_responseCharset;
}

WString WinHttpClient::GetRequestHost(void)
{
    return m_requestHost;
}

bool WinHttpClient::SaveResponseToFile(const WString &filePath)
{
    if (m_pResponse == NULL || m_responseByteCountReceived <= 0)
    {
        return false;
    }
    FILE *f = NULL;
    int iResult = _wfopen_s(&f, filePath.Begin(), L"wb");
    if (iResult == 0 && f != NULL)
    {
        fwrite(m_pResponse, m_responseByteCountReceived, 1, f);
        fclose(f);
        return true;
    }

    return false;
}

bool WinHttpClient::SetProgress(unsigned int byteCountReceived)
{
    bool bReturn = false;
    if (m_pfProcessProc != NULL && m_responseByteCount > 0)
    {
        double dProgress = (double)byteCountReceived * 100 / m_responseByteCount;
        m_pfProcessProc(dProgress);
        bReturn = true;
    }

    return bReturn;
}

WString WinHttpClient::GetResponseCookies(void)
{
    return m_responseCookies;
}

bool WinHttpClient::SetAdditionalRequestCookies(const WString &cookies)
{
    m_additionalRequestCookies = cookies;

    return true;
}

bool WinHttpClient::SetAdditionalDataToSend(BYTE *data, unsigned int dataSize)
{
    if (data == NULL || dataSize < 0)
    {
        return false;
    }

    if (m_pDataToSend != NULL)
    {
        delete[] m_pDataToSend;
    }
    m_pDataToSend = NULL;
    m_pDataToSend = new BYTE[dataSize];
    if (m_pDataToSend != NULL)
    {
        memcpy(m_pDataToSend, data, dataSize);
        m_dataToSendSize = dataSize;
        return true;
    }

    return false;
}

// Reset additional data fields
bool WinHttpClient::ResetAdditionalDataToSend(void)
{
    if (m_pDataToSend != NULL)
    {
        delete[] m_pDataToSend;
    }

    m_pDataToSend = NULL;
    m_dataToSendSize = 0;

    return true;
}

// Allow us to reset the url on subsequent requests
bool WinHttpClient::UpdateUrl(const WString &url)
{
    m_requestURL = url;
    ResetAdditionalDataToSend();

    return true;
}

bool WinHttpClient::SetAdditionalRequestHeaders(const WString &additionalRequestHeaders)
{
    m_additionalRequestHeaders = additionalRequestHeaders;

    return true;
}

bool WinHttpClient::SetProxy(const WString &proxy)
{
    m_proxy = proxy;

    return true;
}

// If we don't require valid SSL Certs then accept any
// certificate on an SSL connection
bool WinHttpClient::SetRequireValidSslCertificates(bool require)
{
    m_requireValidSsl = require;

    return true;
}

const BYTE *WinHttpClient::GetRawResponseContent(void)
{
    return m_pResponse;
}

unsigned int WinHttpClient::GetRawResponseContentLength(void)
{
    return m_responseByteCount;
}

unsigned int WinHttpClient::GetRawResponseReceivedContentLength(void)
{
    return m_responseByteCountReceived;
}

DWORD WinHttpClient::GetLastError(void)
{
    return m_dwLastError;
}

WString WinHttpClient::GetResponseStatusCode(void)
{
    return m_statusCode;
}

bool WinHttpClient::SetUserAgent(const WString &userAgent)
{
    m_userAgent = userAgent;

    return true;
}

bool WinHttpClient::SetForceCharset(const WString &charset)
{
    m_responseCharset = charset;

    return true;
}

bool WinHttpClient::SetProxyUsername(const WString &username)
{
    m_proxyUsername = username;

    return true;
}

bool WinHttpClient::SetProxyPassword(const WString &password)
{
    m_proxyPassword = password;

    return true;
}
    
WString WinHttpClient::GetResponseLocation(void)
{
    return m_location;
}

bool WinHttpClient::SetTimeouts(unsigned int resolveTimeout,
                                unsigned int connectTimeout,
                                unsigned int sendTimeout,
                                unsigned int receiveTimeout)
{
    m_resolveTimeout = resolveTimeout;
    m_connectTimeout = connectTimeout;
    m_sendTimeout = sendTimeout;
    m_receiveTimeout = receiveTimeout;

    return true;
}

#endif // WINHTTPCLIENT_H
