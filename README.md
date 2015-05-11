# https_cpp_wrapper 



The library allows you to download pages through http/https protocol.
You need Ultimate++ Ide and Windows. It consists of one header file only.
The original source depended on atl.



Usage:
```c++
#include "winhttpclient.h"


WinHttpClient client("https://www.httpssite.com");
client.SetRequireValidSslCertificates(false);
client.SendHttpRequest();
WString httpResponseHeader = client.GetResponseHeader();
String httpResponseContent = client.GetResponseContent().ToString();
LOG(httpResponseContent);
```
Also, see tttp://www.codeproject.com/Articles/66625/A-Fully-Featured-Windows-HTTP-Wrapper-in-C





