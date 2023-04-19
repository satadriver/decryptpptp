
#include <windows.h>


#define LOG_FILE_NAME  "log.txt"

wchar_t* GB2312ToUnicode(const char* szGBString)
{
	UINT nCodePage = 936; //GB2312
	int nLength=MultiByteToWideChar(nCodePage,0,szGBString,-1,NULL,0);
	wchar_t* pBuffer = new wchar_t[nLength+1];
	MultiByteToWideChar(nCodePage,0,szGBString,-1,pBuffer,nLength);
	pBuffer[nLength]=0;
	return pBuffer;
}


char * GBKToUTF8(unsigned char * strGBK)
{
	int nLen = MultiByteToWideChar(CP_ACP, 0, (char*)strGBK, -1, NULL, 0);
	WCHAR * wszUTF8 = new WCHAR[nLen];
	int ret = MultiByteToWideChar(CP_ACP, 0, (char*)strGBK, -1, wszUTF8, nLen);

	nLen = WideCharToMultiByte(CP_UTF8, 0, wszUTF8, -1, NULL, 0, NULL, NULL);
	char * szUTF8 = new char[nLen];
	ret = WideCharToMultiByte(CP_UTF8, 0, wszUTF8, -1, szUTF8, nLen, NULL, NULL);

	delete[]wszUTF8;
	return szUTF8;
}



int WriteLogFile(char * lplog){
	HANDLE hf = CreateFileA(LOG_FILE_NAME,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	if (hf != INVALID_HANDLE_VALUE)
	{
		DWORD dwcnt = 0;
		int ret = WriteFile(hf,lplog,strlen(lplog),&dwcnt,0);
		CloseHandle(hf);
		if (ret)
		{
			return TRUE;
		}else{
			return FALSE;
		}
	}
	return FALSE;
}
