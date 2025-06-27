
#define g_szHelloMsg	((TCHAR*)GetHelloData())

#define VERSION (__DATE__ " " __TIME__)


typedef struct _tagLOGON_USER_V2
{
	int nUserID;
	int nHallSvrID;
	int nAgentGroupID;
	DWORD dwIPAddr;
	DWORD dwLogonFlags;
	LONG lTokenID;
	TCHAR szUsername[MAX_USERNAME_LEN];
	TCHAR szPassword[MAX_PASSWORD_LEN];
	TCHAR szHardID[MAX_HARDID_LEN];
	TCHAR szVolumeID[MAX_HARDID_LEN];
	TCHAR szMachineID[MAX_HARDID_LEN];
	TCHAR szHashPwd[DEF_HASHPWD_LEN + 2];
	TCHAR szRndKey[MAX_RNDKEY_LEN_EX];
	DWORD dwSysVer;
	int nLogonSvrID;
	int nHallBuildNO;
	int nHallNetDelay;
	int nHallRunCount;
	int nGameID; //自身游戏id
	DWORD dwGameVer;
	int nRecommenderID; //推广码
	int nChannelID; //渠道号
	char szAppCode[MAX_GAME_CODE_MINI_LEN]; //应该是appcode
	int nRecommGameID; //推荐游戏id
	char szRecommAppCode[MAX_GAME_CODE_MINI_LEN]; //应该是appcode
	int nHallVersion;
	int nReserved2[2];
} LOGON_USER_V2, * LPLOGON_USER_V2;

typedef struct _tagLOGON_SUCCEED_V2
{
	int nUserID;
	int nNickSex;
	int nPortrait;
	int nUserType;
	int nClothingID;
	int nRegisterGroup;
	int nDownloadGroup;
	int nAgentGroupID;
	int nExpiration;
	int nMemberLevel;
	int nHallID;
	TCHAR szUserName[MAX_USERNAME_LEN];
	TCHAR szNickName[MAX_NEW_NICKNAME_LEN];
	TCHAR szUniqueID[MAX_UNIQUEID_LEN];
	TCHAR szIMToken[MAX_IM_TOKEN_LEN];
	TCHAR szIDCard[MAX_IDCARD_LEN];
} LOGON_SUCCEED_V2, * LPLOGON_SUCCEED_V2;

typedef struct _tagGET_AREAS
{
	int nGameID;
	int nAreaType;
	int nSubType;
	int nAgentGroupID;
	DWORD dwGetFlags;
	DWORD dwVersion;
	int nReserved[3];
} GET_AREAS, * LPGET_AREAS;

typedef struct _tagAREAS
{
	int nCount;
	int nLinkCount;
	int nReserved[2];
} AREAS, * LPAREAS;


typedef struct _tagGET_ROOMS {
	int nAreaID;
	int nGameID;
	int nAgentGroupID;
	DWORD dwGetFlags;
	int nReserved[4];
}GET_ROOMS, * LPGET_ROOMS;

typedef struct _tagROOMS
{
	int nRoomCount;
	int nLinkCount;
	int nReserved[2];
} ROOMS, * LPROOMS;



enum http_status
{
	unknown = 0,
	continue_ = 100,
	ok = 200,
	accepted = 202,
	multiple_choices = 300,
	not_modified = 304,
	bad_request = 400,
	unauthorized = 401,
	forbidden = 403,
	not_found = 404,
	request_timeout = 408,
	too_many_requests = 429,
	bad_gateway = 502,
};

enum E_MODCONFIG_ACCESS
{
	PRIVATE = 0x00000000,	//私有,必须授权才可访问
	PUBLIC = 0x00000001,	//公有,不须授权就可访问
	READONLY = 0x00000002,	//只读,锁定文件,必须授权才可操作
	CRYPT = 0x00000010,		//加密
	BASE64 = 0x00000020,	//base64编码(未使用)
	BASE94 = 0x00000040,	//base94编码
	INVALID = 0xFFFFFFFF
};

inline BOOL HasExt(const CString& sName, const CString& sExt) {
	return sName.GetLength() >= sExt.GetLength()
		&& sName.Right(sExt.GetLength()).CompareNoCase(sExt) == 0;
}


inline BOOL IsBinaryFile(const CString& sName)
{
	return HasExt(sName, ".xlam")
		|| HasExt(sName, ".exe")
		/* || HasExt(sName, ".jsb")*/;
}


inline std::unique_ptr<char[]> GetPrivateProfileKeys(const std::string& appname, const std::string& config)
{
	std::unique_ptr<char[]> buff;
	for (int len = MAX_PATH; true; len *= 2)
	{
		buff.reset(new char[len]);
		if (len - 2 != GetPrivateProfileString(appname.c_str(), NULL, "", buff.get(), len, config.c_str())) {
			break;
		}
	}

	return buff;
}


inline std::string GetPrivateProfileString(const std::string& appname, const std::string& keyname, const std::string& def, const std::string& config)
{
	std::unique_ptr<char[]> buff;
	for (int len = MAX_PATH; true; len *= 2)
	{
		buff.reset(new char[len]);
		buff[0] = '\0';
		if (len - 1 != GetPrivateProfileString(appname.c_str(), keyname.c_str(), def.c_str(), buff.get(), len, config.c_str())) {
			break;
		}
	}

	return buff.get();
}



inline BOOL ReadStringFromFile(std::string& sContent, const std::string& sFile)
{
	const int max_retry = 1000;

	auto h = std::unique_ptr<std::remove_pointer_t<HANDLE>, void(*)(HANDLE)>(INVALID_HANDLE_VALUE,
		[](HANDLE h) {
			if (h != INVALID_HANDLE_VALUE) {
				CloseHandle(h);
			}
		}
	);

	for (int i = 0; TRUE; i++)
	{
		h.reset(CreateFile(sFile.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0));

		if (h.get() != INVALID_HANDLE_VALUE) {
			break;
		}
		if (GetLastError() != ERROR_SHARING_VIOLATION) {
			return FALSE;
		}
		if (i >= max_retry) {
			LOG_ERROR("read over max retry");
			return FALSE;
		}
		Sleep(15);
	}

	auto l = GetFileSize(h.get(), nullptr);
	auto p = std::make_unique<char[]>(l);
	DWORD n = 0;
	if (!ReadFile(h.get(), p.get(), l, &n, nullptr)) {
		return FALSE;
	}
	if (l != n) {
		return FALSE;
	}

	sContent.assign(p.get(), p.get() + l);
	return TRUE;
}


inline BOOL WriteStringToFile(const std::string& sContent, const std::string& sFile)
{
	const int max_retry = 1000;

	auto h = std::unique_ptr<std::remove_pointer_t<HANDLE>, void(*)(HANDLE)>(INVALID_HANDLE_VALUE,
		[](HANDLE h) {
			if (h != INVALID_HANDLE_VALUE) {
				CloseHandle(h);
			}
		}
	);

	for (int i = 0; TRUE; i++)
	{
		h.reset(CreateFile(sFile.c_str(), GENERIC_WRITE,
			0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0));

		if (h.get() != INVALID_HANDLE_VALUE) {
			break;
		}
		if (GetLastError() != ERROR_SHARING_VIOLATION) {
			return FALSE;
		}
		if (i >= max_retry) {
			LOG_ERROR("write over max retry");
			return FALSE;
		}
		Sleep(15);
	}

	DWORD n = 0;
	if (!WriteFile(h.get(), sContent.c_str(), sContent.length(), &n, NULL)) {
		return FALSE;
	}

	if (sContent.length() != n) {
		return FALSE;
	}

	return TRUE;
}

inline BOOL RunCmd(const std::string& cmd, DWORD& code, std::string& output)
{
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hRead = INVALID_HANDLE_VALUE;
	HANDLE hWrite = INVALID_HANDLE_VALUE;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		return FALSE;
	}
	///////////////////////////////////////////////////
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	PROCESS_INFORMATION pi = { 0 };
	auto cmd2 = cmd;
	if (!CreateProcess(NULL, cmd2.data(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) {
		return FALSE;
	}
	CloseHandle(hWrite);
	///////////////////////////////////////////////////
	{
		char buff[1024] = { 0 };
		DWORD dwRead = 0;
		while (ReadFile(hRead, buff, sizeof(buff) - 1, &dwRead, NULL)) {
			output.append(buff, dwRead);
		}
	}
	CloseHandle(hRead);
	///////////////////////////////////////////////////
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return TRUE;
}


inline std::string TransMsg(const std::string& msg)
{
	auto config = theApp.GetConfig();
	if (auto buff = GetPrivateProfileKeys("TransMsg", (LPCTSTR)config)) {
		for (auto p = buff.get(); *p; p += _tcslen(p) + 1) {
			if (msg.find(p) != std::string::npos) {
				TCHAR buff[MAX_PATH] = {};
				GetPrivateProfileString("TransMsg", p, msg.c_str(), buff, _countof(buff), config);
				return buff;
			}
		}
	}
	return msg;
}

template < UINT TYPE = MB_OK, typename FMT, typename... ARGS >
int MsgBox(const FMT& fmt, const ARGS&... args) {
	auto msg = strprintf(fmt, args...);
	msg = TransMsg(msg);
	auto ret = AfxMessageBox(msg.c_str(), TYPE);

	if (msg.find(TransMsg("CheckRequest failed")) != std::string::npos) {
		CUserVerifyDlg uvdlg;
		if (uvdlg.DoModal() != IDOK) {
			//AfxGetApp()->m_pMainWnd->PostMessage(WM_QUIT);
		}
	}

	return ret;
}



inline bool aes_decrypt(const std::string& crypt, std::string& plain, const std::string& _key)
{
	std::string key = _key;
	key.resize(16);

	std::string tmp;
	tmp.resize(crypt.size());

	UINT len = tmp.size();
	if (!xyAes128DecryptCbc((BYTE*)key.data(), (BYTE*)crypt.data(), crypt.size(), (BYTE*)tmp.data(), len)) {
		return false;
	}

	tmp.resize(len);
	plain = std::move(tmp);
	return true;
}


inline BOOL CheckResp(const std::string& resp_body, Json::Value& resp)
{
	try
	{
		Json::Reader reader;
		if (!reader.parse(resp_body, resp)) {
			MsgBox("parse failed: %s", resp_body);
			return FALSE;
		}

		auto& errs = resp["errs"];
		if (errs.isArray() && !errs.empty()) {
			MsgBox("failed code: %d, msg: %s, line: %d",
				errs[0]["code"].asInt(),
				errs[0]["msg"].asString(),
				errs[0]["line"].asInt());
			return FALSE;
		}
	}
	catch (Json::Exception& e)
	{
		MsgBox("catch error: %s", e.what());
		return FALSE;
	}
	catch (...)
	{
		MsgBox("catch error: %s", resp_body);
		return FALSE;
	}

	return TRUE;
}



inline LRESULT DoCtrlA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (Msg == WM_KEYDOWN
		&& (GetKeyState(VK_CONTROL) & 0x8000)
		&& wParam == 'A')
	{
		auto pEdit = (CEdit*)CWnd::FromHandle(hWnd);
		pEdit->SetSel(0, -1);
		return 1;
	}
	return 0;
}

inline LRESULT DoCtrlC(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (/*Msg == WM_KEYDOWN
	&& (GetKeyState(VK_CONTROL) & 0x8000)
	&& wParam == 'C'
	|| */Msg == WM_COPY)
	{
		CString sData;
		{
			auto pEdit = (CEdit*)CWnd::FromHandle(hWnd);
			pEdit->GetWindowText(sData);

			int nSelEnd = 0, nSelStart = 0;
			pEdit->GetSel(nSelStart, nSelEnd);
			sData = sData.Mid(nSelStart, nSelEnd - nSelStart);
		}

		if (AfxGetMainWnd()->OpenClipboard())
		{
			bstr_t s = sData;
			auto h = GlobalAlloc(GHND, (s.length() + 1) * 2);
			auto p = (wchar_t*)GlobalLock(h);
			StrCpyW(p, s);
			GlobalUnlock(h);

			EmptyClipboard();
			SetClipboardData(CF_UNICODETEXT, h);
			CloseClipboard();
		}

		return 1;
	}
	return 0;
}

inline LRESULT DoCtrlV(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (/*Msg == WM_KEYDOWN
	&& (GetKeyState(VK_CONTROL) & 0x8000)
	&& wParam == 'V'
	|| */Msg == WM_PASTE)
	{
		CString sData;

		if (AfxGetMainWnd()->OpenClipboard())
		{
			HANDLE hClipboardData = GetClipboardData(CF_UNICODETEXT);
			auto pchData = (LPCWSTR)GlobalLock(hClipboardData);
			sData = pchData;
			GlobalUnlock(hClipboardData);
			CloseClipboard();
		}

		//if (hWnd == AfxGetMainWnd()->GetDlgItem(IDC_EDIT_NAME)->m_hWnd) {
		//	sData.MakeLower();
		//}

		auto pEdit = (CEdit*)CWnd::FromHandle(hWnd);
		pEdit->ReplaceSel(sData, TRUE);
		return 1;
	}
	return 0;
}

inline LRESULT DoCtrlX(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (/*Msg == WM_KEYDOWN
		&& (GetKeyState(VK_CONTROL) & 0x8000)
		&& wParam == 'X'
		|| */Msg == WM_CUT)
	{
		auto pEdit = (CEdit*)CWnd::FromHandle(hWnd);

		CString sData;
		{
			pEdit->GetWindowText(sData);

			int nSelEnd = 0, nSelStart = 0;
			pEdit->GetSel(nSelStart, nSelEnd);
			sData = sData.Mid(nSelStart, nSelEnd - nSelStart);
		}

		if (AfxGetMainWnd()->OpenClipboard())
		{
			bstr_t s = sData;
			auto h = GlobalAlloc(GHND, (s.length() + 1) * 2);
			auto p = (wchar_t*)GlobalLock(h);
			StrCpyW(p, s);
			GlobalUnlock(h);

			EmptyClipboard();
			SetClipboardData(CF_UNICODETEXT, h);
			CloseClipboard();
		}

		pEdit->ReplaceSel("", TRUE);
		return 1;
	}
	return 0;
}


inline LRESULT DoTab(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (Msg == WM_KEYDOWN
		&& (GetKeyState(VK_TAB) & 0x8000))
	{
		auto pEdit = (CEdit*)CWnd::FromHandle(hWnd);
		pEdit->ReplaceSel("\t", TRUE);
		return 1;
	}
	return 0;
}