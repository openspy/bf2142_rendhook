#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>

#define ORIGINAL_DLL "RendDX9_ori.dll"

FILE* console_fd;

void install_fesl_patches();

struct {
	char *gpcm;
	char *gpsp;
	char *gamestats;

	char *qr_wildcard;
	char *avail_wildcard;

	char *sb;
	char *sb_wildcard;

	char *stella_hostname;
	char *stella_http_name;

	char* gamespy_online_check;
} sGameSpyInfo;

void patchString(char *dstAddress, char *srcAddress) {
	DWORD old;
	VirtualProtect(dstAddress, strlen(dstAddress), PAGE_EXECUTE_READWRITE, &old);
	WriteProcessMemory(GetCurrentProcess(), dstAddress, srcAddress, strlen(srcAddress), NULL);

	VirtualProtect(dstAddress, strlen(dstAddress), old, &old);
	FlushInstructionCache(GetCurrentProcess(), dstAddress, strlen(dstAddress));
}
void patchErrorNeg206() {
	const char *update_string = "\xEB\x2E\x90";
	int instruction_length = 3;
	void *instruction_address = (void *)0x833F7F;
	DWORD old;
	VirtualProtect(instruction_address, instruction_length, PAGE_EXECUTE_READWRITE, &old);
	WriteProcessMemory(GetCurrentProcess(), instruction_address, update_string, instruction_length, NULL);

	VirtualProtect(instruction_address, instruction_length, old, &old);
	FlushInstructionCache(GetCurrentProcess(), instruction_address, instruction_length);
}
void patchDeleteSoldierHang() {
	//patch infinite loop of waiting for findnextfile to fail...???
	int instruction_length = 6;
	void *instruction_address = (void *)0x69F7CD;
	const char *update_string = "\x90\x90\x90\x90\x90\x90";
	DWORD old;
	VirtualProtect(instruction_address, instruction_length, PAGE_EXECUTE_READWRITE, &old);
	WriteProcessMemory(GetCurrentProcess(), instruction_address, update_string, instruction_length, NULL);

	VirtualProtect(instruction_address, instruction_length, old, &old);
	FlushInstructionCache(GetCurrentProcess(), instruction_address, instruction_length);
}
#define BASE_ADDRESS 0x400000
static int patched = false;

//HMODULE original_dll;
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD     fdwReason,
	LPVOID    lpvReserved
) {
	char buff[1024];
	DWORD old;
	switch (fdwReason) {
	default:
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
			if (!patched) {
				patched = true;
				/*AllocConsole();
				console_fd = fopen("CONOUT$", "wb");*/

				
				install_fesl_patches();

				//OutputDebugString("Patching hostnames...\n");

				sGameSpyInfo.gamestats = (char *)(0x00A081A0);

				sGameSpyInfo.gpsp = (char *)(0x00A08BC0);
				sGameSpyInfo.gpcm = (char *)(0x00A08B80);
				sGameSpyInfo.qr_wildcard = (char *)(0x0099F57C);

				sGameSpyInfo.avail_wildcard = (char *)(0x0099F2E8);
				sGameSpyInfo.sb_wildcard = (char *)(0x009A0208);

				sGameSpyInfo.stella_hostname = (char *)(0x009645C4);
				sGameSpyInfo.stella_http_name = (char *)(0x009645A4);

				sGameSpyInfo.gamespy_online_check = (char*)0x00925424;

				patchString(sGameSpyInfo.avail_wildcard, "%s.available.openspy.net");
				patchString(sGameSpyInfo.sb_wildcard, "%s.ms%d.openspy.net");
				patchString(sGameSpyInfo.qr_wildcard, "%s.master.openspy.net");

				patchString(sGameSpyInfo.gpsp, "gpsp.openspy.net");
				patchString(sGameSpyInfo.gpcm, "gpcm.openspy.net");
				patchString(sGameSpyInfo.gamestats, "gamestats.openspy.net");

				//.rdata:009645A4 00000020 C http://stella.prod.gamespy.com/
				patchString(sGameSpyInfo.stella_hostname, "stella.prod.openspy.net");
				patchString(sGameSpyInfo.stella_http_name, "http://stella.prod.openspy.net");

				//.rdata:00925424	0000000C	C	gamespy.com
				patchString(sGameSpyInfo.gamespy_online_check, "openspy.net");

				patchErrorNeg206();
				patchDeleteSoldierHang();


			}

//			sprintf(buff, "dns: %s - %s - %s - %s - %s, FESL: %s - %p\n", sGameSpyInfo.gamestats, sGameSpyInfo.gpsp, sGameSpyInfo.gpcm, sGameSpyInfo.sb_wildcard, sGameSpyInfo.qr_wildcard, *sGameSpyInfo.fesl_dns_address, fesl_hostname);
	//		OutputDebugString(buff);
			break;
		case DLL_PROCESS_DETACH:
			//fclose(fd);
			//FreeLibrary(original_dll);
			break;
	}
	return TRUE;
}


extern "C" int __cdecl deinitDll() {
	/*int (*true_deinitDll)();

	true_deinitDll = (int (*)())GetProcAddress(original_dll, "deinitDll");
	return true_deinitDll();
	*/
	return 0;
}

extern "C" bool __cdecl initDll(int a1) {
	/*bool (*true_initDll)(int);

	true_initDll = (bool (*)(int))GetProcAddress(original_dll, "initDll");

	fprintf(fd, "test: %p\n", true_initDll);
	return true_initDll(a1);*/
	return true;
	
}