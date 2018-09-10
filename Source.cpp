#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>

#define ORIGINAL_DLL "RendDX9_ori.dll"

struct {
	char *gpcm;
	char *gpsp;
	char *gamestats;

	char *qr_wildcard;
	char *avail_wildcard;

	char *sb;
	char *sb_wildcard;

	void **fesl_dns_address;

	void **fesl_base_domain;

	char *stella_hostname;
	char *stella_http_name;
} sGameSpyInfo;

void patchString(char *dstAddress, char *srcAddress) {
	DWORD old;
	VirtualProtect(dstAddress, strlen(dstAddress), PAGE_EXECUTE_READWRITE, &old);
	WriteProcessMemory(GetCurrentProcess(), dstAddress, srcAddress, strlen(srcAddress), NULL);

	VirtualProtect(dstAddress, strlen(dstAddress), old, &old);
	FlushInstructionCache(GetCurrentProcess(), dstAddress, strlen(dstAddress));
}
void patchSSL() {
	const char *update_string = "\xB8\x15\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC";
	int instruction_length = 12;
	void *instruction_address = (void *)0x860A87;
	DWORD old;
	VirtualProtect(instruction_address, instruction_length, PAGE_EXECUTE_READWRITE, &old);
	WriteProcessMemory(GetCurrentProcess(), instruction_address, update_string, instruction_length, NULL);

	VirtualProtect(instruction_address, instruction_length, old, &old);
	FlushInstructionCache(GetCurrentProcess(), instruction_address, instruction_length);
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
const char *fesl_hostname = "fesl.openspy.net";

int debugPrint(int arg0, int arg4, char *fmt, ...) {

	char buffer[1024];
	va_list args;
	va_start(args, fmt);
	vsprintf(buffer, fmt, args);
	OutputDebugStringA(buffer);
	va_end(args);
	return 0;
}

int FESL_ResolveHandler(void *this_ptr, const char *ea_gamename, int a3, const char *a4, int a5, int a6) {
	return 0;
}

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

				void *fesldebugFuncAddr = (void *)0x009C11DC;
				void *debugPrintAddr = (void *)debugPrint;

				VirtualProtect(fesldebugFuncAddr, sizeof(void *), PAGE_EXECUTE_READWRITE, &old);
				WriteProcessMemory(GetCurrentProcess(), fesldebugFuncAddr, &debugPrintAddr, sizeof(void *), NULL);

				VirtualProtect(fesldebugFuncAddr, sizeof(void *), old, &old);
				FlushInstructionCache(GetCurrentProcess(), fesldebugFuncAddr, sizeof(void *));
				

				//OutputDebugString("Patching hostnames...\n");

				sGameSpyInfo.gamestats = (char *)(0x00A081A0);

				sGameSpyInfo.gpsp = (char *)(0x00A08BC0);
				sGameSpyInfo.gpcm = (char *)(0x00A08B80);
				sGameSpyInfo.qr_wildcard = (char *)(0x0099F57C);

				sGameSpyInfo.avail_wildcard = (char *)(0x0099F2E8);
				sGameSpyInfo.sb_wildcard = (char *)(0x009A0208);

				sGameSpyInfo.stella_hostname = (char *)(0x009645C4);
				sGameSpyInfo.stella_http_name = (char *)(0x009645A4);

				patchString(sGameSpyInfo.avail_wildcard, "%s.available.openspy.net");
				patchString(sGameSpyInfo.sb_wildcard, "%s.ms%d.openspy.net");
				patchString(sGameSpyInfo.qr_wildcard, "%s.master.openspy.net");

				patchString(sGameSpyInfo.gpsp, "gpsp.openspy.net");
				patchString(sGameSpyInfo.gpcm, "gpcm.openspy.net");
				patchString(sGameSpyInfo.gamestats, "gamestats.openspy.net");

				//.rdata:009645A4 00000020 C http://stella.prod.gamespy.com/
				patchString(sGameSpyInfo.stella_hostname, "stella.prod.openspy.net");
				patchString(sGameSpyInfo.stella_http_name, "http://stella.prod.openspy.net");

				sGameSpyInfo.fesl_dns_address = (void **)0x833DB7;

				sGameSpyInfo.fesl_base_domain = (void **)0x8342CA;



				patchString((char *)0x9C5C7C, ".open");
				patchString((char *)0x9C5C74, "spy");
				patchString((char *)0x9C5C78, "net");

				patchSSL();
				patchErrorNeg206();
				patchDeleteSoldierHang();


				VirtualProtect((void *)sGameSpyInfo.fesl_dns_address, sizeof(void *), PAGE_EXECUTE_READWRITE, &old);
				WriteProcessMemory(GetCurrentProcess(), sGameSpyInfo.fesl_dns_address, (void *)&fesl_hostname, sizeof(void *), NULL);
				VirtualProtect((void *)sGameSpyInfo.fesl_dns_address, sizeof(void *), old, &old);
				FlushInstructionCache(GetCurrentProcess(), sGameSpyInfo.fesl_dns_address, sizeof(void *));


				//OutputDebugString("Done patching hostnames...\n");

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