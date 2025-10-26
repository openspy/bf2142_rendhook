//#define _CRT_SECURE_NO_WARNINGS
//#include <windows.h>
//#include <stdio.h>
//extern FILE* console_fd;
//int debugPrint(int arg0, int arg4, char* fmt, ...) {
//
//	char buffer[1024];
//	va_list args;
//	va_start(args, fmt);
//	vsprintf(buffer, fmt, args);
//	vfprintf(console_fd, fmt, args);
//	OutputDebugStringA(buffer);
//	va_end(args);
//	return 0;
//}
//
//static void* originalFunc = (void*)0x8341c0;
//static int (*OriginalFuncCB)(void*, const char*, const char*, const char*, void*, void*) = (int (*)(void*, const char*, const char*, const char*, void*, void*))originalFunc;
//
//static void* silly_stack[8];
//void useful_resolve_handler() {
//	fprintf(console_fd, "FESL RESOLVE: %p %p %p %p\n", silly_stack[0], silly_stack[1], silly_stack[2], silly_stack[3]);
//	fflush(console_fd);
//
//	void* this_ptr = (void*)silly_stack[0];
//	void* gamename_ptr = (void*)silly_stack[1];
//	void* region_ptr = (void*)silly_stack[2];
//	void* dstbuf_ptr = (void*)silly_stack[3];
//	void* port_ptr = (void*)silly_stack[4];
//	void *cb_ptr = (void*)silly_stack[5];
//
//	/*stack layout (size is 12):
//	*	dstbuf
//	*	port
//	*	unkcb
//	*/
//	__asm {
//		mov eax, this_ptr
//	}
//
//	//bf2142-test.openspy.tst
//}
//__declspec(naked) void  FESL_ResolveHandler() {
//
//	__asm {
//		mov silly_stack[0 * 4], edx //this ptr
//
//		mov eax, [esp + 4] //gamename
//		mov silly_stack[1 * 4], eax
//
//		mov eax, [esp + 8] //region
//		mov silly_stack[2 * 4], eax
//
//		mov eax, [esp + 12] //dst?
//		mov silly_stack[3 * 4], eax
//
//		mov eax, [esp + 16] //port
//		mov silly_stack[4 * 4], eax
//
//		mov eax, [esp + 20] //unknown callback
//		mov silly_stack[5 * 4], eax
//	};
//	useful_resolve_handler();
//
//
//	__asm retn 20;
//}
//
//
//void install_fesl_patches() {
//	DWORD old;
//	void* fesldebugFuncAddr = (void*)0x009C11DC;
//	void* debugPrintAddr = (void*)debugPrint;
//
//	VirtualProtect(fesldebugFuncAddr, sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
//	WriteProcessMemory(GetCurrentProcess(), fesldebugFuncAddr, &debugPrintAddr, sizeof(void*), NULL);
//
//	VirtualProtect(fesldebugFuncAddr, sizeof(void*), old, &old);
//	FlushInstructionCache(GetCurrentProcess(), fesldebugFuncAddr, sizeof(void*));
//
//	//void* feslResolveFuncAddr = (void*)0x9C5BE8;
//	//void* ourFeslResolveAddr = (void*)FESL_ResolveHandler;
//
//	//VirtualProtect(feslResolveFuncAddr, sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
//	//WriteProcessMemory(GetCurrentProcess(), feslResolveFuncAddr, &ourFeslResolveAddr, sizeof(void*), NULL);
//
//	//VirtualProtect(feslResolveFuncAddr, sizeof(void*), old, &old);
//	//FlushInstructionCache(GetCurrentProcess(), feslResolveFuncAddr, sizeof(void*));
//}