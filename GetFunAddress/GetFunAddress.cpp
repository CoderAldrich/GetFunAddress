// GetFunAddress.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "GetFunAddress.h"
#include <windows.h>
//
//typedef DWORD (WINAPI *PGetProcAddress)(  __in  HMODULE hModule, __in  LPCSTR lpProcName);
//
//DWORD WINAPI GetKernelBase()
//{
//	__asm
//	{
//		push		esi
//		xor         eax, eax
//		mov         eax, dword ptr fs:[30h]     //获取PEB基址
//		mov         eax, dword ptr [eax+0ch]
//		mov         esi, dword ptr [eax+1ch]
//		lods        dword ptr [esi]
//		mov         eax, [eax+8]
//		pop         esi
//	}
//	return;
//}
//
//DWORD WINAPI GetENTaddress(DWORD pDllBase)
//{
//	DWORD local1;
//	DWORD local2;
//	DWORD local3;
//	DWORD local4;
//	__asm
//	{
//		mov         esi, 3Ch
//			add         esi, pDllBase
//			mov         eax, dword ptr [esi]
//		add         eax, pDllBase                //此时eax保存的地址指向“PE”标志
//			mov         esi, dword ptr [eax+78h]
//		add         esi, 18h
//			add         esi, pDllBase
//			mov         eax, dword ptr [esi]
//		mov         local1, eax
//			add         esi, 4
//			lea         edi, [local2]
//		lods        dword ptr [esi]
//		add         eax, pDllBase
//			stos        dword ptr es:[edi]
//		mov         local2, eax
//			lods        dword ptr [esi]
//		add         eax, pDllBase
//			push        eax
//			stos        dword ptr es:[edi]
//		mov         local3, eax
//			mov         eax, dword ptr [esi]
//		add         eax, pDllBase
//			mov        local4, eax
//			pop         esi
//			mov         eax, dword ptr [esi]
//		add         eax, pDllBase
//			add esp, 0x10
//	}
//	return;
//}
//
//DWORD WINAPI HashString(PCHAR pstr)
//{
//	__asm
//	{
//		mov         edi, pstr
//			mov         ebx, edi
//			push        edi
//			xor         al,al
//
//strlen:
//		scas        byte    ptr es:[edi]
//		jnz         strlen
//
//			pop         esi                         //此时esi保存的是字符串首地址
//			sub         edi, ebx                    //此时edi为字符串长度，包含结尾空字符
//			cld
//			xor         ecx, ecx
//			dec         ecx
//			mov         edx, ecx
//
//
//count:
//		xor         eax, eax
//			xor         ebx, ebx
//			lods        byte    ptr [esi]           //加载esi处的第一个byte到eax
//			xor         al, cl
//			mov         cl, ch
//			mov         ch, dl
//			mov         dl, dh
//			mov         dh, 8
//singlechar:
//		shr     bx, 1
//			rcr     ax, 1
//			jnb     test_1
//			xor     ax, 8320h
//			xor     bx, 0EDB8h
//test_1:
//		dec     dh
//			jnz     singlechar
//			xor     ecx, eax
//			xor     edx, ebx
//			dec     edi
//			jnz     count
//
//			not        edx
//			not        ecx
//			mov        eax, edx
//			rol        eax, 10h
//			mov        ax, cx
//	}
//	return;
//}
//
//DWORD WINAPI GetFunAddress(DWORD pDllBase, DWORD dwHash)
//{
//	PCHAR straddress = 0;
//	__asm
//	{
//		mov         edx, pDllBase
//			push        edx
//			call        GetENTaddress                  
//			mov         straddress, eax                //获取EXPORT_NAME_TABLE的第一个函数名地址
//
//			mov         edx, straddress
//gethash:
//		push        edx
//			call        HashString
//			mov         ebx, dwHash
//			cmp         eax, ebx                        //比较当前函数名的hash是否和所需的相同
//			jz          retcode
//			xor         eax, eax
//			xor         ecx, ecx
//nextstr:
//		mov         al, byte ptr [edx]
//		inc         edx
//			cmp         al, cl
//			jnz         nextstr
//			jmp         gethash
//
//
//retcode:
//		mov         eax, edx
//	}
//	return;
//}

//
// 实现GetProcaddress
DWORD WINAPI myGetFunAddress( HMODULE hModule, char *FuncName )
{
	DWORD retAddr = 0;
	DWORD *namerav, *funrav;
	DWORD cnt = 0;
	DWORD maxIndex, minIndex, temp, lasttemp;
	WORD *nameOrdinal;
	WORD nIndex = 0;
	int cmpresult = 0;
	char *ModuleBase = (char*)hModule;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptHeader;
	PIMAGE_EXPORT_DIRECTORY pExportDir;

	if(hModule == 0)
		return 0;

	pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	pFileHeader = (PIMAGE_FILE_HEADER)(ModuleBase + pDosHeader->e_lfanew + 4);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER)((char*)pFileHeader + sizeof( IMAGE_FILE_HEADER ));
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	namerav = (DWORD*)(ModuleBase + pExportDir->AddressOfNames);
	funrav = (DWORD*)(ModuleBase + pExportDir->AddressOfFunctions);
	nameOrdinal = (WORD*)(ModuleBase + pExportDir->AddressOfNameOrdinals);
	if((DWORD)FuncName < 0x0000FFFF)
	{
		retAddr = (DWORD)(ModuleBase + funrav[(WORD)FuncName]);
	}
	else
	{

		maxIndex = pExportDir->NumberOfFunctions;
		minIndex = 0;
		lasttemp = 0;
		while(1)
		{
			temp = (maxIndex + minIndex) / 2;
			if(temp == lasttemp)
			{
				//Not Found!
				retAddr = 0;
				break;
			}
			cmpresult = strcmp( FuncName, ModuleBase + namerav[temp] );
			if(cmpresult < 0)
			{
				maxIndex = lasttemp = temp;
			}
			else if(cmpresult > 0)
			{
				minIndex = lasttemp = temp;
			}
			else
			{
				nIndex = nameOrdinal[temp];
				retAddr = (DWORD)(ModuleBase + funrav[nIndex]);
				break;
			}

		}
	}
	return retAddr;
}



int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	DWORD pKernelBase = 0;
	CHAR *pHeapAlloc = "HeapAlloc";
	DWORD dwHash = 0x4134D1AD;
	HMODULE hKernel32 = 0;
	DWORD HeapAlloc = 0;

	hKernel32 = LoadLibraryA("user32.dll");
	DWORD pGetProcAddress = (DWORD)myGetFunAddress(hKernel32, "MessageBoxA");
	__asm
	{
		push    0
			push	pHeapAlloc
			push	pHeapAlloc
			push	0
		call	pGetProcAddress
		mov		HeapAlloc, eax
	}
	return 1;
}