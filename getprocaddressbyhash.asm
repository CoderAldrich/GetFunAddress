.386
.model      flat,stdcall
option      casemap:none

.data

dwkernel32base      		dd      0                   ;����kernel32.dll�Ļ�ַ
dwGetProcAddresshash  		dd      0FFC97C1Fh
dwLoadLibraryExA					dd 			9746A3D6h
dwLoadLibraryA					dd		4134D1ADh
dwMessageBoxA						dd		0D8556CF7h
GetProcAddress       		dd      0
LoadLibraryExA						dd 				0
LoadLibraryA						dd 				0
szUser32							db 	"user32.dll"
hUser32								dd 		0
szMessageBoxA					db  "MessageBoxA"
MessageBoxA						dd		0
szNote								db	'Note', 0
szText								db	'Done!', 0


.code
; -------------------------------------------------------------------------
;ͨ��PEB�ṹ��ȡkernelbase.dll��ַ
_getkernel32base    proc
                    assume      fs:nothing
                    push        esi
                    xor         eax, eax
                    mov         eax, dword ptr fs:[30h]     ;��ȡPEB��ַ
                    mov         eax, dword ptr [eax+0ch]
                    mov         esi, dword ptr [eax+1ch]
                    lods        dword ptr [esi]
                    mov         eax, [eax+08h]
                    pop         esi
                    ret

_getkernel32base    endp
; -------------------------------------------------------------------------


; -------------------------------------------------------------------------
;�����ַ����׵�ַ�����ַ���hashֵ
;ADDRESSOFSTRING    �ȴ�����hashֵ���ַ����׵�ַ
_gethash            proc        uses edi esi ebx edx ecx,ADDRESSOFSTRING:DWORD

                    mov         edi, ADDRESSOFSTRING
                    mov         ebx, edi
                    push        edi
                    xor         al,al
; ������������������������������������������������������������������������?
                    
            strlen:
                    scas        byte    ptr es:[edi]
                    jnz         strlen
; ������������������������������������������������������������������������?
                    
                    pop         esi                         ;��ʱesi��������ַ����׵�ַ
                    sub         edi, ebx                    ;��ʱediΪ�ַ������ȣ�������β���ַ�
                    cld
                    xor         ecx, ecx
                    dec         ecx
                    mov         edx, ecx
                    
; ������������������������������������������������������������������������?
                    
            count:
                    xor         eax, eax
                    xor         ebx, ebx
                    lods        byte    ptr [esi]           ;����esi���ĵ�һ��byte��eax
                    xor         al, cl
                    mov         cl, ch
                    mov         ch, dl
                    mov         dl, dh
                    mov         dh, 8
                    singlechar:
                                shr     bx, 1
                                rcr     ax, 1
                                jnb     test_1
                                xor     ax, 8320h
                                xor     bx, 0EDB8h
                                test_1:
                                        dec     dh
                                        jnz     singlechar
                                xor     ecx, eax
                                xor     edx, ebx
                                dec     edi
                                jnz     count
; ������������������������������������������������������������������������?
                                
                     not        edx
                     not        ecx
                     mov        eax, edx
                     rol        eax, 10h
                     mov        ax, cx
                     ret

_gethash            endp
; -------------------------------------------------------------------------

; -------------------------------------------------------------------------
;��ȡָ��DLL�е�ĳ��������ַ
;BASEADDRESS    DLL�ļ��ڴ��ַ
;HASHOFNAME     ��������hashֵ
GetFunAddress     proc        uses edx ebx ecx esi edi,BASEADDRESS:DWORD,HASHOFNAME:DWORD
                    local       @straddress:DWORD
                    local       @strhash:DWORD
                    local				@funIndex:DWORD
                    local				@pDosHeader:DWORD
                    local				@pFileHeader:DWORD
                    local				@pOptHeader:DWORD
                    local				@pExportDir:DWORD
                    local				@namerav:DWORD
                    local				@funrav:DWORD
                    local				@nameOrdinal:DWORD

										xor 				eax, eax
										mov					@funIndex, eax									; ������ų�ʼ��
                    mov 				eax, BASEADDRESS
            				mov 				@pDosHeader, eax
            				add					eax, 3ch
            				mov					eax, [eax]
            				add					eax, BASEADDRESS
            				add					eax, 4
            				mov 				@pFileHeader, eax
            				add					eax, 14h
            				mov 				@pOptHeader, eax
            				add					eax, 60h													; ��ȡDataDirectory��ַ
            				mov 				eax, [eax]
            				add					eax, BASEADDRESS
            				mov					@pExportDir, eax
            				add					eax, 20h
            				mov					eax, [eax]												; ��ȡAddressOfNamesƫ��
            				add					eax, BASEADDRESS
            				mov					@namerav, eax											; �õ�namerav�ĵ�ַ                  
            				mov					eax, [eax]
            				
            gethash:
                    add					eax, BASEADDRESS
                    mov         @straddress, eax                ; ��ȡEXPORT_NAME_TABLE�ĵ�һ����������ַ
                    mov         edx, @straddress
                    push        edx
                    call        _gethash
                    mov         ebx, HASHOFNAME
                    cmp         eax, ebx                        ; �Ƚϵ�ǰ��������hash�Ƿ���������ͬ
                    jz          getaddr
                    xor         eax, eax
                    xor         ecx, ecx
            ;nextstr:
                    ;mov         al, byte ptr [edx]
                    ;inc         edx
                    ;cmp         al, cl
                    ;jnz         nextstr
                    add					@funIndex, 1										; �õ���������ţ��Ա��ڵ������������Ҷ�Ӧ�ĵ�ַ
                    mov					eax, @namerav
                    mov					edx, @funIndex
                    add					edx, edx
                    add					edx, edx
                    add					eax, edx
                    mov					eax, [eax]
                    jmp         gethash
                    
                    
            getaddr:
            				mov					eax, @pExportDir
            				add					eax, 1ch
            				mov					eax, [eax]												; ��ȡAddressOfFunctionsƫ��
            				add					eax, BASEADDRESS
            				mov					@funrav, eax											; �õ�funrav��ַ
            				mov					eax, @pExportDir
            				add					eax, 24h
            				mov					eax, [eax]												; ��ȡAddressOfNameOrdinalsƫ��
            				add					eax, BASEADDRESS
            				mov					@nameOrdinal, eax									; �õ�nameOrdinal��ַ
            				mov					eax, @funIndex
            				add					eax, eax
            				add					eax, @nameOrdinal
            				mov					ax, WORD ptr [eax]
            				add					ax, ax
            				add					ax, ax
            				movzx				eax, ax
            				add					eax, @funrav
            				mov					eax, [eax]
            				add					eax, BASEADDRESS
                    ret
GetFunAddress     endp
; -------------------------------------------------------------------------


start:

                    invoke      	_getkernel32base
                    mov         	dwkernel32base, eax
                    push        	dwGetProcAddresshash
                    push        	dwkernel32base
                    call        	GetFunAddress
                    mov						GetProcAddress, eax
                    push					dwLoadLibraryExA
                    push					dwkernel32base
                    call        	GetFunAddress
                    mov						LoadLibraryExA, eax
                    push					1
                    push					0
                    push					offset szUser32
                    call					LoadLibraryExA
                    mov 					hUser32, eax
                    push					offset szMessageBoxA
                    push					hUser32
                    call					GetProcAddress
                    mov						MessageBoxA, eax
                    push					0
                    push					offset	szNote
                    push					offset	szText
                    push					0
                    call					MessageBoxA
end     start