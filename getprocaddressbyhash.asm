.386
.model      flat,stdcall
option      casemap:none

.data

dwkernel32base      		dd      0                   ;保存kernel32.dll的基址
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
;通过PEB结构获取kernelbase.dll基址
_getkernel32base    proc
                    assume      fs:nothing
                    push        esi
                    xor         eax, eax
                    mov         eax, dword ptr fs:[30h]     ;获取PEB基址
                    mov         eax, dword ptr [eax+0ch]
                    mov         esi, dword ptr [eax+1ch]
                    lods        dword ptr [esi]
                    mov         eax, [eax+08h]
                    pop         esi
                    ret

_getkernel32base    endp
; -------------------------------------------------------------------------


; -------------------------------------------------------------------------
;根据字符串首地址计算字符串hash值
;ADDRESSOFSTRING    等待计算hash值的字符串首地址
_gethash            proc        uses edi esi ebx edx ecx,ADDRESSOFSTRING:DWORD

                    mov         edi, ADDRESSOFSTRING
                    mov         ebx, edi
                    push        edi
                    xor         al,al
; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい?
                    
            strlen:
                    scas        byte    ptr es:[edi]
                    jnz         strlen
; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい?
                    
                    pop         esi                         ;此时esi保存的是字符串首地址
                    sub         edi, ebx                    ;此时edi为字符串长度，包含结尾空字符
                    cld
                    xor         ecx, ecx
                    dec         ecx
                    mov         edx, ecx
                    
; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい?
                    
            count:
                    xor         eax, eax
                    xor         ebx, ebx
                    lods        byte    ptr [esi]           ;加载esi处的第一个byte到eax
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
; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい?
                                
                     not        edx
                     not        ecx
                     mov        eax, edx
                     rol        eax, 10h
                     mov        ax, cx
                     ret

_gethash            endp
; -------------------------------------------------------------------------

; -------------------------------------------------------------------------
;获取指定DLL中的某个函数地址
;BASEADDRESS    DLL文件内存基址
;HASHOFNAME     函数名的hash值
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
										mov					@funIndex, eax									; 函数序号初始化
                    mov 				eax, BASEADDRESS
            				mov 				@pDosHeader, eax
            				add					eax, 3ch
            				mov					eax, [eax]
            				add					eax, BASEADDRESS
            				add					eax, 4
            				mov 				@pFileHeader, eax
            				add					eax, 14h
            				mov 				@pOptHeader, eax
            				add					eax, 60h													; 获取DataDirectory地址
            				mov 				eax, [eax]
            				add					eax, BASEADDRESS
            				mov					@pExportDir, eax
            				add					eax, 20h
            				mov					eax, [eax]												; 获取AddressOfNames偏移
            				add					eax, BASEADDRESS
            				mov					@namerav, eax											; 得到namerav的地址                  
            				mov					eax, [eax]
            				
            gethash:
                    add					eax, BASEADDRESS
                    mov         @straddress, eax                ; 获取EXPORT_NAME_TABLE的第一个函数名地址
                    mov         edx, @straddress
                    push        edx
                    call        _gethash
                    mov         ebx, HASHOFNAME
                    cmp         eax, ebx                        ; 比较当前函数名的hash是否和所需的相同
                    jz          getaddr
                    xor         eax, eax
                    xor         ecx, ecx
            ;nextstr:
                    ;mov         al, byte ptr [edx]
                    ;inc         edx
                    ;cmp         al, cl
                    ;jnz         nextstr
                    add					@funIndex, 1										; 得到函数的序号，以便在导出函数表中找对应的地址
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
            				mov					eax, [eax]												; 获取AddressOfFunctions偏移
            				add					eax, BASEADDRESS
            				mov					@funrav, eax											; 得到funrav地址
            				mov					eax, @pExportDir
            				add					eax, 24h
            				mov					eax, [eax]												; 获取AddressOfNameOrdinals偏移
            				add					eax, BASEADDRESS
            				mov					@nameOrdinal, eax									; 得到nameOrdinal地址
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