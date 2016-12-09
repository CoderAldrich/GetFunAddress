.386
.model      flat,stdcall
option      casemap:none

.data

dwkernel32base      		dd      0                   ;隠贋kernel32.dll議児峽
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
;宥狛PEB潤更資函kernelbase.dll児峽
_getkernel32base    proc
                    assume      fs:nothing
                    push        esi
                    xor         eax, eax
                    mov         eax, dword ptr fs:[30h]     ;資函PEB児峽
                    mov         eax, dword ptr [eax+0ch]
                    mov         esi, dword ptr [eax+1ch]
                    lods        dword ptr [esi]
                    mov         eax, [eax+08h]
                    pop         esi
                    ret

_getkernel32base    endp
; -------------------------------------------------------------------------


; -------------------------------------------------------------------------
;功象忖憲堪遍仇峽柴麻忖憲堪hash峙
;ADDRESSOFSTRING    吉棋柴麻hash峙議忖憲堪遍仇峽
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
                    
                    pop         esi                         ;緩扮esi隠贋議頁忖憲堪遍仇峽
                    sub         edi, ebx                    ;緩扮edi葎忖憲堪海業��淫根潤硫腎忖憲
                    cld
                    xor         ecx, ecx
                    dec         ecx
                    mov         edx, ecx
                    
; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい?
                    
            count:
                    xor         eax, eax
                    xor         ebx, ebx
                    lods        byte    ptr [esi]           ;紗墮esi侃議及匯倖byte欺eax
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
;資函峺協DLL嶄議蝶倖痕方仇峽
;BASEADDRESS    DLL猟周坪贋児峽
;HASHOFNAME     痕方兆議hash峙
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
										mov					@funIndex, eax									; 痕方會催兜兵晒
                    mov 				eax, BASEADDRESS
            				mov 				@pDosHeader, eax
            				add					eax, 3ch
            				mov					eax, [eax]
            				add					eax, BASEADDRESS
            				add					eax, 4
            				mov 				@pFileHeader, eax
            				add					eax, 14h
            				mov 				@pOptHeader, eax
            				add					eax, 60h													; 資函DataDirectory仇峽
            				mov 				eax, [eax]
            				add					eax, BASEADDRESS
            				mov					@pExportDir, eax
            				add					eax, 20h
            				mov					eax, [eax]												; 資函AddressOfNames陶卞
            				add					eax, BASEADDRESS
            				mov					@namerav, eax											; 誼欺namerav議仇峽                  
            				mov					eax, [eax]
            				
            gethash:
                    add					eax, BASEADDRESS
                    mov         @straddress, eax                ; 資函EXPORT_NAME_TABLE議及匯倖痕方兆仇峽
                    mov         edx, @straddress
                    push        edx
                    call        _gethash
                    mov         ebx, HASHOFNAME
                    cmp         eax, ebx                        ; 曳熟輝念痕方兆議hash頁倦才侭俶議�猴�
                    jz          getaddr
                    xor         eax, eax
                    xor         ecx, ecx
            ;nextstr:
                    ;mov         al, byte ptr [edx]
                    ;inc         edx
                    ;cmp         al, cl
                    ;jnz         nextstr
                    add					@funIndex, 1										; 誼欺痕方議會催��參宴壓擬竃痕方燕嶄孀斤哘議仇峽
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
            				mov					eax, [eax]												; 資函AddressOfFunctions陶卞
            				add					eax, BASEADDRESS
            				mov					@funrav, eax											; 誼欺funrav仇峽
            				mov					eax, @pExportDir
            				add					eax, 24h
            				mov					eax, [eax]												; 資函AddressOfNameOrdinals陶卞
            				add					eax, BASEADDRESS
            				mov					@nameOrdinal, eax									; 誼欺nameOrdinal仇峽
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