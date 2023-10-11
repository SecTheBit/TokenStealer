# TokenStealer

### About

Token Stealer is based on Token Theft Attack, where it helps the Red Teamers to Steal the Access Token of a User, if a process is running in the context of Victim.

### Windows API Used

1. OpenProcessToken
2. LookupPrivilegeValueA
3. AdjustTokenPrivileges
4. OpenProcess
5. DuplicateTokenEx
6. CreateProcessWithTokenW

### Usage
1. First change the process name in the code . I have used the "Notepad.exe" in the Code.
2. Compile the Program
3. Use the executable
4. The executable should be running in High Integrity Process , as an Administrator

### Compiler Compabitity
![POC](https://github.com/SecTheBit/TokenStealer/assets/46895441/2219b197-9e69-493b-bc8b-1346de4dace5)


### Demo

https://github.com/SecTheBit/TokenStealer/assets/46895441/f56f2170-6074-460a-b7e9-683994aae93b




