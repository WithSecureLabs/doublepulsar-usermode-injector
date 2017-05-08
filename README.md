Author: Matt Hillman (matt.hillman@countercept.com - @sp1nl0ck)

Company: Countercept (@countercept)

Website: https://countercept.com


A utility to use the usermode shellcode from the DOUBLEPULSAR payload to reflectively load an arbitrary DLL into another process, for use in testing detection techniques or other security research.


## Background

The DOUBLEPULSAR payload released by Shadow Brokers initially runs in kernel mode and reflectively loads a DLL into a usermode process using an Asynchronous Procedure Call (APC). The actual loading of the DLL occurs in usermode, and this utility makes use of that usermode shellcode to load a DLL in a specified process and execute a given ordinal. This is to help with testing attack detection and digital forensic incident response techniques against the payload.

The loader is of interest as it works with any arbitrary DLL without making use of the standard LoadLibrary call. Avoiding LoadLibrary can make the load more stealthy as it avoids the need to write the DLL to disk, can avoid anything monitoring LoadLibrary calls, and can also avoid having an entry in the Process Environment Block (PEB), which is usually how a list of loaded modules is obtained. Such techniques are now fairly common place, but up to now we were not aware of any public code that could load an arbitrary DLL in this way - existing code requires the DLL to be custom built to support being loaded. DOUBLEPULSAR is different in that it implements a more complete loader that can load almost any DLL. This loader works on almost any version of Windows as-is.

While DOUBLEPULSAR itself uses an APC call from kernel mode queued against a usermode process, this utility queues the APC from usermode; this makes little practical difference. Additionally, this utility can trigger the shellcode using CreateRemoteThread instead.


## Usage
```
C:\>DOUBLEPULSAR-usermode-injector.exe
USAGE: <pid> <shellcode_file> <dll_to_inject> <ordinal_to_execute> [use_CreateRe
moteProcess]

The last argument is optional, if specified 'true' then CreateRemoteProcess will be used instead of using an APC call 
which is the default way Doublepulsar works. This is to allow people to test it out in different ways.
The default is using APC. This will inject into ALL threads in the target, which makes it more likely one of them will 
trigger quickly. This is only suitable for testing as it may be undesirable to call the payload more than once.
```

For example, inject `somelibrary.dll` into process `1234` using an Asynchronous Procedure Call (APC) and call ordinal `1`:
```
C:\>dopu-usermode-injector.exe 1234 dopu-64bit-usermode-shellcode.bin somelibrary.dll 1
Using thread: 2456
Using thread: 2032
Using thread: 3876
```

Or as above, but using CreateRemoteThread instead of APC:
```
C:\>dopu-usermode-injector.exe 1234 dopu-64bit-usermode-shellcode.bin somelibrary.dll 1 true
```

## More information 

A full analysis of the usermode shellcode of DOUBLEPULSAR:

<LINK_COMING_VERY_SOON>

Prior work on the kernel component of DOUBLEPULSAR:

https://www.countercept.com/our-thinking/analyzing-the-doublepulsar-kernel-dll-injection-technique/

https://zerosum0x0.blogspot.co.uk/2017/04/doublepulsar-initial-smb-backdoor-ring.html
