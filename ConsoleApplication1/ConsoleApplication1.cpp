#define _CRTDBG_MAP_ALLOC

#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#include <intsafe.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <stdio.h>
#include <assert.h>
#include <crtdbg.h>
#include <conio.h>
#include <psapi.h>
#include "intrin.h"
#include <tchar.h>
#include <winioctl.h>
#include "TlHelp32.h"
#include <fltuser.h>

#include "threadpool.h"

#pragma comment(lib, "fltlib.lib")

#include "Trace.h"
#include <stdlib.h>


typedef struct _REPLY_DATA
{
    WCHAR message[1024];
    ULONG messageLength;
} REPLY_DATA, *PREPLY_DATA;

typedef struct _MY_CUSTOM_MESSAGE
{
    FILTER_MESSAGE_HEADER headers;
    REPLY_DATA replyData;

} MY_CUSTOM_MESSAGE, *PMY_CUSTOM_MESSAGE;

SRWLOCK fLock;
HANDLE hFile;

typedef struct _WORKER_CONTEXT
{
    HANDLE port;
    HANDLE hFile;
} WORKER_CONTEXT, *PWORKER_CONTEXT;

MY_THREAD_POOL tp = { 0 };

NTSTATUS
SendCustomMessageToDriver(HANDLE port, const WCHAR* message)
{
    //__debugbreak();

    MY_CUSTOM_MESSAGE customMessage = { 0 };
	ULONG bytesReturned = 0;

    wcscpy_s(customMessage.replyData.message, sizeof(customMessage.replyData.message) / sizeof(WCHAR), message);
    customMessage.replyData.messageLength = wcslen(customMessage.replyData.message) * sizeof(WCHAR);

	printf("Sending message to driver: %S\n", customMessage.replyData.message);

    return FilterSendMessage(port, &customMessage, sizeof(MY_CUSTOM_MESSAGE), NULL, 0, &bytesReturned);
}

DWORD WINAPI GetWorker(PVOID ctx)
{
    HANDLE port = (HANDLE)ctx;

    if (!port)
    {
        return STATUS_UNSUCCESSFUL;
    }

    while (TRUE)
    {
        MY_CUSTOM_MESSAGE msg = { 0 };

        HRESULT hr = FilterGetMessage(
            port,
            &msg.headers,
            sizeof(msg),
            NULL
        );

        if (!SUCCEEDED(hr))
        {
            /*AcquireSRWLockExclusive(&fLock);
            WriteFile(hFile, "Something went wrong\n", sizeof("Something went wrong\n") - 1, NULL, NULL);
            ReleaseSRWLockExclusive(&fLock);*/

            return STATUS_UNSUCCESSFUL;
        }

        AcquireSRWLockExclusive(&fLock);

        HANDLE hLog = CreateFileA("output.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        SetFilePointer(hLog, 0, NULL, FILE_END);

        DWORD bytesWritten = 0;
        BOOL res = WriteFile(hLog, msg.replyData.message, msg.replyData.messageLength, &bytesWritten, NULL);
        if (!res || bytesWritten != msg.replyData.messageLength) {
            printf("WriteFile failed: %d\n", GetLastError());
        }

        CloseHandle(hLog);

        ReleaseSRWLockExclusive(&fLock);

        //TpEnqueueWorkItem(&tp, GetWorker, port);
    }

    return STATUS_SUCCESS;
}

DWORD WINAPI CommunicationWithDriver(PVOID ctx)
{
    HANDLE port = (HANDLE)ctx;
    while (true)
    {
        WCHAR userInput[1024] = { 0 };
        printf("Enter command: ");
        scanf_s("%ls", userInput, (unsigned)_countof(userInput));

        SendCustomMessageToDriver(port, userInput);

        userInput[0] = '\0';
    }

    return 0;
}

int main() {
    HANDLE port;
    HRESULT hr;

	MY_CUSTOM_MESSAGE customMessage = { 0 };

    printf("Type any combination of process, image, thread, file, registry. Only after reopening this app the output file will be populated.\n");

    hr = FilterConnectCommunicationPort(L"\\MyFilterPort", 0, NULL, 0, NULL, &port);
    if (IS_ERROR(hr)) {
        printf("Connection failed. Error 0x%X\n", hr);
        return 1;
    }


    InitializeSRWLock(&fLock);
    
    /*hFile = CreateFileA("output.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CloseHandle(hFile);*/

    //__debugbreak();

    //WCHAR userInput[1024] = { 0 };
    //printf("Enter command: ");
	//scanf_s("%ls", userInput, (unsigned)_countof(userInput));
    //printf("Sending image to driver\n");

	CreateThread(NULL, 0, CommunicationWithDriver, port, 0, NULL);


	//SendCustomMessageToDriver(port, userInput);

	//printf("Image sent to driver\n");

	//MY_CONTEXT ctx = { 0 };

    NTSTATUS status = TpInit(&tp, 5);
    if (!NT_SUCCESS(status))
    {
        return 1;
    }
    
    //InitializeSRWLock(&ctx.ContextLock);
    //ctx.Number = 0;

    //printf("Image sent to driver\n");

    for (int i = 0; i < 5; i++)
    {
        TpEnqueueWorkItem(&tp, GetWorker, port);
    }

	WaitForMultipleObjects(tp.NumberOfThreads, tp.ThreadHandles, TRUE, INFINITE);

	TpUninit(&tp);

    //CloseHandle(hFile);
    CloseHandle(port);
    return 0;
}