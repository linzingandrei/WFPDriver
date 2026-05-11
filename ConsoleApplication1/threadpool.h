#pragma once

//
// MY_THREAD_POOL - simple thread pool implementation
//
typedef struct _MY_THREAD_POOL
{
    /* When this event is signaled The threads should stop. */
    HANDLE StopThreadPoolEvent;
    /* This event is used to signal that the threads have work to perform. */
    HANDLE WorkScheduledEvent;
    /* Number of threads in the ThreadHandles array. */
    UINT32 NumberOfThreads;
    /* List of threads started in thread pool. */
    HANDLE* ThreadHandles;
    /* The list of work items and the mutex  protecting. */
    SRWLOCK QueueLock;
    /* Enqueued work items - represented as a double linked list. */
    LIST_ENTRY Queue;
} MY_THREAD_POOL;

//
// MY_WORK_ITEM - A very basic work item
//
typedef struct _MY_WORK_ITEM
{
    /* Required by the MY_THREAD_POOL, so it can be enqueued and dequeued. */
    LIST_ENTRY ListEntry;
    /* Callback to be called. */
    LPTHREAD_START_ROUTINE WorkRoutine;
    /* Caller defined context. To be passed to work routine. */
    PVOID Context;
} MY_WORK_ITEM;

//
// **********************************************************
// *                        LIST API                        *
// **********************************************************
//

void
ListInitializeHead(
    _Inout_ PLIST_ENTRY ListHead
);

bool
ListIsEmpty(
    _In_ _Const_ const PLIST_ENTRY ListHead
);

void
ListInsertHead(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Element
);

PLIST_ENTRY
ListRemoveTail(
    _Inout_ PLIST_ENTRY ListHead
);

//
// **********************************************************
// *                        TP API                          *
// **********************************************************
//

DWORD WINAPI
TpRoutine(
    _In_opt_ PVOID Context
);

void
TpUninit(
    _Inout_ MY_THREAD_POOL* ThreadPool
);

NTSTATUS
TpInit(
    _Inout_ MY_THREAD_POOL* ThreadPool,
    _In_ UINT32 NumberOfThreads
);

NTSTATUS
TpEnqueueWorkItem(
    _Inout_ MY_THREAD_POOL* ThreadPool,
    _In_ LPTHREAD_START_ROUTINE WorkRoutine,
    _In_opt_ PVOID Context
);
