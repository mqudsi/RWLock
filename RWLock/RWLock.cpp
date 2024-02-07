/*
 * RWLock
 * Author: Mahmoud Al-Qudsi <mqudsi@neosmart.net>
 * Copyright (C) 2011 by NeoSmart Technologies
 * This code is released under the terms of the MIT License
*/

#include "stdafx.h"
#include "RWLock.h"

#include <tchar.h>
#include <assert.h>
#include <stdlib.h>

#define SRW_MASK_READERS 0x00007FFFUL // not changed
#define SRW_FLAG_WRITING 0x00008000UL // changed from 0x40000000
#define SRW_MASK_WAITERS 0x7FFF0000UL // changed from 0x3FFF8000
#define SRW_FLAG_READIED 0x80000000UL // not changed

__forceinline UINT32 ReaderCount(UINT32 lock)
{
	return lock & SRW_MASK_READERS;
}

__forceinline UINT32 SetReaders(UINT32 lock, UINT32 readers)
{
	return (lock & ~SRW_MASK_READERS) | readers;
}

__forceinline UINT32 WaitingCount(UINT32 lock)
{
	return ((lock & SRW_MASK_WAITERS) >> 16);
}

__forceinline UINT32 SetWaiting(UINT32 lock, UINT32 waiting)
{
	return (lock & ~SRW_MASK_WAITERS) | (waiting << 16);
}

__forceinline bool Writer(UINT32 lock)
{
	return (lock & SRW_FLAG_WRITING) != 0;
}

__forceinline UINT32 SetWriter(UINT32 lock, bool writer)
{
	if (writer)
		return lock | SRW_FLAG_WRITING;
	else
		return lock & ~SRW_FLAG_WRITING;
}

__forceinline bool AllClear(UINT32 lock)
{
	return (lock & (SRW_MASK_READERS | SRW_FLAG_WRITING)) == 0;
}

__forceinline bool Initialized(UINT32 lock)
{
	return (lock & SRW_FLAG_READIED) != 0;
}

__forceinline UINT32 SetInitialized(UINT32 lock, bool initialized)
{
	if (initialized)
		return lock | SRW_FLAG_READIED;
	else
		return lock & ~SRW_FLAG_READIED;
}

void RWLockIPC::InitSRWLockNative_()
{
	SRWInit_((PVOID *)_lock);
}

void RWLockIPC::SRWStartReadNative_()
{
	SRWStartRead_((PVOID *)_lock);
}

void RWLockIPC::SRWEndReadNative_()
{
	SRWEndRead_((PVOID *)_lock);
}

void RWLockIPC::SRWStartWriteNative_()
{
	SRWStartWrite_((PVOID *)_lock);
}

void RWLockIPC::SRWEndWriteNative_()
{
	SRWEndWrite_((PVOID *)_lock);
}

void RWLockIPC::CloseEventNative_()
{
	CloseHandle(_event);
}

RWLockIPC::RWLockIPC(intptr_t *lock, LPCTSTR guid)
	: _lock((unsigned __int32 *)lock)
	, _guid(guid)
	, _event(NULL)
{
	//Silently switch to SRW Locks?
	HMODULE hModule;
	//kernel32.dll is always loaded
	if (((hModule = GetModuleHandleW(L"KERNEL32.DLL")) != NULL) &&
		((SRWInit_ = (InitializeSRWLockPtr)GetProcAddress(hModule, "InitializeSRWLock")) != NULL))
	{
		SRWStartRead_ = (AcquireSRWLockSharedPtr)GetProcAddress(hModule, "AcquireSRWLockShared");
		SRWEndRead_ = (ReleaseSRWLockSharedPtr)GetProcAddress(hModule, "ReleaseSRWLockShared");
		SRWStartWrite_ = (AcquireSRWLockExclusivePtr)GetProcAddress(hModule, "AcquireSRWLockExclusive");
		SRWEndWrite_ = (ReleaseSRWLockExclusivePtr)GetProcAddress(hModule, "ReleaseSRWLockExclusive");
		InitSRWLock_ = &RWLockIPC::InitSRWLockNative_;
		StartSRWRead_ = &RWLockIPC::SRWStartReadNative_;
		EndSRWRead_ = &RWLockIPC::SRWEndReadNative_;
		StartSRWWrite_ = &RWLockIPC::SRWStartWriteNative_;
		EndSRWWrite_ = &RWLockIPC::SRWEndWriteNative_;
		CloseEvent_ = &RWLockIPC::CloseEventNative_;
	}
	else
	{
		SRWInit_ = NULL;
		SRWStartRead_ = NULL;
		SRWEndRead_ = NULL;
		SRWStartWrite_ = NULL;
		SRWEndWrite_ = NULL;
		InitSRWLock_ = &RWLockIPC::InitSRWLockImpl_;
		StartSRWRead_ = &RWLockIPC::SRWStartReadImpl_;
		EndSRWRead_ = &RWLockIPC::SRWEndReadImpl_;
		StartSRWWrite_ = &RWLockIPC::SRWStartWriteImpl_;
		EndSRWWrite_ = &RWLockIPC::SRWEndWriteImpl_;
		CloseEvent_ = &RWLockIPC::CloseEventImpl_;
	}
}

RWLockIPC::~RWLockIPC()
{
	(this->*CloseEvent_)();
}

void RWLockIPC::InitSRWLockImpl_()
{
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = &sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

	//Create local volatile pointer for double-checked locking to work
	volatile unsigned __int32 *vLock = _lock;

	_event = CreateEvent(&sa, FALSE, FALSE, _guid);

	if (!Initialized(*vLock))
	{
		HANDLE hMutex = CreateMutex(&sa, FALSE, _guid);
		WaitForSingleObject(hMutex, INFINITE);

		if (!Initialized(*vLock))
		{
			*vLock = RWLOCK_INIT;
			*vLock = SetInitialized(*vLock, true);
		}

		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
	}
}

void RWLockIPC::SRWStartReadImpl_()
{
	for (int i = 0; ; ++i)
	{
		unsigned __int32 temp = *_lock;
		if (!Writer(temp))
		{
			if (InterlockedCompareExchange(_lock, SetReaders(temp, ReaderCount(temp) + 1), temp) == temp)
				return;
			else
				continue;
		}
		else
		{
			if (i < MAX_SPIN)
			{
				YieldProcessor();
				continue;
			}

			//The pending write operation is taking too long, so we'll drop to the kernel and wait
			if (InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) + 1), temp) != temp)
				continue;

			i = 0; //Reset the spincount for the next time
			WaitForSingleObject(_event, INFINITE);

			do
			{
				temp = *_lock;
			} while (InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) - 1), temp) != temp);
		}
	}
}

void RWLockIPC::SRWEndReadImpl_()
{
	while (true)
	{
		unsigned __int32 temp = *_lock;
		assert(ReaderCount(temp) > 0);

		if (ReaderCount(temp) == 1 && WaitingCount(temp) != 0)
		{
			//Note: this isn't nor has to be thread-safe, as the worst a duplicate notification can do
			//is cause a waiting to reader to wake, perform a spinlock, then go back to sleep

			//We're the last reader and there's a pending write
			//Wake one waiting writer
			SetEvent(_event);
		}

		//Decrement reader count
		if (InterlockedCompareExchange(_lock, SetReaders(temp, ReaderCount(temp) - 1), temp) == temp)
			break;
	}
}

void RWLockIPC::SRWStartWriteImpl_()
{
	for (int i = 0; ; ++i)
	{
		unsigned __int32 temp = *_lock;
		if (AllClear(temp))
		{
			if (InterlockedCompareExchange(_lock, SetWriter(temp, true), temp) == temp)
				return;
			else
				continue;
		}
		else
		{
			if (i < MAX_SPIN)
			{
				YieldProcessor();
				continue;
			}

			//The pending read operations are taking too long, so we'll drop to the kernel and wait
			if (InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) + 1), temp) != temp)
				continue;

			i = 0; //Reset the spincount for the next time
			WaitForSingleObject(_event, INFINITE);

			do
			{
				temp = *_lock;
			} while (InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) - 1), temp) != temp);
		}
	}
}

void RWLockIPC::SRWEndWriteImpl_()
{
	while (true)
	{
		unsigned __int32 temp;

		while (true)
		{
			temp = *_lock;
			assert(Writer(temp));
			if (WaitingCount(temp) == 0)
				break;

			//Note: this is thread-safe (there's guaranteed not to be another EndWrite simultaneously)
			//Wake all waiting readers or writers, loop until wake confirmation is received
			SetEvent(_event);
		}

		//Decrement writer count
		if (InterlockedCompareExchange(_lock, SetWriter(temp, false), temp) == temp)
			break;
	}
}

void RWLockIPC::CloseEventImpl_()
{
}

void RWLockIPC::StartRead()
{
	(this->*StartSRWRead_)();
}

void RWLockIPC::EndRead()
{
	(this->*EndSRWRead_)();
}

void RWLockIPC::StartWrite()
{
	(this->*StartSRWWrite_)();
}

void RWLockIPC::EndWrite()
{
	(this->*EndSRWWrite_)();
}

RWLock::RWLock()
	: _rwLock(&(_lock = 0), NULL)
{
}

RWLock::~RWLock()
{
}

void RWLock::StartRead()
{
	_rwLock.StartRead();
}

void RWLock::EndRead()
{
	_rwLock.EndRead();
}

void RWLock::StartWrite()
{
	_rwLock.StartWrite();
}

void RWLock::EndWrite()
{
	_rwLock.EndWrite();
}

struct THREAD_ENTRY
{
	SLIST_ENTRY ItemEntry;
	UINT *ThreadPointer;
};

RWLockIPCReentrant::RWLockIPCReentrant(intptr_t *lock, LPCTSTR guid)
	: _rwLock(lock, guid)
{
	_tlsIndex = TlsAlloc();

	_threadPointers = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), MEMORY_ALLOCATION_ALIGNMENT);
	InitializeSListHead(_threadPointers);
}

RWLockIPCReentrant::~RWLockIPCReentrant()
{
	THREAD_ENTRY *entry;
	while((entry = (THREAD_ENTRY*) InterlockedPopEntrySList(_threadPointers)) != NULL)
	{
		delete entry->ThreadPointer;
		_aligned_free(entry);
	}

	_aligned_free(_threadPointers);

	TlsFree(_tlsIndex);
}

void RWLockIPCReentrant::StartRead()
{
	UINT *threadCounter = (UINT *)TlsGetValue(_tlsIndex);
	if (threadCounter == NULL)
	{
		threadCounter = new UINT(0);
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY *)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	if (InterlockedIncrement(threadCounter) == 1)
		_rwLock.StartRead();
}

void RWLockIPCReentrant::EndRead()
{
	UINT *threadCounter = (UINT *)TlsGetValue(_tlsIndex);
	if (threadCounter == NULL)
	{
		threadCounter = new UINT(0);
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY *)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	assert(*threadCounter > 0);
	if (InterlockedDecrement(threadCounter) == 0)
		_rwLock.EndRead();
}

void RWLockIPCReentrant::StartWrite()
{
	UINT *threadCounter = (UINT *)TlsGetValue(_tlsIndex);
	if (threadCounter == NULL)
	{
		threadCounter = new UINT(0);
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY *)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	if (InterlockedIncrement(threadCounter) == 1)
		_rwLock.StartWrite();
}

void RWLockIPCReentrant::EndWrite()
{
	UINT *threadCounter = (UINT *)TlsGetValue(_tlsIndex);
	if (threadCounter == NULL)
	{
		threadCounter = new UINT(0);
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY *)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	assert(*threadCounter > 0);
	if (InterlockedDecrement(threadCounter) == 0)
		_rwLock.EndWrite();
}

RWLockReentrant::RWLockReentrant()
	: _rwLock(&(_lock = 0), NULL)
{
}

RWLockReentrant::~RWLockReentrant()
{
}

void RWLockReentrant::StartRead()
{
	_rwLock.StartRead();
}

void RWLockReentrant::EndRead()
{
	_rwLock.EndRead();
}

void RWLockReentrant::StartWrite()
{
	_rwLock.StartWrite();
}

void RWLockReentrant::EndWrite()
{
	_rwLock.EndWrite();
}
