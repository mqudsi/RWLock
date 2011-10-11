/*
 * RWLock
 * Author: Mahmoud Al-Qudsi <mqudsi@neosmart.net>
 * Copyright (C) 2011 by NeoSmart Technologies
 * This code is released under the terms of the MIT License
*/

#include "stdafx.h"
#include "RWLock.h"

#define MAX_SPIN 50000
#include <tchar.h>
#include <assert.h>
#include <stdlib.h>

__forceinline __int16 ReaderCount(unsigned __int32 lock)
{
	return lock & 0x00007FFF;
}

__forceinline __int32 SetReaders(unsigned __int32 lock, unsigned __int16 readers)
{
	return (lock & ~0x00007FFF) | readers;
}

__forceinline __int16 WaitingCount(unsigned __int32 lock)
{
	return (lock & 0x3FFF8000) >> 15;
}

__forceinline __int32 SetWaiting(unsigned __int32 lock, unsigned __int16 waiting)
{
	return (lock & ~0x3FFF8000) | (waiting << 15);
}


__forceinline bool Writer(unsigned __int32 lock)
{
	return (lock & 0x40000000) != 0;
}

__forceinline __int32 SetWriter(unsigned __int32 lock, bool writer)
{
	if(writer)
		return lock | 0x40000000;
	else
		return lock & ~0x40000000;
}

__forceinline bool AllClear(unsigned __int32 lock)
{
	return (lock & 0x40007FFF) == 0;
}

__forceinline bool Initialized(unsigned __int32 lock)
{
	return (lock & 0x80000000) != 0;
}

__forceinline __int32 SetInitialized(unsigned __int32 lock, bool initialized)
{
	if(initialized)
		return lock | 0x80000000;
	else
		return lock & ~0x80000000;
}

RWLockIPC::RWLockIPC(unsigned __int32 *lock, LPCTSTR guid)
{
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = &sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE); 

	_lock = lock;

	_event = CreateEvent(&sa, FALSE, FALSE, guid);

	if(!Initialized(*_lock))
	{
		HANDLE hMutex = CreateMutex(&sa, FALSE, guid);
		WaitForSingleObject(hMutex, INFINITE);

		if(!Initialized(*_lock))
		{
			*_lock = 0;
			*_lock = SetInitialized(*_lock, true);
		}

		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
	}
}

RWLockIPC::~RWLockIPC()
{
	CloseHandle(_event);
}

void RWLockIPC::StartRead()
{
	for(int i = 0; ; ++i)
	{
		__int32 temp = *_lock;
		if(!Writer(temp))
		{
			if(InterlockedCompareExchange((LONG*)_lock, SetReaders(temp, ReaderCount(temp) + 1), temp) == temp)
				return;
			else
				continue;
		}
		else
		{
			if(i < MAX_SPIN)
				continue;

			//The pending write operation is taking too long, so we'll drop to the kernel and wait
			if(InterlockedCompareExchange((LONG*)_lock, SetWaiting(temp, WaitingCount(temp) + 1), temp) != temp)
				continue;

			i = 0; //reset the spincount for the next time
			WaitForSingleObject(_event, INFINITE);

			do
			{
				temp = *_lock;
			} while(InterlockedCompareExchange((LONG*)_lock, SetWaiting(temp, WaitingCount(temp) - 1), temp) != temp);
		}
	}
}

void RWLockIPC::StartWrite()
{
	for(int i = 0; ; ++i)
	{
		__int32 temp = *_lock;
		if(AllClear(temp))
		{
			if(InterlockedCompareExchange((LONG*)_lock, SetWriter(temp, true), temp) == temp)
				return;
			else
				continue;
		}
		else
		{
			if(i < MAX_SPIN)
				continue;

			//The pending read operations are taking too long, so we'll drop to the kernel and wait
			if(InterlockedCompareExchange((LONG*)_lock, SetWaiting(temp, WaitingCount(temp) + 1), temp) != temp)
				continue;

			i = 0; //reset the spincount for the next time
			WaitForSingleObject(_event, INFINITE);

			do
			{
				temp = *_lock;
			} while(InterlockedCompareExchange((LONG*)_lock, SetWaiting(temp, WaitingCount(temp) - 1), temp) != temp);
		}
	}
}

void RWLockIPC::EndRead()
{
	while(true)
	{
		__int32 temp = *_lock;
		assert(ReaderCount(temp) > 0);

		if(ReaderCount(temp) == 1 && WaitingCount(temp) != 0)
		{
			//Note: this isn't nor has to be thread-safe
			//We're the last reader and there's a pending write
			//Wake one waiting writer
			SetEvent(_event);
		}

		//Decrement reader count
		if(InterlockedCompareExchange((LONG*)_lock, SetReaders(temp, ReaderCount(temp) - 1), temp) == temp)
			break;
	}
}

void RWLockIPC::EndWrite()
{
	while(true)
	{
		__int32 temp;

		while(true)
		{
			temp = *_lock;
			assert(Writer(temp));
			__int16 waitingCount = WaitingCount(temp);
			if(waitingCount == 0)
				break;

			//Note: This is thread-safe (there's guaranteed not to be another EndWrite simultaneously)
			//Wake all waiting readers or writers
			SetEvent(_event);
		}

		//Decrement writer count
		if(InterlockedCompareExchange((LONG*)_lock, SetWriter(temp, false), temp) == temp)
			break;
	}
}

RWLock::RWLock()
	: _rwLock(&(*(_lock = (new unsigned int)) = RWLOCK_INIT), NULL)
{
}

RWLock::~RWLock()
{
	delete _lock;
}

void RWLock::StartRead()
{
	_rwLock.StartRead();
}

void RWLock::StartWrite()
{
	_rwLock.StartWrite();
}

void RWLock::EndRead()
{
	_rwLock.EndRead();
}

void RWLock::EndWrite()
{
	_rwLock.EndWrite();
}

struct THREAD_ENTRY
{
	SLIST_ENTRY ItemEntry;
	unsigned int* ThreadPointer;
};

RWLockIPCReentrant::RWLockIPCReentrant(unsigned __int32 *lock, LPCTSTR guid)
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
		_aligned_free(entry);
	}

	_aligned_free(_threadPointers);

	TlsFree(_tlsIndex);
}

void RWLockIPCReentrant::StartRead()
{
	unsigned int *threadCounter = (unsigned int*)TlsGetValue(_tlsIndex);
	if(threadCounter == NULL)
	{
		threadCounter = new unsigned int;
		*threadCounter = 0;
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY*)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	if(InterlockedIncrement((LONG*)threadCounter) == 1)
		_rwLock.StartRead();
}

void RWLockIPCReentrant::StartWrite()
{
	unsigned int *threadCounter = (unsigned int*)TlsGetValue(_tlsIndex);
	if(threadCounter == NULL)
	{
		threadCounter = new unsigned int;
		*threadCounter = 0;
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY*)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	if(InterlockedIncrement((LONG*)threadCounter) == 1)
		_rwLock.StartWrite();
}

void RWLockIPCReentrant::EndRead()
{
	unsigned int *threadCounter = (unsigned int*)TlsGetValue(_tlsIndex);
	if(threadCounter == NULL)
	{
		threadCounter = new unsigned int;
		*threadCounter = 0;
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY*)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	assert(*threadCounter > 0);
	if(InterlockedDecrement((LONG*)threadCounter) == 0)
		_rwLock.EndRead();
}

void RWLockIPCReentrant::EndWrite()
{
	unsigned int *threadCounter = (unsigned int*)TlsGetValue(_tlsIndex);
	if(threadCounter == NULL)
	{
		threadCounter = new unsigned int;
		*threadCounter = 0;
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY*)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	assert(*threadCounter > 0);
	if(InterlockedDecrement((LONG*)threadCounter) == 0)
		_rwLock.EndWrite();
}

RWLockReentrant::RWLockReentrant()
	: _rwLock(&(*(_lock = (new unsigned int)) = RWLOCK_INIT), NULL)
{
}

RWLockReentrant::~RWLockReentrant()
{
	delete _lock;
}

void RWLockReentrant::StartRead()
{
	_rwLock.StartRead();
}

void RWLockReentrant::StartWrite()
{
	_rwLock.StartWrite();
}

void RWLockReentrant::EndRead()
{
	_rwLock.EndRead();
}

void RWLockReentrant::EndWrite()
{
	_rwLock.EndWrite();
}
