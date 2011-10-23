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
	return (__int16) ((lock & 0x3FFF8000) >> 15);
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

//SRW imports
typedef VOID (WINAPI *InitializeSRWLockPtr)(__out  PVOID *SRWLock);
typedef VOID (WINAPI *ReleaseSRWLockExclusivePtr)(__inout  PVOID *SRWLock);
typedef VOID (WINAPI *ReleaseSRWLockSharedPtr)(__inout  PVOID *SRWLock);
typedef VOID (WINAPI *AcquireSRWLockExclusivePtr)(__inout  PVOID *SRWLock);
typedef VOID (WINAPI *AcquireSRWLockSharedPtr)(__inout  PVOID *SRWLock);

InitializeSRWLockPtr SRWInit;
ReleaseSRWLockExclusivePtr SRWEndWrite;
ReleaseSRWLockSharedPtr SRWEndRead;
AcquireSRWLockExclusivePtr SRWStartWrite;
AcquireSRWLockSharedPtr SRWStartRead;

RWLockIPC::RWLockIPC(intptr_t *lock, LPCTSTR guid)
{
	_lock = (unsigned __int32 *) lock;

	//Silently switch to SRW Locks?
	HMODULE hModule = LoadLibrary(_T("KERNEL32.DLL"));
	SRWInit = guid ? NULL : (InitializeSRWLockPtr) GetProcAddress(hModule, "InitializeSRWLock");
	if(SRWInit != NULL)
	{
		SRWEndWrite = (ReleaseSRWLockExclusivePtr) GetProcAddress(hModule, "ReleaseSRWLockExclusive");
		SRWEndRead = (ReleaseSRWLockSharedPtr) GetProcAddress(hModule, "ReleaseSRWLockShared");
		SRWStartWrite = (AcquireSRWLockExclusivePtr) GetProcAddress(hModule, "AcquireSRWLockExclusive");
		SRWStartRead = (AcquireSRWLockSharedPtr) GetProcAddress(hModule, "AcquireSRWLockShared");

		FreeModule(hModule);

		SRWInit((PVOID*)_lock);
	}
	else
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

		_event = CreateEvent(&sa, FALSE, FALSE, guid);

		if(!Initialized(*vLock))
		{
			HANDLE hMutex = CreateMutex(&sa, FALSE, guid);
			WaitForSingleObject(hMutex, INFINITE);

			if(!Initialized(*vLock))
			{
				*vLock = RWLOCK_INIT;
				*vLock = SetInitialized(*vLock, true);
			}

			ReleaseMutex(hMutex);
			CloseHandle(hMutex);
		}
	}
}

RWLockIPC::~RWLockIPC()
{
	if(SRWInit == NULL)
	{
		CloseHandle(_event);
	}
}

void RWLockIPC::StartRead()
{
	if(SRWInit != NULL)
	{
		SRWStartRead((PVOID*)_lock);
	}
	else
	{
		for(int i = 0; ; ++i)
		{
			unsigned __int32 temp = *_lock;
			if(!Writer(temp))
			{
				if(InterlockedCompareExchange(_lock, SetReaders(temp, ReaderCount(temp) + 1), temp) == temp)
					return;
				else
					continue;
			}
			else
			{
				if(i < MAX_SPIN)
				{
					YieldProcessor();
					continue;
				}

				//The pending write operation is taking too long, so we'll drop to the kernel and wait
				if(InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) + 1), temp) != temp)
					continue;

				i = 0; //Reset the spincount for the next time
				WaitForSingleObject(_event, INFINITE);

				do
				{
					temp = *_lock;
				} while(InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) - 1), temp) != temp);
			}
		}
	}
}

void RWLockIPC::StartWrite()
{
	if(SRWInit != NULL)
	{
		SRWStartWrite((PVOID*)_lock);
	}
	else
	{
		for(int i = 0; ; ++i)
		{
			unsigned __int32 temp = *_lock;
			if(AllClear(temp))
			{
				if(InterlockedCompareExchange(_lock, SetWriter(temp, true), temp) == temp)
					return;
				else
					continue;
			}
			else
			{
				if(i < MAX_SPIN)
				{
					YieldProcessor();
					continue;
				}

				//The pending read operations are taking too long, so we'll drop to the kernel and wait
				if(InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) + 1), temp) != temp)
					continue;

				i = 0; //Reset the spincount for the next time
				WaitForSingleObject(_event, INFINITE);

				do
				{
					temp = *_lock;
				} while(InterlockedCompareExchange(_lock, SetWaiting(temp, WaitingCount(temp) - 1), temp) != temp);
			}
		}
	}
}

void RWLockIPC::EndRead()
{
	if(SRWInit != NULL)
	{
		SRWEndRead((PVOID*)_lock);
	}
	else
	{
		while(true)
		{
			unsigned __int32 temp = *_lock;
			assert(ReaderCount(temp) > 0);

			if(ReaderCount(temp) == 1 && WaitingCount(temp) != 0)
			{
				//Note: this isn't nor has to be thread-safe, as the worst a duplicate notification can do
				//is cause a waiting to reader to wake, perform a spinlock, then go back to sleep

				//We're the last reader and there's a pending write
				//Wake one waiting writer
				SetEvent(_event);
			}

			//Decrement reader count
			if(InterlockedCompareExchange(_lock, SetReaders(temp, ReaderCount(temp) - 1), temp) == temp)
				break;
		}
	}
}

void RWLockIPC::EndWrite()
{
	if(SRWInit != NULL)
	{
		SRWEndWrite((PVOID*)_lock);
	}
	else
	{
		while(true)
		{
			unsigned __int32 temp;

			while(true)
			{
				temp = *_lock;
				assert(Writer(temp));
				if(WaitingCount(temp) == 0)
					break;

				//Note: this is thread-safe (there's guaranteed not to be another EndWrite simultaneously)
				//Wake all waiting readers or writers, loop until wake confirmation is received
				SetEvent(_event);
			}

			//Decrement writer count
			if(InterlockedCompareExchange(_lock, SetWriter(temp, false), temp) == temp)
				break;
		}
	}
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
	unsigned int *threadCounter = (unsigned int*)TlsGetValue(_tlsIndex);
	if(threadCounter == NULL)
	{
		threadCounter = new unsigned int;
		*threadCounter = 0;
		TlsSetValue(_tlsIndex, threadCounter);
		THREAD_ENTRY *entry = (THREAD_ENTRY*)_aligned_malloc(sizeof(THREAD_ENTRY), MEMORY_ALLOCATION_ALIGNMENT);
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	if(InterlockedIncrement(threadCounter) == 1)
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
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	if(InterlockedIncrement(threadCounter) == 1)
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
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	assert(*threadCounter > 0);
	if(InterlockedDecrement(threadCounter) == 0)
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
		entry->ThreadPointer = threadCounter;
		InterlockedPushEntrySList(_threadPointers, &(entry->ItemEntry));
	}
	assert(*threadCounter > 0);
	if(InterlockedDecrement(threadCounter) == 0)
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
