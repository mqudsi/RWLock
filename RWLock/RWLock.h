/*
 * RWLock
 * Author: Mahmoud Al-Qudsi <mqudsi@neosmart.net>
 * Copyright (C) 2011 by NeoSmart Technologies
 * This code is released under the terms of the MIT License
*/

#pragma once

#ifndef RWLOCK_API
#ifdef RWLOCK_EXPORTS
#define RWLOCK_API __declspec(dllexport)
#else 
#ifdef RWLOCK_CPP
#define RWLOCK_API 
#else
#define RWLOCK_API __declspec(dllimport)
#endif
#endif
#endif

#define RWLOCK_CC __fastcall
#define MAX_SPIN 50000

const unsigned __int32 RWLOCK_INIT = 0x00000000;

class RWLOCK_API RWLockIPC
{
	//SRW imports
	typedef void (WINAPI *InitializeSRWLockPtr)(__out PVOID *SRWLock);
	typedef void (WINAPI *AcquireSRWLockSharedPtr)(__inout PVOID *SRWLock);
	typedef void (WINAPI *ReleaseSRWLockSharedPtr)(__inout PVOID *SRWLock);
	typedef void (WINAPI *AcquireSRWLockExclusivePtr)(__inout PVOID *SRWLock);
	typedef void (WINAPI *ReleaseSRWLockExclusivePtr)(__inout PVOID *SRWLock);

	InitializeSRWLockPtr SRWInit_;
	AcquireSRWLockSharedPtr SRWStartRead_;
	ReleaseSRWLockSharedPtr SRWEndRead_;
	AcquireSRWLockExclusivePtr SRWStartWrite_;
	ReleaseSRWLockExclusivePtr SRWEndWrite_;

private:
	void InitSRWLockNative_();
	void SRWStartReadNative_();
	void SRWEndReadNative_();
	void SRWStartWriteNative_();
	void SRWEndWriteNative_();
	void CloseEventNative_();

private:
	void InitSRWLockImpl_();
	void SRWStartReadImpl_();
	void SRWEndReadImpl_();
	void SRWStartWriteImpl_();
	void SRWEndWriteImpl_();
	void CloseEventImpl_();

private:
	void (RWLockIPC::*InitSRWLock_)();
	void (RWLockIPC::*StartSRWRead_)();
	void (RWLockIPC::*EndSRWRead_)();
	void (RWLockIPC::*StartSRWWrite_)();
	void (RWLockIPC::*EndSRWWrite_)();
	void (RWLockIPC::*CloseEvent_)();

private:
	unsigned __int32 *_lock;
	LPCTSTR _guid;
	HANDLE _event;

public:
	RWLockIPC(intptr_t *lock, LPCTSTR guid);
	~RWLockIPC();

	void RWLOCK_CC StartRead();
	void RWLOCK_CC EndRead();
	void RWLOCK_CC StartWrite();
	void RWLOCK_CC EndWrite();
};

class RWLOCK_API RWLock
{
private:
	RWLockIPC _rwLock;
	intptr_t _lock;

public:
	RWLock();
	~RWLock();

	void RWLOCK_CC StartRead();
	void RWLOCK_CC EndRead();
	void RWLOCK_CC StartWrite();
	void RWLOCK_CC EndWrite();
};

class RWLOCK_API RWLockIPCReentrant
{
private:
	RWLockIPC _rwLock;
	DWORD _tlsIndex;
	PSLIST_HEADER _threadPointers;

public:
	RWLockIPCReentrant(intptr_t *lock, LPCTSTR guid);
	~RWLockIPCReentrant();

	void RWLOCK_CC StartRead();
	void RWLOCK_CC EndRead();
	void RWLOCK_CC StartWrite();
	void RWLOCK_CC EndWrite();
};

class RWLOCK_API RWLockReentrant
{
private:
	RWLockIPCReentrant _rwLock;
	intptr_t _lock;

public:
	RWLockReentrant();
	~RWLockReentrant();

	void RWLOCK_CC StartRead();
	void RWLOCK_CC EndRead();
	void RWLOCK_CC StartWrite();
	void RWLOCK_CC EndWrite();
};
