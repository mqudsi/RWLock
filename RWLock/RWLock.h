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
private:
	HANDLE _event;
	unsigned __int32 *_lock;

public:
	RWLockIPC(unsigned __int32 *lock, LPCTSTR guid);
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
	unsigned __int32 *_lock;

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
	unsigned int _tlsIndex;
	PSLIST_HEADER _threadPointers;

public:
	RWLockIPCReentrant(unsigned __int32 *lock, LPCTSTR guid);
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
	unsigned __int32 *_lock;

public:
	RWLockReentrant();
	~RWLockReentrant();

	void RWLOCK_CC StartRead();
	void RWLOCK_CC EndRead();
	void RWLOCK_CC StartWrite();
	void RWLOCK_CC EndWrite();
};
