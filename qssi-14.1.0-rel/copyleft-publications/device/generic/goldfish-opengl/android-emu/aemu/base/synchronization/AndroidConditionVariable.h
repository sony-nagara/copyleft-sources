// Copyright (C) 2014 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "aemu/base/Compiler.h"
#include "aemu/base/synchronization/AndroidLock.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <assert.h>

namespace android {
namespace base {
namespace guest {

// A class that implements a condition variable, which can be used in
// association with a Lock to blocking-wait for specific conditions.
// Useful to implement various synchronization data structures.
class ConditionVariable {
public:
    // A set of functions to efficiently unlock the lock used with
    // the current condition variable and signal or broadcast it.
    //
    // The functions are needed because on some platforms (Posix) it's more
    // efficient to signal the variable before unlocking mutex, while on others
    // (Windows) it's exactly the opposite. Functions implement the best way
    // for each platform and abstract it out from the user.
    template <bool IsRecursive>
    void signalAndUnlock(StaticLock<IsRecursive>* lock);

    template <class Lockable>
    void signalAndUnlock(AutoLock<Lockable>* lock);

    template <bool IsRecursive>
    void broadcastAndUnlock(StaticLock<IsRecursive>* lock);

    template <class Lockable>
    void broadcastAndUnlock(AutoLock<Lockable>* lock);

    template <class Lockable>
    void wait(AutoLock<Lockable>* userLock) {
        assert(userLock->mLocked);
        wait(&userLock->mLock);
    }

    //
    // Convenience functions to get rid of the loop in condition variable usage
    // Instead of hand-writing a loop, e.g.
    //
    //      while (mRefCount < 3) {
    //          mCv.wait(&mLock);
    //      }
    //
    // use the following two wait() overloads:
    //
    //      mCv.wait(&mLock, [this]() { return mRefCount >= 3; });
    //
    // Parameters:
    // |lock| - a Lock or AutoLock pointer used with the condition variable.
    // |pred| - a functor predicate that's compatible with "bool pred()"
    //          signature and returns a condition when one should stop waiting.
    //

    template <bool IsRecursive, class Predicate>
    void wait(StaticLock<IsRecursive>* lock, Predicate pred) {
        while (!pred()) {
            this->wait(lock);
        }
    }

    template <class Lockable, class Predicate>
    void wait(AutoLock<Lockable>* lock, Predicate pred) {
        this->wait(&lock->mLock, pred);
    }

#ifdef _WIN32

    ConditionVariable() {
        ::InitializeConditionVariable(&mCond);
    }

    // There's no special function to destroy CONDITION_VARIABLE in Windows.
    ~ConditionVariable() = default;

    // Wait until the condition variable is signaled. Note that spurious
    // wakeups are always a possibility, so always check the condition
    // in a loop, i.e. do:
    //
    //    while (!condition) { condVar.wait(&lock); }
    //
    // instead of:
    //
    //    if (!condition) { condVar.wait(&lock); }
    //
    template <bool IsRecursive>
    void wait(StaticLock<IsRecursive>* userLock) {
        ::SleepConditionVariableSRW(&mCond, &userLock->mLock, INFINITE, 0);
    }

    template <bool IsRecursive>
    bool timedWait(StaticLock<IsRecursive>* userLock, System::Duration waitUntilUs) {
        const auto now = System::get()->getUnixTimeUs();
        const auto timeout =
                std::max<System::Duration>(0, waitUntilUs  - now) / 1000;
        return ::SleepConditionVariableSRW(
                    &mCond, &userLock->mLock, timeout, 0) != 0;
    }

    // Signal that a condition was reached. This will wake at least (and
    // preferrably) one waiting thread that is blocked on wait().
    void signal() {
        ::WakeConditionVariable(&mCond);
    }

    // Like signal(), but wakes all of the waiting threads.
    void broadcast() {
        ::WakeAllConditionVariable(&mCond);
    }

private:
    CONDITION_VARIABLE mCond;

#else  // !_WIN32

    // Note: on Posix systems, make it a naive wrapper around pthread_cond_t.

    ConditionVariable() {
        pthread_cond_init(&mCond, NULL);
    }

    ~ConditionVariable() {
        pthread_cond_destroy(&mCond);
    }

    template <bool IsRecursive>
    void wait(StaticLock<IsRecursive>* userLock) {
        pthread_cond_wait(&mCond, &userLock->mLock);
    }

    template <bool IsRecursive>
    bool timedWait(StaticLock<IsRecursive>* userLock, uint64_t waitUntilUs) {
        timespec abstime;
        abstime.tv_sec = waitUntilUs / 1000000LL;
        abstime.tv_nsec = (waitUntilUs % 1000000LL) * 1000;
        return timedWait(userLock, abstime);
    }

    template <bool IsRecursive>
    bool timedWait(StaticLock<IsRecursive>* userLock, const timespec& abstime) {
        return pthread_cond_timedwait(&mCond, &userLock->mLock, &abstime) == 0;
    }

    void signal() {
        pthread_cond_signal(&mCond);
    }

    void broadcast() {
        pthread_cond_broadcast(&mCond);
    }

private:
    pthread_cond_t mCond;

#endif  // !_WIN32

    DISALLOW_COPY_ASSIGN_AND_MOVE(ConditionVariable);
};

#ifdef _WIN32
template <bool IsRecursive>
inline void ConditionVariable::signalAndUnlock(StaticLock<IsRecursive>* lock) {
    lock->unlock();
    signal();
}
template <class Lockable>
inline void ConditionVariable::signalAndUnlock(AutoLock<Lockable>* lock) {
    lock->unlock();
    signal();
}

template <bool IsRecursive>
inline void ConditionVariable::broadcastAndUnlock(StaticLock<IsRecursive>* lock) {
    lock->unlock();
    broadcast();
}
template <class Lockable>
inline void ConditionVariable::broadcastAndUnlock(AutoLock<Lockable>* lock) {
    lock->unlock();
    broadcast();
}
#else  // !_WIN32

template <bool IsRecursive>
inline void ConditionVariable::signalAndUnlock(StaticLock<IsRecursive>* lock) {
    signal();
    lock->unlock();
}
template <class Lockable>
inline void ConditionVariable::signalAndUnlock(AutoLock<Lockable>* lock) {
    signal();
    lock->unlock();
}
template <bool IsRecursive>
inline void ConditionVariable::broadcastAndUnlock(StaticLock<IsRecursive>* lock) {
    broadcast();
    lock->unlock();
}
template <class Lockable>
inline void ConditionVariable::broadcastAndUnlock(AutoLock<Lockable>* lock) {
    broadcast();
    lock->unlock();
}
#endif  // !_WIN32

}  // namespace guest
}  // namespace base
}  // namespace android
