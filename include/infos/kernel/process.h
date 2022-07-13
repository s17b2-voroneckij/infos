/* SPDX-License-Identifier: MIT */

/*
 * include/kernel/process.h
 *
 * InfOS
 * Copyright (C) University of Edinburgh 2016.  All Rights Reserved.
 *
 * Tom Spink <tspink@inf.ed.ac.uk>
 */
#pragma once

#include <infos/kernel/thread.h>
#include <infos/mm/vma.h>
#include <infos/util/list.h>
#include <infos/util/string.h>
#include <infos/util/event.h>
#include <infos/util/map.h>
#include <infos/util/wakequeue.h>
#include <infos/util/lock.h>

struct ExceptionPrepareInfo {
    void* unwind_address;
    void *(*malloc_ptr) (uint64_t);
    void (*free_ptr)(void *);
};

namespace infos
{
	namespace kernel
	{
		class Process
		{
		public:
			Process(const util::String& name, bool kernel_process, Thread::thread_proc_t entry_point);
			virtual ~Process();

			const util::String& name() const { return _name; }

			void start();
			void terminate(int rc);
			bool terminated() const { return _terminated; }

			inline bool kernel_process() const { return _kernel_process; }

			mm::VMA& vma() { return _vma; }
			Thread& main_thread() const { return *_main_thread; }

			Thread& create_thread(ThreadPrivilege::ThreadPrivilege privilege, Thread::thread_proc_t entry_point,
			        const util::String& name, SchedulingEntityPriority::SchedulingEntityPriority priority = SchedulingEntityPriority::NORMAL);

			util::Event& state_changed() { return _state_changed; }

            ExceptionPrepareInfo getExceptionPrepareInfo() const {
                return exceptionPrepareInfo;
            }

            void setExceptionPrepareInfo(ExceptionPrepareInfo a) {
                exceptionPrepareInfo = a;
				exceptionInfoPresent = true;
            }

			bool exceptionInfoAvailable() const {
				return exceptionInfoPresent;
			}

			void set_thread_waiting(Thread& t, virt_addr_t va) {
				futex_mutex.lock();
				if (!wake_queue_map.contains_key(va)) {
					wake_queue_map.add(va, new util::WakeQueue());
				}
				auto queue = wake_queue_map.get_value(va);
				futex_mutex.unlock();
				queue->sleep(t);
			}

			void wake_up_threads(virt_addr_t va, uint64_t number) {
				infos::util::WakeQueue* queue;
				if (!wake_queue_map.try_get_value(va, queue)) {
					return;
				}
				queue->wakeMax(number);
			}

			void lock() {
				futex_mutex.lock();
			}

			void unlock() {
				futex_mutex.unlock();
			}

		private:
			const util::String _name;
			bool _kernel_process, _terminated;
			mm::VMA _vma;
			util::List<Thread *> _threads;
			Thread *_main_thread;

			util::Event _state_changed;

            ExceptionPrepareInfo exceptionPrepareInfo;
			bool exceptionInfoPresent = false;

			util::Map<virt_addr_t, util::WakeQueue*> wake_queue_map;

			util::Mutex futex_mutex;
		};
	}
}
