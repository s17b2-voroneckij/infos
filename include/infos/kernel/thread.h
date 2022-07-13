/* SPDX-License-Identifier: MIT */

/*
 * include/kernel/thread.h
 *
 * InfOS
 * Copyright (C) University of Edinburgh 2016.  All Rights Reserved.
 *
 * Tom Spink <tspink@inf.ed.ac.uk>
 */
#pragma once

#include <infos/define.h>
#include <infos/kernel/thread-context.h>
#include <infos/kernel/sched-entity.h>
#include <infos/util/list.h>
#include <infos/util/string.h>

namespace infos
{
	namespace kernel
	{
		class Process;

		namespace ThreadPrivilege
		{
			enum ThreadPrivilege
			{
				Kernel = 0,
				User = 1
			};
		}

		class Thread : public SchedulingEntity
		{
		public:
			typedef void (*thread_proc_t)(void *);

			Thread(Process& owner, ThreadPrivilege::ThreadPrivilege privilege, thread_proc_t entry_point,
                   SchedulingEntityPriority::SchedulingEntityPriority priority, const util::String& name = "?");
			virtual ~Thread();

			ThreadPrivilege::ThreadPrivilege privilege() const { return _privilege; }
			bool is_kernel_thread() const { return _privilege == ThreadPrivilege::Kernel; }

			void start();
			void stop(bool simple_exit);
			void sleep();
			void wake_up();

			void allocate_user_stack(virt_addr_t vaddr, size_t size);
			void add_entry_argument(void *arg);

			ThreadContext& context() { return _context; }

			bool activate(SchedulingEntity *prev) override;

			Process& owner() const { return _owner;}

			static Thread& current();

			const util::String& name() const { return _name; }
			void name(const util::String& n) { _name = n; }

			void set_thread_id(unsigned int id) {thread_id = id;};

			auto get_thread_id() const {return thread_id;};

			void enter_syscall() {
				in_syscall = true;
				before_syscall_context = _context.native_context;
			}

			void leave_syscall() {
				in_syscall = false;
			}

		private:
			void prepare_initial_stack();

			Process& _owner;
			ThreadPrivilege::ThreadPrivilege _privilege;
			thread_proc_t _entry_point;
			unsigned int _current_entry_argument;
			unsigned int thread_id;

			ThreadContext _context;
			util::String _name;
			bool in_syscall = false;
			X86Context* before_syscall_context;
		};
	}
}
