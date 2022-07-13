/* SPDX-License-Identifier: MIT */

#pragma once

#include <infos/define.h>
#include <infos/util/list.h>
#include <infos/util/lock.h>

namespace infos
{
	namespace kernel
	{
		class Thread;
	}

	namespace util
	{
		class WakeQueue
		{
		public:
            void sleep(kernel::Thread& thread);
            void wake();
			void wakeMax(int n);

		private:
			util::List<kernel::Thread *> _waiters;
			util::Mutex _lock;
		};
	}
}
