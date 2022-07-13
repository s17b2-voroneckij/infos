#include <infos/kernel/abi.h>
#include <infos/kernel/subsystem.h>
#include <infos/mm/page-allocator.h>
#include <infos/mm/object-allocator.h>
#include <infos/mm/vma.h>
#include <infos/mm/mm.h>
#include <infos/kernel/kernel.h>
#include <infos/util/string.h>
#include <infos/mm/vma.h>
#include <infos/kernel/thread.h>
#include <infos/kernel/process.h>
#include <infos/kernel/log.h>

using infos::kernel::syslog;
using namespace infos::kernel::LogLevel;
using namespace infos::kernel;

typedef const uint8_t* LSDA_ptr;

extern "C" {
extern int strlen(const char *str);
}

struct LSDA_call_site_Header {
    LSDA_call_site_Header(LSDA_ptr *lsda);

    LSDA_call_site_Header() = default;

    uint8_t encoding;
    uint64_t length;
};

struct Action {
    uint8_t type_index;
    int8_t next_offset;
    LSDA_ptr my_ptr;
};

struct LSDA_call_site {
    explicit LSDA_call_site(LSDA_ptr* lsda);

    LSDA_call_site() = default;

    bool has_landing_pad() const {
        return landing_pad;
    }

    bool valid_for_throw_ip(_Unwind_Context* context) const {
        uintptr_t func_start = _Unwind_GetRegionStart(context);
        uintptr_t try_start = func_start + start;
        uintptr_t try_end = try_start + len;
        uintptr_t throw_ip = _Unwind_GetIP(context) - 1;
        if (throw_ip > try_end || throw_ip < try_start) {
            return false;
        }
        return true;
    }

    uint64_t start;
    uint64_t len;
    uint64_t landing_pad;
    uint64_t action;
};


uint64_t read_uleb_128(const uint8_t **data) {
    uint64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    do {
        byte = **data;
        (*data)++;
        result |= (byte & 0b1111111) << shift;
        shift += 7;
    } while (byte & 0b10000000);
    return result;
}

int64_t read_sleb_128(const uint8_t **data) {
    uint64_t result = 0;
    int shift = 0;
    uint8_t byte = 0;
    auto p = *data;
    do {
        byte = *p;
        p++;
        result |= (byte & 0b1111111) << shift;
        shift += 7;
    } while (byte & 0b10000000);
    if ((byte & 0x40) && (shift < (sizeof(result) << 3))) {
        result |= static_cast<uintptr_t>(~0) << shift;
    }
    return result;
}

LSDA_call_site_Header::LSDA_call_site_Header(LSDA_ptr *lsda) {
    LSDA_ptr read_ptr = *lsda;
    encoding = read_ptr[0];
    *lsda += 1;
    length = read_uleb_128(lsda);
}

LSDA_call_site::LSDA_call_site(LSDA_ptr* lsda) {
    LSDA_ptr read_ptr = *lsda;
    start = read_uleb_128(lsda);
    len = read_uleb_128(lsda);
    landing_pad = read_uleb_128(lsda);
    action = read_uleb_128(lsda);
}

namespace __cxxabiv1 {
    struct __class_type_info {
        virtual void foo() {}
    } ti;
}

// for freeing exceptions_on_stack
const unsigned MAX_THREADS = 10;
/*thread_local*/ __cxa_exception* last_exception[MAX_THREADS];

void* read_int_tbltype(const int* ptr, uint8_t type_encoding) {
    if (type_encoding == 3) {
        return (void *) *ptr;
    } else if (type_encoding == 0) {
        auto new_ptr = (unsigned long long*)ptr;
        //syslog.messagef(DEBUG, "read addr: %x", (void*) *new_ptr);
        return (void *) *new_ptr;
    } else if (type_encoding == 0x9b) {
        uintptr_t result = *ptr;
        if (result == 0) {
            return nullptr;
        }
        result += (uintptr_t) ptr;
        result = *((uintptr_t*)result);
        return (void *)result;
    } else {
        syslog.messagef(DEBUG, "bad encoding type: %x", type_encoding);
    }
}

const unsigned PAGE_SIZE = 4096;

extern "C" {
    void panic() {
        syslog.message(DEBUG, "panic!");
        while (true) {
        }
    }

    void* __cxa_allocate_exception(size_t thrown_size) {
        if (Thread::current().owner().exceptionInfoAvailable()) {
            auto ptr = (*Thread::current().owner().getExceptionPrepareInfo().malloc_ptr)(thrown_size + sizeof(__cxa_exception));
            if (ptr) {
                return ptr + sizeof(__cxa_exception);
            }
        }
        auto ptr = DefaultSyscalls::sys_allocate_memory((thrown_size + sizeof(__cxa_exception) - 1) / 0x1000 + 1);
        if (!ptr) {
            syslog.message(FATAL, "unable to allocate memory for an exception");
        }
        return ptr + sizeof(__cxa_exception);
    }

    void __cxa_free_exception(void* thrown_exception) {
        if (Thread::current().owner().exceptionInfoAvailable()) {
            (*Thread::current().owner().getExceptionPrepareInfo().free_ptr)(thrown_exception - sizeof(__cxa_exception));
        } else {
            DefaultSyscalls::sys_release_memory(thrown_exception - sizeof(__cxa_exception));
        }
    }

    void __cxa_throw(
            void* thrown_exception, type_info *tinfo, void (*dest)(void*)) {
        __cxa_exception *header = (__cxa_exception *) thrown_exception - 1;
        header->exceptionDestructor = dest;
        header->nextException = nullptr;
        auto typeName = tinfo->getName();
        char* newAddr = NULL;
        if (Thread::current().owner().exceptionInfoAvailable()) {
            newAddr = (char *)(*Thread::current().owner().getExceptionPrepareInfo().malloc_ptr)(strlen(typeName) + 1);
        } else {
            newAddr = (char *)DefaultSyscalls::sys_allocate_memory(1);
        }
        if (!newAddr) {
            syslog.message(ERROR, "unable to allocate memory");
        }
        memcpy(newAddr, typeName, strlen(typeName) + 1);
        header->exceptionTypeName = newAddr;
        _Unwind_RaiseException(&header->unwindHeader);
        syslog.messagef(DEBUG, "no one handled __cxa_throw, terminate!\n");
        panic();
    }

    void* __cxa_begin_catch(_Unwind_Exception* unwind_exception) {
        __cxa_exception* exception_header = (__cxa_exception*)(unwind_exception + 1) - 1;
        auto thread_id = Thread::current().get_thread_id();
        exception_header->nextException = last_exception[thread_id];
        last_exception[thread_id] = exception_header;
        return exception_header + 1;
    }

    void __cxa_end_catch() {
        // we need do destroy the last exception
        auto thread_id = Thread::current().get_thread_id();
        __cxa_exception* exception_header = last_exception[thread_id];
        last_exception[thread_id] = exception_header->nextException;
        if (Thread::current().owner().exceptionInfoAvailable()) {
            (*Thread::current().owner().getExceptionPrepareInfo().free_ptr)(exception_header->exceptionTypeName);
        } else {
            DefaultSyscalls::sys_release_memory(exception_header->exceptionTypeName);
        }
        if (exception_header->exceptionDestructor) {
            exception_header->exceptionDestructor(exception_header + 1);
        }
        __cxa_free_exception((char *)(exception_header + 1));
    }

    void* __cxa_get_exception_ptr(_Unwind_Exception* unwind_exception) {
        __cxa_exception* exception_header = (__cxa_exception*)(unwind_exception + 1) - 1;
        return exception_header + 1;
    }

    struct LSDA {
        explicit LSDA(_Unwind_Context* context) {
            lsda = (uint8_t*)_Unwind_GetLanguageSpecificData(context);
            start_encoding = lsda[0];
            type_encoding = lsda[1];
            lsda += 2;
            if (type_encoding != 0xff) { // TODO: think
                type_table_offset = read_uleb_128(&lsda);
            }
            types_table_start = ((const int*)(lsda + type_table_offset));
            call_site_header = LSDA_call_site_Header(&lsda);
            call_site_table_end = lsda + call_site_header.length;
            next_call_site_ptr = lsda;
            action_table_start = call_site_table_end;
        }

        LSDA_call_site* get_next_call_site() {
            if (next_call_site_ptr > call_site_table_end) {
                return nullptr;
            }
            next_call_site = LSDA_call_site(&next_call_site_ptr);
            return &next_call_site;
        }

        uint8_t start_encoding;
        uint8_t type_encoding;
        uint64_t type_table_offset;

        LSDA_ptr lsda;
        LSDA_ptr call_site_table_end;
        LSDA_call_site next_call_site;
        LSDA_ptr next_call_site_ptr;
        LSDA_call_site_Header call_site_header;
        LSDA_ptr action_table_start;
        Action current_action;
        const int* types_table_start;

        Action* get_first_action(LSDA_call_site* call_site) {
            if (call_site->action == 0) {
                return nullptr;
            }
            LSDA_ptr raw_ptr = action_table_start + call_site->action - 1;
            current_action.type_index = raw_ptr[0];
            raw_ptr++;
            current_action.next_offset = read_sleb_128(&raw_ptr);
            current_action.my_ptr = raw_ptr;
            return &current_action;
        }

        Action* get_next_action() {
            if (current_action.next_offset == 0) {
                return nullptr;
            }
            LSDA_ptr raw_ptr = current_action.my_ptr + current_action.next_offset;
            current_action.type_index = raw_ptr[0];
            raw_ptr++;
            current_action.next_offset = read_sleb_128(&raw_ptr);
            current_action.my_ptr = raw_ptr;
            return &current_action;
        }
    };

    _Unwind_Reason_Code set_landing_pad(_Unwind_Context* context, _Unwind_Exception* unwind_exception, uintptr_t landing_pad, uint8_t type_index) {
        int r0 = __builtin_eh_return_data_regno(0);
        int r1 = __builtin_eh_return_data_regno(1);

        _Unwind_SetGR(context, r0, (uintptr_t)(unwind_exception));
        _Unwind_SetGR(context, r1, (uintptr_t)(type_index));

        _Unwind_SetIP(context, landing_pad);
        return _URC_INSTALL_CONTEXT;
    }

    _Unwind_Reason_Code __gxx_personality_v0 (
            int, _Unwind_Action actions, uint64_t exceptionClass,
            _Unwind_Exception* unwind_exception, _Unwind_Context* context) {
        // Pointer to the beginning of the raw LSDA
        LSDA header(context);
        bool have_cleanup = false;
        // Loop through each entry in the call_site table
        for (LSDA_call_site* call_site = header.get_next_call_site(); call_site; call_site = header.get_next_call_site()) {
            if (call_site->has_landing_pad()) {
                uintptr_t func_start = _Unwind_GetRegionStart(context);
                if (!call_site->valid_for_throw_ip(context)) {
                    continue;
                }
                __cxa_exception* exception_header = (__cxa_exception*)(unwind_exception + 1) - 1;
                auto thrown_exception_type = exception_header->exceptionTypeName;
                if (call_site->action == 0 && actions & _UA_CLEANUP_PHASE) {
                    // clean up block?
                    return set_landing_pad(context, unwind_exception, func_start + call_site->landing_pad, 0);
                }
                for (Action* action = header.get_first_action(call_site); action; action = header.get_next_action()) {
                    if (action->type_index == 0) {
                        // clean up action
                        if (actions & _UA_CLEANUP_PHASE) {
                            set_landing_pad(context, unwind_exception, func_start + call_site->landing_pad, 0);
                            have_cleanup = true;
                        }
                    } else {
                        // this landing pad can handle exceptions_on_stack
                        // we need to check types
                        int multiplier = 1;
                        if (header.type_encoding == 0) {
                            multiplier *= 2;
                        }
                        auto got = read_int_tbltype(header.types_table_start - action->type_index * multiplier, header.type_encoding);
                        type_info* this_type_info = reinterpret_cast<type_info *>(got);
                        if (got == nullptr || strcmp(this_type_info->getName(), thrown_exception_type) == 0) {
                            if (actions & _UA_SEARCH_PHASE) {
                                return _URC_HANDLER_FOUND;
                            } else if (actions & _UA_CLEANUP_PHASE) {
                                return set_landing_pad(context, unwind_exception, func_start + call_site->landing_pad,
                                                       action->type_index);
                            }
                        }
                    }
                }
            }
        }

        if ((actions & _UA_CLEANUP_PHASE) && have_cleanup) {
            return _URC_INSTALL_CONTEXT;
        }
        return _URC_CONTINUE_UNWIND;
    }

}

extern "C" {
void* get_syscall_rip() {
    return (void *)Thread::current().context().native_context->rip;
}

extern void _Unwind_ReturnToUser2(struct _Unwind_Exception* exc, const void* user_callback, const void* rip);

void _Unwind_ReturnToUser(struct _Unwind_Exception *exc) {
    //syslog.messagef(DEBUG, "in Unwind_ReturnToUser rip=%x\n", get_syscall_rip());
    if (Thread::current().owner().exceptionInfoAvailable()) {
        _Unwind_ReturnToUser2(exc, Thread::current().owner().getExceptionPrepareInfo().unwind_address, get_syscall_rip());
    } else {
        syslog.message(DEBUG, "process unable to catch exceptions");
        Thread::current().owner().terminate(1);
    }
}
}