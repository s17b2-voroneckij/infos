#include <infos/unwind/unwind-dw2.h>
#include <infos/unwind/tconfig.h>

extern "C" {
extern int strcmp(const char *l, const char *r);
}

class type_info {
    void* god_knows_what;
    char* name;

public:
    char* getName() const {
        return name;
    }

    bool operator == (const type_info& other) const {
        return strcmp(getName(), other.getName()) == 0;
    }
};

struct __cxa_exception {
    char* exceptionTypeName;
    void (*exceptionDestructor) (void *);
    __cxa_exception*   nextException;

    _Unwind_Exception   unwindHeader;
};

typedef void (*unexpected_handler)(void);
typedef void (*terminate_handler)(void);
