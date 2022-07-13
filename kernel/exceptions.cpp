#include <infos/kernel/log.h>
#include <infos/kernel/syscall.h>

#define __packed __attribute__((packed))

using infos::kernel::DefaultSyscalls;

int instances = 0;

void my_assert(bool b) {
    if (!b) {
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "panic!!!!\n");
    }
}

class A {
        public:
        A() {
            instances++;
        }

        //A(A&& a) = delete;
        A(const A &a) {
            instances++;
        }

        A &operator=(const A &a) = delete;

        A &operator=(A &&a) = delete;

        ~A() {
            instances--;
        }
};

class Int {
        public:
        explicit Int(unsigned int a) {
            n = a;
        }

        unsigned int n;
};

class Char {
        public:
        explicit Char(char a) {
            n = a;
        }

        char n;
};

void firstTest() {
    A a;
    try {
        A d;
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "going to throw");
        throw Int(1);
        A f;
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "firstTest after throw executed");
        my_assert(false);
    } catch (Int& a) {
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "caught");
        my_assert(a.n == 1);
        A b;
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "firstTest correct catch\n");
    } catch (Char &t) {
        A c;
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "firstTest incorrect catch\n");
        my_assert(false);
    }
    my_assert(instances == 1);
}

void secondTest() {
    A a;
    try {
        A b;
        throw Char('a');
    } catch (Int &n) {
        my_assert(false);
    } catch (Char &c) {
        A u;
        my_assert(c.n == 'a');
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "secondTest correct catch\n");
    } catch (Char b) {
        my_assert(false);
    }
}

void innerHelper() {
    A a;
    throw A();
}

void middleHelper() {
    try {
        A b;
        innerHelper();
        A m;
    } catch (Int &a) {
        A b;
        my_assert(false);
    }
}

void outerHelper() {
    try {
        A o;
        middleHelper();
    } catch (A& a) {
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "thirdTest correct catch\n");
        A y;
    }
}

void thirdTest() {
    outerHelper();
}

void fourthTest() {
    try {
        int f = 0; // does not throw
    } catch (...) {
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "fourthTest wrong catch\n");
        my_assert(false);
    }

    try {
        throw A();
    } catch (...) {
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "fourthTest correct catch\n");
    }

    try {
        int yr = 0; // does not throw
    } catch (...) {
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "fourthTest wrong catch\n");
        my_assert(false);
    }
}

void throw5() {
    throw Int(5);
}

void fifthTest() {
    try {
        innerHelper();
    } catch (A a) {
        A b;
    }

    try {
        throw5();
    } catch (Int& exc) {
        my_assert(exc.n == 5);
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "fifthTest correct catch\n");
    }
}

void sixthTest() {
    try {
        try {
            throw A();
        } catch (Int& a) {
            infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "sixthTest wrong catch\n");
            my_assert(false);
        }
    } catch (A& a) {
        infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "sixthTest correct catch\n");
    }
}

void seventhTest() {
    for (int i = 0; i < 100; i++) {
        try {
            throw A();
        } catch (A& a) {

        }
    }
    infos::kernel::syslog.messagef(infos::kernel::LogLevel::DEBUG, "seventhTest success\n");
}

void run_exception_tests() {
    firstTest();
    my_assert(instances == 0);
    secondTest();
    my_assert(instances == 0);
    thirdTest();
    my_assert(instances == 0);
    fourthTest();
    my_assert(instances == 0);
    fifthTest();
    my_assert(instances == 0);
    sixthTest();
    my_assert(instances == 0);
    seventhTest();
    my_assert(instances == 0);
}
