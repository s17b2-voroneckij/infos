#include <infos/kernel/syscall.h>

extern "C" {
extern void init_unwinding(const void*, const void*);
}

using infos::kernel::DefaultSyscalls;


#define __packed __attribute__((packed))
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long int uint64_t;

struct ELF64Header
{
    struct
    {
        union
        {
            char magic_bytes[4];
            uint32_t magic_number;
        };

        uint8_t eclass, data, version, osabi, abiversion;
        uint8_t pad[7];
    } ident __packed;

    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry_point;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} __packed;

typedef struct {
    uint32_t	sh_name;
    uint32_t	sh_type;
    uint64_t	sh_flags;
    uint64_t	sh_addr;
    uint64_t	sh_offset;
    uint64_t	sh_size;
    uint32_t	sh_link;
    uint32_t	sh_info;
    uint64_t	sh_addralign;
    uint64_t	sh_entsize;
} Elf64_Shdr;

extern "C" {
extern void init_unwinding(const void*, const void*);
extern int strcmp(const char *l, const char *r);
}

void prepare_exceptions(const char* FILE_NAME) {
    auto fd = DefaultSyscalls::sys_open((uintptr_t)FILE_NAME, 0);
    ELF64Header hdr;
    DefaultSyscalls::sys_pread(fd, (uintptr_t)&hdr, sizeof(ELF64Header), 0);
    Elf64_Shdr string_table_section;
    DefaultSyscalls::sys_pread(fd, (uintptr_t)&string_table_section, sizeof(Elf64_Shdr),hdr.shoff + hdr.shstrndx * sizeof(Elf64_Shdr));
    char strings[string_table_section.sh_size];
    DefaultSyscalls::sys_pread(fd, (uintptr_t)strings, string_table_section.sh_size, string_table_section.sh_offset);
    const void* EH_FRAME_START;
    const void* NEXT_SECTION_START;
    bool previos_eh_frame = false;
    for (int i = 1; i < hdr.shnum; i++) {
        Elf64_Shdr section_header;
        DefaultSyscalls::sys_pread(fd, (uintptr_t)&section_header, sizeof(Elf64_Shdr), hdr.shoff + i * sizeof(Elf64_Shdr));
        char* name = &strings[section_header.sh_name];
        if (previos_eh_frame) {
            NEXT_SECTION_START = (void *)section_header.sh_addr;
            break;
        }
        if (strcmp(name, ".eh_frame") == 0) {
            previos_eh_frame = true;
            EH_FRAME_START = (void *)section_header.sh_addr;
        }
    }
    init_unwinding(EH_FRAME_START, NEXT_SECTION_START);
}
