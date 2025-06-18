#include <elf.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int open_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if(fd == -1) {
        perror("Problem openning the binary file. \n");
    } else {
        printf("Open file seccusfuly \n");
    }
    return fd;
}

int read_elf_header(int fd, Elf64_Ehdr *elf) {
    if(read(fd, elf, sizeof(*elf)) == -1) {
        perror("Problem in reading the file into header object. \n");
        return -1;
    }
    printf("Read file seccusfuly \n");
    return 0;
}

int validate_elf(const Elf64_Ehdr *elf) {
    if(elf->e_ident[0] != ELFMAG0 || elf->e_ident[1] != ELFMAG1 ||
       elf->e_ident[2] != ELFMAG2 || elf->e_ident[3] != ELFMAG3) {
        perror("Not a valid elf file. \n");
        return -1;
    }
    return 0;
}

int load_segments(int fd, const Elf64_Ehdr *elf) {
    Elf64_Phdr phdr;

    lseek(fd, elf->e_phoff, SEEK_SET);

    for(int i = 0; i < elf->e_phnum; i++) {
        if(sizeof(phdr) != elf->e_phentsize) {
            perror("The excpected and actual size are differ \n");
        }

        if(read(fd, &phdr, elf->e_phentsize) == -1) {
            perror("Problem in reading the file into header object. \n");
            return -1;
        }

        if(phdr.p_type != PT_LOAD) {
            continue;
        }

        int flags = 0;
        if (phdr.p_flags & PF_R) flags |= PROT_READ;
        if (phdr.p_flags & PF_W) flags |= PROT_WRITE;
        if (phdr.p_flags & PF_X) flags |= PROT_EXEC;

        char* memory_p = (char*) mmap((void*)phdr.p_vaddr, phdr.p_memsz, flags,
                                      MAP_PRIVATE | MAP_FIXED, fd, phdr.p_offset);
        if (memory_p == MAP_FAILED) {
            perror("mmap failed");
            return -1;
        }

        if(phdr.p_filesz < phdr.p_memsz) {
            memset(memory_p + phdr.p_filesz, 0, phdr.p_memsz - phdr.p_filesz);
        }
    }

    return 0;
}

void jump_to_entry(Elf64_Addr entry) {
    void (*entry_func)(void) = (void (*)(void)) entry;
    entry_func();
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        perror("Please type one and only one binary file path as an argument. \n");
        return -1;
    }

    int fd = open_file(argv[1]);
    if(fd == -1) return -1;

    Elf64_Ehdr elf;
    if(read_elf_header(fd, &elf) == -1) {
        close(fd);
        return -1;
    }

    if(validate_elf(&elf) == -1) {
        close(fd);
        return -1;
    }

    if(load_segments(fd, &elf) == -1) {
        close(fd);
        return -1;
    }

    close(fd);

    jump_to_entry(elf.e_entry);

    return 0;
}
