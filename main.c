#include <elf.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int open_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        perror("Problem opening the binary file.");
    }
    else
    {
        printf("Open file successfully\n");
    }
    return fd;
}

int read_elf_header(int fd, Elf64_Ehdr *elf)
{
    if (read(fd, elf, sizeof(*elf)) != sizeof(*elf))
    {
        fprintf(stderr, "Problem in reading the file into header object\n");
        return -1;
    }

    if (elf->e_type != ET_EXEC)
    {
        fprintf(stderr, "ELF is not ET_EXEC type\n");
        exit(1);
    }

    printf("Read file seccusfuly\n");
    return 0;
}

int validate_elf(const Elf64_Ehdr *elf)
{
    if (memcmp(elf->e_ident, ELFMAG, SELFMAG) != 0)
    {
        perror("Not a valid ELF file");
        return -1;
    }
    return 0;
}

Elf64_Addr align_down(Elf64_Addr value, long page_size)
{
    return (value / page_size) * page_size;
}

Elf64_Addr align_up(Elf64_Addr value, long page_size)
{
    return ((value + page_size - 1) / page_size) * page_size;
}

int load_segments(int fd, const Elf64_Ehdr *elf)
{
    Elf64_Phdr phdr;
    long page_size = sysconf(_SC_PAGESIZE);

    if (sizeof(phdr) != elf->e_phentsize)
    {
        perror("e_phentsize not equal to sizeof(phdr)");
    }

    if (lseek(fd, elf->e_phoff, SEEK_SET) == -1)
    {
        perror("lseek failed");
        return -1;
    }

    if (sizeof(Elf64_Phdr) != elf->e_phentsize)
    {
        perror("The expected and actual size are different");
        return -1;
    }

    for (int i = 0; i < elf->e_phnum; i++)
    {
        if (read(fd, &phdr, elf->e_phentsize) != sizeof(phdr))
        {
            perror("Problem in reading program header");
            return -1;
        }

        if (phdr.p_type != PT_LOAD)
        {
            continue;
        }

        Elf64_Addr aligned_vaddr = align_down(phdr.p_vaddr, page_size);
        Elf64_Off aligned_offset = align_down(phdr.p_offset, page_size);
        size_t padding = phdr.p_vaddr - aligned_vaddr;
        size_t size = align_up(phdr.p_memsz + padding, page_size);

        int flags = 0;
        if (phdr.p_flags & PF_R)
            flags |= PROT_READ;
        if (phdr.p_flags & PF_W)
            flags |= PROT_WRITE;
        if (phdr.p_flags & PF_X)
            flags |= PROT_EXEC;

        char *memory_p = (char *)mmap((void *)aligned_vaddr, size, flags,
                                      MAP_PRIVATE | MAP_FIXED, fd, aligned_offset);

        if (memory_p == MAP_FAILED)
        {
            perror("mmap failed");
            return -1;
        }

        system("cat /proc/self/maps");

        if (phdr.p_filesz < phdr.p_memsz)
        {
            memset(memory_p + (phdr.p_vaddr - aligned_vaddr) + phdr.p_filesz, 0,
                   phdr.p_memsz - phdr.p_filesz);
        }

        printf("Segment loaded at: %p\n", memory_p);
    }

    return 0;
}

void jump_to_entry(Elf64_Addr entry)
{
    void (*entry_func)(void) = (void (*)(void))entry;
    entry_func();
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Please provide one ELF binary path as argument.\n");
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0)
    {
        int fd = open_file(argv[1]);
        if (fd == -1)
            exit(1);

        Elf64_Ehdr elf;
        if (read_elf_header(fd, &elf) == -1)
        {
            close(fd);
            exit(1);
        }

        if (validate_elf(&elf) == -1)
        {
            close(fd);
            exit(1);
        }

        if (load_segments(fd, &elf) == -1)
        {
            close(fd);
            exit(1);
        }

        close(fd);

        printf("Entry point: 0x%lx\n", elf.e_entry);
        jump_to_entry(elf.e_entry);
        exit(0);
    }
    else if (pid > 0)
    {
        // parent process
        wait(NULL);
    }
    else
    {
        perror("fork failed");
        return -1;
    }

    return 0;
}
