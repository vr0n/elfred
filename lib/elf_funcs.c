#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "elf_funcs.h"
#include "utils.h"

/*
 * Utilities
 */
static char*
get_phdr_perms_from_int(int perms) {
  switch(perms) {
    case 1:
      return "--X   \0";
    case 2:
      return "-W-   \0";
    case 3:
      return "-WX   \0";
    case 4:
      return "R--   \0";
    case 5:
      return "R-X   \0";
    case 6:
      return "RW-   \0";
    case 7:
      return "RWX   \0";
    default:
      return "UNKOWN\0";
  }
}

static char*
get_phdr_type_from_int(int phdr) {
  switch(phdr) {
    case 0x01:
      return "EHDR_LOAD        \0";
    case 0x02:
      return "EHDR_DYNAMIC     \0";
    case 0x03:
      return "EHDR_INTERP      \0";
    case 0x04:
      return "EHDR_NOTE        \0";
    case 0x05:
      return "EHDR_NOTE        \0";
    case 0x06:
      return "EHDR_PHDR        \0";
    case 0x06474e550:
      return "EHDR_GNU_EH_FRAME\0";
    case 0x06474e551:
      return "EHDR_GNU_STACK   \0";
    case 0x06474e552:
      return "EHDR_GNU_RELRO   \0";
    case 0x06474e553:
      return "EHDR_GNU_PROPERTY\0";
    default:
      return "EHDR_UNKNOWN     \0";
  }
}


int
dump_elf(unsigned char* file, long long len) {
    FILE* output = fopen("./elf.out", "w");

    if (len != fwrite(file, len, 1, output)) {
        fclose(output);

        return -1;
    }

    fclose(output);

    return 0;
}

/*
 * Parsers
 */
int
parse_section_headers(unsigned char* elf_file, elf_bin_t* bin)
{
  unsigned short shnum = bin->hdr->e_shnum;
  bin->shdr = malloc(sizeof(Elf64_Shdr) * shnum);

  unsigned char* tmp_file = elf_file;
  tmp_file = tmp_file + bin->hdr->e_shoff;

  for (int i = 0; i < shnum; i++) {
    memcpy(bin->shdr + (sizeof(Elf64_Shdr) * 1), tmp_file, sizeof(Elf64_Shdr));
    tmp_file = tmp_file + sizeof(Elf64_Shdr);
  }

  return 0;
}

int
parse_sections(unsigned char* elf_file, elf_bin_t* bin)
{
  return 0;
}

int
parse_elf(unsigned char* elf_file, elf_bin_t* bin)
{
  parse_header(elf_file, bin);
  parse_program_headers(elf_file, bin);
  parse_section_headers(elf_file, bin);
  parse_sections(elf_file, bin);

  return 0;
}

int
parse_header(unsigned char* elf_file, elf_bin_t* bin)
{
  bin->hdr = malloc(sizeof(Elf64_Ehdr));
  memcpy(bin->hdr, elf_file, EHDR_SIZE);

  return 0;
}

int 
parse_program_headers(unsigned char* elf_file, elf_bin_t* bin) {
  unsigned short phnum = bin->hdr->e_phnum;
  bin->phdr = malloc(sizeof(Elf64_Phdr) * phnum);
  if (NULL == bin->phdr) {
    log_err("Failed to allocate space for program headers");

    return -1;
  }

  unsigned char* tmp_file = elf_file;
  tmp_file = tmp_file + bin->hdr->e_phoff; // Get to program header offset

  for (int i = 0; i < phnum; i++) {
    memcpy(bin->phdr + (sizeof(Elf64_Phdr) * i), tmp_file, sizeof(Elf64_Phdr));
    tmp_file = tmp_file + sizeof(Elf64_Phdr);
  }

  return 0;
}

/*
 * Setters
 */
int
set_hdr_type(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_type);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_machine(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_machine);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_version(unsigned char* file, elf_bin_t* bin, Elf64_Word new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_version);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_entry(unsigned char* file, elf_bin_t* bin, Elf64_Addr new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_entry);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_phoff(unsigned char* file, elf_bin_t* bin, Elf64_Off new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_phoff);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shoff(unsigned char* file, elf_bin_t* bin, Elf64_Off new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shoff);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_flags(unsigned char* file, elf_bin_t* bin, Elf64_Word new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_flags);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_ehsize(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_ehsize);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_phentsize(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_phentsize);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_phnum(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_phnum);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shentsize(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shentsize);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shnum(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shnum);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shstrndx(unsigned char* file, elf_bin_t* bin, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shstrndx);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_align(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Xword new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_align);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_memsz(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Xword new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_memsz);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_filesz(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Xword new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_filesz);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_paddr(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Addr new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_paddr);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_vaddr(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Addr new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_vaddr);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_flags(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Word new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_flags);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_type(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Word new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_type);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_offset(unsigned char* file, elf_bin_t* bin, unsigned int phdr, Elf64_Off new_val) {
    if (phdr-1 > bin->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = bin->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_offset);
    unsigned char* tmp_file = file;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

/*
 * Printers
 */
void
print_elf_header(elf_bin_t* bin) {
  printf("\nElf Header:\n");
  printf("===========================\n");

  printf("Magic: ");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%.2x ", bin->hdr->e_ident[i]);
  }

  printf("\nEntry: 0x%016llx\n", bin->hdr->e_entry);

  printf("\
Phdr offset        Phdr size    Phdr num\n\
0x%016llx %08d     %08d\n",
    bin->hdr->e_phoff, bin->hdr->e_phentsize, bin->hdr->e_phnum);

  printf("\
Shdr offset        Shdr size    Shdr num\n\
0x%016llx %08d     %08d\n",
    bin->hdr->e_shoff, bin->hdr->e_shentsize, bin->hdr->e_shnum);

  printf("\
Obj type           Obj version  Strtab index\n\
%08d           %08d     %08d\n",
    bin->hdr->e_type, bin->hdr->e_version, bin->hdr->e_shstrndx);

  printf("\
Header size        Machine    Proc flags\n\
%08d           %08d     %08d\n",
    bin->hdr->e_ehsize, bin->hdr->e_machine, bin->hdr->e_flags);
}

void
print_program_headers(elf_bin_t* bin) {
  Elf64_Phdr* tmp_phdr = bin->phdr;
  char* phdr_str = calloc(1, 1024);
  char* perms_str = calloc(1, 1024);

  printf("Elf program headers\n");
  printf("===========================\n");

  for (int i = 0; i < bin->hdr->e_phnum; i++) {
    phdr_str = get_phdr_type_from_int(tmp_phdr->p_type);
    perms_str = get_phdr_perms_from_int(tmp_phdr->p_flags);

    printf("Phdr %d\n", i+1);
    puts("--------");
    printf("\
Type               Perms              Offset             Vaddr\n\
%s  %s             0x%016llx 0x%016llx\n\
Paddr              Filesz             Memsz              Align\n\
0x%016llx 0x%016llx 0x%016llx 0x%016llx\n\n",
    phdr_str, perms_str, tmp_phdr->p_offset, tmp_phdr->p_vaddr, tmp_phdr->p_paddr, tmp_phdr->p_filesz, tmp_phdr->p_memsz, tmp_phdr->p_align);

    tmp_phdr += sizeof(Elf64_Phdr);
    phdr_str = NULL;
    perms_str = NULL;
  }
}

void
print_section_headers(elf_bin_t* bin) {
}