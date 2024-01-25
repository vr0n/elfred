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
int
get_ehdr_type_from_int(int type, char* type_str) {
  int len = 8;
  switch(type) {
    case 0:
      memcpy(type_str, "ET_NONE\0", len);
      break;
    case 1:
      memcpy(type_str, "ET_REL \0", len);
      break;
    case 2:
      memcpy(type_str, "ET_EXEC\0", len);
      break;
    case 3:
      memcpy(type_str, "ET_DYN \0", len);
      break;
    case 4:
      memcpy(type_str, "ET_CORE\0", len);
      break;
    default:
      memcpy(type_str, "UNKNOWN\0", len);
      return -1;
  }

  return 0;
}

int
get_phdr_perms_from_int(int perms, char* perms_str) {
  int len = 8;
  switch(perms) {
    case 1:
      memcpy(perms_str, "--X    \0", len);
      break;
    case 2:
      memcpy(perms_str, "-W-    \0", len);
      break;
    case 3:
      memcpy(perms_str, "-WX    \0", len);
      break;
    case 4:
      memcpy(perms_str, "R--    \0", len);
      break;
    case 5:
      memcpy(perms_str, "R-X    \0", len);
      break;
    case 6:
      memcpy(perms_str, "RW-    \0", len);
      break;
    case 7:
      memcpy(perms_str, "RWX    \0", len);
      break;
    default:
      memcpy(perms_str, "UNKNOWN\0", len);
      return -1;
  }

  return 0;
}

int
get_phdr_type_from_int(int phdr, char* type_str) {
  int len = 16;
  switch(phdr) {
    case 0x01:
      memcpy(type_str, "PT_LOAD        \0", len);
      break;
    case 0x02:
      memcpy(type_str, "PT_DYNAMIC     \0", len);
      break;
    case 0x03:
      memcpy(type_str, "PT_INTERP      \0", len);
      break;
    case 0x04:
      memcpy(type_str, "PT_NOTE        \0", len);
      break;
    case 0x05:
      memcpy(type_str, "PT_NOTE        \0", len);
      break;
    case 0x06:
      memcpy(type_str, "PT_PHDR        \0", len);
      break;
    case 0x06474e550:
      memcpy(type_str, "PT_GNU_EH_FRAME\0", len);
      break;
    case 0x06474e551:
      memcpy(type_str, "PT_GNU_STACK   \0", len);
      break;
    case 0x06474e552:
      memcpy(type_str, "PT_GNU_RELRO   \0", len);
      break;
    case 0x06474e553:
      memcpy(type_str, "PT_GNU_PROPERTY\0", len);
      break;
    default:
      memcpy(type_str, "PT_UNKNOWN     \0", len);
      return -1;
  }

  return 0;
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
  char* ehdr_type = calloc(1, 256);
  get_ehdr_type_from_int(bin->hdr->e_type, ehdr_type);

  printf("\nElf Header:\n");
  printf("===========================\n");

  printf("Magic: ");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%.2x ", bin->hdr->e_ident[i]);
  }

  printf("\nEntry: 0x%016llx\n", bin->hdr->e_entry);

  printf("\
Header Size        Obj type     Obj version\n\
%08d           %s      %08d\n",
    bin->hdr->e_ehsize, ehdr_type, bin->hdr->e_version);

  printf("\
Machine            Proc flags   Strtab index\n\
%08d           %08d     %08d\n",
    bin->hdr->e_machine, bin->hdr->e_flags, bin->hdr->e_shstrndx);

  printf("\
Phdr offset        Phdr size    Phdr num\n\
0x%016llx %08d     %08d\n",
    bin->hdr->e_phoff, bin->hdr->e_phentsize, bin->hdr->e_phnum);

  printf("\
Shdr offset        Shdr size    Shdr num\n\
0x%016llx %08d     %08d\n",
    bin->hdr->e_shoff, bin->hdr->e_shentsize, bin->hdr->e_shnum);

  free(ehdr_type);
}

void
print_program_headers(elf_bin_t* bin) {
  Elf64_Phdr* tmp_phdr = bin->phdr;
  char* phdr_str = calloc(1, 256);
  char* perms_str = calloc(1, 256);

  printf("Elf program headers\n");
  printf("===========================\n");

  for (int i = 0; i < bin->hdr->e_phnum; i++) {
    get_phdr_type_from_int(tmp_phdr->p_type, phdr_str);
    get_phdr_perms_from_int(tmp_phdr->p_flags, perms_str);

    printf("Phdr %d\n", i+1);
    puts("--------");
    printf("\
Type               Perms              Offset             Vaddr\n\
%s    %s            0x%016llx 0x%016llx\n\
Paddr              Filesz             Memsz              Align\n\
0x%016llx 0x%016llx 0x%016llx 0x%016llx\n\n",
    phdr_str, perms_str, tmp_phdr->p_offset, tmp_phdr->p_vaddr, tmp_phdr->p_paddr, tmp_phdr->p_filesz, tmp_phdr->p_memsz, tmp_phdr->p_align);

    tmp_phdr += sizeof(Elf64_Phdr);
    *phdr_str = '\0';
    *perms_str = '\0';
  }

  free(phdr_str);
  free(perms_str);
}

void
print_section_headers(elf_bin_t* bin) {
}
