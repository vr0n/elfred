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

const char* OUT_NAME = "elf.out";

/*
 * Utilities
 */
int
get_ehdr_type_from_int(int type, char* type_str) {
  int len = 8;
  switch(type) {
    case ET_NONE:
      memcpy(type_str, "ET_NONE\0", len);
      break;
    case ET_REL:
      memcpy(type_str, "ET_REL \0", len);
      break;
    case ET_EXEC:
      memcpy(type_str, "ET_EXEC\0", len);
      break;
    case ET_DYN:
      memcpy(type_str, "ET_DYN \0", len);
      break;
    case ET_CORE:
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
    case PT_LOAD:
      memcpy(type_str, "PT_LOAD        \0", len);
      break;
    case PT_DYNAMIC:
      memcpy(type_str, "PT_DYNAMIC     \0", len);
      break;
    case PT_INTERP:
      memcpy(type_str, "PT_INTERP      \0", len);
      break;
    case PT_NOTE:
      memcpy(type_str, "PT_NOTE        \0", len);
      break;
    case PT_SHLIB:
      memcpy(type_str, "PT_SHLIB       \0", len);
      break;
    case PT_PHDR:
      memcpy(type_str, "PT_PHDR        \0", len);
      break;
    case PT_GNU_EH_FRAME:
      memcpy(type_str, "PT_GNU_EH_FRAME\0", len);
      break;
    case PT_GNU_STACK:
      memcpy(type_str, "PT_GNU_STACK   \0", len);
      break;
    case PT_GNU_RELRO:
      memcpy(type_str, "PT_GNU_RELRO   \0", len);
      break;
    case PT_GNU_PROPERTY:
      memcpy(type_str, "PT_GNU_PROPERTY\0", len);
      break;
    default:
      memcpy(type_str, "PT_UNKNOWN     \0", len);
      return -1;
  }

  return 0;
}

elf_bin_t*
open_elf(const char* target_file) {
  struct stat stats;
  if (0 != stat(target_file, &stats)) {
    return NULL;
  }

  elf_bin_t* elf = malloc(sizeof(elf_bin_t));
  if (NULL == elf) {
    return NULL;
  }

  elf->size = stats.st_size;

  FILE* fp = fopen(target_file, "r+b");
  elf->bin = malloc(elf->size);
  fread(elf->bin, elf->size, 1, fp);
  fclose(fp);
  
  parse_elf(elf);
  
  return elf;
}

int
dump_elf(elf_bin_t* elf) {
    FILE* output = fopen(OUT_NAME, "w");
    unsigned long long len = 0;

    if (len != fwrite(elf->bin, elf->size, 1, output)) {
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
parse_sections(unsigned char* elf_file, elf_bin_t* bin)
{
  return 0;
}

int
parse_elf(elf_bin_t* elf)
{
  parse_header(elf->bin, elf);
  parse_program_headers(elf->bin, elf);
  parse_section_headers(elf->bin, elf);
  parse_sections(elf->bin, elf);

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
  bin->phdr = (Elf64_Phdr*)malloc(sizeof(Elf64_Phdr) * phnum);
  if (NULL == bin->phdr) {
    return -1;
  }

  unsigned char* tmp_file = elf_file;
  tmp_file = tmp_file + bin->hdr->e_phoff; // Get to program header offset

  for (int i = 0; i < phnum; i++) {
    memcpy(bin->phdr + i, tmp_file, sizeof(Elf64_Phdr));
    tmp_file = tmp_file + sizeof(Elf64_Phdr);
  }

  return 0;
}

int
parse_section_headers(unsigned char* elf_file, elf_bin_t* bin)
{
  unsigned short shnum = bin->hdr->e_shnum;
  bin->shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr) * shnum);

  unsigned char* tmp_file = elf_file;
  tmp_file = tmp_file + bin->hdr->e_shoff;

  for (int i = 0; i < shnum; i++) {
    memcpy(bin->shdr + i, tmp_file, sizeof(Elf64_Shdr));
    tmp_file = tmp_file + sizeof(Elf64_Shdr);
  }

  return 0;
}

/*
 * Setters
 */
int
set_hdr_type(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_type);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_machine(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_machine);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_version(elf_bin_t* elf, Elf64_Word new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_version);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_entry(elf_bin_t* elf, Elf64_Addr new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_entry);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_phoff(elf_bin_t* elf, Elf64_Off new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_phoff);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shoff(elf_bin_t* elf, Elf64_Off new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shoff);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_flags(elf_bin_t* elf, Elf64_Word new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_flags);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_ehsize(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_ehsize);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_phentsize(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_phentsize);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_phnum(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_phnum);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shentsize(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shentsize);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shnum(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shnum);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_hdr_shstrndx(elf_bin_t* elf, Elf64_Half new_val) {
    size_t offset = offsetof(Elf64_Ehdr, e_shstrndx);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_align(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_align);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_memsz(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_memsz);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_filesz(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_filesz);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_paddr(elf_bin_t* elf, unsigned int phdr, Elf64_Addr new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_paddr);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_vaddr(elf_bin_t* elf, unsigned int phdr, Elf64_Addr new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_vaddr);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_flags(elf_bin_t* elf, unsigned int phdr, Elf64_Word new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_flags);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_type(elf_bin_t* elf, unsigned int phdr, Elf64_Word new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_type);
    unsigned char* tmp_file = elf->bin;

    tmp_file += offset;
    memcpy(tmp_file, &new_val, sizeof(new_val));

    return 0;
}

int
set_phdr_offset(elf_bin_t* elf, unsigned int phdr, Elf64_Off new_val) {
    if (phdr > elf->hdr->e_phnum) {
        return -1;
    }
    unsigned long long offset = elf->hdr->e_phoff +
        (sizeof(Elf64_Phdr) * (phdr-1)) +
        offsetof(Elf64_Phdr, p_offset);
    unsigned char* tmp_file = elf->bin;

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
  Elf64_Shdr* tmp_shdr = bin->shdr;

  printf("Elf section headers\n");
  printf("===========================\n");

  for (int i = 0; i < bin->hdr->e_shnum; i++) {
    printf("Shdr %d\n", i+1);
    puts("--------");
    printf("\
Addr: 0x%016llx\n\
Offset: 0x%016llx\n\
Name    Type    Flags    Size\n\
%d      %d      %llu       %llu\n\
Link    Info    Addralign    Entry size\n\
%d      %d      %llu           %llu\n",
     tmp_shdr->sh_addr, tmp_shdr->sh_offset, tmp_shdr->sh_name, tmp_shdr->sh_type, tmp_shdr->sh_flags, tmp_shdr->sh_size, tmp_shdr->sh_link, tmp_shdr->sh_info, tmp_shdr->sh_addralign, tmp_shdr->sh_entsize);
    tmp_shdr += sizeof(Elf64_Shdr);
  }
}
