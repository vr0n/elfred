# Ælfred

An elf parsing/editing library.

This simply wraps a bunch of elf-oriented tasks I do frequently into library functions.

# Examples

Some examples:

An example of parsing everything into an elf_bin_t struct:
```
// Task: You need to parse the Elf header, program headers,
// section headers, and sections for reading/writing

elf_bin_t* parsed_elf = open_elf("./path/to/file");;
```

An example of reading and referencing a particular program header:
```
// Task: You need to read and reference the contents of program
// headers

elf_bin_t* parsed_elf = open_elf("./path/to/file");

print_program_headers(parsed_elf);

Elf64_Phdr* p = &(parsed_elf->phdr[3]);
printf("Value of the 'p_vaddr' field in the 4th program header: %016llx\n", p->p_vaddr);
```

Note that all of the 'parse' functions should not be used independently.

An example of editing an elf's program headers.
```
// Task: You need to alter the value the 'p_flags' field in the 3rd program header

elf_bin_t* parsed_elf = open_elf("./path/to/file");

Elf64_Word new_val = 0xffffff;
set_phdr_flags(parsed_elf, 3, new_val);

// The 'set' functions write to the original byte-stream of the target elf. 
// To actually make the changes, use the following function.
// Note that the newly written binary will always be named 'elf.out'
dump_elf(elf);
```

# Available Methods

```
/*
 * Utilities
 */
int get_ehdr_type(int, char*); int get_phdr_type(int, char*);
int get_phdr_perms(int, char*);
int dump_elf(elf_bin_t* elf);
elf_bin_t* open_elf(const char* target_elf);
/*
 * Parsers
 */
int parse_section_headers(elf_bin_t* elf);
int parse_program_headers(elf_bin_t* elf);
int parse_header(elf_bin_t*);
int parse_sections(elf_bin_t*);
int parse_elf(elf_bin_t* elf);
/*
 * Setters
 */
//hdr
int set_hdr_type(elf_bin_t* elf, Elf64_Half new_val);
int set_hdr_machine(elf_bin_t* elf, Elf64_Half new_val);
int set_hdr_version(elf_bin_t* elf, Elf64_Word new_val);
int set_hdr_entry(elf_bin_t* elf, Elf64_Addr new_val);
int set_hdr_phoff(elf_bin_t* elf, Elf64_Off new_val);
int set_hdr_shoff(elf_bin_t* elf, Elf64_Off new_val);
int set_hdr_flags(elf_bin_t* elf, Elf64_Word new_val);
int set_hdr_ehsize(elf_bin_t* elf, Elf64_Half new_val);
int set_hdr_phentsize(elf_bin_t* elf, Elf64_Half new_val);
int set_hdr_phnum(elf_bin_t* elf, Elf64_Half new_val);
int set_hdr_shentsize(elf_bin_t* elf, Elf64_Half new_val);
int set_hdr_shnum(elf_bin_t* elf, Elf64_Half new_val);
int set_hdr_shstrndx(elf_bin_t* elf, Elf64_Half new_val);
// phdrs
int set_phdr_type(elf_bin_t* elf, unsigned int phdr, Elf64_Word new_val);
int set_phdr_flags(elf_bin_t* elf, unsigned int phdr, Elf64_Word new_val);
int set_phdr_offset(elf_bin_t* elf, unsigned int phdr, Elf64_Off new_val);
int set_phdr_vaddr(elf_bin_t* elf, unsigned int phdr, Elf64_Addr new_val);
int set_phdr_paddr(elf_bin_t* elf, unsigned int phdr, Elf64_Addr new_val);
int set_phdr_filesz(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val);
int set_phdr_memsz(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val);
int set_phdr_align(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val);
//shdrs
int set_shdr_name(elf_bin_t* elf, unsigned int shdr, Elf64_Word new_val);
int set_shdr_type(elf_bin_t* elf, unsigned int shdr, Elf64_Word new_val);
int set_shdr_flags(elf_bin_t* elf, unsigned int shdr, Elf64_Xword new_val);
int set_shdr_addr(elf_bin_t* elf, unsigned int shdr, Elf64_Addr new_val);
int set_shdr_offset(elf_bin_t* elf, unsigned int shdr, Elf64_Off new_val);
int set_shdr_size(elf_bin_t* elf, unsigned int shdr, Elf64_Xword new_val);
int set_shdr_link(elf_bin_t* elf, unsigned int shdr, Elf64_Word new_val);
int set_shdr_info(elf_bin_t* elf, unsigned int shdr, Elf64_Word new_val);
int set_shdr_addralign(elf_bin_t* elf, unsigned int shdr, Elf64_Xword new_val);
int set_shdr_entsize(elf_bin_t* elf, unsigned int shdr, Elf64_Xword new_val);
/*
 * Printers
 */
void print_elf_header(elf_bin_t*);
void print_program_headers(elf_bin_t*);
void print_section_headers(elf_bin_t*);
```
