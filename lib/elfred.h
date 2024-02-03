#define EI_NIDENT    16 // Byte length of the ELF magic
#define EHDR_32_SIZE 52
#define EHDR_64_SIZE 64
#define EHDR_SIZE    64 // Assume 64-bit for now

#define ET_NONE 0x00
#define ET_REL  0x01
#define ET_EXEC 0x02
#define ET_DYN  0x03
#define ET_CORE 0x04

#define PT_NULL         0x00
#define PT_LOAD         0x01
#define PT_DYNAMIC      0x02
#define PT_INTERP       0x03
#define PT_NOTE         0x04
#define PT_SHLIB        0x05
#define PT_PHDR         0x06
#define PT_GNU_EH_FRAME 0x6474e550
#define PT_GNU_STACK    0x6474e551
#define PT_GNU_RELRO    0x6474e552
#define PT_GNU_PROPERTY 0x6474e553

#define SHT_NULL     0x00
#define SHT_PROGBITS 0x01
#define SHT_SYMTAB   0x02
#define SHT_STRTAB   0x03
#define SHT_RELA     0x04
#define SHT_HASH     0x05
#define SHT_DYNAMIC  0x06
#define SHT_NOTE     0x07
#define SHT_NOBITS   0x08
#define SHT_REL      0x09
#define SHT_SHLIB    0x0a
#define SHT_DYNSYM   0x0b

typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned short Elf64_Half;      // 2 bytes
typedef signed short Elf64_SHalf;       // 2 bytes
typedef unsigned long long Elf64_Off;   // 8 bytes
typedef unsigned int Elf64_Word;        // 4 bytes
typedef signed int Elf64_SWord;         // 4 bytes
typedef unsigned long long Elf64_Xword; // 8 bytes
typedef signed long long Elf64_SXword;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes

typedef struct {
  unsigned char e_ident[EI_NIDENT]; // 16 bytes: To capture the ELF magic
  Elf64_Half e_type;      // 2 bytes: Object file type
  Elf64_Half e_machine;   // 2 bytes: Machine type
  Elf64_Word e_version;   // 4 bytes: Object file version
  Elf64_Addr e_entry;     // 8 bytes: Entry point address
  Elf64_Off  e_phoff;     // 8 bytes: Program header offset
  Elf64_Off  e_shoff;     // 8 bytes: Section header offset
  Elf64_Word e_flags;     // 4 bytes: Processor specific flags
  Elf64_Half e_ehsize;    // 2 bytes: Elf header size
  Elf64_Half e_phentsize; // 2 bytes: Size of program header entry
  Elf64_Half e_phnum;     // 2 bytes: Number of program header entries
  Elf64_Half e_shentsize; // 2 bytes: Size of section header entry
  Elf64_Half e_shnum;     // 2 bytes: Number of section header entries
  Elf64_Half e_shstrndx;  // 2 bytes: Section name string table index
} Elf64_Ehdr; // 64 bytes

typedef struct {
  Elf64_Word  p_type;   // 4 bytes: Segment type
  Elf64_Word  p_flags;  // 4 bytes: Segment flags
  Elf64_Off   p_offset; // 8 bytes: Offset of this segment from start of file
  Elf64_Addr  p_vaddr;  // 8 bytes: Address in memory
  Elf64_Addr  p_paddr;  // 8 bytes: For physical addressing systems
  Elf64_Xword p_filesz; // 8 bytes: File image size of this segment
  Elf64_Xword p_memsz;  // 8 bytes: Memory image size of this segment
  Elf64_Xword p_align;  // 8 bytes: Alignment constraint of this segment
} Elf64_Phdr; // 56 bytes

typedef struct {
  Elf64_Word  sh_name;      // 4 bytes: Section name
  Elf64_Word  sh_type;      // 4 bytes: Section type
  Elf64_Xword sh_flags;     // 8 bytes: Section flags
  Elf64_Addr  sh_addr;      // 8 bytes: Address in memory
  Elf64_Off   sh_offset;    // 8 bytes: Section offset in the file
  Elf64_Xword sh_size;      // 8 bytes: Size of section
  Elf64_Word  sh_link;      // 4 bytes: Link to another section
  Elf64_Word  sh_info;      // 4 bytes: Additional info for section
  Elf64_Xword sh_addralign; // 8 bytes: Alignment constraint of section
  Elf64_Xword sh_entsize;   // 8 bytes: Entry size if section holds a table
} Elf64_Shdr; // 64 bytes

typedef struct {
  Elf64_Word sec_name;
  unsigned char* sec_data;
} Elf64_Sec;

typedef struct {
} Elf64_Seg;

typedef struct elf_bin {
  Elf64_Ehdr* hdr;
  Elf64_Phdr* phdr;
  Elf64_Shdr* shdr;
  Elf64_Sec* sec;
  Elf64_Seg* seg;
  unsigned long perms;
  char* perms_chr;
  unsigned long long size;
  unsigned char* bin;
  Elf64_Sec* sections;
} elf_bin_t;

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
int update_section(elf_bin_t* elf, unsigned char* bytes, unsigned long long len, unsigned long long offset);
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
