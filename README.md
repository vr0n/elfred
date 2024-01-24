# Ælfred

An elf parsing/editing library.

This simply wraps a bunch of elf-oriented tasks I do frequently into library functions.

# Examples

Some examples:

An example of parsing everything into an elf_bin_t struct:
```
// Task: You need to parse the Elf header, program headers,
// section headers, and sections for reading/writing

struct stat stats;
char* target_elf = "./target_elf";
stat(target_elf, &stats);

FILE* fp = fopen(target_elf, "r+b");
unsigned char *elf = malloc(stats.st_size);
fread(elf, stats.st_size, 1, fp);
fclose(fp);

// Everything above this comment is the minimum required to grab an
// elf from disk. This is just an example, as there are many ways
// to do this. These tasks will not be repeated in further examples

elf_bin_t* parsed_elf = malloc(sizeof(elf_bin_t));
parse_elf(elf, parsed_elf);

// parsed_elf is now an elf_bin_t struct, which can be used to parse
// the entire contents of the read in elf in a reasonable fashion
```

An example of reading and referencing a particular program header:
```
// Task: You need to read and reference the contents of program
// headers

elf_bin_t* parsed_elf = malloc(sizeof(elf_bin_t));
parse_elf(elf, parsed_elf);

print_program_headers(parsed_elf);

Elf64_Phdr* p = parsed_elf->phdr + (sizeof(Elf64_Phdr) * 10);
printf("Value of the 'p_vaddr' field in the 11th program header: %016llx\n", p->p_vaddr);
```

An example of editing an elf's program headers (If you plan on editing and elf,
you must keep the original unsigned char* raw elf around, since that is the object
that is actually being edited):
```
// Task: You need to alter the value 'p_flags' field in the 3rd program header

elf_bin_t* parsed_elf = malloc(sizeof(elf_bin_t));
parse_elf(elf, parsed_elf);

Elf64_Word new_val = 0xffffff;
set_phdr_flags(elf, parsed_elf, 3, new_val);

// The 'set' functions take the parsed elf and the original stream of bytes representing
// the raw elf. It edits the original stream, which can them be written to disk, using
// the following command. This creates a new file named 'elf.out' to avoid overwriting
// the original elf that was parsed, in case you still need it
dump_elf(elf);
```