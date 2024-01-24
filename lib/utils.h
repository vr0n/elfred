#define PARSE_ARG    0x01
#define HELP_ARG     0x02
#define DATA_ARG     0x04
#define VERBOSE_ARG  0x08

#define FUNC_FAIL -1
#define FUNC_PASS 0

#define FUNC_TRUE  1
#define FUNC_FALSE 0

#define MAX_PATH 4096

int read_args(char**, long*);
void log_msg(char*);
void log_err(char*);
void exit_on_error(int, char*);
void help (char*);
void usage (char*);
