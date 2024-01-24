#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "utils.h"

static int
parse_arg(char* arg, long* args)
{


  if (NULL == arg || NULL == args) {
    log_err("A required argument was NULL");
    return FUNC_FAIL;
  }

  int offset = 0;
  if (arg[offset++] == 0x2d) { // Check for a tac ('-')
    int arg_len = strlen(arg); // In case they pass multiple args in one
    for (offset; offset < arg_len; offset++) {
      if (arg[offset] == 0x0a || arg[offset] == 0x20) { // newline or space
        break;
      }

      switch(arg[offset]) {
        case 'p':
          *args |= PARSE_ARG;
          break;
        case 'h':
          *args |= HELP_ARG;
          break;
        case 'd':
          *args |= DATA_ARG;
          break;
        default:
          break;
      }
    }
  }

  return FUNC_PASS;
}

int
read_args(char** argv, long* arg_set)
{

  int offset = 1; // Skip arg 0, which is just the program name
  while (NULL != argv[offset]) {
    parse_arg(argv[offset], arg_set);
    offset++;
  }

  return FUNC_PASS;
}

/*
 * Simple colorful logging functions
 */
void
log_msg(char *log)
{
  fprintf(stdout, "\033[0;34m[+] %s\n\033[0m", log);
}

void
log_err(char *log)
{
  fprintf(stderr, "\033[0;31m[+] %s\n\033[0m", log);
  exit(FUNC_FAIL); 
}

void
exit_on_error(int err_no, char *err)
{
  fprintf(stderr, "\033[0;31m[-] %s -- errno: %d\n", err, err_no);
  exit(FUNC_FAIL); 
}

void
help(char* program)
{
  fprintf(stdout, "Usage: %s [ OPTIONS ] [ TARGET ]\n\n", program);
  fprintf(stdout, "TARGET must be a valid ELF executable file\n\n");
  fprintf(stdout, "OPTIONS:\n");
  fprintf(stdout, "    -h    Print this help menu\n");
  fprintf(stdout, "    -d    Run parsers on the data section of the ELF\n");
  fprintf(stdout, "    -p    Fully parse the ELF and print results\n");
  fprintf(stdout, "    -v    Log verbosely\n");

  exit(FUNC_PASS);
}

void
usage(char* program)
{
  fprintf(stderr, "Usage: %s [ OPTIONS ] [ TARGET ]\n\n", program);
  fprintf(stderr, "Use %s -h to see the help menu\n", program);
  exit(FUNC_FAIL);
}
