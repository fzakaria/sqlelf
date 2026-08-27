/* Source for the committed ELF test fixture (tests/data/hello-x86_64.elf).
 *
 * The fixture only has to be a small, well-formed, dynamically linked ELF
 * binary: it is parsed by the test-suite, never executed. The calls below
 * exist to give the fixture a PLT, relocations and glibc symbol version
 * requirements, which the elf_* tables are asserted against.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *who = argc > 1 ? argv[1] : "world";
  printf("hello, %s (%zu)\n", who, strlen(who));
  return EXIT_SUCCESS;
}
