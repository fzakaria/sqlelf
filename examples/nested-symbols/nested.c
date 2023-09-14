#include <stdio.h>

void outer_function() {
  printf("This is the beginning of the outer function.\n");

  asm volatile(
      ".global inner_symbol\n"
      "inner_symbol:\n"
      "nop\n");

  printf("This is the end of the outer function.\n");
}

int main() {
  outer_function();
  return 0;
}
