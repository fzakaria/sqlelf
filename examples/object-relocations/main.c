#include <stdio.h>

#include "sum.h"

int array[4] = {1, 2, 3, 4};

int main() {
  int val = sum(array, 4);
  printf("Sum: %d\n", val);
  return 0;
}