#include <iostream>

typedef struct Input {
  int x;
  int y;
} Input;

int product(Input input) {
  int result = input.x * input.y;
  return result;
}

int main() {
  int a = 5;
  int b = 3;
  int result = product({a, b});
  std::cout << "The product is: " << result << std::endl;
  return 0;
}