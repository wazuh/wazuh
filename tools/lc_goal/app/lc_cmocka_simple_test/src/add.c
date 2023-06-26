#include <stdio.h>
#include <add.h>

int added(int a, int b) {
  int ad = add(a,b);
  printf("Added: %d, mocked %d", a+b, ad);
  return a+b;
}
 
__attribute__((weak))
int add(int a, int b) {
  return a+b;
}

