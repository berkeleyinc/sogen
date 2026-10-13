#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
__attribute__((noinline)) __declspec(dllexport) void vulnerable(const uint8_t* d, size_t s) { (void)d; (void)s; exit(42); }
int main(void) { uint8_t b[1] = {0}; void (*volatile f)(const uint8_t*, size_t) = vulnerable; f(b, 1); return 0; }
