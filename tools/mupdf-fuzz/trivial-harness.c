// Measures the fuzzer's per-testcase infrastructure cost: no library, just the exported entry point.
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

__attribute__((noinline)) __declspec(dllexport) void vulnerable(const uint8_t* data, size_t size)
{
    volatile uint8_t sum = 0;

    for (size_t i = 0; i < size; ++i)
    {
        sum ^= data[i];
    }

    (void)sum;

    // Known bad input: writing to the unmapped page 0 faults inside the guest.
    if (size >= 4 && data[0] == 'A' && data[3] == 'D')
    {
        __asm__ volatile("int3");
    }
}

int main(void)
{
    uint8_t buffer[1] = {0};
    void (*volatile entry)(const uint8_t*, size_t) = vulnerable;
    entry(buffer, sizeof(buffer));
    return 0;
}
