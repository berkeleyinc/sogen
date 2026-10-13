// pshufb conformance checks: icicle has no helper for the pshufb pcodeop, so the SLEIGH spec supplies it.

#include <emmintrin.h>
#include <stdio.h>
#include <tmmintrin.h>

static const unsigned char src[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const unsigned char reverse[16] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
static const unsigned char high_bits[16] = {0x80, 0x81, 0x8f, 0xff, 0x80, 0x88, 0x8a, 0x8c, 0x90, 0x91, 0x98, 0x9f, 0xa0, 0xb0, 0xc0, 0x80};
static const unsigned char constant_five[16] = {5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};
static const unsigned char out_of_range[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const unsigned char index_high[16] = {0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10};

static void show(const char* name, const unsigned char* mask)
{
    unsigned char out[16];

    const __m128i source = _mm_loadu_si128((const __m128i*)src);
    const __m128i shuffle = _mm_loadu_si128((const __m128i*)mask);
    _mm_storeu_si128((__m128i*)out, _mm_shuffle_epi8(source, shuffle));

    fprintf(stderr, "%s: ", name);
    for (int i = 0; i < 16; ++i)
    {
        fprintf(stderr, "%02x", out[i]);
    }
    fprintf(stderr, "\n");
}

int main(void)
{
    show("reverse", reverse);
    show("high_bits", high_bits);
    show("constant_five", constant_five);
    show("index_high", index_high);
    show("out_of_range", out_of_range);
    return 0;
}
