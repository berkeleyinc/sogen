// Fuzz target for sogen's guest fuzzer (src/fuzzer): the fuzzer snapshots the emulator on entry of the
// exported "vulnerable" function and re-enters it for every testcase with rcx/rdx pointing at the input
// buffer. The PDF bytes therefore arrive as (data, size) and never touch the guest filesystem.

#include <mupdf/fitz.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

// Main must really *call* the exported symbol: the fuzzer snapshots the emulator on entry of it, so an
// inlined copy would leave the snapshot somewhere else entirely.
extern "C" __declspec(dllexport) __attribute__((noinline)) void vulnerable(const uint8_t* data, size_t size);

namespace
{
    fz_context* g_ctx = nullptr;
    int g_last_pages = -1;

    // Returns the page count, or -1 if the input is not a document mupdf can open. mupdf's own warnings are
    // silenced: reaching the end without an abort is what matters to the fuzzer.
    int parse(const uint8_t* data, const size_t size)
    {
        if (size == 0 || !g_ctx)
        {
            return -1;
        }

        fz_context* ctx = g_ctx;
        int pages = -1;

        fz_try(ctx)
        {
            fz_buffer* buffer = fz_new_buffer_from_copied_data(ctx, data, size);
            fz_stream* stream = fz_open_buffer(ctx, buffer);
            fz_document* document = fz_open_document_with_stream(ctx, "application/pdf", stream);

            pages = fz_count_pages(ctx, document);

            for (int i = 0; i < pages && i < 4; ++i)
            {
                fz_page* page = fz_load_page(ctx, document, i);
                fz_device* device = fz_new_list_device(ctx, fz_new_display_list(ctx, fz_infinite_rect));
                fz_run_page(ctx, page, device, fz_identity, nullptr);
                fz_close_device(ctx, device);
                fz_drop_device(ctx, device);
                fz_drop_page(ctx, page);
            }

            fz_drop_document(ctx, document);
            fz_drop_stream(ctx, stream);
            fz_drop_buffer(ctx, buffer);
        }
        fz_catch(ctx)
        {
            return -1;
        }

        fprintf(stderr, "sz=%zu pages=%d\n", size, pages);

        return pages;
    }

    void discard_message(void*, const char*)
    {
    }

    std::vector<uint8_t> read_file(const char* path)
    {
        std::ifstream file(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }
}

extern "C" __declspec(dllexport) __attribute__((noinline)) void vulnerable(const uint8_t* data, const size_t size)
{
    g_last_pages = parse(data, size);
}

int main(int argc, char** argv)
{
    g_ctx = fz_new_context(nullptr, nullptr, FZ_STORE_DEFAULT);

    if (!g_ctx)
    {
        fputs("fz_new_context failed\n", stderr);
        return 2;
    }

    fz_register_document_handlers(g_ctx);
    fz_set_warning_callback(g_ctx, discard_message, nullptr);
    fz_set_error_callback(g_ctx, discard_message, nullptr);

    static constexpr uint8_t empty_pdf[] = "%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n";
    std::vector<uint8_t> data{std::begin(empty_pdf), std::end(empty_pdf)};

    if (argc > 1)
    {
        data = read_file(argv[1]);
    }

    void (*volatile entry)(const uint8_t*, size_t) = vulnerable;
    entry(data.data(), data.size());
    fprintf(stderr, "mupdf-harness: %zu bytes -> %d page(s)\n", data.size(), g_last_pages);

    return g_last_pages >= 0 ? 0 : 1;
}
