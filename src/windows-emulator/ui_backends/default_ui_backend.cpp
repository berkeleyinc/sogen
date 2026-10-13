#include "../std_include.hpp"
#include <platform/ui_backend.hpp>

namespace sogen
{
    std::unique_ptr<ui_backend> create_default_ui_backend()
    {
#ifdef OS_EMSCRIPTEN
        return create_web_ui_backend();
#elif defined(SOGEN_HAS_SDL3)
        // SDL's video subsystem does not like being driven by several emulator instances at once (one per
        // fuzzing worker, for example), so allow opting into the headless backend. The emulated desktop is
        // unaffected, only host presentation is.
        if (const char* backend = std::getenv("SOGEN_UI_BACKEND"); backend != nullptr && std::string_view{backend} == "headless")
        {
            return std::make_unique<null_ui_backend>();
        }

        return create_sdl_ui_backend();
#else
        return std::make_unique<null_ui_backend>();
#endif
    }
}
