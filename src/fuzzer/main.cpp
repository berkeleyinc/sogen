#include "std_include.hpp"

#include <windows_emulator.hpp>
#include <fuzzer.hpp>

#include <CLI/CLI.hpp>
#include <cstdlib>

#include <utils/finally.hpp>

#include <backend_selection.hpp>

#ifdef _MSC_VER
#pragma warning(disable : 4702)
#endif

namespace sogen
{

    bool use_gdb = false;

    namespace
    {
        // Honors EMULATOR_ICICLE/EMULATOR_KVM like the other tools; unicorn is the default because it covers
        // the largest part of the instruction set.
        std::unique_ptr<x86_64_emulator> create_emulator_backend()
        {
            return create_x86_64_emulator_from_environment();
        }

        void run_emulation(windows_emulator& win_emu, const uint64_t budget)
        {
            bool has_exception = false;
            const auto _ = utils::finally([&] {
                win_emu.callbacks.on_exception = {}; //
            });

            try
            {
                win_emu.callbacks.on_exception = [&] {
                    has_exception = true;
                    win_emu.stop();
                };

                win_emu.log.disable_output(true);
                win_emu.start(static_cast<size_t>(budget));

                if (has_exception)
                {
                    throw std::runtime_error("Exception!");
                }
            }
            catch (...)
            {
                win_emu.log.disable_output(false);
                win_emu.log.error("Emulation failed at: 0x%" PRIx64 "\n", win_emu.emu().read_instruction_pointer());
                throw;
            }

            win_emu.log.disable_output(false);
        }

        uint64_t max_instructions{};

        // Guest stdout is otherwise dropped on the floor, which makes a crashing target hard to diagnose.
        emulator_callbacks make_callbacks()
        {
            emulator_callbacks callbacks{};
            callbacks.on_stdout = [](const std::string_view data) {
                static std::mutex mutex{};
                const std::lock_guard lock{mutex};
                fwrite(data.data(), 1, data.size(), stdout);
                fflush(stdout);
            };
            return callbacks;
        }

        // Returns the address of the `vulnerable` export, or 0 if the target does not have one. Without it
        // the whole process is re-run for every testcase instead of a single exported function.
        uint64_t forward_emulator(windows_emulator& win_emu)
        {
            // The main modules are only mapped once the process is set up, but the fuzz target's export has
            // to be resolved before anything runs.
            win_emu.setup_process_if_necessary();

            // Without the export the whole process is the target, so the run stops at its entry point to
            // give the snapshot a started - but not yet executing - process.
            const auto target = win_emu.mod_manager.executable->find_export("vulnerable");
            const auto stop_at = target ? target : win_emu.mod_manager.executable->entry_point;

            win_emu.emu().hook_memory_execution(stop_at, [&](cpu_interface&, uint64_t) {
                win_emu.emu().stop(); //
            });

            run_emulation(win_emu, max_instructions);
            return target;
        }

        void write_ppm(const std::filesystem::path& path, const uint32_t width, const uint32_t height, const std::vector<uint32_t>& pixels)
        {
            std::ofstream file{path, std::ios::binary | std::ios::trunc};
            file << "P6\n" << width << " " << height << "\n255\n";

            for (const auto pixel : pixels)
            {
                const std::array<char, 3> rgb = {static_cast<char>((pixel >> 16) & 0xFF), static_cast<char>((pixel >> 8) & 0xFF),
                                                 static_cast<char>(pixel & 0xFF)};
                file.write(rgb.data(), rgb.size());
            }
        }

        struct fuzzer_executer : fuzzer::executer
        {
            windows_emulator emu;
            uint64_t entry{};
            std::span<const std::byte> emulator_data{};
            std::unordered_set<uint64_t> visited_blocks{};
            const std::function<fuzzer::coverage_functor>* handler{nullptr};
            uint64_t input_address{};
            uint64_t input_size{};
            windows_path input_path{};
            std::filesystem::path input_host_path{};
            std::filesystem::path dump_windows{};
            uint32_t worker_id_{};

            fuzzer_executer(const emulator_settings& settings, const std::span<const std::byte> data, const uint64_t entry,
                            windows_path input_path, std::filesystem::path dump_windows)
                : emu(create_emulator_backend(), settings, make_callbacks()),
                  entry(entry),
                  emulator_data(data),
                  input_path(std::move(input_path)),
                  dump_windows(std::move(dump_windows))
            {
                emu.emu().hook_basic_block([&](cpu_interface&, const basic_block& block) {
                    if (this->handler && visited_blocks.emplace(block.address).second)
                    {
                        (*this->handler)(block.address);
                    }
                });

                utils::buffer_deserializer deserializer{emulator_data};
                emu.deserialize(deserializer);
                emu.save_snapshot();

                static std::atomic<uint32_t> worker_id{};
                this->worker_id_ = worker_id.fetch_add(1);

                if (!this->input_path.empty())
                {
                    // The testcase goes into a file the target reads. Every worker gets its own host file so
                    // they do not overwrite each other's input while the guest is reading it.
                    const auto directory =
                        std::filesystem::temp_directory_path() / "sogen-fuzz" / std::to_string(static_cast<uint64_t>(::getpid()));
                    std::error_code error{};
                    std::filesystem::create_directories(directory, error);

                    this->input_host_path = directory / ("input-" + std::to_string(this->worker_id_) + ".bin");
                    const std::ofstream create{this->input_host_path, std::ios::binary};

                    emu.file_sys.map(this->input_path, this->input_host_path);
                }

                if (this->entry)
                {
                    // The testcase is handed over through the fuzz target's parameters. They have to be written
                    // from a hook: resuming reloads the active thread's registers, so values set before start()
                    // are overwritten.
                    emu.emu().hook_memory_execution(this->entry, [this](cpu_interface& cpu, uint64_t) {
                        cpu.write_raw_register(static_cast<int>(x86_register::rcx), &this->input_address, sizeof(this->input_address));
                        cpu.write_raw_register(static_cast<int>(x86_register::rdx), &this->input_size, sizeof(this->input_size));
                    });
                }

                const auto return_address = emu.emu().read_stack(0);
                emu.emu().hook_memory_execution(return_address, [&](cpu_interface&, const uint64_t) {
                    emu.emu().stop(); //
                });
            }

            // The guest windows as the emulator renders them: the only way to see what a UI target does
            // while fuzzing.
            void write_windows() const
            {
                std::error_code error{};
                std::filesystem::create_directories(this->dump_windows, error);

                for (const auto& [hwnd, surface] : emu.process.gdi_window_surfaces)
                {
                    if (surface.width == 0 || surface.height == 0 || surface.pixels.empty())
                    {
                        continue;
                    }

                    write_ppm(this->dump_windows / ("window-" + std::to_string(this->worker_id_) + "-" + std::to_string(hwnd) + ".ppm"),
                              surface.width, surface.height, surface.pixels);
                }
            }

            void restore_emulator()
            {
                /*utils::buffer_deserializer deserializer{ emulator_data };
                emu.deserialize(deserializer);*/
                emu.restore_snapshot();
            }

            static inline std::atomic<uint64_t> restore_ns{};
            static inline std::atomic<uint64_t> run_ns{};
            static inline std::atomic<uint64_t> iterations{};

            fuzzer::execution_result execute(const std::span<const uint8_t> data,
                                             const std::function<fuzzer::coverage_functor>& coverage_handler) override
            {
                this->handler = &coverage_handler;
                this->visited_blocks.clear();

                if (!this->input_host_path.empty())
                {
                    // Delivered through a file for targets that read their input instead of taking it in
                    // registers.
                    std::ofstream file{this->input_host_path, std::ios::binary | std::ios::trunc};
                    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
                }

                const auto restore_start = std::chrono::steady_clock::now();
                auto restore_end = restore_start;
                fuzzer::execution_result result = fuzzer::execution_result::success;

                try
                {
                    restore_emulator();
                    restore_end = std::chrono::steady_clock::now();

                    if (this->entry)
                    {
                        // Register delivery for targets that take the input in rcx/rdx. Whole process targets
                        // read the file instead, so they get no extra region that could interfere with the
                        // guest's own allocations.
                        const auto memory =
                            emu.memory.allocate_memory(static_cast<size_t>(page_align_up(std::max(data.size(), static_cast<size_t>(1)))),
                                                       memory_permission::read_write);
                        emu.emu().write_memory(memory, data.data(), data.size());

                        this->input_address = memory;
                        this->input_size = data.size();
                    }

                    run_emulation(emu, max_instructions);
                }
                catch (const std::exception& e)
                {
                    // Worth surfacing: the emulation failure is the reason the iteration is reported as a crash.
                    static std::atomic<uint32_t> reported{};
                    if (reported.fetch_add(1) < 8)
                    {
                        fprintf(stderr, "[fuzzer] emulation failed: %s\n", e.what());
                    }

                    result = fuzzer::execution_result::error;
                }
                catch (...)
                {
                    result = fuzzer::execution_result::error;
                }

                if (!this->dump_windows.empty())
                {
                    this->write_windows();
                }

                {
                    static std::atomic<uint32_t> reported{};
                    if (reported.fetch_add(1) < 3)
                    {
                        fprintf(stderr, "[fuzzer] iteration with %zu blocks, %zu instructions, exit status %x\n",
                                this->visited_blocks.size(), static_cast<size_t>(emu.get_executed_instructions()), emu.process.exit_status);
                    }
                }

                const auto run_end = std::chrono::steady_clock::now();
                restore_ns +=
                    static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(restore_end - restore_start).count());
                run_ns += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(run_end - restore_end).count());

                // Snapshot restore dominates the per-testcase cost, so report the split occasionally.
                if (iterations.fetch_add(1) % 4096 == 0)
                {
                    const auto count = static_cast<double>(iterations.load() + 1);
                    fprintf(stderr, "[fuzzer] %zu testcases, restore %.1fms, run %.1fms each\n", static_cast<size_t>(count),
                            static_cast<double>(restore_ns.load()) / count / 1e6, static_cast<double>(run_ns.load()) / count / 1e6);
                }

                return result;
            }
        };

        struct my_fuzzing_handler : fuzzer::fuzzing_handler
        {
            emulator_settings settings{};
            std::vector<std::byte> emulator_state{};
            uint64_t entry{};
            windows_path input_path{};
            std::filesystem::path dump_windows{};
            std::atomic_bool stop_fuzzing{false};

            my_fuzzing_handler(emulator_settings settings, std::vector<std::byte> emulator_state, const uint64_t entry,
                               windows_path input_path, std::filesystem::path dump_windows)
                : settings(std::move(settings)),
                  emulator_state(std::move(emulator_state)),
                  entry(entry),
                  input_path(std::move(input_path)),
                  dump_windows(std::move(dump_windows))
            {
            }

            std::unique_ptr<fuzzer::executer> make_executer() override
            {
                return std::make_unique<fuzzer_executer>(this->settings, emulator_state, entry, input_path, dump_windows);
            }

            bool stop() override
            {
                return stop_fuzzing;
            }
        };

        void run_fuzzer(const windows_emulator& base_emulator, emulator_settings settings, const uint64_t entry, windows_path input_path,
                        size_t workers, const std::filesystem::path& dump_windows)
        {
            const auto concurrency = workers > 0 ? workers : (std::thread::hardware_concurrency() + 4);

            utils::buffer_serializer serializer{};
            base_emulator.serialize(serializer);

            my_fuzzing_handler handler{std::move(settings), serializer.move_buffer(), entry, std::move(input_path), dump_windows};

            fuzzer::run(handler, concurrency);
        }

        struct cli_options
        {
            std::filesystem::path emulation_root{};
            std::filesystem::path dump_windows{};
            std::string input_file{};
            std::vector<std::string> arguments{};
            std::string application{};
            uint64_t max_instructions{};
            size_t workers{};
            bool use_gdb{false};
        };

        void run(const cli_options& options)
        {
            application_settings application_settings{
                .application = options.application,
            };

            for (const auto& argument : options.arguments)
            {
                fprintf(stderr, "[fuzzer] arg: '%s'\n", argument.c_str());
                application_settings.arguments.emplace_back(argument.begin(), argument.end());
            }

            emulator_settings settings{};
            settings.emulation_root = options.emulation_root;
            max_instructions = options.max_instructions;

            windows_emulator win_emu{create_emulator_backend(), std::move(application_settings), settings, make_callbacks()};

            const auto target = forward_emulator(win_emu);
            run_fuzzer(win_emu, settings, target, windows_path{options.input_file}, options.workers, options.dump_windows);
        }

        int run_main(const int argc, char** argv)
        {
            CLI::App app{"Sogen Fuzzer"};
            argv = app.ensure_utf8(argv);

            cli_options options{};
            app.add_option("-e,--emulation", options.emulation_root, "Set emulation root path");
            app.add_option("-i,--input-file", options.input_file, "Guest path the testcase is written to before every run");
            app.add_option("-a,--arg", options.arguments, "Argument passed to the application, can be repeated");
            app.add_option("-w,--workers", options.workers, "Number of fuzzing workers (default: hardware concurrency + 4)");
            app.add_option("-m,--max-instructions", options.max_instructions,
                           "Stop a testcase after this many instructions (0 = until the target exits)");
            app.add_option("--dump-windows", options.dump_windows, "Write the guest windows as PPM files into this directory");
            app.add_flag("-d,--debug", options.use_gdb, "Enable GDB debugging mode");
            app.add_option("application", options.application, "The application to fuzz")->required();

            CLI11_PARSE(app, argc, argv);

            if (options.emulation_root.empty())
            {
                if (const char* root = std::getenv("EMULATOR_ROOT"); root != nullptr && root[0] != '\0')
                {
                    options.emulation_root = root;
                }
            }

            use_gdb = options.use_gdb;

            // Progress and crash reports come from the pool's worker threads; keep them visible when stdout
            // is redirected to a file.
            setvbuf(stdout, nullptr, _IOLBF, 0);

            // Every worker owns an emulator, and SDL's video subsystem is shared process wide: drive it
            // headless unless the user asked otherwise.
#ifdef OS_WINDOWS
            if (std::getenv("SOGEN_UI_BACKEND") == nullptr)
            {
                _putenv_s("SOGEN_UI_BACKEND", "headless");
            }
#else
            ::setenv("SOGEN_UI_BACKEND", "headless", 0);
#endif

            try
            {
                do
                {
                    run(options);
                } while (use_gdb);

                return 0;
            }
            catch (std::exception& e)
            {
                puts(e.what());

#if defined(_WIN32) && 0
                MessageBoxA(nullptr, e.what(), "ERROR", MB_ICONERROR);
#endif
            }

            return 1;
        }
    }

} // namespace sogen

int main(const int argc, char** argv)
{
    return sogen::run_main(argc, argv);
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, PSTR, int)
{
    return sogen::run_main(__argc, __argv);
}
#endif
