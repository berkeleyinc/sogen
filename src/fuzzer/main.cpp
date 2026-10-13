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

        void run_emulation(windows_emulator& win_emu)
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
                win_emu.start();

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

        void forward_emulator(windows_emulator& win_emu)
        {
            // The main modules are only mapped once the process is set up, but the fuzz target's export has
            // to be resolved before anything runs.
            win_emu.setup_process_if_necessary();

            const auto target = win_emu.mod_manager.executable->find_export("vulnerable");
            win_emu.emu().hook_memory_execution(target, [&](cpu_interface&, uint64_t) {
                win_emu.emu().stop(); //
            });

            run_emulation(win_emu);
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

            fuzzer_executer(const emulator_settings& settings, const std::span<const std::byte> data, const uint64_t entry)
                : emu(create_emulator_backend(), settings, make_callbacks()),
                  entry(entry),
                  emulator_data(data)
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

                // The testcase is handed over through the fuzz target's parameters. They have to be written
                // from a hook: resuming reloads the active thread's registers, so values set before start()
                // are overwritten.
                emu.emu().hook_memory_execution(this->entry, [this](cpu_interface& cpu, uint64_t) {
                    cpu.write_raw_register(static_cast<int>(x86_register::rcx), &this->input_address, sizeof(this->input_address));
                    cpu.write_raw_register(static_cast<int>(x86_register::rdx), &this->input_size, sizeof(this->input_size));
                });

                const auto return_address = emu.emu().read_stack(0);
                emu.emu().hook_memory_execution(return_address, [&](cpu_interface&, const uint64_t) {
                    emu.emu().stop(); //
                });
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

                const auto restore_start = std::chrono::steady_clock::now();
                restore_emulator();
                const auto restore_end = std::chrono::steady_clock::now();

                const auto memory = emu.memory.allocate_memory(
                    static_cast<size_t>(page_align_up(std::max(data.size(), static_cast<size_t>(1)))), memory_permission::read_write);
                emu.emu().write_memory(memory, data.data(), data.size());

                this->input_address = memory;
                this->input_size = data.size();

                fuzzer::execution_result result = fuzzer::execution_result::success;

                try
                {
                    run_emulation(emu);
                }
                catch (...)
                {
                    result = fuzzer::execution_result::error;
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
            std::atomic_bool stop_fuzzing{false};

            my_fuzzing_handler(emulator_settings settings, std::vector<std::byte> emulator_state, const uint64_t entry)
                : settings(std::move(settings)),
                  emulator_state(std::move(emulator_state)),
                  entry(entry)
            {
            }

            std::unique_ptr<fuzzer::executer> make_executer() override
            {
                return std::make_unique<fuzzer_executer>(this->settings, emulator_state, entry);
            }

            bool stop() override
            {
                return stop_fuzzing;
            }
        };

        void run_fuzzer(const windows_emulator& base_emulator, emulator_settings settings, const uint64_t entry)
        {
            const auto concurrency = std::thread::hardware_concurrency() + 4;

            utils::buffer_serializer serializer{};
            base_emulator.serialize(serializer);

            my_fuzzing_handler handler{std::move(settings), serializer.move_buffer(), entry};

            fuzzer::run(handler, concurrency);
        }

        struct cli_options
        {
            std::filesystem::path emulation_root{};
            std::string application{};
            bool use_gdb{false};
        };

        void run(const cli_options& options)
        {
            application_settings application_settings{
                .application = options.application,
            };

            emulator_settings settings{};
            settings.emulation_root = options.emulation_root;

            windows_emulator win_emu{create_emulator_backend(), std::move(application_settings), settings, make_callbacks()};

            forward_emulator(win_emu);
            run_fuzzer(win_emu, settings, win_emu.mod_manager.executable->find_export("vulnerable"));
        }

        int run_main(const int argc, char** argv)
        {
            CLI::App app{"Sogen Fuzzer"};
            argv = app.ensure_utf8(argv);

            cli_options options{};
            app.add_option("-e,--emulation", options.emulation_root, "Set emulation root path");
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
