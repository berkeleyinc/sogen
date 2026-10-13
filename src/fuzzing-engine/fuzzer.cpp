#include "fuzzer.hpp"
#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>

#include "input_generator.hpp"

#include <utils/timer.hpp>
#include <utils/string.hpp>
#include <utils/finally.hpp>

namespace sogen::fuzzer
{
    namespace
    {
        class fuzzing_context
        {
          public:
            fuzzing_context(input_generator& generator, fuzzing_handler& handler)
                : generator(generator),
                  handler(handler)
            {
            }

            void stop()
            {
                this->stop_ = true;
            }

            bool should_stop()
            {
                if (this->stop_)
                {
                    return true;
                }

                if (!handler.stop())
                {
                    return false;
                }

                this->stop_ = true;
                return true;
            }

            input_generator& generator;
            fuzzing_handler& handler;
            std::atomic_uint64_t executions{0};

          private:
            std::atomic_bool stop_{false};
        };

        std::string format_binary_data(const std::span<const uint8_t> input)
        {
            std::string data;
            std::string bytes;
            std::string text;

            const auto wrap_line = [&] {
                if (bytes.empty())
                {
                    return;
                }

                while (bytes.size() < 16 * 3)
                {
                    bytes.push_back(' ');
                }

                data += bytes;
                data += "| ";
                data += text;
                data += "\n";

                bytes.clear();
                text.clear();
            };

            for (size_t i = 0; i < input.size(); ++i)
            {
                if (i % 16 == 0)
                {
                    wrap_line();
                }

                const auto in = input[i];
                bytes += sogen::utils::string::va("%02X ", static_cast<uint32_t>(in));
                text.push_back(isprint(in) ? static_cast<char>(in) : '.');
            }

            wrap_line();

            return data;
        }

        uint64_t hash_input(const std::span<const uint8_t> input)
        {
            uint64_t hash = 0xcbf29ce484222325ULL;

            for (const auto byte : input)
            {
                hash = (hash ^ byte) * 0x100000001b3ULL;
            }

            return hash;
        }

        // Named by content so repeated hits of the same input collapse into one file.
        std::filesystem::path save_crash(const std::span<const uint8_t> input)
        {
            const auto path = std::filesystem::path{"crashes"} /
                              sogen::utils::string::va("crash-%016" PRIx64 "-%zu.bin", hash_input(input), input.size());

            std::error_code error{};
            std::filesystem::create_directories(path.parent_path(), error);

            if (!std::filesystem::exists(path, error))
            {
                std::ofstream file{path, std::ios::binary};
                file.write(reinterpret_cast<const char*>(input.data()), static_cast<std::streamsize>(input.size()));
            }

            return path;
        }

        // A target that faults on (nearly) every input would otherwise flood the log; the reproducer file is
        // written either way, only the hexdump is limited to inputs that were not reported yet.
        bool report_crash(const uint64_t hash)
        {
            static std::mutex mutex{};
            static std::set<uint64_t> reported{};

            const std::lock_guard lock{mutex};
            return reported.insert(hash).second;
        }

        void print_crash(const std::span<const uint8_t> input)
        {
            const auto path = save_crash(input);

            if (!report_crash(hash_input(input)))
            {
                return;
            }

            // Multi-hundred-kB inputs would otherwise flood the log with a full hexdump; the file has it all.
            constexpr size_t max_dump = 256;
            const auto dump = input.subspan(0, std::min(input.size(), max_dump));

            std::string text = sogen::utils::string::va("\nFound crash for input (length %zu, saved to %s%s):\n", input.size(),
                                                        path.string().c_str(), input.size() > max_dump ? ", dump truncated" : "");
            text += format_binary_data(dump);

            printf("%.*s\n", static_cast<int>(text.size()), text.c_str());
        }

        void perform_fuzzing_iteration(fuzzing_context& context, executer& executer)
        {
            ++context.executions;
            context.generator.access_input([&](const std::span<const uint8_t> input) {
                uint64_t score{0};
                const auto result = executer.execute(input, [&](uint64_t) {
                    ++score; //
                });

                if (result == execution_result::error)
                {
                    print_crash(input);
                }

                return score;
            });
        }

        void worker(fuzzing_context& context)
        {
            const auto executer = context.handler.make_executer();

            while (!context.should_stop())
            {
                perform_fuzzing_iteration(context, *executer);
            }
        }

        struct worker_pool
        {
            fuzzing_context* context_{nullptr};
            std::vector<std::thread> workers_{};

            worker_pool(fuzzing_context& context, const size_t concurrency)
                : context_(&context)
            {
                this->workers_.reserve(concurrency);

                for (size_t i = 0; i < concurrency; ++i)
                {
                    this->workers_.emplace_back([&context] {
                        worker(context); //
                    });
                }
            }

            ~worker_pool()
            {
                if (this->workers_.empty())
                {
                    return;
                }

                this->context_->stop();

                for (auto& w : this->workers_)
                {
                    w.join();
                }
            }
        };
    }

    void run(fuzzing_handler& handler, const size_t concurrency)
    {
        const sogen::utils::timer<> t{};
        input_generator generator{};
        fuzzing_context context{generator, handler};
        worker_pool pool{context, concurrency};

        while (!context.should_stop())
        {
            std::this_thread::sleep_for(std::chrono::seconds{1});

            const auto executions = context.executions.exchange(0);
            const auto highest_scorer = context.generator.get_highest_scorer();
            const auto avg_score = context.generator.get_average_score();
            printf("Executions/s: %" PRIu64 " - Score: %" PRIx64 " - Avg: %.3f\n", executions, highest_scorer.score, avg_score);
            fflush(stdout);
        }

        const auto duration = t.elapsed();
        const int64_t seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        printf("Fuzzing stopped after %" PRIi64 "s\n", seconds);
    }
} // namespace sogen::fuzzer
