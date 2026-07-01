#include "secure_cipher/crypto/work_pool.h"

#include "secure_cipher/config.h"
#include "secure_cipher/crypto/decrypt.h"
#include "secure_cipher/crypto/encrypt.h"
#include "secure_cipher/path.h"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <ftw.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

namespace {

std::mutex g_collect_mutex;
std::vector<std::string> g_collected_paths;

int collect_encrypt_path(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void) ftwbuf;

    if (typeflag != FTW_F || !S_ISREG(sb->st_mode)) {
        return 0;
    }

    if (path_ends_with(fpath, ".enc") || path_ends_with(fpath, RECOVERY_FILENAME)) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(g_collect_mutex);
    g_collected_paths.emplace_back(fpath);
    return 0;
}

int collect_decrypt_path(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void) ftwbuf;

    if (typeflag != FTW_F || !S_ISREG(sb->st_mode)) {
        return 0;
    }

    if (!path_ends_with(fpath, ".enc")) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(g_collect_mutex);
    g_collected_paths.emplace_back(fpath);
    return 0;
}

int collect_directory_paths(const char *dir_path, int (*callback)(const char *, const struct stat *, int, struct FTW *)) {
    g_collected_paths.clear();
    g_collected_paths.reserve(256);

    if (nftw(dir_path, callback, 64, FTW_PHYS) != 0) {
        return 0;
    }

    return 1;
}

int run_parallel_jobs(
    const AppContext *ctx,
    const std::vector<std::string> &paths,
    int (*process_file)(const AppContext *, const char *, int)
) {
    if (paths.empty()) {
        return 1;
    }

    const int worker_count = ctx->worker_threads;
    std::atomic<size_t> next_index{0};
    std::atomic<int> failures{0};
    std::atomic<int> successes{0};

    auto worker = [&]() {
        while (true) {
            const size_t index = next_index.fetch_add(1);
            if (index >= paths.size()) {
                break;
            }

            if (process_file(ctx, paths[index].c_str(), 1)) {
                successes.fetch_add(1);
            } else {
                failures.fetch_add(1);
            }
        }
    };

    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(worker_count));

    for (int i = 0; i < worker_count; ++i) {
        workers.emplace_back(worker);
    }

    for (std::thread &thread : workers) {
        thread.join();
    }

    if (ctx->dry_run) {
        printf(
            "[dry-run] processed %zu file(s) with %d worker thread(s)\n",
            paths.size(),
            worker_count
        );
    } else {
        printf(
            "Processed %d of %zu file(s) with %d worker thread(s)\n",
            successes.load(),
            paths.size(),
            worker_count
        );
    }

    if (failures.load() > 0) {
        fprintf(stderr, "%d file(s) failed (see errors above).\n", failures.load());
        return 0;
    }

    return 1;
}

} // namespace

int work_pool_encrypt_directory(const AppContext *ctx, const char *dir_path) {
    if (!collect_directory_paths(dir_path, collect_encrypt_path)) {
        fprintf(stderr, "Directory walk failed for '%s'.\n", dir_path);
        return 0;
    }

    if (g_collected_paths.empty()) {
        printf("No files to encrypt under '%s'.\n", dir_path);
        return 1;
    }

    if (!run_parallel_jobs(ctx, g_collected_paths, encrypt_file)) {
        return 0;
    }

    if (!ctx->dry_run) {
        printf("Directory processed: %s\n", dir_path);
    }

    return 1;
}

int work_pool_decrypt_directory(const AppContext *ctx, const char *dir_path) {
    if (!collect_directory_paths(dir_path, collect_decrypt_path)) {
        fprintf(stderr, "Directory walk failed for '%s'.\n", dir_path);
        return 0;
    }

    if (g_collected_paths.empty()) {
        printf("No encrypted files found under '%s'.\n", dir_path);
        return 1;
    }

    if (!run_parallel_jobs(ctx, g_collected_paths, decrypt_file)) {
        return 0;
    }

    if (!ctx->dry_run) {
        printf("Directory decrypted: %s\n", dir_path);
    }

    return 1;
}
