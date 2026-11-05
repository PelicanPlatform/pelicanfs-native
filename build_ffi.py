"""CFFI build script for the libpelicanclient bindings.

API (out-of-line) mode: the generated extension ``#include``s the real
``pelican/client.h``, so every declaration below is checked against the
installed header by the C compiler.  A signature that drifts out of sync
with pelican-c is a build failure, not a runtime surprise -- which is
what makes it safe for this binding to live in a separate repository
from the library it wraps.

The library is located with pkg-config.  Set ``PELICAN_C_PREFIX`` to use
an install tree that is not on the pkg-config search path, or
``PELICAN_C_BUILD_DIR`` to link straight against a pelican-c build tree.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys

from cffi import FFI

PKG = "libpelicanclient"


def _pkg_config(*args: str) -> list[str]:
    env = dict(os.environ)
    prefix = os.environ.get("PELICAN_C_PREFIX")
    if prefix:
        pcdir = os.path.join(prefix, "lib", "pkgconfig")
        existing = env.get("PKG_CONFIG_PATH")
        env["PKG_CONFIG_PATH"] = f"{pcdir}:{existing}" if existing else pcdir
    try:
        out = subprocess.run(
            ["pkg-config", *args, PKG],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise SystemExit(
            f"pelicanfs-native requires {PKG} (from pelican-c) at build time.\n"
            f"pkg-config could not find it: {detail.strip()}\n\n"
            "Install pelican-c (`make install PREFIX=...`) and either put its\n"
            "lib/pkgconfig on PKG_CONFIG_PATH or set PELICAN_C_PREFIX to the\n"
            "install prefix.  To build against a pelican-c source tree, set\n"
            "PELICAN_C_BUILD_DIR to the checkout instead."
        ) from exc
    return shlex.split(out)


def _flags() -> dict[str, list[str]]:
    build_dir = os.environ.get("PELICAN_C_BUILD_DIR")
    if build_dir:
        # Link against an uninstalled pelican-c checkout: headers in
        # include/, the shared object in build/.
        libdir = os.path.join(build_dir, "build")
        return {
            "include_dirs": [os.path.join(build_dir, "include")],
            "library_dirs": [libdir],
            "runtime_library_dirs": [] if sys.platform == "darwin" else [libdir],
            # The dylib's install name is @rpath-relative in the build
            # tree, so macOS needs an explicit rpath; runtime_library_dirs
            # is a no-op there.
            "extra_link_args": ["-Wl,-rpath," + libdir] if sys.platform == "darwin" else [],
        }

    include_dirs = [a[2:] for a in _pkg_config("--cflags-only-I") if a.startswith("-I")]
    library_dirs = [a[2:] for a in _pkg_config("--libs-only-L") if a.startswith("-L")]
    return {
        "include_dirs": include_dirs,
        "library_dirs": library_dirs,
        # An installed ELF consumer records only the soname, so a
        # non-default prefix has to be baked in as an rpath or the
        # extension will not load.  macOS resolves the dylib's absolute
        # install name and needs nothing.
        "runtime_library_dirs": [] if sys.platform == "darwin" else library_dirs,
        "extra_link_args": [],
    }


# Declarations mirrored from pelican/client.h.  Only the subset this
# binding calls is declared; the compiler checks each one against the
# real header.
CDEF = """
typedef struct pelican_error pelican_error;
typedef struct pelican_context pelican_context;
typedef struct pelican_transfer_opts pelican_transfer_opts;
typedef struct pelican_result pelican_result;
typedef struct pelican_result_list pelican_result_list;
typedef struct pelican_file_info pelican_file_info;
typedef struct pelican_file_info_list pelican_file_info_list;
typedef struct pelican_file pelican_file;

/* Errors */
const char *pelican_error_message(const pelican_error *err);
int pelican_error_is_retryable(const pelican_error *err);
int pelican_error_code(const pelican_error *err);
void pelican_error_free(pelican_error *err);

/* Library setup */
pelican_error *pelican_config_set(const char *key, const char *value);
pelican_error *pelican_client_init(const char *config_file);
const char *pelican_version(void);

typedef enum {
    PELICAN_LOG_ERROR = 0,
    PELICAN_LOG_WARNING,
    PELICAN_LOG_INFO,
    PELICAN_LOG_DEBUG,
    PELICAN_LOG_TRACE
} pelican_log_level;
pelican_error *pelican_log_set_level(pelican_log_level level);

/* Cancellation contexts */
pelican_context *pelican_context_new(void);
void pelican_context_cancel(pelican_context *ctx);
void pelican_context_free(pelican_context *ctx);

/* Transfer options */
pelican_transfer_opts *pelican_transfer_opts_new(void);
void pelican_transfer_opts_free(pelican_transfer_opts *opts);
void pelican_transfer_opts_set_token(pelican_transfer_opts *opts, const char *token);
void pelican_transfer_opts_set_token_location(pelican_transfer_opts *opts, const char *path);
void pelican_transfer_opts_set_recursive(pelican_transfer_opts *opts, int recursive);
void pelican_transfer_opts_add_cache(pelican_transfer_opts *opts, const char *cache_url);

/* Results */
long long pelican_result_transferred_bytes(const pelican_result *res);
const pelican_error *pelican_result_error(const pelican_result *res);
void pelican_result_free(pelican_result *res);
size_t pelican_result_list_count(const pelican_result_list *list);
const pelican_result *pelican_result_list_get(const pelican_result_list *list, size_t i);
void pelican_result_list_free(pelican_result_list *list);

/* Synchronous transfers */
pelican_error *pelican_get(pelican_context *ctx, const char *remote_url,
                           const char *local_path, const pelican_transfer_opts *opts,
                           pelican_result_list **results);
pelican_error *pelican_put(pelican_context *ctx, const char *local_path,
                           const char *remote_url, const pelican_transfer_opts *opts,
                           pelican_result_list **results);

/* Namespace operations */
const char *pelican_file_info_name(const pelican_file_info *info);
long long pelican_file_info_size(const pelican_file_info *info);
long long pelican_file_info_mtime(const pelican_file_info *info);
int pelican_file_info_is_collection(const pelican_file_info *info);
void pelican_file_info_free(pelican_file_info *info);
size_t pelican_file_info_list_count(const pelican_file_info_list *list);
const pelican_file_info *pelican_file_info_list_get(const pelican_file_info_list *list, size_t i);
void pelican_file_info_list_free(pelican_file_info_list *list);

pelican_error *pelican_stat(pelican_context *ctx, const char *remote_url,
                            const pelican_transfer_opts *opts, pelican_file_info **info);
pelican_error *pelican_list(pelican_context *ctx, const char *remote_url,
                            const pelican_transfer_opts *opts,
                            pelican_file_info_list **entries);
pelican_error *pelican_delete(pelican_context *ctx, const char *remote_url,
                              const pelican_transfer_opts *opts);

/* File I/O */
#define PELICAN_O_RDONLY ...
#define PELICAN_O_WRONLY ...
#define PELICAN_O_RDWR ...
#define PELICAN_O_CREATE ...

pelican_error *pelican_fs_open(const char *remote_url, int flags,
                               const pelican_transfer_opts *opts, pelican_file **file);
long long pelican_file_read(pelican_file *file, void *buf, size_t len, pelican_error **err);
long long pelican_file_pread(pelican_file *file, void *buf, size_t len,
                             long long offset, pelican_error **err);
long long pelican_file_write(pelican_file *file, const void *buf, size_t len,
                             pelican_error **err);
long long pelican_file_seek(pelican_file *file, long long offset, int whence,
                            pelican_error **err);
pelican_error *pelican_file_stat(pelican_file *file, pelican_file_info **info);
pelican_error *pelican_file_close(pelican_file *file);
"""

ffibuilder = FFI()
ffibuilder.cdef(CDEF)
ffibuilder.set_source(
    "pelicanfs_native._pelican_cffi",
    "#include <pelican/client.h>",
    libraries=["pelicanclient"],
    **_flags(),
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
