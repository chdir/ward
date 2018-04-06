
#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <err.h>
#include <dirent.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>

#include <seccomp.h>

#include "linux_syscall_support.h"

#define VERSION "1"

#define O_TMPFILE_MASK (__O_TMPFILE | O_DIRECTORY | O_CREAT)

#define PRINT(fmt, ...) do {\
  char* tempStr; \
  if (asprintf(&tempStr, fmt, ##__VA_ARGS__) != -1) { \
  write(STDERR_FILENO, tempStr, __builtin_strlen(tempStr) + 1); \
  free(tempStr); } \
} while(0)

#define DEBUGX(fmt, ...) PRINT(fmt "\n", ##__VA_ARGS__)

#define DEBUG(str) (syscall(__NR_write, STDERR_FILENO, str "\n", __builtin_strlen(str) + 1))

__attribute__((format(printf, 2, 3))) static void check_posix(intmax_t rc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (rc == -1) verr(EXIT_FAILURE, fmt, args);
    va_end(args);
}

static int get_syscall_nr(const char *name) {
  int result = seccomp_syscall_resolve_name(name);
  if (result == __NR_SCMP_ERROR) {
    errx(EXIT_FAILURE, "non-existent syscall: %s", name);
  }

  return result;
}

// Close all extra file descriptors. Only `stdin`, `stdout` and `stderr` are left open.
static void close_inherited_files() {
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) err(EXIT_FAILURE, "opendir");

  struct dirent *dp;
  while ((dp = readdir(dir))) {
    char *end;
    int fd = (int)strtol(dp->d_name, &end, 10);
    if (*end == '\0' && fd > 2 && fd != dirfd(dir)) {
      check_posix(ioctl(fd, FIOCLEX), "ioctl");
    }
  }

  closedir(dir);
}

static void check(int rc) {
    if (rc < 0) errx(EXIT_FAILURE, "%s", strerror(-rc));
}

static void sighandler(int signum, siginfo_t *info, void *ptr)
{
    DEBUGX("Received signal %d, syscall: %d", signum, info->si_syscall);
}

static void load_seccomp(uint32_t def_action) {
  scmp_filter_ctx ctx = seccomp_init(def_action);
  if (!ctx) errx(EXIT_FAILURE, "seccomp_init");

  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_write, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_read, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_preadv, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_pwritev, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_pread64, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_pwrite64, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_lseek, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR__llseek, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_brk, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_mmap, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_munmap, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_getrusage, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_getpid, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_fstat, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_fcntl, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_lseek, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_rt_sigreturn, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_exit, 0));

  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_dup, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_close, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_umask, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_getcwd, 0));

  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_mprotect, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_madvise, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_clone, 0));

  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_futex, 0));
  check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_get_robust_list, 0));

  check(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), __NR_open, 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_TMPFILE_MASK, 0)));
  check(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), __NR_openat, 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_TMPFILE_MASK, 0)));

  check(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EOPNOTSUPP), __NR_ioctl, 0));

  check(seccomp_load(ctx));
}

static void debug_setup() {
  DEBUGX("Loading debug security filter");

  load_seccomp(SCMP_ACT_TRACE(ENOENT));
}

static void release_setup() {
  DEBUGX("Loading release security filter");

  load_seccomp(SCMP_ACT_ERRNO(ENOENT));
}

__attribute__((constructor))
static void hookStart() {
  DEBUGX("Here we come");

  close_inherited_files();

  // arrange for signal to kill us after specified time
  alarm(10);

  // set limits (the program won't be able to override them
  // thanks to filter, preventing further serlimit calls
  struct rlimit limit = {};

  // at most 5 seconds of CPU time
  limit.rlim_cur = 5,
  limit.rlim_max = 5,
  setrlimit(RLIMIT_CPU, &limit);

  // no core dumps
  limit.rlim_cur = 0,
  limit.rlim_max = 0,
  setrlimit(RLIMIT_CORE, &limit);

  // up to 50M of memory per process
  limit.rlim_cur = 50 * 1024 * 1024,
  limit.rlim_max = 50 * 1024 * 1024,
  setrlimit(RLIMIT_DATA, &limit);

  // up to 40M of stack per process
  limit.rlim_cur = 40 * 1024 * 1024,
  limit.rlim_max = 40 * 1024 * 1024,
  setrlimit(RLIMIT_STACK, &limit);

  // up to 200M of disk space
  limit.rlim_cur = 200 * 1024 * 1024,
  limit.rlim_max = 200 * 1024 * 1024,
  setrlimit(RLIMIT_FSIZE, &limit);

  char* debugFilter = secure_getenv("SYSCALL_DEBUG");
  if (debugFilter != NULL && !strcmp(debugFilter, "1")) {
    debug_setup();
  } else {
    release_setup();
  }
}

int main(int argc, char** argv) {
  DEBUG("I was started");

  close(0);

  sys__exit(0);
}

/*

_Noreturn static void usage(FILE *out) {
    fprintf(out, "usage: %s [options] [command ...]\n", program_invocation_short_name);
    fputs("Options:\n"
          " -h, --help                  display this help\n"
          " -v, --version               display version\n",
          out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char** argv) {
  close_inherited_files();

  static const struct option opts[] = {
    { "help",          no_argument,       NULL, 'h' },
    { "version",       no_argument,       NULL, 'v' },
    { NULL, 0, NULL, 0 }
  };

  for (;;) {
    int opt = getopt_long(argc, argv, "hv", opts, NULL);
    if (opt == -1)
            break;

    switch (opt) {
      case 'h':
        usage(stdout);
      case 'v':
        printf("%s %s\n", program_invocation_short_name, VERSION);
        return 0;
      default:
        usage(stderr);
    }
  }

  if (argc - optind < 2) {
    usage(stderr);
  }

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  if (!ctx) errx(EXIT_FAILURE, "seccomp_init");

  FILE *whitelist = NULL;

  check_posix(execvp(argv[optind], argv + optind), "execvp");

  exit(0);
}
*/
