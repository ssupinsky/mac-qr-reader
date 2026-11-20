// sandbox-probe — test-only. Tries things the helper sandbox must deny and prints one line
// per check: "<name> ALLOWED" or "<name> denied". Run unsandboxed as a control (everything
// ALLOWED) and under native/qr-decode.sb (everything denied). See test/native/sandbox.test.mjs.
//   sandbox-probe <tcp-port on 127.0.0.1> <file to create> <dir to list> <file to read>
// Build: cc -O2 -o <out> test/native/probes/sandbox-probe.c
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <notify.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <unistd.h>

static void report(const char *what, int ok) { printf("%s %s\n", what, ok ? "ALLOWED" : "denied"); fflush(stdout); }

static int mach_ok(const char *name) {
  mach_port_t p = MACH_PORT_NULL;
  return bootstrap_look_up(bootstrap_port, name, &p) == KERN_SUCCESS;
}

int main(int argc, char **argv) {
  if (argc != 5) { fprintf(stderr, "usage: sandbox-probe <port> <create-file> <list-dir> <read-file>\n"); return 2; }
  int port = atoi(argv[1]);
  {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    report("tcp-connect-loopback", s >= 0 && connect(s, (struct sockaddr *)&a, sizeof a) == 0);
    if (s >= 0) close(s);
  }
  {
    int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
    report("file-create-tmp", fd >= 0);
    if (fd >= 0) { close(fd); unlink(argv[2]); }
  }
  {
    DIR *d = opendir(argv[3]);
    report("list-home", d != NULL);
    if (d) closedir(d);
  }
  {
    int fd = open(argv[4], O_RDONLY);
    report("read-user-file", fd >= 0);
    if (fd >= 0) close(fd);
  }
  {
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un a = {0};
    a.sun_family = AF_UNIX; strncpy(a.sun_path, "/private/var/run/syslog", sizeof a.sun_path - 1);
    report("unix-connect-syslog", s >= 0 && connect(s, (struct sockaddr *)&a, sizeof a) == 0);
    if (s >= 0) close(s);
  }
  report("read-etc-passwd", open("/private/etc/passwd", O_RDONLY) >= 0);
  {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t sz = 0;
    report("sysctl-process-list", sysctl(mib, 4, NULL, &sz, NULL, 0) == 0 && sz > 0);
  }
  report("notify-post", notify_post("local.qr-reader.sandbox-probe") == NOTIFY_STATUS_OK);
  const char *svcs[] = {"com.apple.trustd", "com.apple.trustd.agent", "com.apple.analyticsd",
                        "com.apple.diagnosticd", "com.apple.runningboard", NULL};
  char buf[128];
  for (int i = 0; svcs[i]; i++) { snprintf(buf, sizeof buf, "mach-lookup:%s", svcs[i]); report(buf, mach_ok(svcs[i])); }
  return 0;
}
