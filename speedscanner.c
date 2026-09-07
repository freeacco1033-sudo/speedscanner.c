#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MIN_SPEED 1.0f
#define MAX_SPEED 20.0f

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return 1;
    }
    waitpid(pid, NULL, 0);

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        perror("fopen maps");
        return 1;
    }

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[8];
        char path[256] = {0};

        if (sscanf(line, "%lx-%lx %s %*x %*s %*d %255s", &start, &end, perms, path) < 3) {
            continue;
        }

        if (strstr(path, "libil2cpp.so") == NULL) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;

        for (unsigned long addr = start; addr < end; addr += 4) {
            long word = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
            if (word == -1) continue;

            float value;
            memcpy(&value, &word, sizeof(value));

            if (value >= MIN_SPEED && value <= MAX_SPEED) {
                printf("0x%lx = %.2f\n", addr, value);
            }
        }
    }

    fclose(maps);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
