#include <sys/auxv.h>
#include <errno.h>

char **environ;

extern void exit(int);
extern void __init_stdio(void);

typedef void init_func_t(int, char*[], char*[]);

extern init_func_t *__preinit_array_start[];
extern init_func_t *__preinit_array_end[];
extern init_func_t *__init_array_start[];
extern init_func_t *__init_array_end[];

static void call_array(init_func_t **start, init_func_t **end, int argc, char *argv[], char *envp[]) {
    unsigned long count = end - start;
    while (count-- > 0) {
        init_func_t* function = *start++;
        (*function)(argc, argv, envp);
    }
}

typedef struct auxv_t {
    unsigned long type;
    unsigned long value;
} auxv_t;

static auxv_t *_auxv;

// Inspired from Linux nolibc
void _start_c(long *sp) {
    long argc;
    char **argv;
    char **envp;
    void **auxv;
    /* silence potential warning: conflicting types for 'main' */
    int __real_main(int, char **, char **) __asm__ ("main");

    /*
     * sp  :    argc          <-- argument count, required by main()
     * argv:    argv[0]       <-- argument vector, required by main()
     *          argv[1]
     *          ...
     *          argv[argc-1]
     *          null
     * environ: environ[0]    <-- environment variables, required by main() and getenv()
     *          environ[1]
     *          ...
     *          null
     * auxv:    auxv[0]       <-- auxiliary vector, required by getauxval()
     *          auxv[1]
     *          ...
     *          null
     */

    /* assign argc and argv */
    argc = *sp;
    argv = (void *)(sp + 1);

    /* find environ */
    environ = envp = argv + argc + 1;

    /* find auxv */
    for (auxv = (void *)envp; *auxv++;)
        ;
    _auxv = (void *) auxv;

    /* call preinit and init */
    __init_stdio();
    call_array(__preinit_array_start, __preinit_array_end, argc, argv, envp);
    call_array(__init_array_start, __init_array_end, argc, argv, envp);

    /* go to application */
    exit(__real_main(argc, argv, envp));
}

unsigned long getauxval(unsigned long type) {
    for (auxv_t *v = _auxv; v->type != AT_NULL; ++v) {
        if (v->type == type) {
            return v->value;
        }
    }
    errno = ENOENT;
    return 0;
}

// Assembly source: bionic/libc/arch-common/bionic/crtbegin.c

#define PRE ".text; .global _start; .type _start,%function; _start:"
#define POST "; .size _start, .-_start"

#if defined(__aarch64__)
__asm__(PRE "bti j; mov x29,#0; mov x30,#0; mov x0,sp; b _start_c" POST);
#elif defined(__arm__)
__asm__(PRE "mov fp,#0; mov lr,#0; mov r0,sp; b _start_c" POST);
#elif defined(__i386__)
__asm__(PRE
        "xorl %ebp,%ebp; movl %esp,%eax; andl $~0xf,%esp; subl $12,%esp; pushl %eax;"
        "call _start_c" POST);
#elif defined(__riscv)
__asm__(PRE "li fp,0; li ra,0; mv a0,sp; tail _start_c" POST);
#elif defined(__x86_64__)
__asm__(PRE "xorl %ebp, %ebp; movq %rsp,%rdi; andq $~0xf,%rsp; callq _start_c" POST);
#else
#error unsupported architecture
#endif

#undef PRE
#undef POST
