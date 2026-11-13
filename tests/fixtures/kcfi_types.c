/* Built with: zig cc -target aarch64-linux-gnu -fsanitize=kcfi -O1 -c kcfi_types.c -o kcfi_types_a64.o
   and zig cc -target bpfel-freestanding-none -g -O2 -c kcfi_types.c -o kcfi_types_btf.o (zig 0.17.1, clang 22.1.8). */
/* Fixture for cfiscope.kcfi_types: every function below is address-taken, so clang -fsanitize=kcfi
   writes its type hash in front of it, and its BTF (bpf target) records its prototype. */
#include <stdarg.h>
struct sk_buff { int len; };
struct file;
union u { int a; long b; };
enum color { RED, GREEN };
typedef struct { unsigned long val; } pte_t;
typedef enum { A0, A1 } anon_e;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef _Bool bool;
typedef void (*cb_t)(int);
struct ops { int (*open)(struct file *, int); void (*release)(struct file *, struct file *); };

long f_ls(short a, int b) { return a + b; }
int f_skb(struct sk_buff *s, const char *n, void (*cb)(int)) { return s->len + n[0]; }
void f_void(void) { }
int f_two(struct sk_buff *a, struct sk_buff *b) { return a->len + b->len; }
int f_cc(const char *a, const char *b) { return a[0] + b[0]; }
u64 f_u64(u32 a, u64 b, bool c) { return a + b + c; }
unsigned char f_uc(signed char a, char b, unsigned short c) { return a + b + c; }
#ifndef __bpf__
pte_t f_pte(pte_t p, anon_e e) { return p; }
int f_enum(enum color c, union u *x) { return c + x->a; }
int f_va(const char *fmt, ...) { return fmt[0]; }
void *f_vp(const volatile void *p, long long n, unsigned long long m) { return (void *)p; }
int f_arr(int a[4], char *restrict p, const int k) { return a[0] + p[0] + k; }
void f_cbt(cb_t a, cb_t b, struct file **pp) { }
int f_fp2(int (*g)(struct file *, int), struct file *f) { return 0; }
double f_dbl(float a, double b) { return a + b; }
#endif
int ops_open(struct file *f, int x) { return x; }
void ops_release(struct file *a, struct file *b) { }
const struct ops my_ops = { ops_open, ops_release };
#ifdef __bpf__
/* BPF cannot compile these bodies; their prototypes reach BTF as struct members of the same names. */
struct protos { pte_t (*f_pte)(pte_t, anon_e); int (*f_enum)(enum color, union u *); int (*f_va)(const char *, ...);
  void *(*f_vp)(const volatile void *, long long, unsigned long long); int (*f_arr)(int [4], char *restrict, const int);
  void (*f_cbt)(cb_t, cb_t, struct file **); int (*f_fp2)(int (*)(struct file *, int), struct file *);
  double (*f_dbl)(float, double); };
struct protos protos;
int f_enum(enum color c, union u *x) { return c + x->a; }
void *table[] = { f_ls, f_skb, f_void, f_two, f_cc, f_u64, f_uc, f_enum, ops_open, ops_release, (void *)&my_ops };
#else
void *table[] = { f_ls, f_skb, f_void, f_two, f_cc, f_u64, f_uc, f_pte, f_enum, f_va, f_vp, f_arr, f_cbt,
                  f_fp2, f_dbl, ops_open, ops_release, (void *)&my_ops };
#endif
