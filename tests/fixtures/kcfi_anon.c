/* Built with: zig cc -target aarch64-linux-gnu -fsanitize=kcfi -O1 -c kcfi_anon.c -o kcfi_anon_a64.o
   and zig cc -target bpfel-freestanding-none -g -O2 -c kcfi_anon.c -o kcfi_anon_btf.o (zig 0.17.1, clang 22.1.8).
   An anonymous struct or enum takes the name of its first typedef for linkage ("typedef struct {..} a2_t, *a2_p":
   an a2_p parameter is mangled P4a2_t), also when reached through the pointer typedef (review s176 m2). BTF keeps
   a typedef only if something uses it: an anonymous type whose first typedef is unused cannot be named. */
typedef struct { int q; } a2_t, *a2_p;
typedef enum { E2_A, E2_B } e2_t, *e2_p;
int anon_ptr_td(a2_p p) { return p->q; }
int anon_ptr_both(a2_p p, a2_t *q) { return p->q + q->q; }
int anon_enum_ptr(e2_p e) { return *e == E2_B; }
int anon_direct(a2_t *p) { return p->q; }
int anon_enum_direct(e2_t e) { return e == E2_A; }
int (*volatile k1)(a2_p) = anon_ptr_td;
int (*volatile k2)(a2_p, a2_t *) = anon_ptr_both;
int (*volatile k3)(e2_p) = anon_enum_ptr;
int (*volatile k4)(a2_t *) = anon_direct;
int (*volatile k5)(e2_t) = anon_enum_direct;
