/* Built with: zig cc -target aarch64-linux-gnu -fsanitize=kcfi -O1 -c kcfi_arrays.c -o kcfi_arrays_a64.o
   and zig cc -target bpfel-freestanding-none -g -O2 -c kcfi_arrays.c -o kcfi_arrays_btf.o (zig 0.17.1, clang 22.1.8).
   BTF writes 0 elements for both "u32 (*)[]" and the GNU zero-length "u32 (*)[0]", but Clang mangles the first A_ and
   the second A0_ (review s176 F1/M1; the android_vh_typec_* hooks of GKI 6.1 take a "u32 (*)[]"). */
typedef unsigned int u32;
void probe_unknown(void *d, unsigned int *n, u32 (*caps)[]) { (void)d; (void)n; (void)caps; }
void probe_zero(void *d, unsigned int *n, u32 (*caps)[0]) { (void)d; (void)n; (void)caps; }
void probe_sized(void *d, unsigned int *n, u32 (*caps)[7]) { (void)d; (void)n; (void)caps; }
void (*volatile keep1)(void *, unsigned int *, u32 (*)[]) = probe_unknown;
void (*volatile keep2)(void *, unsigned int *, u32 (*)[0]) = probe_zero;
void (*volatile keep3)(void *, unsigned int *, u32 (*)[7]) = probe_sized;
