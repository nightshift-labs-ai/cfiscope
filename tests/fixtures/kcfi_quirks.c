/* Built with: zig cc -target aarch64-linux-gnu -fsanitize=kcfi -O1 -c kcfi_quirks.c -o kcfi_quirks_a64.o
   and zig cc -target bpfel-freestanding-none -g -O2 -c kcfi_quirks.c -o kcfi_quirks_btf.o (zig 0.17.1, clang 22.1.8).
   Cases where BTF and the kCFI mangling disagree on the surface (from the review_s175 ground-truth corpus):
   a const return type is kept (_ZTSFKivE), K&R () mangles with no parameter code (_ZTSFlE), and a K&R
   function pointer (BTF: one unnamed varargs parameter) mangles as PFiE, not PFizE. */
const int q_const_ret_toplevel(void) { return 0; }
volatile long q_volatile_ret(int a) { return a; }
int q_plain_ret(void) { return 0; }
void fp_noproto_cb(int (*legacy)()) { }
void fp_void_cb(int (*cb)(void)) { }
long n_void_params(void) { return 0; }
long n_noproto() { return 0; }
int n_noproto_int() { return 0; }
void *quirk_table[] = {
  (void *)q_const_ret_toplevel, (void *)q_volatile_ret, (void *)q_plain_ret, (void *)fp_noproto_cb,
  (void *)fp_void_cb, (void *)n_void_params, (void *)n_noproto, (void *)n_noproto_int,
};
