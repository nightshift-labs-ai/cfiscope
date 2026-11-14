/* Candidates stored in a matching static slot are listed first (internal review s193 #2). Built by
   `python3 tools/gen_fixtures.py --slots-only` (zig cc: aarch64 kCFI code, plus the BTF of this file) into
   kcfi_slots_a64.o.
   - net_ops.xmit (offset 16), file_ops.write (0) and file_ops.read (8) share the type int (struct msg *, int), so every
     call below has the same 6 candidates;
   - call_net loads net_ops.xmit: net_xmit_a (net_a+16), net_xmit_b (net_tbl[0]+16, byte 16 of net_tbl) and net_xmit_c
     (net_tbl[1]+16, byte 40 of net_tbl: 40 modulo sizeof(struct net_ops) = 24 is 16) are stored in such a slot;
   - call_file_write and call_file_read load file_ops.write and file_ops.read: file_write and file_read;
   - runtime_only is stored by code at run time (set_hook), in no static slot: it stays in every list, after the others.
   The file_* functions come first in the code, so before this change they were listed first for call_net too.
   Added in review s197, after the calls (their addresses stay):
   - net_xmit_rw is static and stored in net_rw, which is not const: it lands in .data (a second data section) with a
     `.text + addend` relocation, and is in a net_ops.xmit slot for call_net;
   - wide_cb is at byte 40 of wide_one: 40 modulo sizeof(struct net_ops) = 24 is 16, but it is the only such word in
     that object (not an array of net_ops), so it is not slot-backed for call_net; net_xmit_c is (net_tbl holds a
     candidate at byte 16 too), but only by array stride, listed after those at the member's offset. */

struct msg { int len; };

struct file_ops {
	int (*write)(struct msg *, int);
	int (*read)(struct msg *, int);
	long pad;
};

struct net_ops {
	long flags;
	long more;
	int (*xmit)(struct msg *, int);
};

struct wide {
	long a[5];
	int (*cb)(struct msg *, int);
};

int file_write(struct msg *m, int f) { return m->len + f; }
int file_read(struct msg *m, int f) { return m->len - f; }
int runtime_only(struct msg *m, int f) { return m->len * f; }
int net_xmit_a(struct msg *m, int f) { return m->len ^ f; }
int net_xmit_b(struct msg *m, int f) { return m->len | f; }
int net_xmit_c(struct msg *m, int f) { return m->len & f; }

const struct file_ops file_tbl = { file_write, file_read, 0 };
const struct net_ops net_a = { 1, 2, net_xmit_a };
const struct net_ops net_tbl[2] = { { 3, 4, net_xmit_b }, { 5, 6, net_xmit_c } };
int (*volatile hook)(struct msg *, int);

void set_hook(void) { hook = runtime_only; }
int call_net(const struct net_ops *o, struct msg *m) { return o->xmit(m, 1) + 1; }
int call_file_write(const struct file_ops *o, struct msg *m) { return o->write(m, 2) + 1; }
int call_file_read(const struct file_ops *o, struct msg *m) { return o->read(m, 3) + 1; }

int wide_cb(struct msg *m, int f) { return m->len - 2 * f; }
static int net_xmit_rw(struct msg *m, int f) { return m->len + 3 * f; }
const struct wide wide_one = { { 0, 0, 0, 0, 0 }, wide_cb };
struct net_ops net_rw = { 7, 8, net_xmit_rw };
