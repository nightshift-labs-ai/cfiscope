/* The struct member each kCFI call loads its pointer from (review s193 judge #1). Built with (zig 0.17.1, clang 22.1.8):
     zig cc -target aarch64-linux-gnu -fsanitize=kcfi -O1 -c kcfi_members.c -o /tmp/kcfi_members_code.o
     zig cc -target bpfel-freestanding-none -g -O2 -c kcfi_members.c -o /tmp/kcfi_members_btf.o
     python3 tools/add_btf_section.py /tmp/kcfi_members_btf.o /tmp/kcfi_members_code.o kcfi_members_a64.o
   so kcfi_members_a64.o is aarch64 kCFI code carrying the BTF of this file. The tests read the true offsets back from
   the off_* constants (offsetof) in that object, not from a copy of these numbers.
   - a_ops.send and b_ops.send/recv share the type int (struct msg *, int) at offsets 16, 0 and 24: each call through
     one of them names its own member;
   - c_ops.poll and d_ops.poll share long (struct msg *, long) at the same offset 8: a call through either is
     "one of 2 members", never a guess;
   - inner_ops is embedded by value in struct outer (notify at 16 in outer) and an anonymous union holds u_cb (at 8 in
     anon_holder): named inner_ops.notify and anon_holder.u_cb;
   - call_param calls a parameter and call_global a global pointer (adrp base): no load of a member, no member. */

struct msg { int len; };

struct a_ops {
	long flags;
	int (*open)(struct msg *);
	int (*send)(struct msg *, int);
	void (*close)(struct msg *);
};

struct b_ops {
	int (*send)(struct msg *, int);
	long pad[2];
	int (*recv)(struct msg *, int);
};

struct c_ops { long a; long (*poll)(struct msg *, long); };
struct d_ops { long b; long (*poll)(struct msg *, long); };

struct inner_ops { void (*notify)(struct msg *, unsigned); };
struct outer { long x; long y; struct inner_ops in; };

struct anon_holder {
	long tag;
	union { void (*u_cb)(struct msg *, short); long raw; };
};

int msg_open(struct msg *m) { return m->len; }
int send_x(struct msg *m, int f) { return m->len + f; }
int send_y(struct msg *m, int f) { return m->len - f; }
void msg_close(struct msg *m) { m->len = 0; }
long poll_x(struct msg *m, long t) { return m->len * t; }
long poll_y(struct msg *m, long t) { return m->len + t; }
void notify_x(struct msg *m, unsigned v) { m->len = v; }
void u_cb_x(struct msg *m, short v) { m->len = v; }

const struct a_ops a_tbl = { 1, msg_open, send_x, msg_close };
const struct b_ops b_tbl = { send_y, { 0, 0 }, send_x };
const struct c_ops c_tbl = { 0, poll_x };
const struct d_ops d_tbl = { 0, poll_y };
struct outer outer_tbl = { 0, 0, { notify_x } };
struct anon_holder anon_tbl = { 0, { u_cb_x } };
/* hidden, as in the kernel (no GOT): adrp + ldr [x8, :lo12:g_send], whose 12-bit offset is not a member offset */
__attribute__((visibility("hidden"))) int (*volatile g_send)(struct msg *, int) = send_y;

int call_a_send(struct a_ops *o, struct msg *m) { return o->send(m, 1) + 1; }
int call_b_send(struct b_ops *o, struct msg *m) { return o->send(m, 2) + 1; }
int call_b_recv(struct b_ops *o, struct msg *m) { return o->recv(m, 3) + 1; }
long call_c_poll(struct c_ops *o, struct msg *m) { return o->poll(m, 4) + 1; }
void call_outer(struct outer *o, struct msg *m) { o->in.notify(m, 5); m->len++; }
void call_anon(struct anon_holder *h, struct msg *m) { h->u_cb(m, 6); m->len++; }
int call_param(int (*f)(struct msg *, int), struct msg *m) { return f(m, 7) + 1; }
int call_global(struct msg *m) { return g_send(m, 8) + 1; }

const unsigned long off_a_ops_send = __builtin_offsetof(struct a_ops, send);
const unsigned long off_b_ops_send = __builtin_offsetof(struct b_ops, send);
const unsigned long off_b_ops_recv = __builtin_offsetof(struct b_ops, recv);
const unsigned long off_c_ops_poll = __builtin_offsetof(struct c_ops, poll);
const unsigned long off_d_ops_poll = __builtin_offsetof(struct d_ops, poll);
const unsigned long off_outer_notify = __builtin_offsetof(struct outer, in.notify);
const unsigned long off_anon_holder_u_cb = __builtin_offsetof(struct anon_holder, u_cb);
