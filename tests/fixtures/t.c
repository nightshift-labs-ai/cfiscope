volatile long sink;
typedef long long (*fp0)(void);
__attribute__((noinline)) long long impl_0_0(void) { ; sink += 0; return (long long)sink; }
__attribute__((noinline)) long long impl_0_1(void) { ; sink += 1; return (long long)sink; }
__attribute__((noinline)) long long impl_0_2(void) { ; sink += 2; return (long long)sink; }
__attribute__((noinline)) long long impl_0_3(void) { ; sink += 3; return (long long)sink; }
__attribute__((noinline)) long long do_call_0(fp0 f) { return f(); }
fp0 tbl0[] = { impl_0_0, impl_0_1, impl_0_2, impl_0_3 };
typedef int (*fp1)(void);
__attribute__((noinline)) int impl_1_0(void) { ; sink += 7; return (int)sink; }
__attribute__((noinline)) int impl_1_1(void) { ; sink += 8; return (int)sink; }
__attribute__((noinline)) int impl_1_2(void) { ; sink += 9; return (int)sink; }
__attribute__((noinline)) int impl_1_3(void) { ; sink += 10; return (int)sink; }
__attribute__((noinline)) int impl_1_4(void) { ; sink += 11; return (int)sink; }
__attribute__((noinline)) int impl_1_5(void) { ; sink += 12; return (int)sink; }
__attribute__((noinline)) int do_call_1(fp1 f) { return f(); }
fp1 tbl1[] = { impl_1_0, impl_1_1, impl_1_2, impl_1_3, impl_1_4, impl_1_5 };
typedef long (*fp2)(short a0, int a1);
__attribute__((noinline)) long impl_2_0(short a0, int a1) { (void)a0; (void)a1; sink += 14; return (long)sink; }
__attribute__((noinline)) long impl_2_1(short a0, int a1) { (void)a0; (void)a1; sink += 15; return (long)sink; }
__attribute__((noinline)) long impl_2_2(short a0, int a1) { (void)a0; (void)a1; sink += 16; return (long)sink; }
__attribute__((noinline)) long do_call_2(fp2 f) { return f((short)0, (int)0); }
fp2 tbl2[] = { impl_2_0, impl_2_1, impl_2_2 };
typedef void* (*fp3)(long long a0, long long a1, char a2, long a3);
__attribute__((noinline)) void* impl_3_0(long long a0, long long a1, char a2, long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 21; return (void*)sink; }
__attribute__((noinline)) void* impl_3_1(long long a0, long long a1, char a2, long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 22; return (void*)sink; }
__attribute__((noinline)) void* impl_3_2(long long a0, long long a1, char a2, long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 23; return (void*)sink; }
__attribute__((noinline)) void* impl_3_3(long long a0, long long a1, char a2, long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 24; return (void*)sink; }
__attribute__((noinline)) void* impl_3_4(long long a0, long long a1, char a2, long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 25; return (void*)sink; }
__attribute__((noinline)) void* impl_3_5(long long a0, long long a1, char a2, long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 26; return (void*)sink; }
__attribute__((noinline)) void* do_call_3(fp3 f) { return f((long long)0, (long long)0, (char)0, (long)0); }
fp3 tbl3[] = { impl_3_0, impl_3_1, impl_3_2, impl_3_3, impl_3_4, impl_3_5 };
typedef char (*fp4)(void);
__attribute__((noinline)) char impl_4_0(void) { ; sink += 28; return (char)sink; }
__attribute__((noinline)) char impl_4_1(void) { ; sink += 29; return (char)sink; }
__attribute__((noinline)) char do_call_4(fp4 f) { return f(); }
fp4 tbl4[] = { impl_4_0, impl_4_1 };
typedef int (*fp5)(long long a0, short a1, long a2, long long a3);
__attribute__((noinline)) int impl_5_0(long long a0, short a1, long a2, long long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 35; return (int)sink; }
__attribute__((noinline)) int impl_5_1(long long a0, short a1, long a2, long long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 36; return (int)sink; }
__attribute__((noinline)) int impl_5_2(long long a0, short a1, long a2, long long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 37; return (int)sink; }
__attribute__((noinline)) int do_call_5(fp5 f) { return f((long long)0, (short)0, (long)0, (long long)0); }
fp5 tbl5[] = { impl_5_0, impl_5_1, impl_5_2 };
typedef long (*fp6)(long a0, int a1, unsigned a2, long a3);
__attribute__((noinline)) long impl_6_0(long a0, int a1, unsigned a2, long a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 42; return (long)sink; }
__attribute__((noinline)) long do_call_6(fp6 f) { return f((long)0, (int)0, (unsigned)0, (long)0); }
fp6 tbl6[] = { impl_6_0 };
typedef unsigned (*fp7)(void* a0, unsigned a1, short a2);
__attribute__((noinline)) unsigned impl_7_0(void* a0, unsigned a1, short a2) { (void)a0; (void)a1; (void)a2; sink += 49; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_7_1(void* a0, unsigned a1, short a2) { (void)a0; (void)a1; (void)a2; sink += 50; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_7_2(void* a0, unsigned a1, short a2) { (void)a0; (void)a1; (void)a2; sink += 51; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_7_3(void* a0, unsigned a1, short a2) { (void)a0; (void)a1; (void)a2; sink += 52; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_7_4(void* a0, unsigned a1, short a2) { (void)a0; (void)a1; (void)a2; sink += 53; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_7_5(void* a0, unsigned a1, short a2) { (void)a0; (void)a1; (void)a2; sink += 54; return (unsigned)sink; }
__attribute__((noinline)) unsigned do_call_7(fp7 f) { return f((void*)0, (unsigned)0, (short)0); }
fp7 tbl7[] = { impl_7_0, impl_7_1, impl_7_2, impl_7_3, impl_7_4, impl_7_5 };
typedef short (*fp8)(int a0, long a1, int a2);
__attribute__((noinline)) short impl_8_0(int a0, long a1, int a2) { (void)a0; (void)a1; (void)a2; sink += 56; return (short)sink; }
__attribute__((noinline)) short impl_8_1(int a0, long a1, int a2) { (void)a0; (void)a1; (void)a2; sink += 57; return (short)sink; }
__attribute__((noinline)) short impl_8_2(int a0, long a1, int a2) { (void)a0; (void)a1; (void)a2; sink += 58; return (short)sink; }
__attribute__((noinline)) short impl_8_3(int a0, long a1, int a2) { (void)a0; (void)a1; (void)a2; sink += 59; return (short)sink; }
__attribute__((noinline)) short impl_8_4(int a0, long a1, int a2) { (void)a0; (void)a1; (void)a2; sink += 60; return (short)sink; }
__attribute__((noinline)) short impl_8_5(int a0, long a1, int a2) { (void)a0; (void)a1; (void)a2; sink += 61; return (short)sink; }
__attribute__((noinline)) short do_call_8(fp8 f) { return f((int)0, (long)0, (int)0); }
fp8 tbl8[] = { impl_8_0, impl_8_1, impl_8_2, impl_8_3, impl_8_4, impl_8_5 };
typedef void* (*fp9)(long long a0);
__attribute__((noinline)) void* impl_9_0(long long a0) { (void)a0; sink += 63; return (void*)sink; }
__attribute__((noinline)) void* impl_9_1(long long a0) { (void)a0; sink += 64; return (void*)sink; }
__attribute__((noinline)) void* do_call_9(fp9 f) { return f((long long)0); }
fp9 tbl9[] = { impl_9_0, impl_9_1 };
typedef const char* (*fp10)(int a0);
__attribute__((noinline)) const char* impl_10_0(int a0) { (void)a0; sink += 70; return (const char*)sink; }
__attribute__((noinline)) const char* impl_10_1(int a0) { (void)a0; sink += 71; return (const char*)sink; }
__attribute__((noinline)) const char* impl_10_2(int a0) { (void)a0; sink += 72; return (const char*)sink; }
__attribute__((noinline)) const char* impl_10_3(int a0) { (void)a0; sink += 73; return (const char*)sink; }
__attribute__((noinline)) const char* impl_10_4(int a0) { (void)a0; sink += 74; return (const char*)sink; }
__attribute__((noinline)) const char* do_call_10(fp10 f) { return f((int)0); }
fp10 tbl10[] = { impl_10_0, impl_10_1, impl_10_2, impl_10_3, impl_10_4 };
typedef long (*fp11)(long long a0, char a1, long a2, short a3);
__attribute__((noinline)) long impl_11_0(long long a0, char a1, long a2, short a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 77; return (long)sink; }
__attribute__((noinline)) long impl_11_1(long long a0, char a1, long a2, short a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 78; return (long)sink; }
__attribute__((noinline)) long impl_11_2(long long a0, char a1, long a2, short a3) { (void)a0; (void)a1; (void)a2; (void)a3; sink += 79; return (long)sink; }
__attribute__((noinline)) long do_call_11(fp11 f) { return f((long long)0, (char)0, (long)0, (short)0); }
fp11 tbl11[] = { impl_11_0, impl_11_1, impl_11_2 };
typedef void* (*fp12)(void);
__attribute__((noinline)) void* impl_12_0(void) { ; sink += 84; return (void*)sink; }
__attribute__((noinline)) void* impl_12_1(void) { ; sink += 85; return (void*)sink; }
__attribute__((noinline)) void* do_call_12(fp12 f) { return f(); }
fp12 tbl12[] = { impl_12_0, impl_12_1 };
typedef char (*fp13)(long long a0, int a1);
__attribute__((noinline)) char impl_13_0(long long a0, int a1) { (void)a0; (void)a1; sink += 91; return (char)sink; }
__attribute__((noinline)) char impl_13_1(long long a0, int a1) { (void)a0; (void)a1; sink += 92; return (char)sink; }
__attribute__((noinline)) char impl_13_2(long long a0, int a1) { (void)a0; (void)a1; sink += 93; return (char)sink; }
__attribute__((noinline)) char impl_13_3(long long a0, int a1) { (void)a0; (void)a1; sink += 94; return (char)sink; }
__attribute__((noinline)) char impl_13_4(long long a0, int a1) { (void)a0; (void)a1; sink += 95; return (char)sink; }
__attribute__((noinline)) char impl_13_5(long long a0, int a1) { (void)a0; (void)a1; sink += 96; return (char)sink; }
__attribute__((noinline)) char do_call_13(fp13 f) { return f((long long)0, (int)0); }
fp13 tbl13[] = { impl_13_0, impl_13_1, impl_13_2, impl_13_3, impl_13_4, impl_13_5 };
typedef const char* (*fp14)(int a0, char a1);
__attribute__((noinline)) const char* impl_14_0(int a0, char a1) { (void)a0; (void)a1; sink += 98; return (const char*)sink; }
__attribute__((noinline)) const char* impl_14_1(int a0, char a1) { (void)a0; (void)a1; sink += 99; return (const char*)sink; }
__attribute__((noinline)) const char* impl_14_2(int a0, char a1) { (void)a0; (void)a1; sink += 100; return (const char*)sink; }
__attribute__((noinline)) const char* do_call_14(fp14 f) { return f((int)0, (char)0); }
fp14 tbl14[] = { impl_14_0, impl_14_1, impl_14_2 };
typedef unsigned (*fp15)(unsigned a0);
__attribute__((noinline)) unsigned impl_15_0(unsigned a0) { (void)a0; sink += 105; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_15_1(unsigned a0) { (void)a0; sink += 106; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_15_2(unsigned a0) { (void)a0; sink += 107; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_15_3(unsigned a0) { (void)a0; sink += 108; return (unsigned)sink; }
__attribute__((noinline)) unsigned do_call_15(fp15 f) { return f((unsigned)0); }
fp15 tbl15[] = { impl_15_0, impl_15_1, impl_15_2, impl_15_3 };
typedef char (*fp16)(int a0, const char* a1, void* a2);
__attribute__((noinline)) char impl_16_0(int a0, const char* a1, void* a2) { (void)a0; (void)a1; (void)a2; sink += 112; return (char)sink; }
__attribute__((noinline)) char impl_16_1(int a0, const char* a1, void* a2) { (void)a0; (void)a1; (void)a2; sink += 113; return (char)sink; }
__attribute__((noinline)) char impl_16_2(int a0, const char* a1, void* a2) { (void)a0; (void)a1; (void)a2; sink += 114; return (char)sink; }
__attribute__((noinline)) char impl_16_3(int a0, const char* a1, void* a2) { (void)a0; (void)a1; (void)a2; sink += 115; return (char)sink; }
__attribute__((noinline)) char impl_16_4(int a0, const char* a1, void* a2) { (void)a0; (void)a1; (void)a2; sink += 116; return (char)sink; }
__attribute__((noinline)) char impl_16_5(int a0, const char* a1, void* a2) { (void)a0; (void)a1; (void)a2; sink += 117; return (char)sink; }
__attribute__((noinline)) char do_call_16(fp16 f) { return f((int)0, (const char*)0, (void*)0); }
fp16 tbl16[] = { impl_16_0, impl_16_1, impl_16_2, impl_16_3, impl_16_4, impl_16_5 };
typedef long long (*fp17)(long long a0, long long a1);
__attribute__((noinline)) long long impl_17_0(long long a0, long long a1) { (void)a0; (void)a1; sink += 119; return (long long)sink; }
__attribute__((noinline)) long long do_call_17(fp17 f) { return f((long long)0, (long long)0); }
fp17 tbl17[] = { impl_17_0 };
typedef int (*fp18)(char a0, long long a1, long long a2);
__attribute__((noinline)) int impl_18_0(char a0, long long a1, long long a2) { (void)a0; (void)a1; (void)a2; sink += 126; return (int)sink; }
__attribute__((noinline)) int do_call_18(fp18 f) { return f((char)0, (long long)0, (long long)0); }
fp18 tbl18[] = { impl_18_0 };
typedef unsigned (*fp19)(long a0, char a1);
__attribute__((noinline)) unsigned impl_19_0(long a0, char a1) { (void)a0; (void)a1; sink += 133; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_19_1(long a0, char a1) { (void)a0; (void)a1; sink += 134; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_19_2(long a0, char a1) { (void)a0; (void)a1; sink += 135; return (unsigned)sink; }
__attribute__((noinline)) unsigned impl_19_3(long a0, char a1) { (void)a0; (void)a1; sink += 136; return (unsigned)sink; }
__attribute__((noinline)) unsigned do_call_19(fp19 f) { return f((long)0, (char)0); }
fp19 tbl19[] = { impl_19_0, impl_19_1, impl_19_2, impl_19_3 };
typedef const char* (*fp20)(long a0, long a1, long long a2);
__attribute__((noinline)) const char* impl_20_0(long a0, long a1, long long a2) { (void)a0; (void)a1; (void)a2; sink += 140; return (const char*)sink; }
__attribute__((noinline)) const char* impl_20_1(long a0, long a1, long long a2) { (void)a0; (void)a1; (void)a2; sink += 141; return (const char*)sink; }
__attribute__((noinline)) const char* do_call_20(fp20 f) { return f((long)0, (long)0, (long long)0); }
fp20 tbl20[] = { impl_20_0, impl_20_1 };
