#if defined(_WIN32) || defined(_WIN64)
typedef unsigned long dw_t;
typedef void* hnd_t;
hnd_t GetStdHandle(dw_t nStdHandle);
int WriteConsoleA(hnd_t hConsoleOutput, const void* lpBuffer, dw_t nChars, dw_t* pCharsWritten, void* pReserved);
#else
typedef unsigned long sz_t;
long write(int fd, const void* buf, sz_t count);
#endif

struct proc_t
{
    char buf[14];
    unsigned long len;
    volatile int st;
};

unsigned long op_sum(unsigned long a, unsigned long b) {
    unsigned long carry;
    while (b != 0) {
        carry = a & b;
        a = a ^ b;
        b = carry << 1;
    }
    return a;
}

unsigned long op_sub(unsigned long a, unsigned long b) {
    return op_sum(a, op_sum(~b, 1));
}

unsigned long op_inc(unsigned long n) {
    return op_sum(n, 1);
}

unsigned long get_len(const char* s)
{
    const char* p = s;
    while (*p) {
        p = (const char*)op_inc((unsigned long)p);
    }
    return op_sub((unsigned long)p, (unsigned long)s);
}

void phase_init(struct proc_t* ctx) {
    ctx->st = op_inc(ctx->st);
}

void phase_decode(struct proc_t* ctx)
{
    const unsigned char SECRET_BLOB[] = {
        0x12, 0x3F, 0x36, 0x36, 0x35, 0x76, 0x7A, 0x0D,
        0x35, 0x28, 0x36, 0x3E, 0x7B, 0x50
    };
    const unsigned char X_KEY = 0x5A;
    
    for (unsigned long i = 0; i < sizeof(SECRET_BLOB); i = op_inc(i))
    {
        char* p_buf = (char*)op_sum((unsigned long)ctx->buf, i);
        const unsigned char* p_src = (const unsigned char*)op_sum((unsigned long)SECRET_BLOB, i);
        *p_buf = *p_src ^ X_KEY;
    }
    ctx->st = op_inc(ctx->st);
}

void phase_len(struct proc_t* ctx) {
    char* p_end = (char*)op_sum((unsigned long)ctx->buf, 13);
    char tmp = *p_end;
    
    *p_end = '\0';
    ctx->len = get_len(ctx->buf);
    *p_end = tmp;
    
    ctx->len = op_inc(ctx->len);
    ctx->len = sizeof(ctx->buf);

    ctx->st = op_inc(ctx->st);
}

void phase_emit(struct proc_t* ctx) {
#if defined(_WIN32) || defined(_WIN64)
    const dw_t h_id = (dw_t)op_sub(0, 11);
    hnd_t h_out = GetStdHandle(h_id);
    dw_t written = 0;
    WriteConsoleA(h_out, ctx->buf, (dw_t)ctx->len, &written, 0);
#else
    const int FD_STDOUT = 1;
    write(FD_STDOUT, ctx->buf, ctx->len);
#endif
    ctx->st = op_inc(ctx->st);
}

void phase_halt(struct proc_t* ctx) {
    ctx->st = op_inc(ctx->st);
}

int main()
{
    struct proc_t ctx = { {0}, 0, 0 };

DISPATCH:
    if (ctx.st == 0) goto P_INIT;
    if (ctx.st == 1) goto P_DECODE;
    if (ctx.st == 2) goto P_LEN;
    if (ctx.st == 3) goto P_EMIT;
    if (ctx.st == 4) goto P_HALT;
    goto DONE;

P_INIT:
    phase_init(&ctx);
    goto DISPATCH;

P_DECODE:
    phase_decode(&ctx); goto DISPATCH;

P_LEN:
    phase_len(&ctx);
    goto DISPATCH;

P_EMIT:
    phase_emit(&ctx);
    goto DISPATCH;

P_HALT:
    phase_halt(&ctx);
    goto DISPATCH;

DONE:
    return 0;
}
