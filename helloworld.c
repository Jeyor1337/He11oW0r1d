#if defined(_WIN32) || defined(_WIN64)
typedef unsigned long dw_t;
typedef void* hnd_t;
typedef unsigned long sz_t;

#ifdef __GNUC__
    #define WINAPI __attribute__((stdcall))
#else
    #define WINAPI __stdcall
#endif

hnd_t WINAPI GetStdHandle(dw_t nStdHandle);
int WINAPI WriteConsoleA(hnd_t hConsoleOutput, const void* lpBuffer, dw_t nChars, dw_t* pCharsWritten, void* pReserved);
int WINAPI WriteFile(hnd_t hFile, const void* lpBuffer, dw_t nNumberOfBytesToWrite, dw_t* lpNumberOfBytesWritten, void* lpOverlapped);
dw_t WINAPI GetFileType(hnd_t hFile);
#else
typedef unsigned long sz_t;
long write(int fd, const void* buf, sz_t count);
#endif

struct proc_t
{
    char buf[14];
    unsigned long len;
    volatile int st;
    unsigned long chk;
    unsigned char rot_key;
    volatile int jmp_tbl[8];
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

unsigned long op_mul(unsigned long a, unsigned long b) {
    unsigned long res = 0;
    while (b != 0) {
        if (b & 1) {
            res = op_sum(res, a);
        }
        a = a << 1;
        b = b >> 1;
    }
    return res;
}

unsigned long op_xor(unsigned long a, unsigned long b) {
    return a ^ b;
}

unsigned long op_rol(unsigned long val, unsigned long n) {
    n = n & 0x1F;
    return (val << n) | (val >> (op_sub(32, n)));
}

unsigned long get_len(const char* s)
{
    const char* p = s;
    while (*p) {
        p = (const char*)op_inc((unsigned long)p);
    }
    return op_sub((unsigned long)p, (unsigned long)s);
}

#define HEAP_SIZE 4096
static char g_heap[HEAP_SIZE];
static void* g_heap_base = 0;

struct mem_block {
    sz_t size;
    int is_free;
    struct mem_block* next;
};

void my_memcpy(void* dest, const void* src, sz_t n) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    sz_t i = 0;
    while (i < n) {
        *d = *s;
        d = (char*)op_inc((unsigned long)d);
        s = (const char*)op_inc((unsigned long)s);
        i = op_inc(i);
    }
}

void init_heap() {
    g_heap_base = (void*)g_heap;
    struct mem_block* head = (struct mem_block*)g_heap_base;
    head->size = op_sub(HEAP_SIZE, sizeof(struct mem_block));
    head->is_free = 1;
    head->next = 0;
}

void* my_malloc(sz_t size) {
    if (g_heap_base == 0) {
        init_heap();
    }

    sz_t remainder = size % sizeof(long);
    if (remainder != 0) {
        size = op_sum(size, op_sub(sizeof(long), remainder));
    }

    struct mem_block* current = (struct mem_block*)g_heap_base;
    void* result = 0;

    while (current != 0) {
        if (current->is_free && current->size >= size) {
            sz_t remaining_size = op_sub(current->size, size);
            if (remaining_size > sizeof(struct mem_block)) {
                struct mem_block* new_block = (struct mem_block*)op_sum((unsigned long)current, op_sum(sizeof(struct mem_block), size));
                new_block->size = op_sub(remaining_size, sizeof(struct mem_block));
                new_block->is_free = 1;
                new_block->next = current->next;

                current->size = size;
                current->next = new_block;
            }
            
            current->is_free = 0;
            result = (void*)op_sum((unsigned long)current, sizeof(struct mem_block));
            break;
        }
        current = current->next;
    }

    return result;
}

void my_free(void* ptr) {
    if (ptr == 0) {
        return;
    }

    struct mem_block* block_header = (struct mem_block*)op_sub((unsigned long)ptr, sizeof(struct mem_block));
    block_header->is_free = 1;

    struct mem_block* current = (struct mem_block*)g_heap_base;
    while (current && current->next) {
        if (current->is_free && current->next->is_free) {
            if ((unsigned long)current->next == op_sum(op_sum((unsigned long)current, sizeof(struct mem_block)), current->size)) {
                current->size = op_sum(current->size, op_sum(sizeof(struct mem_block), current->next->size));
                current->next = current->next->next;
            } else {
                current = current->next;
            }
        } else {
            current = current->next;
        }
    }
}


void phase_init(struct proc_t* ctx) {
    for (unsigned long i = 0; i < 8; i = op_inc(i)) {
        ctx->jmp_tbl[i] = (int)i;
    }
    ctx->rot_key = 0;
    ctx->chk = 0;
    ctx->st = op_inc(ctx->st);
}

void phase_prng(struct proc_t* ctx) {
    unsigned long seed = 0x12345678;
    for (unsigned long i = 0; i < 3; i = op_inc(i)) {
        seed = op_xor(seed, op_rol(seed, 13));
        seed = op_xor(seed, seed >> 17);
        seed = op_xor(seed, op_rol(seed, 5));
    }
    ctx->rot_key = (unsigned char)(seed & 0xFF);
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

void phase_transform(struct proc_t* ctx) {
    for (unsigned long i = 0; i < sizeof(ctx->buf); i = op_inc(i)) {
        unsigned char tmp = ctx->buf[i];
        if (tmp >= 'A' && tmp <= 'Z') {
            tmp = op_sum(tmp, ctx->rot_key);
            tmp = op_sub(tmp, ctx->rot_key);
        }
        ctx->buf[i] = tmp;
    }
    ctx->st = op_inc(ctx->st);
}

void phase_checksum(struct proc_t* ctx) {
    unsigned long acc = 0x9E3779B9;
    for (unsigned long i = 0; i < sizeof(ctx->buf); i = op_inc(i)) {
        unsigned long byte_val = (unsigned long)(unsigned char)ctx->buf[i];
        acc = op_xor(acc, byte_val);
        acc = op_rol(acc, 7);
        acc = op_sum(acc, 0x6A09E667);
    }
    ctx->chk = acc;
    ctx->st = op_inc(ctx->st);
}

void phase_validate(struct proc_t* ctx) {
    unsigned long expected = op_xor(ctx->chk, ctx->chk);
    expected = op_sum(expected, 0);

    volatile int guard = 1;
    for (unsigned long i = 0; i < 100; i = op_inc(i)) {
        guard = op_xor(guard, guard);
        guard = op_inc(guard);
    }

    if (guard != 1) {
        ctx->st = 99;
    } else {
        ctx->st = op_inc(ctx->st);
    }
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

void phase_indirect(struct proc_t* ctx) {
    for (unsigned long i = 0; i < 8; i = op_inc(i)) {
        unsigned long j = op_sub(7, i);
        int tmp = ctx->jmp_tbl[i];
        ctx->jmp_tbl[i] = ctx->jmp_tbl[j];
        ctx->jmp_tbl[j] = tmp;
    }

    for (unsigned long i = 0; i < 8; i = op_inc(i)) {
        unsigned long j = op_sub(7, i);
        int tmp = ctx->jmp_tbl[i];
        ctx->jmp_tbl[i] = ctx->jmp_tbl[j];
        ctx->jmp_tbl[j] = tmp;
    }
    ctx->st = op_inc(ctx->st);
}

void phase_emit(struct proc_t* ctx) {
#if defined(_WIN32) || defined(_WIN64)
    const dw_t FILE_TYPE_CHAR = 0x0002;
    const dw_t h_id = (dw_t)op_sub(0, 11);
    hnd_t h_out = GetStdHandle(h_id);
    dw_t written = 0;
    dw_t file_type = GetFileType(h_out);

    if (file_type == FILE_TYPE_CHAR) {
        WriteConsoleA(h_out, ctx->buf, (dw_t)ctx->len, &written, 0);
    } else {
        WriteFile(h_out, ctx->buf, (dw_t)ctx->len, &written, 0);
    }
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
    struct proc_t ctx = { {0}, 0, 0, 0, 0, {0} };

DISPATCH:
    if (ctx.st == 0) goto P_INIT;
    if (ctx.st == 1) goto P_PRNG;
    if (ctx.st == 2) goto P_DECODE;
    if (ctx.st == 3) goto P_TRANSFORM;
    if (ctx.st == 4) goto P_CHECKSUM;
    if (ctx.st == 5) goto P_VALIDATE;
    if (ctx.st == 6) goto P_INDIRECT;
    if (ctx.st == 7) goto P_LEN;
    if (ctx.st == 8) goto P_EMIT;
    if (ctx.st == 9) goto P_HALT;
    goto DONE;

P_INIT:
    phase_init(&ctx);
    goto DISPATCH;

P_PRNG:
    phase_prng(&ctx);
    goto DISPATCH;

P_DECODE:
    phase_decode(&ctx);
    goto DISPATCH;

P_TRANSFORM:
    phase_transform(&ctx);
    goto DISPATCH;

P_CHECKSUM:
    phase_checksum(&ctx);
    goto DISPATCH;

P_VALIDATE:
    phase_validate(&ctx);
    goto DISPATCH;

P_INDIRECT:
    phase_indirect(&ctx);
    goto DISPATCH;

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
