/* encode.c
 * 双击: 扫描当前目录所有 .txt -> 逐个加密为同名 .bin
 * 编译: tcc encode.c -o encode.exe
 * 源文件: UTF-8 无 BOM
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "aes_sha.h"

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#ifndef CP_ACP
#define CP_ACP 0
#endif
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
extern __declspec(dllimport) int  __stdcall MultiByteToWideChar(
    unsigned int, unsigned long, const char*, int, wchar_t*, int);
extern __declspec(dllimport) int  __stdcall WideCharToMultiByte(
    unsigned int, unsigned long, const wchar_t*, int, char*, int, const char*, int*);
extern __declspec(dllimport) void __stdcall Sleep(unsigned long);
#endif

#define MAX_FILES 128

static void set_utf8_console(void) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
}
static void end_delay(unsigned int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    (void)ms;
#endif
}

static void read_pw(char *buf, int n) {
#ifdef _WIN32
    int i = 0, c;
    while (i < n - 1 && (c = _getch()) != 13) {
        if (c == 8) { if (i > 0) { i--; printf("\b \b"); } }
        else if (c == 0 || c == 0xE0) _getch();
        else if (c >= 32) { buf[i++] = (char)c; putchar('*'); }
    }
    buf[i] = 0;
    putchar('\n');
#else
    int i = 0;
    if (fgets(buf, n, stdin)) {
        while (buf[i] && buf[i] != '\n' && buf[i] != '\r') i++;
        buf[i] = 0;
    }
#endif
}

#ifdef _WIN32
/* 文件名（ANSI）转 UTF-8 用于显示 */
static void name_to_utf8(const char *in, char *out, size_t outsz) {
    int wlen = MultiByteToWideChar(CP_ACP, 0, in, -1, NULL, 0);
    if (wlen > 0) {
        wchar_t *w = (wchar_t*)malloc(((size_t)wlen + 1) * sizeof(wchar_t));
        if (w) {
            int u8len;
            MultiByteToWideChar(CP_ACP, 0, in, -1, w, wlen);
            u8len = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
            if (u8len > 0 && (size_t)u8len <= outsz) {
                WideCharToMultiByte(CP_UTF8, 0, w, -1, out, u8len, NULL, NULL);
                free(w);
                return;
            }
            free(w);
        }
    }
    {
        size_t n = strlen(in);
        if (n + 1 > outsz) n = outsz - 1;
        memcpy(out, in, n);
        out[n] = 0;
    }
}

static int has_ext(const char *name, const char *ext) {
    size_t ln = strlen(name), le = strlen(ext), i;
    if (ln < le) return 0;
    for (i = 0; i < le; i++) {
        char a = name[ln - le + i], b = ext[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

static int cmp_name(const void *a, const void *b) {
    return strcmp((const char*)a, (const char*)b);
}

static int find_txt(char names[][MAX_PATH], int max_n) {
    WIN32_FIND_DATAA fd;
    HANDLE h;
    int n = 0;
    h = FindFirstFileA("*.txt", &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!has_ext(fd.cFileName, ".txt")) continue;
        if (n < max_n) {
            strncpy(names[n], fd.cFileName, MAX_PATH - 1);
            names[n][MAX_PATH - 1] = 0;
            n++;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return n;
}
#endif

static void change_ext(const char *in, const char *new_ext, char *out, size_t outsz) {
    size_t len = strlen(in);
    size_t ne_len = strlen(new_ext);
    size_t dot = len;
    while (dot > 0 && in[dot-1] != '.') dot--;
    if (dot == 0) {
        if (len + ne_len + 1 > outsz) { out[0] = 0; return; }
        memcpy(out, in, len);
        memcpy(out + len, new_ext, ne_len + 1);
    } else {
        size_t base = dot - 1;
        if (base + ne_len + 1 > outsz) { out[0] = 0; return; }
        memcpy(out, in, base);
        memcpy(out + base, new_ext, ne_len + 1);
    }
}

static int is_utf8(const unsigned char *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        if (c < 0x80) { i++; continue; }
        if ((c & 0xE0) == 0xC0) { if (i+1 >= n || (s[i+1]&0xC0)!=0x80) return 0; i+=2; }
        else if ((c & 0xF0) == 0xE0) { if (i+2 >= n || (s[i+1]&0xC0)!=0x80 || (s[i+2]&0xC0)!=0x80) return 0; i+=3; }
        else if ((c & 0xF8) == 0xF0) { if (i+3 >= n || (s[i+1]&0xC0)!=0x80 || (s[i+2]&0xC0)!=0x80 || (s[i+3]&0xC0)!=0x80) return 0; i+=4; }
        else return 0;
    }
    return 1;
}

static char *load_text(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    long sz;
    char *raw, *r;
    size_t n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    raw = (char*)malloc((size_t)sz + 1);
    if (!raw) { fclose(f); return NULL; }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) { free(raw); fclose(f); return NULL; }
    fclose(f);
    raw[sz] = 0;
    n = (size_t)sz;

    if (n >= 3 && (unsigned char)raw[0]==0xEF && (unsigned char)raw[1]==0xBB && (unsigned char)raw[2]==0xBF) {
        memmove(raw, raw + 3, n - 3 + 1);
        n -= 3;
    }

#ifdef _WIN32
    if (n > 0 && !is_utf8((const unsigned char*)raw, n)) {
        int wlen = MultiByteToWideChar(CP_ACP, 0, raw, (int)n, NULL, 0);
        if (wlen > 0) {
            wchar_t *w = (wchar_t*)malloc(((size_t)wlen + 1) * sizeof(wchar_t));
            if (w) {
                MultiByteToWideChar(CP_ACP, 0, raw, (int)n, w, wlen);
                {
                    int u8len = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
                    if (u8len > 0) {
                        r = (char*)malloc((size_t)u8len + 1);
                        if (r) {
                            WideCharToMultiByte(CP_UTF8, 0, w, wlen, r, u8len, NULL, NULL);
                            r[u8len] = 0;
                            *out_len = (size_t)u8len;
                            free(w); free(raw);
                            return r;
                        }
                    }
                }
                free(w);
            }
        }
    }
#endif
    *out_len = n;
    return raw;
}

int main(void) {
    char pw[256];
    char names[MAX_FILES][MAX_PATH];
    char byline[256], datestr[64], header[1024];
    size_t header_len;
    uint8_t key[32];
    int n, i, ok_count = 0;
    time_t now;
    struct tm *lt;
    AES_CTX *ctx;
    char disp[512];

    set_utf8_console();

    now = time(NULL);
    lt = localtime(&now);
    if (lt) strftime(datestr, sizeof(datestr), "%Y-%m-%d", lt);
    else    strcpy(datestr, "unknown");

#ifdef _WIN32
    n = find_txt(names, MAX_FILES);
#else
    n = 0;
#endif
    if (n == 0) {
        printf("当前目录没有 .txt 文件\n");
        end_delay(3000);
        return 1;
    }
#ifdef _WIN32
    qsort(names, (size_t)n, MAX_PATH, cmp_name);
#endif
    printf("发现 %d 个 .txt 文件:\n", n);
    for (i = 0; i < n; i++) {
        name_to_utf8(names[i], disp, sizeof(disp));
        printf("  %s\n", disp);
    }
    printf("\n");

    printf("署名: ");
    if (!fgets(byline, sizeof(byline), stdin)) byline[0] = 0;
    {
        size_t bl = strlen(byline);
        while (bl > 0 && (byline[bl-1] == '\n' || byline[bl-1] == '\r')) byline[--bl] = 0;
    }

    printf("密码: ");
    read_pw(pw, sizeof(pw));
    if (!pw[0]) { printf("密码为空\n"); end_delay(2000); return 1; }

    sha256((const uint8_t*)pw, strlen(pw), key);

    if (byline[0])
        sprintf(header, "署名: %s\n日期: %s\n\n", byline, datestr);
    else
        sprintf(header, "日期: %s\n\n", datestr);
    header_len = strlen(header);

    ctx = (AES_CTX*)malloc(sizeof(AES_CTX));
    if (!ctx) return 1;

    printf("\n");
    for (i = 0; i < n; i++) {
        size_t tlen = 0, N, j;
        char *text;
        uint8_t *plain, *cipher;
        uint8_t iv[16];
        uint32_t seed;
        FILE *fo;
        char out[MAX_PATH], disp_in[512], disp_out[512];

        text = load_text(names[i], &tlen);
        if (!text) {
            name_to_utf8(names[i], disp, sizeof(disp));
            printf("  跳过 %s (读取失败)\n", disp);
            continue;
        }

        change_ext(names[i], ".bin", out, sizeof(out));
        if (!out[0]) {
            free(text);
            continue;
        }

        seed = (uint32_t)now ^ (uint32_t)(uintptr_t)&seed ^ ((uint32_t)i * 2654435761u);
        for (j = 0; j < 16; j++) {
            seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
            iv[j] = (uint8_t)seed;
        }

        N = 8 + header_len + tlen;
        plain  = (uint8_t*)malloc(N);
        cipher = (uint8_t*)malloc(N);
        if (!plain || !cipher) { free(text); free(plain); free(cipher); continue; }
        memcpy(plain, "SCRTAES1", 8);
        memcpy(plain + 8, header, header_len);
        memcpy(plain + 8 + header_len, text, tlen);
        memcpy(cipher, plain, N);

        AES_init_ctx(ctx, key, iv);
        AES_CTR_xcrypt(ctx, cipher, N);

        fo = fopen(out, "wb");
        if (!fo) { free(text); free(plain); free(cipher); continue; }
        fwrite(iv, 1, 16, fo);
        fwrite(cipher, 1, N, fo);
        fclose(fo);

        name_to_utf8(names[i], disp_in,  sizeof(disp_in));
        name_to_utf8(out,      disp_out, sizeof(disp_out));
        printf("  %s -> %s\n", disp_in, disp_out);
        ok_count++;
        free(text); free(plain); free(cipher);
    }

    free(ctx);
    printf("\n完成 %d/%d\n", ok_count, n);
    end_delay(2500);
    return ok_count > 0 ? 0 : 1;
}