/* decode.c
 * 双击: 扫描当前目录所有 .bin -> 选择一个 -> 输密码 -> 显示该文件明文
 * 编译: tcc decode.c -o decode.exe
 * 源文件: UTF-8 无 BOM
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#endif

#define MAX_FILES 128

static void set_utf8(void) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
}

static void pause_exit(void) {
#ifdef _WIN32
    printf("\n按任意键退出...");
    _getch();
#else
    printf("\n按回车键退出...");
    getchar();
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

static int find_bin(char names[][MAX_PATH], int max_n) {
    WIN32_FIND_DATAA fd;
    HANDLE h;
    int n = 0;
    h = FindFirstFileA("*.bin", &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!has_ext(fd.cFileName, ".bin")) continue;
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

int main(int argc, char **argv) {
    char pw[256];
    char names[MAX_FILES][MAX_PATH];
    char infile[MAX_PATH];
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t *cipher = NULL, *plain = NULL;
    size_t N;
    FILE *f;
    long fsz;
    int n, i, sel = 1;
    AES_CTX ctx;
    char disp[512];

    set_utf8();

    if (argc >= 2) {
        /* 命令行 / 拖拽文件: 直接用 */
        strncpy(infile, argv[1], MAX_PATH - 1);
        infile[MAX_PATH - 1] = 0;
    } else {
#ifdef _WIN32
        n = find_bin(names, MAX_FILES);
#else
        n = 0;
#endif
        if (n == 0) {
            printf("当前目录没有 .bin 文件\n");
            pause_exit();
            return 1;
        }
#ifdef _WIN32
        qsort(names, (size_t)n, MAX_PATH, cmp_name);
#endif

        if (n == 1) {
            strcpy(infile, names[0]);
            name_to_utf8(infile, disp, sizeof(disp));
            printf("密文: %s\n", disp);
        } else {
            char line[64];
            printf("发现 %d 个 .bin 文件:\n", n);
            for (i = 0; i < n; i++) {
                name_to_utf8(names[i], disp, sizeof(disp));
                printf("  [%d] %s\n", i + 1, disp);
            }
            printf("选择编号 (默认 1): ");
            if (fgets(line, sizeof(line), stdin)) {
                int v;
                if (sscanf(line, "%d", &v) == 1 && v >= 1 && v <= n) sel = v;
            }
            strcpy(infile, names[sel - 1]);
        }
    }

    f = fopen(infile, "rb");
    if (!f) {
        name_to_utf8(infile, disp, sizeof(disp));
        printf("找不到 %s\n", disp);
        pause_exit();
        return 1;
    }
    fseek(f, 0, SEEK_END);
    fsz = ftell(f);
    if (fsz < 24) { fclose(f); printf("文件损坏\n"); pause_exit(); return 1; }
    N = (size_t)(fsz - 16);
    fseek(f, 0, SEEK_SET);
    if (fread(iv, 1, 16, f) != 16) { fclose(f); printf("读取失败\n"); pause_exit(); return 1; }

    cipher = (uint8_t*)malloc(N);
    if (!cipher) { fclose(f); printf("内存不足\n"); pause_exit(); return 1; }
    if (fread(cipher, 1, N, f) != N) { fclose(f); free(cipher); printf("读取失败\n"); pause_exit(); return 1; }
    fclose(f);

    printf("密码: ");
    read_pw(pw, sizeof(pw));
    sha256((const uint8_t*)pw, strlen(pw), key);

    plain = (uint8_t*)malloc(N);
    if (!plain) { free(cipher); pause_exit(); return 1; }
    memcpy(plain, cipher, N);
    free(cipher);

    AES_init_ctx(&ctx, key, iv);
    AES_CTR_xcrypt(&ctx, plain, N);

    if (N < 8 || memcmp(plain, "SCRTAES1", 8) != 0) {
        printf("密码错误\n");
        free(plain);
        pause_exit();
        return 1;
    }

    fwrite(plain + 8, 1, N - 8, stdout);
    printf("\n");
    free(plain);
    pause_exit();
    return 0;
}