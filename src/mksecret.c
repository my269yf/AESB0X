/* mksecret.c
 * 双击运行: 读 input.txt -> 输入署名 -> 输入密码 -> 生成 secret.exe -> 自动关闭
 * 命令行  : mksecret [input.txt] [output.exe]
 * 编译    : tcc mksecret.c -o mksecret.exe   (或 gcc)
 * 源文件  : UTF-8 无 BOM 保存
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

/* TCC 精简 windows.h 补丁 */
#ifndef CP_ACP
#define CP_ACP 0
#endif
#ifndef CP_UTF8
#define CP_UTF8 65001
#endif
extern __declspec(dllimport) int  __stdcall MultiByteToWideChar(
    unsigned int, unsigned long, const char*, int, wchar_t*, int);
extern __declspec(dllimport) int  __stdcall WideCharToMultiByte(
    unsigned int, unsigned long, const wchar_t*, int, char*, int, const char*, int*);
extern __declspec(dllimport) void __stdcall Sleep(unsigned long);
#endif

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
#endif

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

int main(int argc, char **argv) {
    char pw[256];
    char infile[512], outname[512];
    char byline[256];
    char datestr[64];
    char header[1024];
    size_t header_len;
    char *text;
    size_t tlen = 0, total, i;
    uint8_t key[32], iv[16], *data;
    FILE *f, *g;
    char cmd[1024], line[4096];
    int rc;
    AES_CTX ctx;

    set_utf8_console();

    /* 双击：input.txt -> secret.exe；命令行可覆盖 */
    strcpy(infile,  argc >= 2 ? argv[1] : "input.txt");
    strcpy(outname, argc >= 3 ? argv[2] : "secret.exe");

    text = load_text(infile, &tlen);
    if (!text) {
        printf("找不到 %s，请把要加密的文字放进 input.txt\n", infile);
        end_delay(3000);
        return 1;
    }
    printf("输入: %s (%lu 字节)\n", infile, (unsigned long)tlen);

    /* ---- 1. 署名（密码之前） ---- */
    printf("署名: ");
    if (!fgets(byline, sizeof(byline), stdin)) byline[0] = 0;
    {
        size_t bl = strlen(byline);
        while (bl > 0 && (byline[bl-1] == '\n' || byline[bl-1] == '\r')) byline[--bl] = 0;
    }

    /* ---- 2. 生成日期（运行时 = 生成时） ---- */
    {
        time_t now = time(NULL);
        struct tm *lt = localtime(&now);
        if (lt) strftime(datestr, sizeof(datestr), "%Y-%m-%d", lt);
        else    strcpy(datestr, "unknown");
    }

    /* ---- 3. 拼 header，与正文一起加密 ---- */
    if (byline[0])
        sprintf(header, "署名: %s\n日期: %s\n\n", byline, datestr);
    else
        sprintf(header, "日期: %s\n\n", datestr);
    header_len = strlen(header);

    /* ---- 4. 密码 ---- */
    printf("密码: ");
    read_pw(pw, sizeof(pw));
    if (!pw[0]) {
        printf("密码为空\n");
        end_delay(2000);
        free(text);
        return 1;
    }

    sha256((const uint8_t*)pw, strlen(pw), key);

    {
        uint32_t s = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)&s;
        for (i = 0; i < 16; i++) {
            s ^= s << 13; s ^= s >> 17; s ^= s << 5;
            iv[i] = (uint8_t)s;
        }
    }

    /* 密文布局: [16B IV][8B magic][header+正文的 AES-CTR 密文] */
    total = 16 + 8 + header_len + tlen;
    data = (uint8_t*)malloc(total);
    if (!data) { free(text); return 1; }
    memcpy(data, iv, 16);
    memcpy(data + 16, "SCRTAES1", 8);
    memcpy(data + 24, header, header_len);
    memcpy(data + 24 + header_len, text, tlen);

    AES_init_ctx(&ctx, key, iv);
    AES_CTR_xcrypt(&ctx, data + 16, 8 + header_len + tlen);

    /* ---- 5. 生成 stub.c ---- */
    f = fopen("_stub.c", "w");
    if (!f) { printf("写入失败\n"); free(text); free(data); return 1; }
    fprintf(f, "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdint.h>\n");
    fprintf(f, "#ifdef _WIN32\n#include <conio.h>\n#include <windows.h>\n#endif\n\n");

    g = fopen("aes_sha.h", "r");
    if (!g) { fclose(f); printf("找不到 aes_sha.h\n"); free(text); free(data); return 1; }
    while (fgets(line, sizeof(line), g)) fputs(line, f);
    fclose(g);

    fprintf(f, "\nstatic const uint8_t DATA[%lu] = {\n", (unsigned long)total);
    for (i = 0; i < total; i++) {
        fprintf(f, "0x%02X,", data[i]);
        if ((i & 15) == 15) fprintf(f, "\n");
    }
    fprintf(f, "\n};\n\n");

    /* secret.exe 主函数：解密后直接 fwrite —— header 和正文一起显示 */
    fputs(
        "static void set_utf8(void){\n"
        "#ifdef _WIN32\n"
        "    SetConsoleOutputCP(65001);\n"
        "    SetConsoleCP(65001);\n"
        "#endif\n"
        "}\n\n"
        "static void pause_exit(void){\n"
        "#ifdef _WIN32\n"
        "    printf(\"\\n按任意键退出...\");\n"
        "    _getch();\n"
        "#else\n"
        "    printf(\"\\n按回车键退出...\");\n"
        "    getchar();\n"
        "#endif\n"
        "}\n\n"
        "static void read_pw(char *buf, int n) {\n"
        "#ifdef _WIN32\n"
        "    int i = 0, c;\n"
        "    while (i < n - 1 && (c = _getch()) != 13) {\n"
        "        if (c == 8) { if (i > 0) { i--; printf(\"\\b \\b\"); } }\n"
        "        else if (c == 0 || c == 0xE0) _getch();\n"
        "        else if (c >= 32) { buf[i++] = (char)c; putchar('*'); }\n"
        "    }\n"
        "    buf[i] = 0;\n"
        "    putchar('\\n');\n"
        "#else\n"
        "    int i = 0;\n"
        "    if (fgets(buf, n, stdin)) {\n"
        "        while (buf[i] && buf[i] != '\\n' && buf[i] != '\\r') i++;\n"
        "        buf[i] = 0;\n"
        "    }\n"
        "#endif\n"
        "}\n\n"
        "int main(void) {\n"
        "    char pw[256];\n"
        "    uint8_t key[32];\n"
        "    uint8_t *iv = (uint8_t*)DATA;\n"
        "    uint8_t *ct = (uint8_t*)DATA + 16;\n"
        "    size_t n = sizeof(DATA) - 16;\n"
        "    uint8_t *p;\n"
        "    AES_CTX ctx;\n"
        "    set_utf8();\n"
        "    printf(\"密码: \");\n"
        "    read_pw(pw, sizeof(pw));\n"
        "    sha256((const uint8_t*)pw, strlen(pw), key);\n"
        "    p = (uint8_t*)malloc(n);\n"
        "    if (!p) { pause_exit(); return 1; }\n"
        "    memcpy(p, ct, n);\n"
        "    AES_init_ctx(&ctx, key, iv);\n"
        "    AES_CTR_xcrypt(&ctx, p, n);\n"
        "    if (n < 8 || memcmp(p, \"SCRTAES1\", 8) != 0) {\n"
        "        printf(\"密码错误\\n\");\n"
        "        free(p);\n"
        "        pause_exit();\n"
        "        return 1;\n"
        "    }\n"
        "    fwrite(p + 8, 1, n - 8, stdout);\n"
        "    printf(\"\\n\");\n"
        "    free(p);\n"
        "    pause_exit();\n"
        "    return 0;\n"
        "}\n", f);
    fclose(f);

    printf("编译中...\n");
    sprintf(cmd, "tcc -o \"%s\" _stub.c", outname);
    rc = system(cmd);
    if (rc != 0) {
        sprintf(cmd, "gcc -O2 -o \"%s\" _stub.c", outname);
        rc = system(cmd);
    }
    remove("_stub.c");

    free(text); free(data);

    if (rc == 0) {
        printf("完成: %s\n", outname);
        end_delay(1500);
    } else {
        printf("编译失败(需要 tcc 或 gcc 在 PATH 中)\n");
        end_delay(3000);
    }
    return rc == 0 ? 0 : 1;
}