/* aes_sha.h - SHA-256 + AES-256-CTR (encrypt only). TCC compatible. */
#ifndef AES_SHA_H
#define AES_SHA_H
#include <stdint.h>
#include <string.h>

/* ---------- SHA-256 ---------- */
typedef struct { uint32_t state[8]; uint64_t bitlen; uint8_t data[64]; uint32_t datalen; } SHA256_CTX;
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i=0,j=0;i<16;++i,j+=4)
        m[i] = ((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)|((uint32_t)data[j+2]<<8)|((uint32_t)data[j+3]);
    for (;i<64;++i) m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (i=0;i<64;++i){
        t1=h+EP1(e)+CH(e,f,g)+k256[i]+m[i];
        t2=EP0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}
static void sha256_init(SHA256_CTX *c){
    c->datalen=0;c->bitlen=0;
    c->state[0]=0x6a09e667;c->state[1]=0xbb67ae85;c->state[2]=0x3c6ef372;c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f;c->state[5]=0x9b05688c;c->state[6]=0x1f83d9ab;c->state[7]=0x5be0cd19;
}
static void sha256_update(SHA256_CTX *c, const uint8_t d[], size_t len){
    size_t i;
    for (i=0;i<len;++i){
        c->data[c->datalen++]=d[i];
        if (c->datalen==64){ sha256_transform(c,c->data); c->bitlen+=512; c->datalen=0; }
    }
}
static void sha256_final(SHA256_CTX *c, uint8_t h[]){
    uint32_t i=c->datalen;
    if (i<56){ c->data[i++]=0x80; while(i<56) c->data[i++]=0; }
    else      { c->data[i++]=0x80; while(i<64) c->data[i++]=0; sha256_transform(c,c->data); memset(c->data,0,56); }
    c->bitlen+=(uint64_t)c->datalen*8;
    c->data[63]=(uint8_t)(c->bitlen); c->data[62]=(uint8_t)(c->bitlen>>8);
    c->data[61]=(uint8_t)(c->bitlen>>16); c->data[60]=(uint8_t)(c->bitlen>>24);
    c->data[59]=(uint8_t)(c->bitlen>>32); c->data[58]=(uint8_t)(c->bitlen>>40);
    c->data[57]=(uint8_t)(c->bitlen>>48); c->data[56]=(uint8_t)(c->bitlen>>56);
    sha256_transform(c,c->data);
    for (i=0;i<4;++i){
        h[i]=(uint8_t)(c->state[0]>>(24-i*8)); h[i+4]=(uint8_t)(c->state[1]>>(24-i*8));
        h[i+8]=(uint8_t)(c->state[2]>>(24-i*8)); h[i+12]=(uint8_t)(c->state[3]>>(24-i*8));
        h[i+16]=(uint8_t)(c->state[4]>>(24-i*8)); h[i+20]=(uint8_t)(c->state[5]>>(24-i*8));
        h[i+24]=(uint8_t)(c->state[6]>>(24-i*8)); h[i+28]=(uint8_t)(c->state[7]>>(24-i*8));
    }
}
static void sha256(const uint8_t *in, size_t len, uint8_t out[32]){
    SHA256_CTX c; sha256_init(&c); sha256_update(&c,in,len); sha256_final(&c,out);
}

/* ---------- AES-256 (encrypt only, for CTR) ---------- */
typedef struct { uint8_t key[240]; uint8_t iv[16]; uint8_t buf[16]; size_t buf_len; } AES_CTX;

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
#define xtime(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))

static void KeyExpansion(uint8_t *rk, const uint8_t *k){
    unsigned i,j; uint8_t t[4];
    for (i=0;i<8;++i){ rk[i*4]=k[i*4]; rk[i*4+1]=k[i*4+1]; rk[i*4+2]=k[i*4+2]; rk[i*4+3]=k[i*4+3]; }
    for (i=8;i<60;++i){
        for (j=0;j<4;++j) t[j]=rk[(i-1)*4+j];
        if (i%8==0){
            uint8_t k0=t[0];
            t[0]=sbox[t[1]]; t[1]=sbox[t[2]]; t[2]=sbox[t[3]]; t[3]=sbox[k0];
            t[0]^=(uint8_t)(1<<(i/8-1));
        } else if (i%8==4){
            t[0]=sbox[t[0]];t[1]=sbox[t[1]];t[2]=sbox[t[2]];t[3]=sbox[t[3]];
        }
        for (j=0;j<4;++j) rk[i*4+j]=rk[(i-8)*4+j]^t[j];
    }
}
static void AddRoundKey(uint8_t r, uint8_t *s, const uint8_t *rk){
    int i; for (i=0;i<16;++i) s[i]^=rk[r*16+i];
}
static void SubBytes(uint8_t *s){ int i; for (i=0;i<16;++i) s[i]=sbox[s[i]]; }
static void ShiftRows(uint8_t *s){
    uint8_t t;
    t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
    t=s[2];s[2]=s[10];s[10]=t;
    t=s[6];s[6]=s[14];s[14]=t;
    t=s[3];s[3]=s[15];s[15]=s[11];s[11]=s[7];s[7]=t;
}
static void MixColumns(uint8_t *s){
    int i; uint8_t a,b,c,d;
    for (i=0;i<4;++i){
        a=s[i*4];b=s[i*4+1];c=s[i*4+2];d=s[i*4+3];
        s[i*4]  = xtime(a)^(xtime(b)^b)^c^d;
        s[i*4+1]= a^xtime(b)^(xtime(c)^c)^d;
        s[i*4+2]= a^b^xtime(c)^(xtime(d)^d);
        s[i*4+3]= (xtime(a)^a)^b^c^xtime(d);
    }
}
static void Cipher(uint8_t *s, const uint8_t *rk){
    uint8_t r;
    AddRoundKey(0,s,rk);
    for (r=1;r<14;++r){ SubBytes(s); ShiftRows(s); MixColumns(s); AddRoundKey(r,s,rk); }
    SubBytes(s); ShiftRows(s); AddRoundKey(14,s,rk);
}
static void AES_init_ctx(AES_CTX *c, const uint8_t *k, const uint8_t *iv){
    KeyExpansion(c->key,k); memcpy(c->iv,iv,16); c->buf_len=0;
}
static void AES_CTR_xcrypt(AES_CTX *c, uint8_t *b, size_t len){
    size_t i=0;
    while (i<len){
        if (c->buf_len==0){
            int j;
            memcpy(c->buf,c->iv,16);
            Cipher(c->buf,c->key);
            for (j=15;j>=0;--j) if (++c->iv[j]) break;
            c->buf_len=16;
        }
        {
            size_t n=len-i, off=16-c->buf_len, k;
            if (n>c->buf_len) n=c->buf_len;
            for (k=0;k<n;++k) b[i+k]^=c->buf[off+k];
            c->buf_len-=n; i+=n;
        }
    }
}
#endif