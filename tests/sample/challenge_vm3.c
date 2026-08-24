/*
 * challenge_vm3.c -- Lethe red-team crackme, ROUND 3 (exponentially harder).
 *
 * The password check runs as HISTORY-KEYED ROLLING bytecode with a per-build
 * shuffled ISA inside an embedded stack VM. There is NO statically-decodable
 * bytecode: at rest the program is ciphertext, and the VM reconstructs ONE
 * instruction at a time from a keystream folded over the execution history of
 * the current basic block. An analyst cannot dump-and-decode (round-2's method);
 * they must trace the LIVE decode, instruction by instruction, and re-derive the
 * shuffled ISA per build. (The whole payload is then packed by Lethe.)
 *
 * The flag remains XOR-keyed to the real password bytes, so a hash collision
 * yields a garbage flag -- only the true password reveals the true flag.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <intrin.h>          /* __readgsqword for the observation-poison */
#include "check_vm3_blob.h"

/* Observation-poison: read PEB->BeingDebugged (0 on every honest run) and fold
 * it, avalanche-spread, into the VM's per-block seed. A clean run is bit-
 * identical to the pack-time encoder (which assumes 0); under a debugger the
 * signal is non-zero, every block mis-decodes, the hash comes out wrong, and
 * the check denies -- with no branch to NOP. Neutralizing it requires clearing
 * BeingDebugged (a stealth-debug move), not a patch. */
static uint64_t vm_poison(void)
{
    const unsigned char *peb = (const unsigned char *)__readgsqword(0x60);
    uint64_t p = peb ? (uint64_t)peb[0x002] : 0;   /* BeingDebugged */
    if (p) { p ^= 0x9E3779B97F4A7C15ULL; p *= 0xFF51AFD7ED558CCDULL; p ^= (p >> 33); }
    return p;   /* 0 clean -> no effect */
}

/* ---- tiny self-contained SHA-256 (mirrors the rolling primitives) -------- */
typedef struct { uint32_t s[8]; uint64_t n; uint8_t b[64]; uint32_t bl; } sha256;
static uint32_t ror(uint32_t x, int r){ return (x>>r)|(x<<(32-r)); }
static void sha256_blk(sha256 *c, const uint8_t *p){
    static const uint32_t K[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64],a,b,cc,d,e,f,g,h; int i;
    for(i=0;i<16;i++) w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for(i=16;i<64;i++){ uint32_t s0=ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1; }
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for(i=0;i<64;i++){ uint32_t S1=ror(e,6)^ror(e,11)^ror(e,25); uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+S1+ch+K[i]+w[i]; uint32_t S0=ror(a,2)^ror(a,13)^ror(a,22);
        uint32_t mj=(a&b)^(a&cc)^(b&cc); uint32_t t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2; }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha256_init(sha256 *c){ c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;
    c->s[3]=0xa54ff53a;c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
    c->n=0;c->bl=0; }
static void sha256_upd(sha256 *c,const uint8_t *p,uint32_t l){ c->n+=l;
    while(l){ uint32_t t=64-c->bl; if(t>l)t=l; memcpy(c->b+c->bl,p,t); c->bl+=t;p+=t;l-=t;
        if(c->bl==64){ sha256_blk(c,c->b); c->bl=0; } } }
static void sha256_fin(sha256 *c,uint8_t out[32]){ uint64_t bits=c->n*8; uint8_t pad=0x80;
    sha256_upd(c,&pad,1); uint8_t z=0; while(c->bl!=56) sha256_upd(c,&z,1);
    uint8_t lb[8]; int i; for(i=0;i<8;i++) lb[i]=(uint8_t)(bits>>(56-i*8)); sha256_upd(c,lb,8);
    for(i=0;i<8;i++){ out[i*4]=c->s[i]>>24;out[i*4+1]=c->s[i]>>16;out[i*4+2]=c->s[i]>>8;out[i*4+3]=c->s[i]; } }
static void sha256_hash(const uint8_t *p,uint32_t l,uint8_t out[32]){ sha256 c; sha256_init(&c); sha256_upd(&c,p,l); sha256_fin(&c,out); }

/* ---- rolling primitives (mirror venice_rolling) -------------------------- */
static uint64_t rotl64(uint64_t v,int r){ r&=63; return r? (v<<r)|(v>>(64-r)) : v; }
static uint64_t rd64le(const uint8_t *p){ uint64_t v=0;int i;for(i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v; }
static uint64_t roll_resync(const uint8_t seed[16], uint32_t leader){
    uint8_t buf[16+1+4],d[32]; int i; for(i=0;i<16;i++)buf[i]=seed[i];
    buf[16]='R'; buf[17]=leader; buf[18]=leader>>8; buf[19]=leader>>16; buf[20]=leader>>24;
    sha256_hash(buf,sizeof(buf),d); return rd64le(d);
}
static void roll_keystream(const uint8_t seed[16], uint32_t pc, uint64_t acc, uint8_t out[9]){
    uint8_t buf[16+1+4+8],d[32]; int i; for(i=0;i<16;i++)buf[i]=seed[i];
    buf[16]='K'; buf[17]=pc;buf[18]=pc>>8;buf[19]=pc>>16;buf[20]=pc>>24;
    for(i=0;i<8;i++) buf[21+i]=(uint8_t)(acc>>(8*i));
    sha256_hash(buf,sizeof(buf),d); for(i=0;i<9;i++) out[i]=d[i];
}
static uint64_t roll_fold(uint64_t acc,const uint8_t *plain,uint32_t len,uint32_t pc){
    uint32_t i; for(i=0;i<len;i++){ acc=rotl64(acc^(uint64_t)plain[i],7); acc=acc+0x9E3779B97F4A7C15ULL; }
    acc^=(uint64_t)pc; return acc;
}
static uint32_t canon_width(uint8_t op){ switch(op){
    case 0x02:return 1; case 0x03:return 4; case 0x04:return 8; case 0x18:case 0x19:case 0x1A:case 0x1B:return 4;
    case 0x1C:return 1; case 0x1D:case 0x1E:return 2; case 0x33:return 2; case 0x37:return 1; default:return 0; } }

/* ---- rolling-decoding stack VM ------------------------------------------- */
static int run_vm3(const uint8_t *ct,uint32_t ct_len,const uint8_t seed[16],
                   const uint8_t *leaders,uint16_t nlead,const uint8_t *data,
                   uint8_t *locals,const uint64_t *args){
    uint64_t st[64]; int sp=0; uint32_t pc=0; uint64_t acc=0;
#define PUSH(v) do{ if(sp>=64)return -1; st[sp++]=(uint64_t)(v); }while(0)
#define POP() (st[--sp])
    while(pc<ct_len){
        uint8_t ks[9],win[9]; uint8_t wire,op; uint32_t w,ilen,i;
        /* leader? reseed acc */
        for(i=0;i<nlead;i++){ uint32_t L=leaders[i*4]|(leaders[i*4+1]<<8)|(leaders[i*4+2]<<16)|((uint32_t)leaders[i*4+3]<<24);
            if(L==pc){ acc=roll_resync(seed,pc) ^ vm_poison(); break; } }
        roll_keystream(seed,pc,acc,ks);
        wire=(uint8_t)(ct[pc]^ks[0]);
        op=CV3_UNMAP[wire];                 /* per-build shuffle unmap */
        if(op>0x37) return -1;
        w=canon_width(op); ilen=1+w;
        if(pc+ilen>ct_len) return -1;
        for(i=0;i<ilen;i++) win[i]=(uint8_t)(ct[pc+i]^ks[i]);
        acc=roll_fold(acc,win,ilen,pc);     /* chain within block */
        /* dispatch on canonical op, operands from `win` */
        switch(op){
        case 0x00: return sp? (int)st[sp-1] : -1;                 /* halt */
        case 0x02: PUSH(win[1]); pc+=2; break;                    /* push_imm8 */
        case 0x04: { uint64_t v=0;int k;for(k=0;k<8;k++)v|=(uint64_t)win[1+k]<<(8*k); PUSH(v);} pc+=9; break; /* push_imm64 */
        case 0x07: { uint64_t a=POP(),b=POP(); PUSH(a);PUSH(b);} pc+=1; break; /* swap */
        case 0x08: { uint64_t b=POP(),a=POP(); PUSH(a+b);} pc+=1; break;
        case 0x0A: { uint64_t b=POP(),a=POP(); PUSH(a^b);} pc+=1; break;
        case 0x0B: { uint64_t b=POP(),a=POP(); PUSH(a&b);} pc+=1; break;
        case 0x0E: { uint64_t b=POP(),a=POP(); PUSH(a>>(b&63));} pc+=1; break;
        case 0x0F: { uint64_t b=POP(),a=POP(); PUSH(a*b);} pc+=1; break;
        case 0x10: { uint64_t ad=POP(); PUSH(*(uint8_t*)(uintptr_t)ad);} pc+=1; break;
        case 0x12: { uint64_t ad=POP(); PUSH(*(uint64_t*)(uintptr_t)ad);} pc+=1; break;
        case 0x13: { uint64_t v=POP(),ad=POP(); *(uint8_t*)(uintptr_t)ad=(uint8_t)v;} pc+=1; break;
        case 0x15: { uint64_t v=POP(),ad=POP(); *(uint64_t*)(uintptr_t)ad=v;} pc+=1; break;
        case 0x16: { uint64_t b=POP(),a=POP(); PUSH(a==b?1:0);} pc+=1; break;
        case 0x17: { uint64_t b=POP(),a=POP(); PUSH(a<b?1:0);} pc+=1; break;
        case 0x18: { uint32_t t=win[1]|(win[2]<<8)|(win[3]<<16)|((uint32_t)win[4]<<24); pc=t;} break;
        case 0x19: { uint64_t c=POP(); uint32_t t=win[1]|(win[2]<<8)|(win[3]<<16)|((uint32_t)win[4]<<24); pc=(c==0)?t:pc+5;} break;
        case 0x1C: PUSH(args[win[1]]); pc+=2; break;              /* push_arg */
        case 0x1D: { uint16_t off=win[1]|(win[2]<<8); PUSH((uintptr_t)&locals[off]); pc+=3; } break;
        case 0x1E: { uint16_t off=win[1]|(win[2]<<8); PUSH((uintptr_t)&data[off]); pc+=3; } break;
        case 0x2D: { uint64_t b=POP(),a=POP(); if(!b)return -1; PUSH(a%b);} pc+=1; break;
        default: return -1;
        }
    }
    return -1;
#undef PUSH
#undef POP
}

int main(int argc,char **argv){
    unsigned char cont[CV3_CONT_LEN]; uint8_t locals[1024]; uint64_t args[1];
    unsigned char k; int i,n,rc;
    if(argc<2){ printf("usage: challenge <password>\n"); return 2; }
    /* de-obfuscate the rolling container */
    k=CV3_XOR_SEED;
    for(i=0;i<CV3_CONT_LEN;i++){ cont[i]=(unsigned char)(CV3_CONT_OBF[i]^k); k=(unsigned char)(k*33+7); }
    /* parse container: [2 'VR'][16 seed][u16 ds][data][u16 nlead][u32 leaders][ct] */
    {
        uint32_t off=2; const uint8_t *seed=cont+off; off+=16;
        uint16_t ds=cont[off]|(cont[off+1]<<8); off+=2;
        const uint8_t *data=cont+off; off+=ds;
        uint16_t nlead=cont[off]|(cont[off+1]<<8); off+=2;
        const uint8_t *leaders=cont+off; off+=(uint32_t)nlead*4;
        const uint8_t *ct=cont+off; uint32_t ct_len=CV3_CONT_LEN-off;

        memset(locals,0,sizeof(locals));
        n=(int)strlen(argv[1]);
        if(n<=0||n>63){ printf("ACCESS DENIED\n"); return 1; }
        memcpy(locals,argv[1],(size_t)n);
        args[0]=(uint64_t)n;

        rc=run_vm3(ct,ct_len,seed,leaders,nlead,data,locals,args);
    }
    if(rc==0){
        char flag[CV3_FLAG_LEN+1];
        memcpy(flag,locals+CV3_FLAG_OFF,CV3_FLAG_LEN); flag[CV3_FLAG_LEN]=0;
        printf("ACCESS GRANTED: %s\n",flag); return 0;
    }
    printf("ACCESS DENIED\n"); return 1;
}
