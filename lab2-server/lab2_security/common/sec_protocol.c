#include "sec_protocol.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

static const uint8_t magic[4] = {'E','5','L','2'};
static const uint8_t client_proof[16] = "client-key-ok-v1";
static const uint8_t server_proof[16] = "server-key-ok-v1";
static bool zero(const uint8_t *b, size_t n) { uint8_t v=0; while(n--) v|=*b++; return v==0; }
static void put32(uint8_t *b,uint32_t v) { for(int i=0;i<4;i++) b[i]=(uint8_t)(v>>(8*i)); }
static uint32_t get32(const uint8_t *b) { return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24; }

/* AES-CTR built from the required AES128 block API. Type, sequence and block
 * occupy disjoint fields. A fresh DH-derived key is used for every session. */
static void crypt(struct protocol *p,uint8_t type,uint32_t seq,uint8_t *out,const uint8_t *in,size_t len)
{
 uint8_t counter[16]={0}, stream[16];
 memcpy(counter,p->iv_prefix,7); counter[7]=type; put32(counter+8,seq);
 for(size_t off=0;off<len;off+=16) {
  put32(counter+12,(uint32_t)(off/16));
  sec_aes128_encrypt(stream,p->key,counter,16);
  size_t n=len-off<16?len-off:16;
  for(size_t j=0;j<n;j++) out[off+j]=in[off+j]^stream[j];
 }
 memset(stream,0,sizeof(stream));
}
static void packet(struct protocol *p,uint8_t type,uint32_t seq,const uint8_t *body,size_t len,bool encrypt)
{
 uint8_t *b=p->tx;
 memcpy(b,magic,4); b[4]=1; b[5]=type; b[6]=(uint8_t)len; b[7]=0; put32(b+8,seq);
 memcpy(b+12,p->client_nonce,16); memcpy(b+28,p->server_nonce,16);
 if(encrypt) crypt(p,type,seq,b+PROTO_HEADER,body,len);
 else if(len) memcpy(b+PROTO_HEADER,body,len);
 sec_sign(b+PROTO_HEADER+len,p->own_priv,p->own_pub,b,PROTO_HEADER+len);
 p->tx_len=PROTO_HEADER+len+SEC_SIG_LEN; p->tx_pending=true;
}
static void hello(struct protocol *p,bool reply)
{
 uint8_t body[64]; memcpy(body,p->own_pub,32); memcpy(body+32,p->dh_pub,32);
 packet(p,reply?HELLO_ACK:HELLO,0,body,sizeof(body),false);
}
static bool derive(struct protocol *p)
{
 uint8_t input[144]={0},digest[32];
 /* Fixed length and ordering bind the secret to both nonces and DH keys. */
 memcpy(input,"ESE5180-DH-v1",13);
 if(!sec_dh_shared(input+16,p->peer_dh,p->dh_priv)) return false;
 memcpy(input+48,p->client_nonce,16); memcpy(input+64,p->server_nonce,16);
 memcpy(input+80,p->client?p->dh_pub:p->peer_dh,32);
 memcpy(input+112,p->client?p->peer_dh:p->dh_pub,32);
 sec_sha256(digest,input,sizeof(input)); memcpy(p->key,digest,16);
 memcpy(p->iv_prefix,digest+16,7); memset(input,0,sizeof(input)); memset(digest,0,sizeof(digest));
 return true;
}
static void restart(struct protocol *p,int64_t now)
{
 memset(p->key,0,sizeof(p->key)); memset(p->dh_priv,0,sizeof(p->dh_priv));
 memset(p->client_nonce,0,16); memset(p->server_nonce,0,16);
 p->seq=0; p->highest=0; p->copies=0; p->acked=false; p->tx_pending=false;
 p->progress=now; p->due=now; p->received_len=0;
 p->state=p->client?WAIT_HELLO_ACK:WAIT_HELLO;
 if(p->client) { sec_random(p->client_nonce,16); sec_dh_keygen(p->dh_pub,p->dh_priv); hello(p,false); }
}
void proto_init(struct protocol *p,bool client,const uint8_t pub[32],const uint8_t priv[32],const uint8_t peer[32],int64_t now)
{
 memset(p,0,sizeof(*p)); p->client=client;
 memcpy(p->own_pub,pub,32); memcpy(p->own_priv,priv,32); memcpy(p->peer_pub,peer,32); restart(p,now);
}
static void data_packet(struct protocol *p)
{
 char text[PROTO_PAYLOAD]; int len=snprintf(text,sizeof(text),"ESE5180 secure hello #%lu",(unsigned long)p->seq);
 packet(p,DATA,p->seq,(const uint8_t *)text,(size_t)len,true);
 p->copies=0; p->acked=false;
}
int proto_receive(struct protocol *p,const uint8_t *b,size_t len,int64_t now)
{
 if(len<PROTO_HEADER+SEC_SIG_LEN || memcmp(b,magic,4) || b[4]!=1 || b[7]!=0 ||
    b[6]>PROTO_PAYLOAD || len!=(size_t)(PROTO_HEADER+b[6]+SEC_SIG_LEN)) return -EINVAL;
 uint8_t type=b[5], n=b[6]; uint32_t seq=get32(b+8); const uint8_t *body=b+PROTO_HEADER;
 if(type<HELLO || type>DATA_ACK || ((type==HELLO||type==HELLO_ACK)?n!=64:
    (type==CONFIRM||type==READY)?n!=16:type==DATA_ACK?n!=0:n==0) ||
    ((type==DATA||type==DATA_ACK)?seq==0:seq!=0)) return -EINVAL;
 /* Never trust the public key advertised inside an incoming packet as a root
  * of identity: verify against the separately provisioned peer key. */
 if(!sec_verify(body+n,p->peer_pub,b,PROTO_HEADER+n)) return -EACCES;
 if(!p->client && type==HELLO) {
  if(memcmp(body,p->peer_pub,32) || zero(b+12,16) || !zero(b+28,16)) return -EACCES;
  if(p->state!=WAIT_HELLO && !memcmp(b+12,p->client_nonce,16)) {
   if(p->state==WAIT_CONFIRM) { hello(p,true); p->due=now+200; }
   return 0;
  }
  restart(p,now); memcpy(p->client_nonce,b+12,16); sec_random(p->server_nonce,16);
  memcpy(p->peer_dh,body+32,32); sec_dh_keygen(p->dh_pub,p->dh_priv);
  if(!derive(p)) { restart(p,now); return -EACCES; }
  p->state=WAIT_CONFIRM; hello(p,true); p->due=now+200; return 0;
 }
 if(memcmp(b+12,p->client_nonce,16)) return -ESTALE;
 if(p->client && type==HELLO_ACK && p->state==WAIT_HELLO_ACK) {
  if(memcmp(body,p->peer_pub,32) || zero(b+28,16)) return -EACCES;
  memcpy(p->server_nonce,b+28,16); memcpy(p->peer_dh,body+32,32);
  if(!derive(p)) { restart(p,now); return -EACCES; }
  p->progress=now; p->state=WAIT_READY;
  packet(p,CONFIRM,0,client_proof,16,true); p->due=now+200; return 0;
 }
 if(memcmp(b+28,p->server_nonce,16)) return -ESTALE;
 if(!p->client && type==CONFIRM && (p->state==WAIT_CONFIRM||p->state==WAIT_DATA||p->state==PAIRED)) {
  uint8_t plain[16]; crypt(p,type,0,plain,body,16);
  if(memcmp(plain,client_proof,16)) return -EACCES;
  if(p->state==WAIT_CONFIRM) { p->state=WAIT_DATA; p->progress=now; }
  packet(p,READY,0,server_proof,16,true); p->due=now+200; return 0;
 }
 if(p->client && type==READY && p->state==WAIT_READY) {
  uint8_t plain[16]; crypt(p,type,0,plain,body,16);
  if(memcmp(plain,server_proof,16)) return -EACCES;
  p->state=PAIRED; p->progress=now; p->seq=1; data_packet(p); p->due=now+400; return 0;
 }
 if(!p->client && type==DATA && (p->state==WAIT_DATA||p->state==PAIRED)) {
  if(seq<p->highest) return -ESTALE;
  p->state=PAIRED; p->progress=now;
  packet(p,DATA_ACK,seq,NULL,0,false); p->due=now+200;
  if(seq==p->highest) return 0; /* ACK duplicates without delivering them twice. */
  crypt(p,type,seq,(uint8_t *)p->received,body,n); p->received[n]=0;
  p->received_len=n; p->highest=seq; return 1;
 }
 if(p->client && type==DATA_ACK && p->state==PAIRED && seq==p->seq) {
  if(!p->acked) p->progress=now;
  p->acked=true; return 0;
 }
 return -ESTALE;
}
size_t proto_poll(struct protocol *p,int64_t now)
{
 if(p->state!=WAIT_HELLO && now-p->progress>=PROTO_TIMEOUT) restart(p,now);
 if(p->client && p->state==PAIRED && now>=p->due && p->copies>=2 && p->acked) {
  if(p->seq==UINT32_MAX) restart(p,now);
  else { ++p->seq; data_packet(p); }
 }
 if(!p->tx_pending || now<p->due) return 0;
 if(p->client && p->state==PAIRED) {
  ++p->copies;
  p->due=now+(p->copies==1?4000:12000);
 } else {
  p->due=now+PROTO_RETRY;
  if(!p->client && p->state==PAIRED) p->tx_pending=false;
 }
 return p->tx_len;
}
bool proto_selftest(void)
{
 static const uint8_t key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
 static const uint8_t pt[16]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
 static const uint8_t expected[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,4,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
 uint8_t ct[16],plain[16],pub[32],priv[32],sig[64];
 sec_aes128_encrypt(ct,key,pt,16); sec_aes128_decrypt(plain,key,ct,16);
 if(memcmp(ct,expected,16)||memcmp(plain,pt,16)) return false;
 sec_sign_keygen(pub,priv); sec_sign(sig,priv,pub,pt,16);
 if(!sec_verify(sig,pub,pt,16)) return false;
 sig[0]^=1; if(sec_verify(sig,pub,pt,16)) return false;
 uint8_t a_pub[32],a_priv[32],b_pub[32],b_priv[32],a[32],b[32];
 sec_dh_keygen(a_pub,a_priv); sec_dh_keygen(b_pub,b_priv);
 bool ok=sec_dh_shared(a,b_pub,a_priv)&&sec_dh_shared(b,a_pub,b_priv)&&!memcmp(a,b,32);
 memset(priv,0,32); memset(a,0,32); memset(b,0,32); return ok;
}
