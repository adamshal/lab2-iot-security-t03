/* Each endpoint compiles this shared application with its own provisioned keys. */
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "sec_protocol.h"
#include "identity.h"
LOG_MODULE_REGISTER(secure_lora, LOG_LEVEL_INF);
static struct protocol session;
static const struct device *radio;
static struct lora_modem_config radio_config;
static bool transmitting;
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
/* Keep the radio listening across state-machine polls: a full packet takes
 * much longer than 100 ms at SF10. A polling RX timeout would abort it. */
struct incoming_packet { uint8_t data[255]; uint16_t len; };
K_MSGQ_DEFINE(radio_rx,sizeof(struct incoming_packet),4,4);
static void received(const struct device *dev,uint8_t *data,uint16_t len,
                     int16_t rssi,int8_t snr,void *user)
{
 ARG_UNUSED(dev); ARG_UNUSED(rssi); ARG_UNUSED(snr); ARG_UNUSED(user);
 if(len>255) return;
 struct incoming_packet packet;
 packet.len=len; memcpy(packet.data,data,len);
 k_msgq_put(&radio_rx,&packet,K_NO_WAIT);
}
static int mode(bool tx)
{
 if(transmitting==tx) return 0;
 if(tx) {
  int rc=lora_recv_async(radio,NULL,NULL);
  if(rc) return rc;
 }
 radio_config.tx=tx;
 int rc=lora_config(radio,&radio_config);
 if(!rc && !tx) rc=lora_recv_async(radio,received,NULL);
 if(!rc) transmitting=tx;
 return rc;
}
int main(void)
{
 radio=DEVICE_DT_GET(DT_ALIAS(lora0));
 if(!device_is_ready(radio)) { LOG_ERR("Radio not ready"); return 1; }
 if(gpio_is_ready_dt(&led)) gpio_pin_configure_dt(&led,GPIO_OUTPUT_INACTIVE);
 if(!proto_selftest()) { LOG_ERR("Crypto self-test FAIL; stopping"); return 1; }
 uint8_t identity_sig[64];
 sec_sign(identity_sig,identity_private,identity_public,identity_public,32);
 if(!sec_verify(identity_sig,identity_public,identity_public,32)) {
  LOG_ERR("Provisioned signing identity self-test FAIL"); return 1;
 }
 LOG_INF("Provisioned signing identity self-test PASS");
 LOG_INF("Crypto self-test PASS (AES vector, signature/tamper, DH agreement)");
 /* Preserve the physical settings supplied by the course starter. */
 radio_config=(struct lora_modem_config){.frequency=433920000,.bandwidth=BW_125_KHZ,
  .datarate=SF_10,.preamble_len=8,.coding_rate=CR_4_5,.iq_inverted=false,
  .public_network=false,.tx_power=-15,.tx=false};
 int rc=lora_config(radio,&radio_config);
 if(rc) { LOG_ERR("Radio config failed: %d",rc); return 1; }
 transmitting=false;
 rc=lora_recv_async(radio,received,NULL);
 if(rc) { LOG_ERR("Continuous RX failed: %d",rc); return 1; }
 proto_init(&session,IS_CLIENT,identity_public,identity_private,peer_public,k_uptime_get());
 LOG_INF("Secure LoRa %s ready: 433.92 MHz, SF10, pinned peer identity",IS_CLIENT?"CLIENT":"SERVER");
 LOG_INF("Max packet %u B; signatures %u B; application payload <= %u B",PROTO_PACKET,SEC_SIG_LEN,PROTO_PAYLOAD);
 struct incoming_packet incoming; enum proto_state previous=session.state;
 while(1) {
  int64_t now=k_uptime_get();
  if(session.state!=WAIT_HELLO && now-session.progress>=PROTO_TIMEOUT) {
   LOG_INF("Peer silent for 60 s; restarting handshake with fresh session keys");
  }
  size_t n=proto_poll(&session,now);
  if(session.state!=previous) {
   LOG_INF("State %d -> %d%s",previous,session.state,session.state==WAIT_HELLO_ACK?" (fresh handshake)":"");
   previous=session.state;
  }
  if(n) {
   rc=mode(true);
   if(!rc) rc=lora_send(radio,session.tx,(uint8_t)n);
   if(rc) LOG_ERR("TX failed: %d",rc);
   else LOG_INF("TX type=%u seq=%lu bytes=%u copy=%lu",session.tx[5],
      (unsigned long)(session.client?session.seq:session.highest),(unsigned)n,(unsigned long)session.copies);
  }
  rc=mode(false);
  if(rc) { LOG_ERR("RX mode failed: %d",rc); k_msleep(100); continue; }
  rc=k_msgq_get(&radio_rx,&incoming,K_MSEC(100));
  if(!rc) {
   int accepted=proto_receive(&session,incoming.data,incoming.len,k_uptime_get());
   if(accepted<0) LOG_WRN("Rejected packet: %d",accepted);
   else if(accepted==1) {
    LOG_INF("DELIVER seq=%lu: %s",(unsigned long)session.highest,session.received);
    if(gpio_is_ready_dt(&led)) gpio_pin_toggle_dt(&led);
   } else LOG_INF("Accepted control/duplicate type=%u",incoming.data[5]);
  } else if(rc!=-EAGAIN && rc!=-ENOMSG) {
   LOG_WRN("RX queue failed: %d",rc); k_msleep(100);
  }
 }
}
