#ifndef __BROADLINK_H
#define __BROADLINK_H 1
#if (ARDUINO >= 100)
 #include <Arduino.h>
#else
 #include <WProgram.h>
 #include <pins_arduino.h>
#endif
#include <WiFiUdp.h>

#define BROADLINK_DEV_RMMINI 0x2737
#define BROADLINK_DEV_MP1 0x4EB5
#define BROADLINK_DEV_SP3S 0x947A

class BroadLinkESP
{
public:
  byte _debug;
  uint16_t _devtype;
  byte _tomac[6];
  IPAddress _toip;
  WiFiUDP _udp;
  int _fgot;
  int _fready;
 
  byte *_ptlearn;
  int _cblearn;

  BroadLinkESP(uint16_t devtype);
  void setDebug(int dbg);
  void setDestIP(char *ipstr);
  void setDestMAC(byte *inmac);  

  void decryptData(byte *payload,int cbpayload);
  void encryptData(byte *payload,int cbpayload);
  void preparePacket(byte cmd,byte *payload,int cbpayload);
  void preparePacketAuth(void);
  void preparePacketSetPowerMask(byte sid_mask,byte state);
  void preparePacketSetPower(byte sno,byte onoff);
  void preparePacketSetSpPower(byte onoff);
  void preparePacketEnterLearn(void);
  void preparePacketCheckData(void);
  void sendPacket(void);
  int checkReadPacket(void);
  int readPacket(int packetSize);
  int isReady(void);

private:
  byte *_packet;
  uint16_t _cbpacket;
  byte _typepacket;
  byte _fwaitresp;
  unsigned long _tsent;
  byte _ntrysend;

  byte _key[16];
  byte _id[4]; 
  uint16_t _seq;
};

#endif
