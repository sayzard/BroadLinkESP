#include "BroadLinkESP.h"
#include <AESLib.h>

static byte brd_key[16] = { 0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02};
static byte brd_iv[N_BLOCK] = { 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58};
BroadLinkESP::BroadLinkESP(uint16_t devtype)
{
  _debug=0;
  _devtype=devtype;
  _packet=NULL;
  _cbpacket=0;
  _typepacket=0;
  _fwaitresp=0;
  _seq=0;
  _fgot=0;
  _fready=0;
  memset(_id,0,sizeof(_id));
  memcpy(_key,brd_key,16);
  _udp.begin(0);
}

void BroadLinkESP::setDestIP(char *ipstr)
{
  _toip.fromString(ipstr);
}

void BroadLinkESP::setDestMAC(byte *inmac)
{
  memcpy(_tomac,inmac,6);
}

void BroadLinkESP::decryptData(byte *payload,int cbpayload)
{
  AES aes;
  int nblk;
  byte cipher[16];
  byte iv[16];
  int idx;
  aes.set_key(_key,sizeof(_key));    
  memcpy(iv,brd_iv,16);
  nblk=cbpayload/16;
  if(_debug)
    Serial.printf("decrypt cbpayload=%d nblk=%d iv=%02x\n",cbpayload,nblk,iv[0]);
  for(idx=0;idx<nblk;idx++)
  {
    aes.cbc_decrypt(payload,cipher,1,iv);
    memcpy(payload,cipher,16);
    if(_debug)
    {
      for(int i=0;i<16;i++)
      {
        Serial.printf("%02X ",cipher[i]);
      }
      Serial.println("\n");
    }
    payload+=16;
  }
}

void BroadLinkESP::encryptData(byte *payload,int cbpayload)
{
  AES aes;
  int nblk;
  byte cipher[16];
  int idx;
  byte iv[16];
  aes.set_key(_key,sizeof(_key));    
  memcpy(iv,brd_iv,16);
  nblk=cbpayload/16;
  for(idx=0;idx<nblk;idx++)
  {
    aes.cbc_encrypt(payload,cipher,1,iv);
    memcpy(payload,cipher,16);
    payload+=16;
  }
}

void BroadLinkESP::preparePacket(byte cmd,byte *payload,int cbpayload)
{
  byte *plbuf=payload;

  int numpad=cbpayload;
  if (cbpayload>0)
  {
    numpad=((cbpayload/16)+1)*16;
  }
  _cbpacket=0x38+numpad;
  if(_packet!=NULL)
    free(_packet);
  _packet=(byte *)malloc(_cbpacket);
  if(!_packet)
    return;
  _seq++;
  memset(_packet,0,_cbpacket);
  _packet[0x00] = 0x5a;
  _packet[0x01] = 0xa5;
  _packet[0x02] = 0xaa;
  _packet[0x03] = 0x55;
  _packet[0x04] = 0x5a;
  _packet[0x05] = 0xa5;
  _packet[0x06] = 0xaa;
  _packet[0x07] = 0x55;
  _packet[0x24] = 0x2a;
  _packet[0x25] = 0x27;
  _packet[0x26] = cmd;
  _packet[0x28] = _seq & 0xff;
  _packet[0x29] = _seq >> 8;
  _packet[0x2a] = _tomac[0];
  _packet[0x2b] = _tomac[1];
  _packet[0x2c] = _tomac[2];
  _packet[0x2d] = _tomac[3];
  _packet[0x2e] = _tomac[4];
  _packet[0x2f] = _tomac[5];
  _packet[0x30] = _id[0];
  _packet[0x31] = _id[1];
  _packet[0x32] = _id[2];
  _packet[0x33] = _id[3]; 
  
  // pad the payload for AES encryption
  if (cbpayload>0)
  {
    plbuf=(byte *)malloc(numpad);
    if(!plbuf)
      return;
    memset(plbuf,0,numpad);
    memcpy(plbuf,payload,cbpayload);
    cbpayload=numpad;
  }
  uint16_t checksum = 0xbeaf;
  int i;
  
  for(i=0;i<cbpayload;i++)
    checksum+=plbuf[i];
    
  _packet[0x34] = checksum & 0xff;
  _packet[0x35] = checksum >> 8;

  encryptData(plbuf,cbpayload);

  for(i=0;i<cbpayload;i++)
  {
    _packet[0x38+i]=plbuf[i];
  }
  checksum = 0xbeaf;
  for(i=0;i<_cbpacket;i++)
  {
    checksum+=_packet[i];
  }
  _packet[0x20] = checksum & 0xff;
  _packet[0x21] = checksum >> 8;

  
  if(plbuf!=payload)
  {
    free(plbuf);
  }
}

void BroadLinkESP::preparePacketAuth(void)
{
  byte payload[0x50];
  memset(payload,0,sizeof(payload));
  // my device id
  payload[0x04] = 0x31;
  payload[0x05] = 0x31;
  payload[0x06] = 0x31;
  payload[0x07] = 0x31;
  payload[0x08] = 0x31;
  payload[0x09] = 0x31;
  payload[0x0a] = 0x31;
  payload[0x0b] = 0x31;
  payload[0x0c] = 0x31;
  payload[0x0d] = 0x31;
  payload[0x0e] = 0x31;
  payload[0x0f] = 0x31;
  payload[0x10] = 0x31;
  payload[0x11] = 0x31;
  payload[0x12] = 0x32;
  
  payload[0x1e] = 0x01;
  payload[0x2d] = 0x01;
  payload[0x30] = 'T';
  payload[0x31] = 'e';
  payload[0x32] = 's';
  payload[0x33] = 't';
  payload[0x34] = ' ';
  payload[0x35] = ' ';
  payload[0x36] = '2';
  preparePacket(0x65,payload,sizeof(payload));
  _typepacket=1;
}

void BroadLinkESP::preparePacketSetPowerMask(byte sid_mask,byte state)
{
  byte packet[16];
  memset(packet,0,sizeof(packet));
  packet[0x00] = 0x0d;
  packet[0x02] = 0xa5;
  packet[0x03] = 0xa5;
  packet[0x04] = 0x5a;
  packet[0x05] = 0x5a;
  if(state)
    packet[0x06] = 0xb2 + (sid_mask<<1);
  else 
    packet[0x06] = 0xb2 + sid_mask;
  packet[0x07] = 0xc0;
  packet[0x08] = 0x02;
  packet[0x0a] = 0x03;
  packet[0x0d] = sid_mask;
  if(state)
    packet[0x0e] = sid_mask;
  else 
    packet[0x0e] = 0;
  preparePacket(0x6A,packet,16);
  _typepacket=2;
}

void BroadLinkESP::preparePacketSetPower(byte sno,byte onoff)
{
  preparePacketSetPowerMask(0x01<<(sno-1),onoff);
}

void BroadLinkESP::sendPacket(void)
{
  if(_debug)
    Serial.printf("Sending %d bytes\n",_cbpacket);
  if(_packet!=NULL)
  {
    _udp.beginPacket(_toip,80);
    _udp.write(_packet,_cbpacket);
    _udp.endPacket();  
    _fwaitresp=_typepacket;
    _tsent=millis();
    _ntrysend=3;
  }
}

int BroadLinkESP::checkReadPacket(void)
{
  if(!_fwaitresp)
   return 0;
  int packetSize;
  packetSize = _udp.parsePacket();
  if(packetSize==0)
  {
    if((millis()-_tsent)>500)
    {
      if(_debug)
        Serial.println("TIMEOUT");
      _ntrysend--;
      if(_ntrysend==0)
        return -99;
      _udp.beginPacket(_toip,80);
      _udp.write(_packet,_cbpacket);
      _udp.endPacket();  
      _tsent=millis();
      return -2;
    }
    return -1;
  }
  if(_debug)
    Serial.printf("pakcetSize=%d\n",packetSize);
  return packetSize;  
}

int BroadLinkESP::readPacket(int packetSize)
{
  if(_debug)
  {
    Serial.print("Received packet of size ");
    Serial.println(packetSize);
    Serial.print("From ");
    IPAddress remoteIp = _udp.remoteIP();
    Serial.print(remoteIp);
    Serial.print(", port ");
    Serial.println(_udp.remotePort());
  }

  byte rbuf[128];
  int rval;
  uint16_t ui2;
  if(packetSize>sizeof(rbuf))
    packetSize=sizeof(rbuf);
  rval=_udp.read(rbuf,packetSize);
  if(_debug)
  {
    for(int i=0;i<rval;i++)
    {
      if(i && ((i % 16)==0))
	Serial.println();
      Serial.printf("%02X ",rbuf[i]);
    }
    Serial.println("\n");
  }

  if((rval<0x38) || (rbuf[0]!=0x5A))
  {
    _fgot=-1;
    return -1;
  }
  ui2=rbuf[0x23]; ui2<<=8; ui2|=rbuf[0x22];
  if(ui2!=0)
    _fgot=-10;
  else
    _fgot=1;
  if(_debug)
    Serial.printf("err=%04X\n",ui2);
  if(rval>=0x38)
  {
    if(_fwaitresp==1)
    {
      decryptData(rbuf+0x38,(rval-0x38));
      memcpy(_key,rbuf+0x38+4,16);
      memcpy(_id,rbuf+0x38,4);
      if(_debug)
        Serial.printf("KEY & ID CHANGED %02x\n",_id[0]);
      if(ui2==0)
      {
	_fready=1;  
      }
    }
    else if(_fwaitresp==2)
    {
    }
  }
  _fwaitresp=0;
  return _fgot;
}

int BroadLinkESP::isReady(void)
{
  return _fready;
}
