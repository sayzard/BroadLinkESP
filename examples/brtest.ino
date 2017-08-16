#include <AESLib.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <BroadLinkESP.h>
AESLib aesLib;
BroadLinkESP besp(BROADLINK_DEV_MP1);

#define WIFI_SSID "....."
#define WIFI_PASS "....."
#define TOADDR "192.168.0.xxx"		//broadlink mp1 ip
byte g_mac[6]={0x34,0xEA,0x34,xx,xx,xx};//boardlink mp1 mac

void setup() 
{
  Serial.begin(115200);
  Serial.println("\nBooting...");  

  WiFi.mode(WIFI_STA);

  // Connect
  Serial.printf("[WIFI] Connecting to %s ", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  // Wait
  while (WiFi.status() != WL_CONNECTED) 
  {
    Serial.print(".");
    delay(200);
  }
  // Connected!
  Serial.printf("[WIFI] STATION Mode, SSID: %s, IP address: %s\n", WiFi.SSID().c_str(), WiFi.localIP().toString().c_str());

  besp.setDestIP(TOADDR);
  besp.setDestMAC(g_mac);
  besp.preparePacketAuth();
  besp.sendPacket(); 
}

int ionoff=1;
void loop() 
{
  int packetSize;
  packetSize=besp.checkReadPacket();
  if(packetSize>0)
  {
    besp.readPacket(packetSize);
  }
  if(Serial.available())
  {
    byte c;
    c=Serial.read();
    if((c>='1') && (c<='4'))
    {
      if(besp.isReady())
      {
        Serial.printf("SWITCH %d %d\n",c,ionoff);
        besp.preparePacketSetPower(c-0x30,ionoff);
        besp.sendPacket();
      }
    }
    else if(c=='a')
      ionoff=1-ionoff;    
  }
  
}
