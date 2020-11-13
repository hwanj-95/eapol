#ifndef DEAUTH_H
#define DEAUTH_H

#endif // DEAUTH_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <pcap/pcap.h>
#include <stdio.h>
#include <netinet/in.h> //ipv4 ip_addr
#include <arpa/inet.h> // inet_ntoa > net add change
#include <algorithm>
#include <string.h>
#include <unistd.h>

#include "mac.h"
using namespace std;

#define MAC_LEN 6
#define version 0x00        // radiotap_header -> it.version setting
#define padding 0x00        // radiotap_header -> it_pad setting
#define radio_len 0x0008     // radiotap_header -> it_len setting
#define flags 0x00000000    // radiotap_header -> flags
#define Type 0x00C0        // deauth packet type
#define duration 0x0000     // deauth_header -> dur setting
#define number 0x0000       // deauth_header -> num setting
#define reason_code 0x0007  // wireless_header -> code setting
#define beacon 0x0080
#define qos_check 0x0288
#define eapol_check 0x03

struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
}__attribute__((__packed__));

struct beacon_header{
    u_int16_t beacon_type;
    u_int16_t beacon_dur;
    Mac beacon_d_addr;
    Mac beacon_s_addr;
    Mac beacon_bssid;
    u_int16_t beacon_fra_sqa_number;
};

struct deauth_header {
    u_int16_t type;
    u_int16_t dur;
    Mac d_addr;
    Mac s_addr;
    Mac bssid;
    u_int16_t num;
};

struct wireless_header {
    u_int16_t code;
};

#pragma pack(push, 1)
struct DeauthPacket {
    radiotap_header radio;
    deauth_header dea;
    wireless_header wir;
};
#pragma pack(pop)

struct qos_data{
    u_int16_t qosType;
    u_int16_t qosDur;
    Mac qos_desAddr;
    Mac qos_bssid;
    Mac qos_sourAddr;
    u_int16_t fra_seq_number;
    u_int16_t qos_control;
};

struct logical_link{
    u_int8_t dsap;
    u_int8_t ssap;
    u_int8_t control_field;
    u_int8_t code1;
    u_int8_t code2;
    u_int8_t code3;
    u_int16_t logicalType;
};

struct eapol_header{
    u_int8_t eapol_version;
    u_int8_t eapol_type;
    u_int16_t len;
    u_int8_t key_type; // eapol
    u_int16_t key_info;
    u_int16_t key_len;
    u_int64_t replay_count;
    u_int64_t wpa_key_1;
    u_int64_t wpa_key_2;
    u_int64_t wpa_key_3;
    u_int64_t wpa_key_4;
    u_int64_t key_iv_1;
    u_int64_t key_iv_2;
    u_int64_t wpa_key_rsc;
    u_int64_t wpa_key_id;
    u_int64_t wpa_key_mic_1;
    u_int64_t wpa_key_mic_2;
    u_int16_t wpa_key_data_len;
};
