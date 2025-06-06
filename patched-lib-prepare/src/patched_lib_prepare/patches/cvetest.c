#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap-int.h>
#include <sf-pcap-ng.h>

#define BT_SHB 0x0A0D0D0A
#define BYTE_ORDER_MAGIC 0x1A2B3C4D

int main() {
    // Simulate pcap_t
    struct pcap pcap_instance;
    memset(&pcap_instance, 0, sizeof(pcap_instance));

    // Magic number
    bpf_u_int32 magic = BT_SHB;
	bpf_u_int32 total_length = 1024 * 1024 + 1337;
	bpf_u_int32 byte_order_magic = BYTE_ORDER_MAGIC;

    // Create dummy PCAP-NG file content (e.g., SHB header)
    bpf_u_int32 dummy_data[] = {
        total_length,
		byte_order_magic
    };

    // Create a memory file using fmemopen
    FILE *fp = fmemopen(dummy_data, sizeof(dummy_data), "rb");
    if (!fp) {
        perror("fmemopen failed");
        return 1;
    }

    // Error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0';

    // Call the function
    int result = pcap_ng_check_header(&pcap_instance, magic, fp, errbuf);

    printf("Result: %d\n", result);
	printf("errbuf: %s\n", errbuf);

    fclose(fp);
    return 0;
}

