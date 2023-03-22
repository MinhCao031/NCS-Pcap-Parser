# Task 
Thu thập, lọc, trích xuất và lưu trữ dữ liệu mạng

# Usage
1. Command
	- Biên dịch: `make com`
	- Biên dịch và chạy: `make run`
	- Biên dịch và chạy để tìm lỗi: `make dbg`
	- Dọn dẹp: `make clean`
2. Main file: main.c`
	- Đọc dữ liệu từ file `sample_SMTP_2.pcap`
	- In ra thông tin các packet trong 1 flow ra file `output_wireshark.txt` sử dụng hàm print_flow()
	- Có thể xem quá trình đọc packet trong file pcap được in ra trong file `output_parse_packet.txt`

## Một vài thao tác cơ bản:
```C
  // Print a single flow
  printf("\nTest 01: Get a random flow\n");
  flow_base_t* flow_test = search_flow(table, 2523804475556696147, stdout);
  if (flow_test) {
    print_flow(*flow_test, stdout);
    printf("\nTest 02: Get payloads in flow\n");
    char* long_payload = payload_to_string(flow_test->head_flow, flow_test->total_payload);
    printf("All payload in this flow:\n%s\n\n<END OF FLOW>\n", long_payload);
  } else printf("Flow not found.\n");
  
  // Print some info about the whole pcap file
  LOG_DBG(fout_list_flow, DBG_FLOW,
    "Number of packets: %u\nNumber of flows: %u\n"
    "Number of inserted packets: %u\nNumber of filtered packets: %u\n",
    packet_count, count_flows(table), inserted_packets, filtered_packets
  );
```

# Description

## Project hoạt động theo trình tự sau:

Sniffer/Parser ==> Handler <==> Database

Với:
1. Sniffer/Parser: `dissection.c`, `dissection.h`, `parsers.c`, `parsers.h` 
	- Đọc dữ liệu mạng (hiện tại là file `pcap`)
	- Bóc tách các Layer bằng các hàm dissector 
	- Trích xuất thông tin cần thiết  bằng các hàm parser

2. Handler: `handler.c`, `handler.h`
	- Thực hiện các thao tác với Database như khởi tạo HashTable, dữ liệu (flow, packet), lưu dữ liệu

3. Database: `hash_table.c`, `hash_table.h`, `linked_list.c`, `linked_list.h`, `flow_api.h`
	- Sử dụng HashTable
	- Mỗi index chứa 1 list các flow, mỗi flow chứa 2 list các payload chiều up/down
	
4. Macro: `log.h`
        - Bao gồm các macro của các hằng số và một số hàm chèn gói tin

# TODO
- [x] Offline sniffer
- [ ] Online sniffer
- [ ] Đa luồng
- [ ] Parser
- [x] Hashtable
- [x] Expect sequence
- [x] Sắp xếp TCP packet theo thứ tự
- [x] Phân loại gói tin theo luồng
- [x] Lọc bỏ các gói lỗi
- [x] Lọc bỏ các gói trùng lặp 
- [x] Lọc gói trong luồng chưa được khởi tạo
- [x] Xử lý trường hợp Ethernet padding và Ethernet trailers gây nhầm lẫn với payload
- [ ] ... 

# FAQ
## Tại sao tách code thao tác hash table?
Mục tiêu là khiến HashTable độc lập nhất có thể (chỉ gồm các Linked List Flow chứa các Linked List Packet, các Node có dạng Key-Value), không liên quan đến cấu trúc dữ liệu của Node value

## Cách cài glib để include không bị lỗi?
Dùng lệnh sau để cài (chỉ hỗ trợ cho Linux):
```
sudo apt-get install libffi-dev libxml2-dev libglib2.0-dev
```
Ví dụ khi compile một đoạn code C dùng thư viện glib:
```
gcc `pkg-config --cflags --libs glib-2.0` -o code.o code.c
```

## Các file phụ thuộc vào nhau như thế nào?
Các file được include một cách tuyến tính, bắt đầu từ main.c và kết thúc ở main.h

`main.c` -> `handle.h` -> `hash_table.h` -> `flow_api.h` -> `linked_list.h` -> `parsers.h` -> `dissection.h` -> `log.h`


