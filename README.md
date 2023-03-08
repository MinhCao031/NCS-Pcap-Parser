# Task 
Thu thập, lọc, trích xuất và lưu trữ dữ liệu mạng

# Usage
1. Command
	- Biên dịch: `make com`
	- Biên dịch và chạy: `make run`
	- Dọn dẹp: `make clean`
2. Main file: `test. c`
	- Đọc dữ liệu từ file `sample.pcap`
	- In ra thông tin các packet trong 1 flow ra file `output_wireshark.txt` sử dụng hàm print_flow()
	- Có thể xem quá trình đọc packet trong file pcap được in ra trong file `output_parse_packet.txt`
	- Có thể lọc packet lỗi dựa vào sequence và ghi lại tiến trình trong file `output_seq_filter.txt`

## Một vài thao tác cơ bản:
```C
  // Print a single flow
  print_flow(*search_flow(table, 2961644043, fout_parser));
  
  // Print some info about the whole pcap file
  LOG_DBG(fout_list_flow, 1, "Number of flows: %d\n", count_flows(table));
  LOG_DBG(fout_list_flow, 1, "Number of packets: %d\n", inserted_packets);
  LOG_DBG(fout_list_flow, 1, "Number of filtered packets: %d\n", filtered_packets);

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
