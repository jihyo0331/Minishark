#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

void* capture_thread(void* arg);
void set_capture_filter(int filter_type); // 추가
void stop_capture();                      // 추가

#endif