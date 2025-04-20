#include <stdio.h>
#include "capture.h"

int main(){
    printf("minishark start");
    const char* interface = "eth0";
    start_capture(interface);
    return 0;
}