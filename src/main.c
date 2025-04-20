#include "gui.h"
#include "shared.h"
#include <pthread.h>

extern void* capture_thread(void* arg);

int main(int argc, char* argv[]) {
    packet_queue = g_async_queue_new();

    pthread_t tid;
    pthread_create(&tid, NULL, capture_thread, (void*)"enp0s1");

    init_gui(argc, argv);
    return 0;
}
