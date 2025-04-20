#include <gtk/gtk.h>
#include <string.h>
#include "gui.h"
#include "shared.h"
#include "capture.h"

static GtkListStore* store;

static gboolean update_gui(gpointer data) {
    char* item = (char*)g_async_queue_try_pop(packet_queue);
    if (item) {
        GtkTreeIter iter;
        char proto[16], src[64], dst[64], port_info[64];
        sscanf(item, "%[^|]|%[^:]:%*d -> %[^:]:%*d", proto, src, dst);
        snprintf(port_info, sizeof(port_info), "%s", item + strlen(proto) + 1);

        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter,
            0, proto,
            1, src,
            2, dst,
            3, port_info,
            -1);
        free(item);
    }
    return TRUE;
}

// 버튼 콜백
static void on_filter_all(GtkButton* btn, gpointer user_data) {
    set_capture_filter(0);
}
static void on_filter_tcp(GtkButton* btn, gpointer user_data) {
    set_capture_filter(1);
}
static void on_filter_udp(GtkButton* btn, gpointer user_data) {
    set_capture_filter(2);
}
static void on_stop_capture(GtkButton* btn, gpointer user_data) {
    stop_capture();
}

void init_gui(int argc, char* argv[]) {
    GtkWidget *window, *tree, *scroll, *box, *btn_box;
    GtkCellRenderer *renderer;

    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "MiniShark - Packet Viewer");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 400);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    store = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

    tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    const char* titles[] = {"Protocol", "Source IP", "Destination IP", "Port Info"};
    for (int i = 0; i < 4; i++) {
        renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn* col = gtk_tree_view_column_new_with_attributes(titles[i], renderer, "text", i, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col);
    }

    scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), tree);

    // 버튼 영역
    GtkWidget* btn_all = gtk_button_new_with_label("All");
    GtkWidget* btn_tcp = gtk_button_new_with_label("TCP");
    GtkWidget* btn_udp = gtk_button_new_with_label("UDP");
    GtkWidget* btn_stop = gtk_button_new_with_label("Stop Capture");

    g_signal_connect(btn_all, "clicked", G_CALLBACK(on_filter_all), NULL);
    g_signal_connect(btn_tcp, "clicked", G_CALLBACK(on_filter_tcp), NULL);
    g_signal_connect(btn_udp, "clicked", G_CALLBACK(on_filter_udp), NULL);
    g_signal_connect(btn_stop, "clicked", G_CALLBACK(on_stop_capture), NULL);

    btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_all, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_tcp, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_udp, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_stop, FALSE, FALSE, 5);

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 5);

    gtk_container_add(GTK_CONTAINER(window), box);

    g_timeout_add(100, update_gui, NULL);

    gtk_widget_show_all(window);
    gtk_main();
}
