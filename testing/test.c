#include "../flow.h"

t_List list;

t_FlowHeader *create_header(){ //TODO
    t_FlowHeader *header = (t_FlowHeader*)malloc(sizeof(t_FlowHeader));  //TODO Osetrit malloc fail!
    header->version = VERSION;
    header->engine_id = 0;
    header->engine_type = 0;
    header->sampling_interval = 0;
    header->count = COUNT;

    return header;
}

void delete_header(t_FlowHeader *header){ //TODO
    free(header);
}

t_Flow *create_flow(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type){ //TODO
   t_Flow *flow = (t_Flow*)malloc(sizeof(t_Flow)); //TODO Osetrit malloc fail!
   flow->header = create_header();
   strcpy(flow->src_IP, src_ip);
   strcpy(flow->dst_IP, dst_ip);
   flow->src_port = src_port;
   flow->dst_port = dst_port;
   flow->prot = type;

   list_add(&list, flow);
   return flow;
}

void delete_flow(t_Flow *flow){ //TODO
   list_delete(&list, flow);
   delete_header(flow->header);

   free(flow);
}


int main(int argc, char **argv){
   list =  ctor_List();
   t_Flow *flow = create_flow("128.1.1.0", "128.1.1.1", 11111, 123, 17);
   t_Flow *flow1 = create_flow("128.1.1.111", "128.1.1.2", 11112, 123, 17);
   t_Flow *flow2 = create_flow("128.1.1.222", "128.1.1.3", 11113, 123, 17);

   t_Flow *current = list_find(&list ,"128.1.1.111", "128.1.1.2", 11112, 123, 17);
   if(current){
      printf("Verze net: %d a src: %s\n", current->header->version, current->src_IP);
   }
   delete_flow(flow);
   delete_flow(flow1);
   delete_flow(flow2);

   return 0;
}