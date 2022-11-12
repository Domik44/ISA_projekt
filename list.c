// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 13.10.2022
// File containing functions for list operations

#include "flow.h"

t_List ctor_List(){ 
    t_List list;
    list.head = NULL;
    list.last = NULL;
    list.counter = 0;

    return list;
}

void list_add(t_List *list, t_Flow *flow){
    if(list->counter == 0){
        list->head = flow;
        list->last = flow;
    }
    else{
        list->last->next = flow;
        flow->previous = list->last;
        list->last = flow;
    }
    list->counter += 1;
}

void list_delete(t_List *list, t_Flow *flow){
    if(list->counter == 1){
        list->head = NULL;
        list->last = NULL;
    }
    else{
        if(list->head == flow){
            list->head = list->head->next;
            list->head->previous = NULL;
        }
        else if(list->last == flow){
            list->last = list->last->previous;
            list->last->next = NULL;
        }
        else{
            flow->previous->next = flow->next;
            flow->next->previous = flow->previous;
        }
    }
    list->counter -= 1;
}


t_Flow *list_find(t_List *list, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type){
    t_Flow *result = NULL;
    t_Flow *current = list->head;

    while(current){
        if(current->prot == type && current->src_IP == src_ip && current->dst_IP == dst_ip && current->src_port == src_port && current->dst_port == dst_port){
            result = current;
            break;
        }
        current = current->next;
    }


    return result;
}