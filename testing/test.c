#include "../flow.h"

// t_List list;

// t_FlowHeader *create_header(){ //TODO
//     t_FlowHeader *header = (t_FlowHeader*)malloc(sizeof(t_FlowHeader));  //TODO Osetrit malloc fail!
//     header->version = VERSION;
//     header->engine_id = 0;
//     header->engine_type = 0;
//     header->sampling_interval = 0;
//     header->count = COUNT;

//     return header;
// }

// void delete_header(t_FlowHeader *header){ //TODO
//     free(header);
// }

// t_Flow *create_flow(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t type){ //TODO
//    t_Flow *flow = (t_Flow*)malloc(sizeof(t_Flow)); //TODO Osetrit malloc fail!
//    flow->header = create_header();
//    strcpy(flow->src_IP, src_ip);
//    strcpy(flow->dst_IP, dst_ip);
//    flow->src_port = src_port;
//    flow->dst_port = dst_port;
//    flow->prot = type;

//    list_add(&list, flow);
//    return flow;
// }

// void delete_flow(t_Flow *flow){ //TODO
//    list_delete(&list, flow);
//    delete_header(flow->header);

//    free(flow);
// }


t_Date split_date(char *given){
    t_Date result;
   int len = strlen(given);
   int space_cnt = 0;
   int date_cnt = 0;
   int time_cnt = 0;
   int j = 0;

   for(int i = 0; i < len; i++){
      if(given[i] == ' '){
         space_cnt++;
         result.year[j] = '\0';
         j = 0;
         continue;
      }
      if(given[i] == '-'){
         date_cnt++;
         if(date_cnt == 1)
            result.day[j] = '\0';
         else if(date_cnt == 2)
            result.month[j] = '\0';
         j = 0;
         continue;
      }
      if(given[i] == ':'){
         time_cnt++;
         if(time_cnt == 1)
            result.hours[j] = '\0';
         else if(date_cnt == 2)
            result.minutes[j] = '\0';
         j = 0;
         continue;
      }
      if(space_cnt == 0){
         if(date_cnt == 0)
            result.day[j] = given[i];
         else if(date_cnt == 1)
            result.month[j] = given[i];
         else
            result.year[j] = given[i];
         j++;
      }
      else{
         if(time_cnt == 0)
            result.hours[j] = given[i];
         else if(time_cnt == 1)
            result.minutes[j] = given[i];
         else
            result.seconds[j] = given[i];
         j++;
      }
   }
   result.seconds[j] = '\0';

    return result;
}

double get_seconds(char *str){
   char *ptr;

   return strtod(str, &ptr);
}

double get_difference(t_Date first, t_Date last){
   double difference = 0.0;
   char *ptr;

   int day_first = atoi(first.day);
   int day_last = atoi(last.day);
   int day_dif = (day_last - day_first)*24*3600;

   double first_sec = get_seconds(first.hours)*3600.0 + get_seconds(first.minutes)*60.0 + get_seconds(first.seconds);
   double last_sec = get_seconds(last.hours)*3600.0 + get_seconds(last.minutes)*60.0 + get_seconds(last.seconds) + (double)day_dif;
   difference = last_sec - first_sec;
   
   return difference;
}


int main(int argc, char **argv){
   
   t_Date date1 = split_date("01-01-2002 23:57:30.111111");
   t_Date date2 = split_date("02-01-2002 00:1:35.111115");

   double difference = get_difference(date1, date2);


   return 0;
}