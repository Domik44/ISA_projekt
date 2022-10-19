// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 13.10.2022
// File containing functions for timers

#include "flow.h"

// t_Date split_date(char *given){
//     t_Date result;
//    int len = strlen(given);
//    int space_cnt = 0;
//    int date_cnt = 0;
//    int time_cnt = 0;
//    int j = 0;

//    for(int i = 0; i < len; i++){
//       if(given[i] == ' '){
//          space_cnt++;
//          result.year[j] = '\0';
//          j = 0;
//          continue;
//       }
//       if(given[i] == '-'){
//          date_cnt++;
//          if(date_cnt == 1)
//             result.day[j] = '\0';
//          else if(date_cnt == 2)
//             result.month[j] = '\0';
//          j = 0;
//          continue;
//       }
//       if(given[i] == ':'){
//          time_cnt++;
//          if(time_cnt == 1)
//             result.hours[j] = '\0';
//          else if(date_cnt == 2)
//             result.minutes[j] = '\0';
//          j = 0;
//          continue;
//       }
//       if(given[i] == '.'){
//          time_cnt++;
//          result.seconds[j] = '\0';
//          j = 0;
//          continue;
//       }
//       if(space_cnt == 0){
//          if(date_cnt == 0)
//             result.day[j] = given[i];
//          else if(date_cnt == 1)
//             result.month[j] = given[i];
//          else
//             result.year[j] = given[i];
//          j++;
//       }
//       else{
//          if(time_cnt == 0)
//             result.hours[j] = given[i];
//          else if(time_cnt == 1)
//             result.minutes[j] = given[i];
//          else if(time_cnt == 2)
//             result.seconds[j] = given[i];
//          else
//             result.useconds[j] = given[i];
//          j++;
//       }
//    }
//    result.useconds[j] = '\0';

//     return result;
// }

double get_seconds(char *str){
   char *ptr;

   return strtod(str, &ptr);
}

#define US_SECONDS 1000000

// double get_difference(t_Date *first, t_Date *last){
//    // double difference = 0.0;

//    // int day_first = atoi(first->day);
//    // int day_last = atoi(last->day);
//    // int day_dif = (day_last - day_first)*24*3600;

//    // double first_sec = get_seconds(first->hours)*3600.0 + get_seconds(first->minutes)*60.0 + get_seconds(first->seconds);
//    // double last_sec = get_seconds(last->hours)*3600.0 + get_seconds(last->minutes)*60.0 + get_seconds(last->seconds) + (double)day_dif;
//    // difference = last_sec - first_sec;

//    double difference = last->time.tv_sec - first->time.tv_sec;
//    difference += (last->time.tv_usec - first->time.tv_usec) / US_SECONDS;
   
//    return difference;
// }

uint64_t get_SysUpTime(t_time *oldest, t_time *current){
   uint64_t result = (current->tv_sec - oldest->tv_sec)*MIKROSECONDS;
   uint64_t mikro;

   if(current->tv_usec < oldest->tv_usec){
      mikro = MIKROSECONDS + current->tv_usec - oldest->tv_usec;
      result -= MIKROSECONDS;
   }
   else{
      mikro = current->tv_usec - oldest->tv_usec;
   }

   result += mikro;

   return result;
}