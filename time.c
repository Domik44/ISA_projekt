// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 13.10.2022
// File containing functions for timers

#include "flow.h"


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