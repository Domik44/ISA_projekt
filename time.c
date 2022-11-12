// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 13.10.2022
// File containing functions for getting Sysup time

#include "flow.h"

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
