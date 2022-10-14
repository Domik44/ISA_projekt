// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// File containing argument procession.

#include "flow.h"

t_Args ctor_Args(){
   t_Args args;
   strcpy(args.fileName, "-");
   strcpy(args.collector, DEFAULT_COLLECTOR);
   args.count = DEFAULT_COUNT;
   args.seconds = DEFAULT_SECONDS;
   args.activeTimer = DEFAULT_TIMER;

   return args;
}

void help_function(){
    fprintf(stdout, "Description:\n");
    fprintf(stdout, "\tNetFlow data generator.\n");
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "\t./flow [-f <file>] [-c ­­<netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n");
    fprintf(stdout, "Parametres:\n");
    fprintf(stdout, "\t -f \n\t\t -> Name of analyzed file or STDIN\n"); 
    fprintf(stdout, "\t -c \n\t\t -> IP address or hostname of NetFlow connector. Additionaly UDP port.\n"); 
    fprintf(stdout, "\t -a \n\t\t -> Interval in seconds. All active records are exported to collector after this timer. \n"); 
    fprintf(stdout, "\t -i \n\t\t -> Interval in seconds. All inactive records are exported to collector after this timer. \n"); 
    fprintf(stdout, "\t -m \n\t\t -> Size of flow-cache.\n"); 
    
    exit(0);   
}


void parse_arguments(int argc, char **argv, t_Args *args){
    int option;

   while((option = getopt(argc, argv, ":f:c:a:i:m:h")) != -1){ 
      switch(option){
         case 'f':
            strcpy(args->fileName, optarg);
            break;
         case 'c':
            strcpy(args->collector, optarg);
            break;
         case 'a':
            args->activeTimer = atoi(optarg);
           break;
         case 'i':
            args->seconds = atoi(optarg);
            break;
         case 'm':
            args->count = atoi(optarg);
            break;
         case 'h':
            help_function();
            break;
         case ':': // TODO
            printf("Option \"%c\" needs a value!\n", optopt);
            exit(-1);
            break;
         case '?': // TODO
            printf("Invalid option \"%c\"!\n", optopt);
            exit(-1);
            break;
      }
   }
}