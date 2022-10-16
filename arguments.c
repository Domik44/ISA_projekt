// Authors: Dominik Pop
// Login: xpopdo00, <xpopdo00@stud.fit.vutbr.cz>
// VUT FIT, 3 BIT, winter semestr
// Date: 12.10.2022
// File containing argument procession.

#include "flow.h"

t_Args ctor_Args(){
   t_Args args;
   strcpy(args.fileName, "-");
   memset(&args.collector,0,sizeof(args.collector)); // erase the server structure
   args.collector.sin_family = AF_INET;   
   if ((args.servent = gethostbyname(DEFAULT_COLLECTOR_IP)) == NULL) // check the first parameter
      errx(1,"gethostbyname() failed\n");
   memcpy(&args.collector.sin_addr,args.servent->h_addr,args.servent->h_length);
   args.collector.sin_port = htons(DEFAULT_COLLECTOR_PORT);
   args.count = DEFAULT_COUNT;
   args.inactiveTimer = DEFAULT_INACTIVE;
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


void split_arg(char *arg, char *ip, char *port){
   int len =  strlen(arg);
   int cnt = 0, j = 0;
   for(int i = 0; i < len; i++){
      if(arg[i] == ':'){
         cnt++;
         ip[i] = '\0';
         continue;
      }
      if(cnt == 0){
         ip[i] = arg[i];
      }
      else{
         port[j] = arg[i];
         j++;
      }
   }
   port[j] = '\0';
}


void parse_arguments(int argc, char **argv, t_Args *args){
    int option;
    char ip[IP_LEN], port[PORT_LEN];

   while((option = getopt(argc, argv, ":f:c:a:i:m:h")) != -1){ 
      switch(option){
         case 'f':
            strcpy(args->fileName, optarg);
            break;
         case 'c':
            split_arg(optarg, ip, port);
            if ((args->servent = gethostbyname(ip)) == NULL) // check the first parameter
               errx(1,"gethostbyname() failed\n");
            memcpy(&args->collector.sin_addr,args->servent->h_addr,args->servent->h_length);
            args->collector.sin_port = htons(atoi(port));
            break;
         case 'a':
            args->activeTimer = get_seconds(optarg); 
           break;
         case 'i':
            args->inactiveTimer = get_seconds(optarg);
            break;
         case 'm':
            args->count = atoi(optarg);
            break;
         case 'h':
            help_function();
            break;
         case ':': // TODO
            errx(1,"Option \"%c\" needs a value!\n", optopt);
            break;
         case '?': // TODO
            errx(1,"Invalid option \"%c\"!\n", optopt);
            break;
      }
   }
}