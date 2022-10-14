#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define ARG_LEN 40
#define DEFAULT_COUNT 1024
#define DEFAULT_SECONDS 10
#define DEFAULT_TIMER 60
#define DEFAULT_COLLECTOR "127.0.0.1:2055"

typedef struct Args{
    char fileName[ARG_LEN];
    char collector[ARG_LEN];
    int activeTimer;
    int seconds;
    int count;
}t_Args;

t_Args ctor_Args(){
   t_Args args;
   strcpy(args.fileName, "-");
   strcpy(args.collector, DEFAULT_COLLECTOR);
   args.count = DEFAULT_COUNT;
   args.seconds = DEFAULT_SECONDS;
   args.activeTimer = DEFAULT_TIMER;

   return args;
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
            // help_function();
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

t_Args args;


void printfunc(){
    printf("%s a %s a %i a %i a %i\n", args.fileName, args.collector, args.activeTimer, args.seconds, args.count);

}

int main(int argc, char **argv){
    int number;

    args = ctor_Args();
    parse_arguments(argc, argv, &args);

    printfunc();
    return 0;
}