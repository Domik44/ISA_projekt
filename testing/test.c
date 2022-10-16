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

int main(int argc, char **argv){
//    int sock;                        // socket descriptor
//   int msg_size, i;
//   struct sockaddr_in server, from; // address structures of the server and the client
//   struct hostent *servent;         // network host entry required by gethostbyname()
//   socklen_t len, fromlen;        
//   char buffer[1024];            

//   if (argc != 3)                   // two parameters required
//     errx(1,"Usage: %s <address> <port>",argv[0]);
  
//   memset(&server,0,sizeof(server)); // erase the server structure
//   server.sin_family = AF_INET;                   

//   // make DNS resolution of the first parameter using gethostbyname()
//   if ((servent = gethostbyname(argv[1])) == NULL) // check the first parameter
//     errx(1,"gethostbyname() failed\n");

//   // copy the first parameter to the server.sin_addr structure
//   memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

//   server.sin_port = htons(atoi(argv[2]));        // server port (network byte order)
   
//   if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
//     err(1,"socket() failed\n");
  
//   printf("* Server socket created\n");
     
//   len = sizeof(server);
//   fromlen = sizeof(from);

//   printf("* Creating a connected UDP socket using connect()\n");                
//   // create a connected UDP socket
//   if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
//     err(1, "connect() failed");

//   //send data to the server
//   while((msg_size=read(STDIN_FILENO,buffer,1024)) > 0) 
//       // read input data from STDIN (console) until end-of-line (Enter) is pressed
//       // when end-of-file (CTRL-D) is received, n == 0
//   { 
//     i = send(sock,buffer,msg_size,0);     // send data to the server
//     if (i == -1)                   // check if data was sent correctly
//       err(1,"send() failed");
//     else if (i != msg_size)
//       err(1,"send(): buffer written partially");

//     // obtain the local IP address and port using getsockname()
//     if (getsockname(sock,(struct sockaddr *) &from, &len) == -1)
//       err(1,"getsockname() failed");

//     printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n",inet_ntoa(from.sin_addr), ntohs(from.sin_port), from.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);
    
//     // read the answer from the server 
//     if ((i = recv(sock,buffer, 1024,0)) == -1)   
//       err(1,"recv() failed");
//     else if (i > 0){
//       // obtain the remote IP adddress and port from the server (cf. recfrom())
//       if (getpeername(sock, (struct sockaddr *)&from, &fromlen) != 0) 
// 	      err(1,"getpeername() failed\n");

//       printf("* UDP packet received from %s, port %d\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port));
//       printf("%.*s",i,buffer);                   // print the answer
//     }
//   } 
//   // reading data until end-of-file (CTRL-D)

//   if (msg_size == -1)
//     err(1,"reading failed");
//   close(sock);
//   printf("* Closing the client socket ...\n");
//   return 0;
int i = PACKET_SIZE;
printf("%d \n", i);
}