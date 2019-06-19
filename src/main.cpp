/*
 * main.cpp
 *
 *  Created on: 03-Apr-2019
 *      Author: Snehasish Kar
 */

#include <iostream>
#include <string>
#include <queue>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <boost/thread.hpp>
#include <semaphore.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "../include/config4cpp/Configuration.h"
#include "../include/fifo_read_write.h"
#include "../include/vipl_printf.h"
#include "../include/viplrfinterface.h"
#include "../include/vipl_wifi_config.h"

int32_t error_lvl = 0x00;

sem_t lock;
sem_t stop_process;
sem_t wait;

extern int errno;

bool wait_done = false;

bool stop_rx = false;
bool stop_gps = false;
bool stop_read_fifo = false;
char oui[300] = {0x00};
char interface[50] = {0x00};

using namespace config4cpp;

void printUsage(void){
	fprintf(stderr,"\t ./viplrfFrontend -e <1/2/3>\n");
	fprintf(stdout,"\t -e:   error level (1/2/3)\n");
	fprintf(stdout,"\t -c:   path to wifi configuration file\n");
	fprintf(stdout,"\t -s:   path to settings file\n");
	fprintf(stdout,"\t -m:   path to manufacturers list file\n");
	fprintf(stdout,"\t -v:   version\n");
}

void version(void){
	fprintf(stderr,"Build on %s:%s by Snehasish Kar",__DATE__, __TIME__);
}

void intHandler(int dummy) {
	stop_rx = true;
	stop_gps = true;
	stop_read_fifo = true;
	if(strlen(interface)!=0){
		char comm[300] = {0x00};
		sprintf(comm, "ifconfig %s down", interface);
		system(comm);
		sprintf(comm, "iwconfig %s mode managed", interface);
		system(comm);
		sprintf(comm, "ifconfig %s up", interface);
		system(comm);
	}
	vipl_printf("ALERT: sigint got..exiting!!", error_lvl, __FILE__, __LINE__);
	sem_post(&stop_process);
	sleep(3);
	sem_destroy(&stop_process);
	exit(EXIT_SUCCESS);
}


void initUSRP(){
	vipl_rf_interface rf_interface;
}

void parse_configfile(char *config_file_path){
	const char default_configFile[300] = {"../config/viplrfConfig.cfg"};
	if(strlen(config_file_path)>0){
		bzero(default_configFile,sizeof(char)*300);
		strcpy(default_configFile,config_file_path);
	}
	FILE *fp = fopen(default_configFile,"r");
	if(fp==NULL){
		vipl_printf("error: unable to find config file", error_lvl, __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	fclose(fp);
	const char *scope = "";
	Configuration *  cfg = Configuration::create();
	StringBuffer filter, m_scope;
	StringVector scopes;
	m_scope = scope;
	Configuration::mergeNames(scope, "uid-board", filter);
	retry:
	int32_t fd_read = open("/tmp/pipe_command_write",666);
	if(fd_read<=0)
	  goto retry;
	label:
	int32_t fd_write = open("/tmp/pipe_command_read",666);
	if(fd_write<=0)
		goto label;
	try{
		cfg->parse(default_configFile);
		cfg->listFullyScopedNames(m_scope.c_str(), "", Configuration::CFG_SCOPE, false, filter.c_str(), scopes);
		int len = scopes.length();
		strcpy(interface, cfg->lookupString("", "interface.name"));
		char handshake[200] = {'\0'};
		strcpy(handshake, cfg->lookupString("", "handshake.path"));
		char offlinePcap[200] = {'\0'};
		strcpy(offlinePcap, cfg->lookupString("", "offline_pcap.path"));
#if 1
		char json_drone_path[200] = {'\0'};
		strcpy(json_drone_path, cfg->lookupString("drone_dumping_mode", "json.path"));
		char drone_dump_addr[34] = {'\0'};
		strcpy(drone_dump_addr, cfg->lookupString("drone_dumping_mode", "tcp.ip_addr"));
		uint32_t port_no=0x00;
		port_no = cfg->lookupInt("drone_dumping_mode", "tcp.port");
		uint32_t drone_dump_mode=0x00;
		if(strlen(json_drone_path)>0)
			drone_dump_mode = 1;
		else
			drone_dump_mode = 0;
#endif
		for(int i=0; i<len; i++){
			char scope[20] = {0x00};
			strcpy(scope, scopes[i]);
			int32_t mode, db_board, mboard, num_channel;
			bool change_freq, change_gain, init_board, ntwrkscan, getgps;
			float freq, gain, samp_rate, atten, bandwidth, lo_offset, tx_power;
			char mboard_addr[34], channel_list[14], band[3], technology[11];
			mode = cfg->lookupInt(scope, "db0.mode");
			db_board = cfg->lookupInt(scope, "db0.db_board");
		    mboard = cfg->lookupInt(scope, "db0.mboard");
			change_freq = cfg->lookupBoolean(scope, "db0.change_freq");
			change_gain = cfg->lookupBoolean(scope, "db0.change_gain");
			init_board = cfg->lookupBoolean(scope, "db0.init_board");
			ntwrkscan = cfg->lookupBoolean(scope, "db0.ntwrkscan");
			getgps = cfg->lookupBoolean(scope, "db0.getgps");
			freq = cfg->lookupFloat(scope, "db0.freq");
			gain = cfg->lookupFloat(scope, "db0.gain");
			samp_rate = cfg->lookupFloat(scope, "db0.samp_rate");
			atten = cfg->lookupFloat(scope, "db0.atten");
			bandwidth = cfg->lookupFloat(scope, "db0.bandwidth");
			lo_offset = cfg->lookupFloat(scope, "db0.lo_offset");
			tx_power = cfg->lookupFloat(scope, "db0.tx_power");
			strcpy(mboard_addr, cfg->lookupString(scope, "db0.mboard_addr"));
			strcpy(channel_list, cfg->lookupString(scope, "db0.channel_list"));
			strcpy(band, cfg->lookupString(scope, "db0.band"));
			strcpy(technology, cfg->lookupString(scope, "db0.technology"));
			num_channel = cfg->lookupInt(scope, "db0.num_channel");
            struct command_from_DSP command_db0;
            bzero(&command_db0, sizeof(struct command_from_DSP));
            command_db0.mode = mode;
            command_db0.db_board = db_board;
            command_db0.mboard = mboard;
            command_db0.change_freq = change_freq;
            command_db0.change_gain = change_gain;
            command_db0.init_board = false;
            command_db0.ntwrkscan = ntwrkscan;
            command_db0.getgps = false;
            command_db0.freq = freq;
            command_db0.gain = gain;
            command_db0.samp_rate = samp_rate;
            command_db0.atten = atten;
            command_db0.bandwidth = bandwidth;
            command_db0.lo_offset = lo_offset;
            command_db0.tx_power = tx_power;
            command_db0.num_channels = num_channel;
            command_db0.port_no = port_no;
            command_db0.drone_dump_mode = drone_dump_mode;
            strcpy(command_db0.mboard_addr, mboard_addr);
            strcpy(command_db0.channel_list, channel_list);
            strcpy(command_db0.band, band);
            strcpy(command_db0.technology, technology);
            strcpy(command_db0.interface, interface);
            strcpy(command_db0.handshake, handshake);
            strcpy(command_db0.offlinePcap, offlinePcap);
            strcpy(command_db0.json_drone_path, json_drone_path);
            strcpy(command_db0.drone_dump_addr, drone_dump_addr);
            if(init_board||ntwrkscan){
           		command_db0.getgps = false;
           		command_db0.ntwrkscan = ntwrkscan;
           		command_db0.init_board = init_board;
           		uint8_t *buffer = (uint8_t*)malloc(sizeof(command_db0));
           		bzero(buffer,sizeof(char)*sizeof(command_db0));
           		memcpy(buffer, &command_db0, sizeof(command_db0));
           		size_t noofBytesRead = write(fd_write, buffer, sizeof(command_db0));
           		if(noofBytesRead!=(sizeof(command_db0))){
           			char msg[100]={0x00};
           			sprintf(msg, "error: read::%s", strerror(errno));
           			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
           			return 0x01;
           		}else{
           			char *msg=(char *)malloc(sizeof(char)*sizeof(command_db0)+20);
           			bzero(msg,sizeof(char)*sizeof(command_db0));
           			char *buff = (char*) malloc(sizeof(command_db0));
           			for(int j=0; j<sizeof(command_db0); j++)
           				buff[j] = static_cast<char>(buffer[j]);
           			sprintf(msg, "info: %d Bytes wrote %s", noofBytesRead, buff);
           			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
           			free(msg);
           		}
           		sem_wait(&wait);

           	}
           	if(getgps){
           		command_db0.getgps = getgps;
           		command_db0.init_board = false;
           		memset(command_db0.technology,0x00, sizeof(char)*6);
           		uint8_t *buffer = (uint8_t*)malloc(sizeof(command_db0));
           		bzero(buffer,sizeof(char)*sizeof(command_db0));
           		memcpy(buffer, &command_db0, sizeof(command_db0));
           		size_t noofBytesRead = write(fd_write, buffer, sizeof(command_db0));
           		if(noofBytesRead!=(sizeof(command_db0))){
           			char msg[100]={0x00};
           			sprintf(msg, "error: read::%s", strerror(errno));
           			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
           			return 0x01;
           		}else{
           			char *msg=(char *)malloc(sizeof(char)*sizeof(command_db0)+20);
           			bzero(msg,sizeof(char)*sizeof(command_db0));
           			sprintf(msg, "info: %d Bytes wrote %s", strerror(errno),(char *)buffer);
           			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
           			free(msg);
           		}
           		sem_wait(&wait);
           		//write command in FIFO
           	}
            mode = cfg->lookupInt(scope, "db1.mode");
			db_board = cfg->lookupInt(scope, "db1.db_board");
			mboard = cfg->lookupInt(scope, "db1.mboard");
			change_freq = cfg->lookupBoolean(scope, "db1.change_freq");
			change_gain = cfg->lookupBoolean(scope, "db1.change_gain");
			init_board = cfg->lookupBoolean(scope, "db1.init_board");
			ntwrkscan = cfg->lookupBoolean(scope, "db1.ntwrkscan");
			getgps = cfg->lookupBoolean(scope, "db1.getgps");
			freq = cfg->lookupFloat(scope, "db1.freq");
			gain = cfg->lookupFloat(scope, "db1.gain");
			samp_rate = cfg->lookupFloat(scope, "db1.samp_rate");
			atten = cfg->lookupFloat(scope, "db1.atten");
			bandwidth = cfg->lookupFloat(scope, "db1.bandwidth");
			lo_offset = cfg->lookupFloat(scope, "db1.lo_offset");
			tx_power = cfg->lookupFloat(scope, "db1.tx_power");
			strcpy(mboard_addr, cfg->lookupString(scope, "db1.mboard_addr"));
			strcpy(channel_list, cfg->lookupString(scope, "db1.channel_list"));
			strcpy(band, cfg->lookupString(scope, "db1.band"));
			strcpy(technology, cfg->lookupString(scope, "db1.technology"));
			num_channel = cfg->lookupInt(scope, "db0.num_channel");
			struct command_from_DSP command_db1;
		    bzero(&command_db1, sizeof(struct command_from_DSP));
		    command_db1.mode = mode;
		    command_db1.db_board = db_board;
		    command_db1.mboard = mboard;
		    command_db1.change_freq = change_freq;
		    command_db1.change_gain = change_gain;
		    command_db1.init_board = false;
		    command_db1.ntwrkscan = ntwrkscan;
		    command_db1.getgps = false;
		    command_db1.freq = freq;
		    command_db1.gain = gain;
		    command_db1.samp_rate = samp_rate;
		    command_db1.atten = atten;
		    command_db1.bandwidth = bandwidth;
		    command_db1.lo_offset = lo_offset;
		    command_db1.tx_power = tx_power;
		    command_db1.num_channels = num_channel;
            command_db1.port_no = port_no;
            command_db1.drone_dump_mode = drone_dump_mode;
		    strcpy(command_db1.mboard_addr, mboard_addr);
		    strcpy(command_db1.channel_list, channel_list);
		    strcpy(command_db1.band, band);
		    strcpy(command_db1.technology, technology);
		    strcpy(command_db1.interface, interface);
		    //strcpy(command_db1.handshake, handshake);
		    //strcpy(command_db1.offlinePcap, offlinePcap);
            //strcpy(command_db1.json_drone_path, json_drone_path);
	        //strcpy(command_db1.drone_dump_addr, drone_dump_addr);
		    if(init_board || ntwrkscan){
		    	command_db1.getgps = false;
		    	command_db1.ntwrkscan = ntwrkscan;
		    	command_db1.init_board = init_board;
		    	uint8_t *buffer = (uint8_t*)malloc(sizeof(command_db1));
		    	bzero(buffer,sizeof(char)*sizeof(command_db1));
		    	memcpy(buffer, &command_db1, sizeof(command_db1));
		    	size_t noofBytesRead = write(fd_write, buffer, sizeof(command_db1));
		    	if(noofBytesRead!=(sizeof(command_db1))){
		    		char msg[100]={0x00};
		    		sprintf(msg, "error: read::%s", strerror(errno));
		    		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		    		return 0x01;
		    	}else{
		    		char *msg=(char *)malloc(sizeof(char)*sizeof(command_db1)+20);
		    		bzero(msg,sizeof(char)*sizeof(command_db1));
		    		sprintf(msg, "info: %d Bytes wrote %s", noofBytesRead,(char *)buffer);
		    		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		    		free(msg);
		    	}
		    	sem_wait(&wait);
		    }
		    if(getgps){
		    	command_db1.init_board = false;
		    	memset(command_db1.technology,0x00, sizeof(char)*6);
		    	command_db1.getgps = getgps;
		    	uint8_t *buffer = (uint8_t*)malloc(sizeof(command_db1));
		    	bzero(buffer,sizeof(char)*sizeof(command_db1));
		    	memcpy(buffer, &command_db1, sizeof(command_db1));
		    	size_t noofBytesRead = write(fd_write, buffer, sizeof(command_db1));
		    	if(noofBytesRead!=(sizeof(command_db1))){
		    		char msg[100]={0x00};
		    		sprintf(msg, "error: read::%s", strerror(errno));
		    		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		    		return 0x01;
		    	}else{
		    		char *msg=(char *)malloc(sizeof(char)*sizeof(command_db1)+20);
		    		bzero(msg,sizeof(char)*sizeof(command_db1));
		    		sprintf(msg, "info: %d Bytes wrote %s", strerror(errno),(char *)buffer);
		    		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		    		free(msg);
		    	}
		    	sem_wait(&wait);
		    	//write command in FIFO
		    }
		}
	} catch(const ConfigurationException &e){
		char msg[100]={0x00};
		sprintf(msg,"warning: problem detected while reading config file %s",e.c_str());
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}
	cfg->destroy();
	//sem_wait(&stop_process);
	int32_t serv_sock;
	struct sockaddr_in serv_addr, client_addr;
	if((serv_sock = socket(AF_INET, SOCK_STREAM, 0))<0){
			vipl_printf("error: socket Creation Failed",error_lvl,__FILE__,__LINE__);
			exit(EXIT_FAILURE);
	}
	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(7370);
	if(bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		vipl_printf("error: bind Failed",error_lvl,__FILE__,__LINE__);
		exit(EXIT_FAILURE);
	}
	socklen_t c=sizeof(client_addr);
	listen(serv_sock,2);
	while(true){
		int32_t client_sock = 0x00;
		if((client_sock = accept(serv_sock, (struct sockaddr *)&client_addr,&c))<=0){
			vipl_printf("error: error in socket accept",error_lvl,__FILE__,__LINE__);
			continue;
	    }
		size_t size_recv = 0x00;
		char buffer[200]={0x00};
		char command[50] = {0x00};
		if(((size_recv = recv(client_sock,(uint8_t *)buffer,sizeof(char)*100,0))>0)){
			char *token = strtok(buffer,":");
			double val;
			int8_t db_board = 0x00;
			strcpy(command, token);
			int32_t count = 0;
			while(token!=NULL){
				token = strtok(NULL, ":");
				if(!count){
					val = atof(token);
					count++;
				}else{
					db_board = atof(token);
				}
			}
			struct command_from_DSP command_db0, command_db1;
			bzero(&command_db0, sizeof(struct command_from_DSP));
			bzero(&command_db1, sizeof(struct command_from_DSP));
			if(strcmp(command,"gain")==0x00){
				if(!db_board){
					command_db0.change_gain = true;
					command_db0.gain = val;
					size_t noofBytesRead = write(fd_write, buffer, sizeof(command_db0));
					if(noofBytesRead!=(sizeof(command_db0))){
						char msg[100]={0x00};
						sprintf(msg, "error: read::%s", strerror(errno));
						vipl_printf(msg, error_lvl, __FILE__, __LINE__);
						return 0x01;
					}else{
						char *msg=(char *)malloc(sizeof(char)*sizeof(command_db0)+20);
						bzero(msg,sizeof(char)*sizeof(command_db0));
						sprintf(msg, "info: %d Bytes wrote %s", noofBytesRead,(char *)buffer);
						vipl_printf(msg, error_lvl, __FILE__, __LINE__);
						free(msg);
					}
				}else{
					command_db1.change_gain = true;
					command_db1.gain = val;
					size_t noofBytesRead = write(fd_write, buffer, sizeof(command_db1));
					if(noofBytesRead!=(sizeof(command_db1))){
						char msg[100]={0x00};
						sprintf(msg, "error: read::%s", strerror(errno));
						vipl_printf(msg, error_lvl, __FILE__, __LINE__);
						return 0x01;
					}else{
						char *msg=(char *)malloc(sizeof(char)*sizeof(command_db1)+20);
						bzero(msg,sizeof(char)*sizeof(command_db1));
						sprintf(msg, "info: %d Bytes wrote %s", noofBytesRead,(char *)buffer);
						vipl_printf(msg, error_lvl, __FILE__, __LINE__);
						free(msg);
					}
				}
			}
#if 0
			else if(strcmp(command,"atten")==0x00){
				if(!db_board){
					 command_db0.change_gain = true;
					 command_db0.gain = val;
				}else{
					  command_db1.change_gain = true;
					  command_db1.gain = val;
				}
			}
#endif

		}
	 }
}
int32_t main(int argc, char *argv[]){
	int32_t opt = 0x00;
	char config_file_path[100] = {0x00};
	if(argc<=1){
		fprintf(stderr,"No parameters found\n");
		return (EXIT_FAILURE);
	}
	//Run-time arguments passing
	char command[300]={"../config/settings.sh"};
	strcpy(oui, "../config/oui.txt");
	while((opt = getopt(argc, argv, "c:e:s:hv:m:"))!= -1) {
		switch(opt){
			case 'h': printUsage();
	            	  exit(EXIT_SUCCESS);
	            	  break;
	        case 'e': sscanf(optarg, "%d", &error_lvl);
	        	 	  break;
	        case 'v': version();
	        		  break;
	        case 'c': strcpy(config_file_path, optarg);
	        		  break;
	        case 's': bzero(command,sizeof(char)*300);
	        		  strcpy(command, optarg);
	        	      break;
	        case 'm': bzero(oui ,sizeof(char)*300);
	        		  strcpy(oui, optarg);
	        	      break;
	        default: exit(EXIT_FAILURE);
	            	  break;
	    }
	}
	FILE* pipe = popen(command, "r");
	if(pipe==NULL)
		vipl_printf("error:unable to find settings", error_lvl, __FILE__, __LINE__);
	sleep(1);
	fclose(pipe);
	//initialize the signal handler
	signal(SIGINT, intHandler);
	sem_init(&stop_process, 0, 1);
	sem_init(&wait, 0, 1);

	//initialize semaphore for raising a signal only when a queue is to be pushed and popped.
	//So that we dont eatup CPU clocks

	sem_init(&lock, 0, 1);
	{
		char msg[200]={0x00};
		sprintf(msg, "info: Process started with pid: %d", getpid());
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}

	//thread for initializing the dequeue process thread..
	boost::thread t1(initUSRP);
	boost::thread t2(parse_configfile, config_file_path);

	//FIFO for receiving the control commands from the GUI
	fifo_read_write control_pipe_init("/tmp/pipe_command_read", "/tmp/pipe_command_write");

	//tcp_serv servport;
	return 0x00;
}
