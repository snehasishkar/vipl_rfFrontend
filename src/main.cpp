/*
 * main.cpp
 *
 *  Created on: 03-Apr-2019
 *      Author: Snehasish Kar
 */

#include <iostream>
#include <string>
#include <queue>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <boost/thread.hpp>
#include <semaphore.h>
#include <signal.h>

#include "../include/fifo_read_write.h"
#include "../include/vipl_printf.h"
#include "../include/viplrfinterface.h"
int32_t error_lvl = 0x00;

sem_t lock;
bool stop_rx = false;
bool stop_gps = false;
bool stop_read_fifo = false;

void printUsage(void){
	fprintf(stderr,"\t ./viplrfFrontend -e <1/2/3>");
	fprintf(stderr,"\t -e: error level <1/2/3>");
}

void version(void){
	fprintf(stderr,"Build on %s:%s by Snehasish Kar",__DATE__, __TIME__);
}

void intHandler(int dummy) {
	stop_rx = true;
	stop_gps = true;
	stop_read_fifo = true;
	vipl_printf("ALERT: sigint got..exiting!!", error_lvl, __FILE__, __LINE__);
	sleep(1);
	exit(EXIT_SUCCESS);
}


void initUSRP(){
	vipl_rf_interface rf_interface;
}


int32_t main(int argc, char *argv[]){
	int32_t opt = 0x00;
	char config_file_path[100] = {0x00};
	const char *scope = "";
	const char *default_configFile = "../config/viplrfConfig.cfg";
	struct command_from_DSP command;

	if(argc<=1){
		fprintf(stderr,"No parameters found\n");
		return (EXIT_FAILURE);
	}
	//Run-time arguements passing

	while((opt = getopt(argc, argv, "c:e:hv"))!= -1) {
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
	        default: exit(EXIT_FAILURE);
	            	   break;
	    }
	}
	//initialize the signal handler
	signal(SIGINT, intHandler);
	//initialize sempahore for raising a signal only when a queue is to be pushed and popped.
	//So that we dont eatup CPU clocks

	sem_init(&lock, 0, 1);
	{
		char msg[200]={0x00};
		sprintf(msg, "info: Process started with pid: %d", getpid());
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}

	//thread for initializing the dequeue process thread..
	boost::thread t1(initUSRP);

	//FIFO for receiving the control commands from the GUI
	fifo_read_write control_pipe_init("/tmp/pipe_command_read", "/tmp/pipe_command_write");

	//tcp_serv servport;
	return 0x00;
}
