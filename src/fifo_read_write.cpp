/*
 * tcpserv.cpp
 *
 *  Created on: 02-Apr-2019
 *      Author: Snehasish Kar
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <queue>
#include <sys/stat.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "../include/fifo_read_write.h"
#include "../include/vipl_printf.h"
#include "../include/viplrfinterface.h"

#define STDMASK 666
#define NMBELEMENT 0x01
#define max_command 100

std::queue<struct command_from_DSP> command_queue;
extern int errno;

void fifo_read_write::fifo_read(){
	struct command_from_DSP command;
	uint8_t *buffer = (uint8_t*)malloc(sizeof(command));
	while(!stop_read_fifo){
		bzero(buffer,sizeof(char)*sizeof(command));
		size_t noofBytesRead = 0x00, noofBytesAlreadyRead = 0x00;
		if(fd_read==NULL)
			return;
		while((noofBytesRead=read(fd_read, buffer+noofBytesAlreadyRead, (sizeof(command)*NMBELEMENT)-noofBytesAlreadyRead))>0x00){
			noofBytesAlreadyRead+=noofBytesRead;
		}
		if(noofBytesAlreadyRead==0x00){
			int32_t rtnval = raise(SIGINT);
			if(rtnval==SIG_ERR)
				vipl_printf("error: failed in raising SIGINT", error_lvl, __FILE__, __LINE__);

		}
		if(noofBytesAlreadyRead!=(sizeof(command)*NMBELEMENT)){
			char msg[100]={0x00};
			sprintf(msg, "error: read::number of bytes read %d and actual size to read %d", noofBytesAlreadyRead, sizeof(command)*NMBELEMENT);
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
			continue;
		}else{
			char *msg=(char *)malloc(sizeof(char)*sizeof(command)*NMBELEMENT+20);
			bzero(msg,sizeof(char)*sizeof(command)*NMBELEMENT);
			sprintf(msg, "info: %d Bytes read %s", noofBytesAlreadyRead,(char *)buffer);
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
			free(msg);
		}
		memcpy(&command,buffer, sizeof(command)*NMBELEMENT);
		if(command_queue.size()<max_command){
			command_queue.push(command);
		}else{
			vipl_printf("warning: queue already full", error_lvl, __FILE__, __LINE__);
			continue;
		}
		if(sem_post(&lock)<-1){
			char msg[100]={0x00};
			sprintf(msg, "error: unable to set sem_wait %s", strerror(errno));
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		}
		sem_post(&wait);
	}
	free(buffer);
}

int8_t fifo_read_write::fifo_write(struct command_from_DSP response){
	uint8_t *buffer = (uint8_t*)malloc(sizeof(response));
	bzero(buffer,sizeof(char)*sizeof(response));
	size_t noofBytesRead = write(fd_write, buffer, sizeof(response)*NMBELEMENT);
	memcpy(buffer, &response, sizeof(response));
	if(noofBytesRead!=(sizeof(response)*NMBELEMENT)){
		char msg[100]={0x00};
		sprintf(msg, "error: read::%s", strerror(errno));
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		return 0x01;
	}else{
		char *msg=(char *)malloc(sizeof(char)*sizeof(response)*NMBELEMENT+20);
		bzero(msg,sizeof(char)*sizeof(response)*NMBELEMENT);
		sprintf(msg, "info: %d Bytes wrote %s", strerror(errno),(char *)buffer);
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		free(msg);
	}

	free(buffer);
	return 0x00;
}


fifo_read_write::fifo_read_write(char *pipe_command_read, char *pipe_command_write) {
	fd_read = 0x00;
	fd_write = 0x00;
	//stop = false;
	struct stat buf;
	//char *pipe_command_read = "/tmp/pipe_command_read";
	//char *pipe_command_write = "/tmp/pipe_command_write";
	bool donot_try = false;
	re_try:
	fd_write = open(pipe_command_write,O_WRONLY);
	if(fd_write==-1){
		{
			char msg[100]={0x00};
			sprintf(msg, "error: unable to open PIPE %s for writing %s",pipe_command_write,strerror(errno));
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);

		}
		if((mkfifo(pipe_command_write,STDMASK)!=0x00) && (donot_try==false)){
			char msg[100]={0x00};
			sprintf(msg, "error: unable to open pipe for writing response %s", strerror(errno));
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
			donot_try=true;
		}
		sleep(1);
		goto re_try;
	}else{
		vipl_printf("info:ready to write to DSP on pipe /tmp/pipe_command_write", error_lvl, __FILE__, __LINE__);
	}
	if((mkfifo(pipe_command_read,STDMASK)!=0x00)){
		char msg[100]={0x00};
		sprintf(msg, "error: unable to create pipe for reading command %s", strerror(errno));
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}
	re_connect:
	fd_read = open(pipe_command_read,O_RDONLY);
	if(fd_read==-1){
		{
			char msg[100]={0x00};
			sprintf(msg, "error: unable to open PIPE %s for writing %s",pipe_command_read,strerror(errno));
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		}
		goto re_connect;
	}else{
		vipl_printf("listening to DSP on pipe /tmp/pipe_command_read", error_lvl, __FILE__, __LINE__);
	}
	fifo_read();
}

fifo_read_write::fifo_read_write(char *pipe_command_read) {
	fd_read = 0x00;
	fd_write = 0x00;
	//stop = false;
	struct stat buf;
	//char *pipe_command_read = "/tmp/pipe_command_read";
	//char *pipe_command_write = "/tmp/pipe_command_write";
	bool donot_try = false;
	if((mkfifo(pipe_command_read,STDMASK)!=0x00)){
		char msg[100]={0x00};
		sprintf(msg, "error: unable to create pipe for reading command %s", strerror(errno));
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}
	re_connect:
	fd_read = open(pipe_command_read,O_RDONLY);
	if(fd_read==-1){
		{
			char msg[100]={0x00};
			sprintf(msg, "error: unable to open PIPE %s for writing %s",pipe_command_read,strerror(errno));
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		}
		goto re_connect;
	}else{
		vipl_printf("listening to DSP on pipe /tmp/pipe_command_read", error_lvl, __FILE__, __LINE__);
		char msg[100]={0x00};
		sprintf(msg, "info:listening to DSP on pipe %s", pipe_command_read);
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}
}

fifo_read_write::fifo_read_write(char *pipe_command_write, bool write=true) {
	fd_read = 0x00;
	fd_write = 0x00;
	//stop = false;
	struct stat buf;
	//char *pipe_command_read = "/tmp/pipe_command_read";
	//char *pipe_command_write = "/tmp/pipe_command_write";
	bool donot_try = false;
	re_try:
	fd_write = open(pipe_command_write,O_WRONLY);
	if(fd_write==-1){
		{
			char msg[100]={0x00};
			sprintf(msg, "error: unable to open PIPE %s for writing %s",pipe_command_write,strerror(errno));
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);

		}
		if((mkfifo(pipe_command_write,STDMASK)!=0x00) && (donot_try==false)){
			char msg[100]={0x00};
			sprintf(msg, "error: unable to open pipe for writing response %s", strerror(errno));
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
			donot_try=true;
		}
		sleep(1);
		goto re_try;
	}else{
		char msg[100]={0x00};
		sprintf(msg, "info:ready to write to DSP on pipe %s", pipe_command_write);
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}
}

int32_t fifo_read_write::samplesWrite(complex<float> *buffer, int32_t bytes_to_write){
	size_t noofBytesWrote = write(fd_write, buffer, bytes_to_write);
	if(noofBytesWrote!=bytes_to_write){
		char msg[100]={0x00};
		sprintf(msg, "error: read::%s", strerror(errno));
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		return -1;
	}else{
		char *msg=(char *)malloc(100);
		bzero(msg,sizeof(char)*100);
		sprintf(msg, "info: %d Bytes wrote", noofBytesWrote);
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		free(msg);
	}
	return noofBytesWrote;
}


fifo_read_write::~fifo_read_write() {
	close(fd_read);
	close(fd_write);
	sem_destroy(&lock);
}
