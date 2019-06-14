/*
 * fifo_read_write.h
 *
 *  Created on: 02-Apr-2019
 *      Author: Snehasish Kar
 */

#ifndef INCLUDE_FIFO_READ_WRITE_H_
#define INCLUDE_FIFO_READ_WRITE_H_

#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <semaphore.h>
#include <unistd.h>
#include <complex>
#include <vector>
#include <queue>

#define port 7370
#define IP "127.0.0.1"
#define total_conn 64

extern bool stop_read_fifo;

#pragma pack (push,1)

struct command_from_DSP{
	int32_t num_channels;
	uint8_t mode;
	uint8_t db_board;
	uint8_t drone_dump_mode;
	uint32_t mboard;
	uint32_t port_no;
	bool change_freq;
	bool change_gain;
	bool init_board;
	bool ntwrkscan;
	bool getgps;
	double freq;
	double gain;
	double samp_rate;
	double atten;
	double bandwidth;
	double lo_offset;
	double tx_power;
	char mboard_addr[34];
	char channel_list[14];
	char band[3];
	char technology[11];
	char interface[50];
	char handshake[200];
	char offlinePcap[200];
	char json_drone_path[200];
	char drone_dump_addr[34];
};
#pragma pop()

using namespace std;

class fifo_read_write{
	int32_t fd_read;
	int32_t fd_write;
	struct command_from_DSP command;
public:
	fifo_read_write(char *pipe_command_read, char *pipe_command_write);
	fifo_read_write(char *pipe_command_read);
	fifo_read_write(char *pipe_command_write, bool write=true);
	virtual ~fifo_read_write();
	void fifo_read();
	int8_t fifo_write(struct command_from_DSP response);
	int32_t samplesWrite(complex<float> *buffer, int32_t bytes_to_write);
};


extern queue<struct command_from_DSP> command_queue;
extern sem_t lock;
extern sem_t wait;


#endif /* INCLUDE_FIFO_READ_WRITE_H_ */
