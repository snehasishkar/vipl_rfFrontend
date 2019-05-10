/*
 * viplrfinterface.h
 *
 *  Created on: 01-Apr-2019
 *      Author: root
 */

#ifndef INCLUDE_VIPLRFINTERFACE_H_
#define INCLUDE_VIPLRFINTERFACE_H_

#include <iostream>
#include <string.h>
#include <stdint.h>
#include <queue>

#include <uhd/exception.hpp>
#include <uhd/types/tune_request.hpp>
#include <uhd/usrp/multi_usrp.hpp>
#include <uhd/utils/safe_main.hpp>
#include <uhd/utils/thread.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "fifo_read_write.h"

#define rx 0
#define tx 1
#define ntwrk_scan 2

extern char IP_ADDR[50];
extern bool stop_rx;
extern bool stop_gps;


struct vipl_rf_tap{
	uint8_t channel;
	float gain;
	double sample_rate;
	double freq;
	double bandwidth;
	double latitude;
	double longitude;
	int32_t altitude;
	int32_t no_of_satellite;
};

class vipl_rf_interface {
	double sample_rate;
	double freq_rx_board_a;
	double freq_rx_board_b;
	double freq_tx_board_a;
	double freq_tx_board_b;
	double bandwidth;
	double lo_offset;
	float gain;
	uint8_t channel;
	std::string subdev;
	int32_t mboard;
	uhd::usrp::multi_usrp::sptr usrp;
	uhd::rx_streamer::sptr rx_stream;
public:
	vipl_rf_interface();
	virtual ~vipl_rf_interface();
	int8_t set_rx_freq(double freq, int8_t channel);
	int8_t set_tx_freq(double freq, int8_t channel);
	int8_t set_gain(double gain, int8_t channel);
	void start_stream(double freq, int8_t mode, uint8_t channel, double rate);
	void get_gps_val(void);
	bool lock_gps(void);
	void dequeue(void);
};

extern std::queue<std::complex<float>> tx_db_a_buffer;
extern std::queue<std::complex<float>> tx_db_b_buffer;
extern std::queue<std::complex<float>> rx_db_a_buffer;
extern std::queue<std::complex<float>> rx_db_b_buffer;

extern struct vipl_rf_tap rftap_dbA;
extern struct vipl_rf_tap rftap_dbB;


#endif /* INCLUDE_VIPLRFINTERFACE_H_ */
