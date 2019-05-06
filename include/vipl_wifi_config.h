/*
 * wifi_config.h
 *
 *  Created on: 25-Apr-2019
 *      Author: Snehasish Kar
 */

#ifndef INCLUDE_VIPL_WIFI_CONFIG_H_
#define INCLUDE_VIPL_WIFI_CONFIG_H_

#include <inttypes.h>

#define DELAY_VAR_A 16
#define DELAY_VAR_B 320
#define VECTOR_SIZE 1
#define WINDOW_SIZE 48
#define MOVING_AVERAGE_LENGTH WINDOW_SIZE+16
#define sync_length 320
#define enable_log false
#define enable_debug false
#define FFT_SIZE 64
#define WIFI_SAMPLE_RATE 20e6
#define WIFI_BUFFER_TIME_IN_SECS 15
#define TOTAL_BUFFER_SIZE WIFI_SAMPLE_RATE*WIFI_BUFFER_TIME_IN_SECS
#define WAIT_TIME 250000000
#define LO_OFFSET_1 6000000
#define LO_OFFSET_2 11000000

void load_map(char *band);
double find_freq(int ch, char band);
void wifi_demod_band_a(int8_t usrp_channel, char *channel_list, bool ntwrkscan);

#endif /* INCLUDE_VIPL_WIFI_CONFIG_H_ */
