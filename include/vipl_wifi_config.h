/*
 * wifi_config.h
 *
 *  Created on: 25-Apr-2019
 *      Author: Snehasish Kar
 */

#ifndef INCLUDE_VIPL_WIFI_CONFIG_H_
#define INCLUDE_VIPL_WIFI_CONFIG_H_

#include <inttypes.h>
#include <semaphore.h>
#include "../include/viplrfinterface.h"

#define DELAY_VAR_A 16
#define DELAY_VAR_B 320
#define VECTOR_SIZE 1
#define WINDOW_SIZE 48
#define MOVING_AVERAGE_LENGTH WINDOW_SIZE+16
#define sync_length 320
#define enable_log false
#define enable_debug false
#define FFT_SIZE 64
#define WIFI_SAMPLE_RATE_A 20000000
#define WIFI_SAMPLE_RATE_G 20000000
#define WIFI_SAMPLE_RATE_P 10000000
#define WIFI_BUFFER_TIME_IN_SECS 15
#define TOTAL_BUFFER_SIZE WIFI_SAMPLE_RATE_A*WIFI_BUFFER_TIME_IN_SECS
#define WAIT_TIME 1000000
#define LO_OFFSET_1 6000000
#define LO_OFFSET_2 11000000
#define channel_length_A 47
#define channel_length_G 15
#define channel_length_P 7

void load_map(char *band);
double find_freq(int ch, char band);
void wifi_demod_band_a(int8_t usrp_channel);
void wifi_demod_band_g(int8_t usrp_channel);
void wifi_demod_band_p(int8_t usrp_channel);
void wifi_demod_band_b(struct command_from_DSP command);

extern int32_t channel_list_band_p[];
extern int32_t channel_list_band_bg[];
extern int32_t channel_list_band_a[];

void load_map_band_a();
void load_map_band_g();
void load_map_band_p();
double find_freq(int32_t ch, char *band);
int8_t shift_freq(double freq, int8_t channel);

extern sem_t stop_process;

#pragma pack (push,1)
struct wifiConfig{
	int8_t mode;
	uint8_t channel;
	int32_t num_channel;
	double rate;
	double spb;
	double freq;
	bool is_hopping;
	int32_t channel_list_command[50];
	char band[4];
	char technology[50];
};
#pragma pop()

extern int32_t channel_list_band_p[channel_length_P];
extern int32_t channel_list_band_bg[channel_length_G];
extern int32_t channel_list_band_a[channel_length_A];
extern char oui[300];

#endif /* INCLUDE_VIPL_WIFI_CONFIG_H_ */
