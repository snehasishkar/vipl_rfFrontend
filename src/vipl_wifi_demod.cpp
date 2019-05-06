/*
 * vipl_wifi_demod.cpp
 *
 *  Created on: 24-Apr-2019
 *      Author: Snehasish Kar
 */

#include <inttypes.h>
#include <stdio.h>
#include <map>

#include <gnuradio/types.h>
#include <gnuradio/top_block.h>
#include <gnuradio/blocks/delay.h>
#include <gnuradio/blocks/complex_to_mag.h>
#include <gnuradio/blocks/moving_average_ff.h>
#include <gnuradio/blocks/conjugate_cc.h>
#include <gnuradio/blocks/multiply_cc.h>
#include <gnuradio/blocks/divide_ff.h>
#include <gnuradio/blocks/streams_to_vector.h>
#include <gnuradio/fft/fft_vcc.h>
#include <gnuradio/fft/window.h>
#include <gnuradio/blocks/file_descriptor_source.h>
#include <gnuradio/blocks/file_descriptor_sink.h>
#include <gnuradio/blocks/complex_to_mag_squared.h>
#include <gnuradio/blocks/stream_to_vector.h>
#include <gnuradio/blocks/file_sink.h>
#include <pmt/pmt.h>

#include <ieee802-11/moving_average_ff.h>
#include <ieee802-11/moving_average_cc.h>
#include <ieee802-11/sync_short.h>
#include <ieee802-11/sync_long.h>
#include <ieee802-11/frame_equalizer.h>
#include <ieee802-11/decode_mac.h>
#include <ieee802-11/parse_mac.h>

#include <foo/wireshark_connector.h>

#include "../include/vipl_wifi_config.h"
#include "../include/vipl_printf.h"
#include "../include/fifo_read_write.h"

#include <boost/thread.hpp>

using namespace gr;
using namespace ieee802_11;

map<int32_t, double> g, a, p;


int32_t channel_list_band_p[]= {172, 174, 176, 178, 180, 182, 184};
int32_t channel_list_band_bg[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0};
int channel_list_band_a[] = {36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  \
							 60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116, \
							 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, \
							 144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173, 0};	\

void load_map_band_g(){
	g[1] = 2412000000.0;
	g[2] = 2417000000.0;
	g[3] = 2422000000.0;
	g[4] = 2427000000.0;
	g[5] = 2432000000.0;
	g[6] = 2437000000.0;
	g[7] = 2442000000.0;
	g[8] = 2447000000.0;
	g[9] = 2452000000.0;
	g[10] = 2457000000.0;
	g[11] = 2462000000.0;
	g[12] = 2467000000.0;
	g[13] = 2472000000.0;
	g[14] = 2484000000.0;
}

void load_map_band_a(){
	a[34] = 5170000000.0;
	a[36] = 5180000000.0;
	a[38] = 5190000000.0;
	a[40] = 5200000000.0;
	a[42] = 5210000000.0;
	a[44] = 5220000000.0;
	a[46] = 5230000000.0;
	a[48] = 5240000000.0;
	a[50] = 5250000000.0;
	a[52] = 5260000000.0;
	a[54] = 5270000000.0;
	a[56] = 5280000000.0;
	a[58] = 5290000000.0;
	a[60] = 5300000000.0;
	a[62] = 5310000000.0;
	a[64] = 5320000000.0;
	a[100] = 5500000000.0;
	a[102] = 5510000000.0;
	a[104] = 5520000000.0;
	a[106] = 5530000000.0;
	a[108] = 5540000000.0;
	a[110] = 5550000000.0;
	a[112] = 5560000000.0;
	a[114] = 5570000000.0;
	a[116] = 5580000000.0;
	a[118] = 5590000000.0;
	a[120] = 5600000000.0;
	a[122] = 5610000000.0;
	a[124] = 5620000000.0;
	a[126] = 5630000000.0;
	a[128] = 5640000000.0;
	a[132] = 5660000000.0;
	a[134] = 5670000000.0;
	a[136] = 5680000000.0;
	a[138] = 5690000000.0;
	a[140] = 5700000000.0;
	a[142] = 5710000000.0;
	a[144] = 5720000000.0;
	a[149] = 5745000000.0;
	a[151] = 5755000000.0;
	a[153] = 5765000000.0;
	a[155] = 5775000000.0;
	a[157] = 5785000000.0;
	a[159] = 5795000000.0;
	a[161] = 5805000000.0;
	a[165] = 5825000000.0;
}

void load_map_band_p(){
	p[172] = 5860000000.0;
	p[174] = 5870000000.0;
	p[176] = 5880000000.0;
	p[178] = 5890000000.0;
	p[180] = 5900000000.0;
	p[182] = 5910000000.0;
	p[184] = 5920000000.0;
}

void load_map(char *band){
	if(strcmp(band,"g")==0x00)
		load_map_band_g();
	else if(strcmp(band,"a")==0x00)
		load_map_band_a();
	else if(strcmp(band,"p")==0x00)
		load_map_band_p();
#if 0
	else if(strcmp(band,"ac")==0x00)
		load_map_band_p();
	else if(strcmp(band,"b")==0x00)
		load_map_band_p();
#endif
}

double find_freq(int ch, char band){
	if(band=='g')
		return g[ch];
	else if(band=='a')
		return a[ch];
	else if(band=='p')
		return p[ch];
	return -1;
}

void change_freq(int8_t usrp_channel, int32_t *channel_list, char band, int32_t no_of_channel, ieee802_11::frame_equalizer::sptr frame_equalizer_blk, fifo_read_write fifo_command){
	reload:
	for(int32_t i = 0x00; i<no_of_channel;i++){
		usleep(WAIT_TIME);
		double freq = find_freq(channel_list[i++], band);
		frame_equalizer_blk->set_frequency(freq);
		struct command_from_DSP command;
		memset(&command, 0x00, sizeof(command));
		command.change_freq = true;
		command.freq = freq;
		int8_t rtnval = fifo_command.fifo_write();
		if(rtnval)
			vipl_printf("error: Freq could not be changed! unable to write to FIFO", error_lvl, __FILE__, __LINE__);
	}
	goto reload;
}

int8_t create_fifo(char *fifo_name){
	if(mkfifo(fifo_name,666)!=0x00){
		char msg[100]={0x00};
		sprintf(msg, "error: unable to open pipe for writing response %s", strerror(errno));
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		return 0x01;
	}
	return 0x00;
}

void wifi_demod_band_a(int8_t channel, char *channel_list, bool ntwrkscan){
	vipl_printf("info: Demodualtion for Band A started",error_lvl, __FILE__, __LINE__);
	char fifo_name[30]={0x00};
	sprintf(fifo_name,"/tmp/samples_write_%d", channel);
	int32_t fd_src;
	label:
	fd_src = open(fifo_name,O_RDONLY);
	if(fd_src<=0x00){
		vipl_printf("error: unable to open FIFO for reading samples...exiting!!", error_lvl, __FILE__, __LINE__);
		goto label;
	}
	bzero(fifo_name, sizeof(char)*30);
	sprintf(fifo_name,"/tmp/samples_read_%d", channel);
	if(create_fifo(fifo_name)!=0x00)
		vipl_printf("error: unable to create FIFO", error_lvl, __FILE__, __LINE__);
	int32_t fd_sink;
#if 0
	fd_sink = open(fifo_name,O_RDONLY);
	if(fd_sink<=0x00){
		vipl_printf("error: unable to open FIFO for reading writing...exiting!!", error_lvl, __FILE__, __LINE__);

	}
#endif
	enum Equalizer channel_estimation_algo = LS;
	blocks::file_descriptor_source::sptr fd_source =  blocks::file_descriptor_source::make(sizeof(std::complex<float>)*1,fd_src, false);
	//blocks::file_descriptor_sink::sptr fd_sink_blk = blocks::file_descriptor_sink::make(sizeof(uint8_t)*1,fd_sink);
	blocks::file_sink::sptr filesink = blocks::file_sink::make(sizeof(uint8_t)*1,"/home/snehasish/test.pcap",true);
	blocks::delay::sptr delay_a = blocks::delay::make(VECTOR_SIZE, DELAY_VAR_A);
	blocks::delay::sptr delay_b = blocks::delay::make(VECTOR_SIZE, DELAY_VAR_B);
	blocks::complex_to_mag_squared::sptr complex2mag_a = blocks::complex_to_mag_squared::make(VECTOR_SIZE);
	blocks::complex_to_mag::sptr complex2mag_b = blocks::complex_to_mag::make(VECTOR_SIZE);
	blocks::conjugate_cc::sptr conjugate_cc = blocks::conjugate_cc::make();
	blocks::multiply_cc::sptr multiply_cc = blocks::multiply_cc::make(VECTOR_SIZE);
	blocks::divide_ff::sptr divide_ff = blocks::divide_ff::make(VECTOR_SIZE);
	ieee802_11::moving_average_cc::sptr moving_average_complex = ieee802_11::moving_average_cc::make(WINDOW_SIZE);
	ieee802_11::moving_average_ff::sptr moving_average_float = ieee802_11::moving_average_ff::make(MOVING_AVERAGE_LENGTH);
	ieee802_11::sync_short::sptr wifi_sync_short = ieee802_11::sync_short::make(0.56, 2, enable_log, enable_debug);
	ieee802_11::sync_long::sptr wifi_sync_long = ieee802_11::sync_long::make(sync_length, enable_log, enable_debug);
	ieee802_11::frame_equalizer::sptr frame_equalizer_blk = ieee802_11::frame_equalizer::make(channel_estimation_algo,5170000000.0,20e6,false, false);
	blocks::streams_to_vector::sptr streams_to_vector = blocks::streams_to_vector::make(VECTOR_SIZE, FFT_SIZE);
	fft::fft_vcc::sptr fft_cc = fft::fft_vcc::make(FFT_SIZE, true, fft::window::rectangular(FFT_SIZE), true, 1);
	blocks::stream_to_vector::sptr stream_to_vect = blocks::stream_to_vector::make(VECTOR_SIZE,FFT_SIZE);
	ieee802_11::decode_mac::sptr decode_mac = ieee802_11::decode_mac::make(enable_log,enable_debug);
#if 1
	ieee802_11::parse_mac::sptr parse_mac = ieee802_11::parse_mac::make(enable_log, enable_debug);
#endif
	foo::wireshark_connector::sptr wireshark = foo::wireshark_connector::make(foo::LinkType::WIFI, enable_debug);
	if(ntwrkscan){
		char read_path[100]={0x00};
		char write_path[100]={0x00};
		sprintf(read_path,"/tmp/command_read_db_%d",channel);
		sprintf(write_path,"/tmp/command_write_db_%d",channel);
		fifo_read_write fifo_command(read_path, write_path);
		boost::thread t1(change_freq, channel, channel_list_band_a, 'a', 48, frame_equalizer_blk, fifo_command);
	}else{
		if(strlen(channel_list)>1){
			int32_t chann_list[60]={0x00}, i=0x00;
			char *token;
			token = strtok(channel_list,",");
			while(token!=NULL){
				chann_list[i++] = atoi(token);
				token = strtok(token,",");
			}
			char read_path[100]={0x00};
			//char write_path[100]={0x00};
			sprintf(read_path,"/tmp/command_read_db_%d",channel);
			//sprintf(write_path,"/tmp/command_write_db_%d",channel);
			fifo_read_write fifo_command(read_path, read_path);
			boost::thread t1(change_freq, channel, chann_list, 'a', i-1, frame_equalizer_blk, fifo_command);
		}else{
			int32_t channel = atoi(channel_list);
			double freq = find_freq(channel, 'a');
			frame_equalizer_blk->set_frequency(freq);
		}
	}
	top_block_sptr tb(make_top_block("wifi_rx"));
	tb->connect(fd_source,0x00,delay_a,0x00);
	tb->connect(fd_source,0x00,complex2mag_a,0x00);
	tb->connect(fd_source,0x00,multiply_cc,0x00);
	tb->connect(complex2mag_a,0x00, moving_average_float, 0x00);
	tb->connect(moving_average_float, 0x00, divide_ff, 0x00);
	tb->connect(complex2mag_b, 0x00, divide_ff, 0x00);
	tb->connect(delay_a,0x00,conjugate_cc,0x00);
	tb->connect(conjugate_cc,0x00,multiply_cc,0x01);
	tb->connect(multiply_cc,0x00,moving_average_complex,0x00);
	tb->connect(moving_average_complex,0x00,complex2mag_b,0x00);
	tb->connect(delay_a,0x00,wifi_sync_short,0x00);
	tb->connect(moving_average_complex,0x00, wifi_sync_short,0x01);
	tb->connect(divide_ff, 0x00, wifi_sync_short, 0x02);
	tb->connect(wifi_sync_short,0x00,wifi_sync_long,0x00);
	tb->connect(wifi_sync_short,0x00,delay_b,0x00);
	tb->connect(delay_b,0x00,wifi_sync_long,0x00);
	tb->connect(wifi_sync_long,0x00,stream_to_vect,0x00);
	tb->connect(stream_to_vect,0x00,fft_cc,0x00);
	tb->connect(fft_cc,0x00,frame_equalizer_blk,0x00);
	tb->connect(fft_cc,0x00,frame_equalizer_blk,0x00);
	tb->connect(frame_equalizer_blk,0x00,decode_mac, 0x00);
#if 1
	tb->msg_connect(decode_mac, "out", parse_mac, "in");
#endif
	tb->msg_connect(decode_mac, "out", wireshark, "in");
	//tb->connect(wireshark, 0x00, fd_sink_blk, 0x00);
	tb->connect(wireshark,0, filesink,0);
	tb->start();
}
