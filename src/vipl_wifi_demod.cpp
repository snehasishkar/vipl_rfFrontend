/*
 * vipl_wifi_demod.cpp
 *
 *  Created on: 24-Apr-2019
 *      Author: Snehasish Kar
 */

#include <inttypes.h>
#include <stdio.h>
#include <map>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

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
#include <gnuradio/blocks/null_sink.h>
#include <pmt/pmt.h>

#include <ieee802-11/moving_average_ff.h>
#include <ieee802-11/moving_average_cc.h>
#include <ieee802-11/sync_short.h>
#include <ieee802-11/sync_long.h>
#include <ieee802-11/frame_equalizer.h>
#include <ieee802-11/decode_mac.h>
#include <ieee802-11/parse_mac.h>

#include <foo/wireshark_connector.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>

#include "../include/vipl_wifi_config.h"
#include "../include/vipl_printf.h"
#include "../include/fifo_read_write.h"
#include "../include/viplrfinterface.h"

#include <boost/thread.hpp>
#include <signal.h>
#include <pcap.h>
#include <pwd.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>

using namespace gr;
using namespace ieee802_11;

double change_freq_val = 0x00;
char *dev = NULL;
pcap_t *descr=NULL;
pcap_dumper_t *dumpfile=NULL;
clock_t start=0;
const char *homedir=NULL;
struct timespec start_time={0,0}, end_time={0,0};
struct timespec channel_start_time={0,0}, channel_end_time={0,0};
char pcap_filename[200], dir_name[200];
int32_t channel_list_command[50]={0x00};
int32_t num_channels=0, k=0;
map<int32_t, double> g, a, p, b;


int32_t channel_list_band_p[]= {172, 174, 176, 178, 180, 182, 184};
int32_t channel_list_band_bg[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0};
int32_t channel_list_band_a[] = {36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  \
							 60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116, \
							 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, \
							 144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173};	\

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
	a[169] = 5845000000.0;
	a[173] = 5865000000.0;
	//a[0] =
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

void load_map_band_b(){
	b[1] = 2412000000.0;
	b[2] = 2417000000.0;
	b[3] = 2422000000.0;
	b[4] = 2427000000.0;
	b[5] = 2432000000.0;
	b[6] = 2437000000.0;
	b[7] = 2442000000.0;
	b[8] = 2447000000.0;
	b[9] = 2452000000.0;
	b[10] = 2457000000.0;
	b[11] = 2462000000.0;
	b[12] = 2467000000.0;
	b[13] = 2472000000.0;
	b[14] = 2484000000.0;
}
ieee802_11::frame_equalizer::sptr frame_equalizer_blk_0;
ieee802_11::frame_equalizer::sptr frame_equalizer_blk_1;

void load_map(char *band){
	if(strcmp(band,"g")==0x00)
		load_map_band_g();
	else if(strcmp(band,"a")==0x00)
		load_map_band_a();
	else if(strcmp(band,"p")==0x00)
		load_map_band_p();
	else if(strcmp(band,"b")==0x00)
		load_map_band_b();
#if 0
	else if(strcmp(band,"ac")==0x00)
		load_map_band_p();
	else if(strcmp(band,"b")==0x00)
		load_map_band_p();
#endif
}

double find_freq(int32_t ch, char *band){
	if(strcmp(band, "g")==0x00)
		return g[ch];
	else if(strcmp(band, "a")==0x00)
		return a[ch];
	else if(strcmp(band, "p")==0x00)
		return p[ch];
	else if(strcmp(band, "b")==0x00){
		return b[ch];
	}
	return -1;
}

int8_t shift_freq(double freq, int8_t channel){
	if(!channel)
		frame_equalizer_blk_0->set_frequency(freq);
	else
		frame_equalizer_blk_1->set_frequency(freq);
	return 0x00;
}


int8_t create_fifo(char *fifo_name){
	if(mkfifo(fifo_name,666)!=0x00){
		char msg[100]={0x00};
		sprintf(msg, "error: unable to create pipe for writing response %s", strerror(errno));
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		return 0x01;
	}
	return 0x00;
}

void wifi_demod_band_a(int8_t channel){
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
#if 0
	bzero(fifo_name, sizeof(char)*30);
	sprintf(fifo_name,"/tmp/samples_read_%d", channel);
	if(create_fifo(fifo_name)!=0x00)
		vipl_printf("error: unable to create FIFO", error_lvl, __FILE__, __LINE__);
	int32_t fd_sink;

	fd_sink = open(fifo_name,O_WRONLY);
	if(fd_sink<=0x00){
		vipl_printf("error: unable to open FIFO for reading writing...exiting!!", error_lvl, __FILE__, __LINE__);

	}
#endif
	enum Equalizer channel_estimation_algo = LS;
	blocks::file_descriptor_source::sptr fd_source =  blocks::file_descriptor_source::make(sizeof(std::complex<float>)*1,fd_src, false);
	//blocks::file_descriptor_sink::sptr fd_sink_blk = blocks::file_descriptor_sink::make(sizeof(uint8_t)*1,fd_sink);
	//blocks::file_sink::sptr filesink = blocks::file_sink::make(sizeof(uint8_t)*1,"/home/decryptor/test1.pcap",true);
	blocks::null_sink::sptr null_sinks = blocks::null_sink::make(sizeof(uint8_t)*1);
	blocks::delay::sptr delay_a = blocks::delay::make(VECTOR_SIZE*sizeof(std::complex<float>), DELAY_VAR_A);
	blocks::delay::sptr delay_b = blocks::delay::make(VECTOR_SIZE*sizeof(std::complex<float>), DELAY_VAR_B);
	blocks::complex_to_mag_squared::sptr complex2mag_a = blocks::complex_to_mag_squared::make(VECTOR_SIZE);
	blocks::complex_to_mag::sptr complex2mag_b = blocks::complex_to_mag::make(VECTOR_SIZE);
	blocks::conjugate_cc::sptr conjugate_cc = blocks::conjugate_cc::make();
	blocks::multiply_cc::sptr multiply_cc = blocks::multiply_cc::make(VECTOR_SIZE);
	blocks::divide_ff::sptr divide_ff = blocks::divide_ff::make(VECTOR_SIZE);
	ieee802_11::moving_average_cc::sptr moving_average_complex = ieee802_11::moving_average_cc::make(WINDOW_SIZE);
	ieee802_11::moving_average_ff::sptr moving_average_float = ieee802_11::moving_average_ff::make(MOVING_AVERAGE_LENGTH);
	ieee802_11::sync_short::sptr wifi_sync_short = ieee802_11::sync_short::make(0.56, 2, enable_log, enable_debug);
	ieee802_11::sync_long::sptr wifi_sync_long = ieee802_11::sync_long::make(sync_length, enable_log, enable_debug);
	if(!channel)
		frame_equalizer_blk_0 = ieee802_11::frame_equalizer::make(channel_estimation_algo,5170000000.0,WIFI_SAMPLE_RATE_A,false, false);
	else
		frame_equalizer_blk_1 = ieee802_11::frame_equalizer::make(channel_estimation_algo,5170000000.0,WIFI_SAMPLE_RATE_A,false, false);
	blocks::streams_to_vector::sptr streams_to_vector = blocks::streams_to_vector::make(VECTOR_SIZE, FFT_SIZE);
	fft::fft_vcc::sptr fft_cc = fft::fft_vcc::make(FFT_SIZE, true, fft::window::rectangular(FFT_SIZE), true, 1);
	blocks::stream_to_vector::sptr stream_to_vect = blocks::stream_to_vector::make(VECTOR_SIZE*sizeof(std::complex<float>),FFT_SIZE);
	ieee802_11::decode_mac::sptr decode_mac = ieee802_11::decode_mac::make(enable_log,enable_debug);
#if 1
	ieee802_11::parse_mac::sptr parse_mac = ieee802_11::parse_mac::make(enable_log, enable_debug);
#endif
	foo::wireshark_connector::sptr wireshark = foo::wireshark_connector::make(foo::LinkType::WIFI, enable_debug);
	top_block_sptr tb(make_top_block("wifi_rx_a"));
	tb->connect(fd_source,0x00,delay_a,0x00);
	tb->connect(fd_source,0x00,complex2mag_a,0x00);
	tb->connect(fd_source,0x00,multiply_cc,0x00);
	tb->connect(complex2mag_a,0x00, moving_average_float, 0x00);
	tb->connect(moving_average_float, 0x00, divide_ff, 0x01);
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
	tb->connect(delay_b,0x00,wifi_sync_long,0x1);
	tb->connect(wifi_sync_long,0x00,stream_to_vect,0x00);
	tb->connect(stream_to_vect,0x00,fft_cc,0x00);
	//tb->connect(fft_cc,0x00,frame_equalizer_blk,0x00);
	if(!channel){
		tb->connect(fft_cc,0x00,frame_equalizer_blk_0,0x00);
		tb->connect(frame_equalizer_blk_0,0x00,decode_mac, 0x00);
	}else{
		tb->connect(fft_cc,0x00,frame_equalizer_blk_1,0x00);
		tb->connect(frame_equalizer_blk_1,0x00,decode_mac, 0x00);
	}
#if 1
	tb->msg_connect(decode_mac, "out", parse_mac, "in");
#endif
	tb->msg_connect(decode_mac, "out", wireshark, "in");
	tb->connect(wireshark, 0x00, null_sinks, 0x00);
	tb->start();
	tb->wait();
	sem_wait(&stop_process);
}

void wifi_demod_band_g(int8_t channel){
	vipl_printf("info: Demodualtion for Band G started",error_lvl, __FILE__, __LINE__);
	char fifo_name[30]={0x00};
	sprintf(fifo_name,"/tmp/samples_write_%d", channel);
	int32_t fd_src;
	label:
	fd_src = open(fifo_name,O_RDONLY);
	if(fd_src<=0x00){
		vipl_printf("error: unable to open FIFO for reading samples...exiting!!", error_lvl, __FILE__, __LINE__);
		goto label;
	}
#if 0
	bzero(fifo_name, sizeof(char)*30);
	sprintf(fifo_name,"/tmp/samples_read_%d", channel);
	if(create_fifo(fifo_name)!=0x00)
		vipl_printf("error: unable to create FIFO", error_lvl, __FILE__, __LINE__);
	int32_t fd_sink;
	fd_sink = open(fifo_name,O_WRONLY);
	if(fd_sink<=0x00){
		vipl_printf("error: unable to open FIFO for reading writing...exiting!!", error_lvl, __FILE__, __LINE__);

	}
#endif
	enum Equalizer channel_estimation_algo = LS;
	blocks::file_descriptor_source::sptr fd_source =  blocks::file_descriptor_source::make(sizeof(std::complex<float>)*1,fd_src, false);
	//blocks::file_descriptor_sink::sptr fd_sink_blk = blocks::file_descriptor_sink::make(sizeof(uint8_t)*1,fd_sink);
	//blocks::file_sink::sptr filesink = blocks::file_sink::make(sizeof(uint8_t)*1,"/home/decryptor/test1.pcap",true);
	blocks::null_sink::sptr null_sinks = blocks::null_sink::make(sizeof(uint8_t)*1);
	blocks::delay::sptr delay_a = blocks::delay::make(VECTOR_SIZE*sizeof(std::complex<float>), DELAY_VAR_A);
	blocks::delay::sptr delay_b = blocks::delay::make(VECTOR_SIZE*sizeof(std::complex<float>), DELAY_VAR_B);
	blocks::complex_to_mag_squared::sptr complex2mag_a = blocks::complex_to_mag_squared::make(VECTOR_SIZE);
	blocks::complex_to_mag::sptr complex2mag_b = blocks::complex_to_mag::make(VECTOR_SIZE);
	blocks::conjugate_cc::sptr conjugate_cc = blocks::conjugate_cc::make();
	blocks::multiply_cc::sptr multiply_cc = blocks::multiply_cc::make(VECTOR_SIZE);
	blocks::divide_ff::sptr divide_ff = blocks::divide_ff::make(VECTOR_SIZE);
	ieee802_11::moving_average_cc::sptr moving_average_complex = ieee802_11::moving_average_cc::make(WINDOW_SIZE);
	ieee802_11::moving_average_ff::sptr moving_average_float = ieee802_11::moving_average_ff::make(MOVING_AVERAGE_LENGTH);
	ieee802_11::sync_short::sptr wifi_sync_short = ieee802_11::sync_short::make(0.56, 2, enable_log, enable_debug);
	ieee802_11::sync_long::sptr wifi_sync_long = ieee802_11::sync_long::make(sync_length, enable_log, enable_debug);
	if(!channel)
		frame_equalizer_blk_0 = ieee802_11::frame_equalizer::make(channel_estimation_algo,5170000000.0,WIFI_SAMPLE_RATE_A,false, false);
	else
		frame_equalizer_blk_1 = ieee802_11::frame_equalizer::make(channel_estimation_algo,5170000000.0,WIFI_SAMPLE_RATE_A,false, false);
	blocks::streams_to_vector::sptr streams_to_vector = blocks::streams_to_vector::make(VECTOR_SIZE, FFT_SIZE);
	fft::fft_vcc::sptr fft_cc = fft::fft_vcc::make(FFT_SIZE, true, fft::window::rectangular(FFT_SIZE), true, 1);
	blocks::stream_to_vector::sptr stream_to_vect = blocks::stream_to_vector::make(VECTOR_SIZE*sizeof(std::complex<float>),FFT_SIZE);
	ieee802_11::decode_mac::sptr decode_mac = ieee802_11::decode_mac::make(enable_log,enable_debug);
#if 1
	ieee802_11::parse_mac::sptr parse_mac = ieee802_11::parse_mac::make(enable_log, enable_debug);
#endif
	foo::wireshark_connector::sptr wireshark = foo::wireshark_connector::make(foo::LinkType::WIFI, enable_debug);
	top_block_sptr tb(make_top_block("wifi_rx_g"));
	tb->connect(fd_source,0x00,delay_a,0x00);
	tb->connect(fd_source,0x00,complex2mag_a,0x00);
	tb->connect(fd_source,0x00,multiply_cc,0x00);
	tb->connect(complex2mag_a,0x00, moving_average_float, 0x00);
	tb->connect(moving_average_float, 0x00, divide_ff, 0x01);
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
	tb->connect(delay_b,0x00,wifi_sync_long,0x1);
	tb->connect(wifi_sync_long,0x00,stream_to_vect,0x00);
	tb->connect(stream_to_vect,0x00,fft_cc,0x00);
	//tb->connect(fft_cc,0x00,frame_equalizer_blk,0x00);
	if(!channel){
		tb->connect(fft_cc,0x00,frame_equalizer_blk_0,0x00);
		tb->connect(frame_equalizer_blk_0,0x00,decode_mac, 0x00);
	}else{
		tb->connect(fft_cc,0x00,frame_equalizer_blk_1,0x00);
		tb->connect(frame_equalizer_blk_1,0x00,decode_mac, 0x00);
	}
#if 1
	tb->msg_connect(decode_mac, "out", parse_mac, "in");
#endif
	tb->msg_connect(decode_mac, "out", wireshark, "in");
	tb->connect(wireshark, 0x00, null_sinks, 0x00);
	tb->start();
	tb->wait();
	sem_wait(&stop_process);
}

void wifi_demod_band_p(int8_t channel){
	vipl_printf("info: Demodualtion for Band P started",error_lvl, __FILE__, __LINE__);
	char fifo_name[30]={0x00};
	sprintf(fifo_name,"/tmp/samples_write_%d", channel);
	int32_t fd_src;
	label:
	fd_src = open(fifo_name,O_RDONLY);
	if(fd_src<=0x00){
		vipl_printf("error: unable to open FIFO for reading samples...exiting!!", error_lvl, __FILE__, __LINE__);
		goto label;
	}
#if 0
	bzero(fifo_name, sizeof(char)*30);
	sprintf(fifo_name,"/tmp/samples_read_%d", channel);
	if(create_fifo(fifo_name)!=0x00)
		vipl_printf("error: unable to create FIFO", error_lvl, __FILE__, __LINE__);
	int32_t fd_sink;

	fd_sink = open(fifo_name,O_WRONLY);
	if(fd_sink<=0x00){
		vipl_printf("error: unable to open FIFO for reading writing...exiting!!", error_lvl, __FILE__, __LINE__);

	}
#endif
	enum Equalizer channel_estimation_algo = LS;
	blocks::file_descriptor_source::sptr fd_source =  blocks::file_descriptor_source::make(sizeof(std::complex<float>)*1,fd_src, false);
	//blocks::file_descriptor_sink::sptr fd_sink_blk = blocks::file_descriptor_sink::make(sizeof(uint8_t)*1,fd_sink);
	//blocks::file_sink::sptr filesink = blocks::file_sink::make(sizeof(uint8_t)*1,"/home/decryptor/test1.pcap",true);
	blocks::null_sink::sptr null_sinks = blocks::null_sink::make(sizeof(uint8_t)*1);
	blocks::delay::sptr delay_a = blocks::delay::make(VECTOR_SIZE*sizeof(std::complex<float>), DELAY_VAR_A);
	blocks::delay::sptr delay_b = blocks::delay::make(VECTOR_SIZE*sizeof(std::complex<float>), DELAY_VAR_B);
	blocks::complex_to_mag_squared::sptr complex2mag_a = blocks::complex_to_mag_squared::make(VECTOR_SIZE);
	blocks::complex_to_mag::sptr complex2mag_b = blocks::complex_to_mag::make(VECTOR_SIZE);
	blocks::conjugate_cc::sptr conjugate_cc = blocks::conjugate_cc::make();
	blocks::multiply_cc::sptr multiply_cc = blocks::multiply_cc::make(VECTOR_SIZE);
	blocks::divide_ff::sptr divide_ff = blocks::divide_ff::make(VECTOR_SIZE);
	ieee802_11::moving_average_cc::sptr moving_average_complex = ieee802_11::moving_average_cc::make(WINDOW_SIZE);
	ieee802_11::moving_average_ff::sptr moving_average_float = ieee802_11::moving_average_ff::make(MOVING_AVERAGE_LENGTH);
	ieee802_11::sync_short::sptr wifi_sync_short = ieee802_11::sync_short::make(0.56, 2, enable_log, enable_debug);
	ieee802_11::sync_long::sptr wifi_sync_long = ieee802_11::sync_long::make(sync_length, enable_log, enable_debug);
	if(!channel)
		frame_equalizer_blk_0 = ieee802_11::frame_equalizer::make(channel_estimation_algo,5170000000.0,WIFI_SAMPLE_RATE_A,false, false);
	else
		frame_equalizer_blk_1 = ieee802_11::frame_equalizer::make(channel_estimation_algo,5170000000.0,WIFI_SAMPLE_RATE_A,false, false);
	blocks::streams_to_vector::sptr streams_to_vector = blocks::streams_to_vector::make(VECTOR_SIZE, FFT_SIZE);
	fft::fft_vcc::sptr fft_cc = fft::fft_vcc::make(FFT_SIZE, true, fft::window::rectangular(FFT_SIZE), true, 1);
	blocks::stream_to_vector::sptr stream_to_vect = blocks::stream_to_vector::make(VECTOR_SIZE*sizeof(std::complex<float>),FFT_SIZE);
	ieee802_11::decode_mac::sptr decode_mac = ieee802_11::decode_mac::make(enable_log,enable_debug);
#if 1
	ieee802_11::parse_mac::sptr parse_mac = ieee802_11::parse_mac::make(enable_log, enable_debug);
#endif
	foo::wireshark_connector::sptr wireshark = foo::wireshark_connector::make(foo::LinkType::WIFI, enable_debug);
	top_block_sptr tb(make_top_block("wifi_rx_p"));
	tb->connect(fd_source,0x00,delay_a,0x00);
	tb->connect(fd_source,0x00,complex2mag_a,0x00);
	tb->connect(fd_source,0x00,multiply_cc,0x00);
	tb->connect(complex2mag_a,0x00, moving_average_float, 0x00);
	tb->connect(moving_average_float, 0x00, divide_ff, 0x01);
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
	tb->connect(delay_b,0x00,wifi_sync_long,0x1);
	tb->connect(wifi_sync_long,0x00,stream_to_vect,0x00);
	tb->connect(stream_to_vect,0x00,fft_cc,0x00);
	//tb->connect(fft_cc,0x00,frame_equalizer_blk,0x00);
	if(!channel){
		tb->connect(fft_cc,0x00,frame_equalizer_blk_0,0x00);
		tb->connect(frame_equalizer_blk_0,0x00,decode_mac, 0x00);
	}else{
		tb->connect(fft_cc,0x00,frame_equalizer_blk_1,0x00);
		tb->connect(frame_equalizer_blk_1,0x00,decode_mac, 0x00);
	}
#if 1
	tb->msg_connect(decode_mac, "out", parse_mac, "in");
#endif
	tb->msg_connect(decode_mac, "out", wireshark, "in");
	//tb->connect(wireshark, 0x00, fd_sink_blk, 0x00);
	//tb->connect(wireshark,0, filesink,0);
	tb->connect(wireshark, 0x00, null_sinks, 0x00);
	tb->start();
	tb->wait();
	sem_wait(&stop_process);
}

int8_t hop_freq(char *device, int32_t frequencyMhz){
	 /* Create the socket and connect to it. */
	 struct nl_sock *sckt = nl_socket_alloc();
	 genl_connect(sckt);
	 /* Allocate a new message. */
	 struct nl_msg *mesg = nlmsg_alloc();
	 /* Check /usr/include/linux/nl80211.h for a list of commands and attributes. */
	 enum nl80211_commands command = NL80211_CMD_SET_WIPHY;
	 /* Create the message so it will send a command to the nl80211 interface. */
	 genlmsg_put(mesg, 0, 0, genl_ctrl_resolve(sckt, "nl80211"), 0, 0, command, 0);
	 /* Add specific attributes to change the frequency of the device. */
	 NLA_PUT_U32(mesg, NL80211_ATTR_IFINDEX, if_nametoindex(device));
	 NLA_PUT_U32(mesg, NL80211_ATTR_WIPHY_FREQ, frequencyMhz);
	 /* Finally send it and receive the amount of bytes sent. */
	 int ret = nl_send_auto_complete(sckt, mesg);
	//    printf("%d Bytes Sent\n", ret);
	 nlmsg_free(mesg);
	 return 0;
	 nla_put_failure:
	     nlmsg_free(mesg);
	     return 1;
}

void dump_packet(u_char *args, const struct pcap_pkthdr *pkh, const u_char *packet){
	if(stop_rx==true)
		pcap_breakloop(descr);
    if(pkh->len<24)
        return;
    int32_t len = strlen(packet);
    if(len<=0&&len>65535)
        return;
    clock_gettime(CLOCK_MONOTONIC,&end_time);
    clock_gettime(CLOCK_MONOTONIC,&channel_end_time);
    pcap_dump((unsigned char*)dumpfile, pkh, packet);
    if(num_channels>1 && (channel_end_time.tv_sec-channel_start_time.tv_sec) >= 0.25){
    	if(k==num_channels)
    		k=0;
    	int32_t freq = find_freq(channel_list_command[k++], "b")/1000000;
    	//printf("index: %d channel: %d freq: %f\n",k-1,  channel_list_command[k-1], find_freq(channel_list_command[k-1], "b"));
    	int8_t rtnval = hop_freq(dev, freq);
    	if(rtnval!=0x00)
    		vipl_printf("error: failed to change channel of interface", error_lvl, __FILE__, __LINE__);
    	else
    		vipl_printf("info: change channel of interface", error_lvl, __FILE__, __LINE__);
    	clock_gettime(CLOCK_MONOTONIC,&channel_start_time);
    }
    if(end_time.tv_sec-start_time.tv_sec>=15){
    	pcap_dump_close(dumpfile);
        vipl_printf("info: pcap file created", error_lvl, __FILE__, __LINE__);
        char command[100]={0x00};
        bzero(dir_name, 200);
        sprintf(dir_name, "%s/wpcap", homedir);
        sprintf(command, "cp %s %s/", pcap_filename, dir_name);
        system(command);
        bzero(dir_name, 200);
        sprintf(dir_name, "%s/wpcap_temp", homedir);
        sprintf(command, "mv %s %s/", pcap_filename, dir_name);
        system(command);
        vipl_printf("info: file moved", error_lvl, __FILE__, __LINE__);
        clock_gettime(CLOCK_MONOTONIC,&start_time);
        start = clock();
        sprintf(pcap_filename, "%s/tmp_pcap_old/wifidump%lu.pcap", homedir, (unsigned long)start);
        dumpfile = pcap_dump_open(descr, pcap_filename);
        if(dumpfile == NULL){
           vipl_printf("error: in opening output file", error_lvl, __FILE__, __LINE__);
           return;
        }
    }
    return;
}

void wifi_demod_band_b(struct command_from_DSP command){
	vipl_printf("info: Demodualtion for Band B started",error_lvl, __FILE__, __LINE__);
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter[] = "";
	struct bpf_program fp;
	int32_t rt, status;
	clock_t start=0;
	dev = command.interface;
	num_channels = command.num_channels;
	int32_t i=0;
	if(command.num_channels>1){
		char *token;
		//printf("channel: %s\n", command.channel_list);
		token = strtok(command.channel_list,",");
		while(token!=NULL){
			channel_list_command[i++] = atoi(token);
			token = strtok(NULL,",");
		}
	}
	if(command.num_channels==1)
		channel_list_command[0] = atoi(command.channel_list);
	if(command.ntwrkscan){
		memcpy(channel_list_command, channel_list_band_bg, sizeof(int32_t)*channel_length_G);
		num_channels = channel_length_G;
	}
	if(dev == NULL){
		vipl_printf(errbuf, error_lvl, __FILE__, __LINE__);
	    return;
	}
	descr = pcap_create(dev, errbuf);
	rt = pcap_set_rfmon(descr, 1);
	pcap_set_snaplen(descr, 2048);
	pcap_set_promisc(descr, 1);
	pcap_set_timeout(descr, 512);
	status = pcap_activate(descr);
	if((homedir = getenv("HOME"))==NULL)
	  homedir = getpwuid(getuid())->pw_dir;
	if(num_channels==1){
		int32_t freq = find_freq(channel_list_command[0], "b")/1000000;
		int8_t rtnval = hop_freq(dev, freq);
		if(rtnval!=0x00)
			vipl_printf("error: failed to change channel of interface", error_lvl, __FILE__, __LINE__);
		else
			vipl_printf("info: change channel of interface", error_lvl, __FILE__, __LINE__);
	}
	start = clock();
	sprintf(pcap_filename, "%s/tmp_pcap_old/wifidump%lu.pcap", homedir, (unsigned long)start);
	dumpfile = pcap_dump_open(descr, pcap_filename);
	if(dumpfile == NULL){
		vipl_printf("error: in opening output file", error_lvl, __FILE__, __LINE__);
	    return;
	}
	clock_gettime(CLOCK_MONOTONIC,&start_time);
	clock_gettime(CLOCK_MONOTONIC,&channel_start_time);
	pcap_loop(descr, -1, dump_packet, "a");
    pcap_close(descr);
    return;
}
