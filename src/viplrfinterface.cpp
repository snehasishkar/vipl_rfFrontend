/*
 * viplrfinterface.cpp
 *
 *  Created on: 01-Apr-2019
 *      Author: Snehasish
 */

#include <iostream>
#include <chrono>
#include <thread>
#include <complex>
#include <string>
#include <boost/thread.hpp>
#include "../include/nmea.h"
#include "../include/nmea/gpgga.h"
#include "../include/viplrfinterface.h"
#include "../include/vipl_printf.h"
#include "../include/vipl_wifi_config.h"

#define num_mboards 2

char IP_ADDR[50] ={0x00};

std::queue<std::complex<float>> tx_db_a_buffer;
std::queue<std::complex<float>> tx_db_b_buffer;
std::queue<std::complex<float>> rx_db_a_buffer;
std::queue<std::complex<float>> rx_db_b_buffer;

struct mboard_list *head, *cont;

vipl_rf_interface::vipl_rf_interface(){
		freq_rx_board_a = 0.00;
		freq_rx_board_b = 0.00;
		freq_tx_board_a = 0.00;
		freq_tx_board_b = 0.00;
		sample_rate = 0.00;
		bandwidth = 0.00;
		mboard = 0x00;
		gain = 0x00;
		lo_offset = 0.00;
		channel = 0x00;
		dequeue();
}
int8_t vipl_rf_interface::set_tx_freq(double freq, int8_t channel){
	char buff[200]={0x00};
	lo_offset = freq;
	uhd::tune_request_t tune_request(freq, lo_offset);
	usrp->set_tx_freq(tune_request, channel);
	if(usrp->get_tx_freq(channel)!=freq){
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"error: unable to set tx frequency %f, channel %d", freq, channel);
		goto error;
	}
	return 0x00;
	error:
	vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	return 0x01;
}

int8_t vipl_rf_interface::set_rx_freq(double freq, int8_t channel){
	char buff[200]={0x00};
	lo_offset = freq;
	uhd::tune_request_t tune_request(freq, lo_offset);
	usrp->set_rx_freq(tune_request, channel);
	if(usrp->get_rx_freq(channel)!=freq){
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"error: unable to set rx frequency %f, channel %d", freq, channel);
		goto error;
	}
	return 0x00;
	error:
	vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	return 0x01;
}

int8_t vipl_rf_interface::set_gain(double gain, int8_t channel){
	char buff[200]={0x00};
	usrp->set_rx_gain(gain, channel);
	if(usrp->get_rx_gain(channel)!=gain){
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"error: unable to set gain %u, channel %d", gain, channel);
		goto error;
	}
	else{
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"info: gain set to %f, channel %d",gain, channel);
		goto error;
	}
	return 0x00;
	error:
	vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	return 0x01;
}

void vipl_rf_interface::get_gps_val(void){
	char *nmeaData;
	nmea_s *rtn_data;
	float latitude, longitude;

	while(!stop_gps){
	 uhd::sensor_value_t gga_string = usrp->get_mboard_sensor("gps_gpgga");
	 nmeaData = (char *)malloc(gga_string.to_pp_string().size()+3);
	 memset(nmeaData, 0x00, gga_string.to_pp_string().size()+3);
	 //std::cout<< boost::format("%s")%gga_string.to_pp_string()<<std::endl;
	 sprintf(nmeaData,"\%s\r\n",gga_string.to_pp_string().c_str()+11);
	 rtn_data = nmea_parse(nmeaData, strlen(nmeaData), 0);
	 if(rtn_data==NULL){
		 vipl_printf("error: receiving GPGGA string", error_lvl, __FILE__, __LINE__);
		 continue;
	 }
	 if(NMEA_GPGGA == rtn_data->type){
		 nmea_gpgga_s *gpgga = (nmea_gpgga_s *) rtn_data;
		 header.latitude = gpgga->latitude.degrees+(gpgga->latitude.minutes/100);
		 header.longitude = gpgga->longitude.degrees+(gpgga->longitude.minutes/100);
		 header.altitude = gpgga->altitude;
		 header.no_of_satellite = gpgga->n_satellites;
		 if(error_lvl==3){
			 fprintf(stderr,"\n=================================================================================\n");
			 fprintf(stderr,"Latitude: %lf Longitude: %lf altitude %lu num of satelites %d\n", header.latitude, header.longitude, header.altitude, header.no_of_satellite);
			 fprintf(stderr,"\n==================================================================================\n");
		 }
	 }
	 nmea_free(rtn_data);
	 free(nmeaData);
	 sleep(2);
	}
}

bool vipl_rf_interface::lock_gps(void){
	char buff[200]={0x00};
	usrp->set_clock_source("gpsdo",mboard);
	std::string rtnval_clock = usrp->get_clock_source(mboard);
	if(rtnval_clock.compare("gpsdo")){
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"error: reference not set to GPSDO, channel %d", mboard);
		goto error;
	}else{
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"info: reference set to GPSDO, channel %d",mboard);
		vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	}
	usrp->set_time_source("gpsdo",mboard);
	std::string rtnval_time = usrp->get_clock_source(mboard);
	if(rtnval_time.compare("gpsdo")){
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"error: reference not set to GPSDO, channel %d", mboard);
		goto error;
	}else{
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"info: reference set to GPSDO, channel %d",mboard);
		vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	}
	std::vector<std::string> sensor_names = usrp->get_mboard_sensor_names(mboard);
	if (std::find(sensor_names.begin(), sensor_names.end(), "ref_locked") != sensor_names.end()) {
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"info:waiting for reference lock...",error_lvl, __FILE__, __LINE__);
	    bool ref_locked = false;
	    for (int i = 0; i < 30 and not ref_locked; i++) {
	    	ref_locked = usrp->get_mboard_sensor("ref_locked", mboard).to_bool();
	        if (not ref_locked) {
	        	sleep(1);
	        }
	    }
	    if (ref_locked) {
	    	memset(buff, 0x00, sizeof(char)*100);
	    	sprintf(buff,"info:locked GPSDO 10 MHz Reference",error_lvl, __FILE__,__LINE__);
	    	vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	    } else {
	    	memset(buff, 0x00, sizeof(char)*100);
	    	sprintf(buff,"error: failed to lock GPSDO 10 MHz Reference",error_lvl, __FILE__,__LINE__);
	    	goto error;
	    }
	}else{
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"error: ref_locked sensor not present on this board",error_lvl, __FILE__,__LINE__);
		goto error;
	}
	size_t num_gps_locked = 0x00;
	bool gps_locked = usrp->get_mboard_sensor("gps_locked", mboard).to_bool();
	if(gps_locked){
	  num_gps_locked++;
	  memset(buff, 0x00, sizeof(char)*100);
	  sprintf(buff,"info: GPS locked",error_lvl, __FILE__,__LINE__);
	  vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	}else{
		memset(buff, 0x00, sizeof(char)*100);
		sprintf(buff,"warning: GPS not locked - time will not be accurate until locked",error_lvl, __FILE__,__LINE__);
		goto error;
	}

	/*
	 *  Set to GPS time
	 */

	uhd::time_spec_t gps_time = uhd::time_spec_t( int64_t(usrp->get_mboard_sensor("gps_time", mboard).to_int()));
	usrp->set_time_next_pps(gps_time + 1.0, mboard);
	if (num_gps_locked == num_mboards and num_mboards > 1) {

	/*
	 *  Check to see if all USRP times are aligned
	 *  First, wait for PPS.
	 */

	uhd::time_spec_t time_last_pps = usrp->get_time_last_pps();
	while (time_last_pps == usrp->get_time_last_pps()) {
		usleep(1000);
	}

	/*
	 * Sleep a little to make sure all devices have seen a PPS edge
	 */

	usleep(200000);

	// Compare times across all mboards
	bool all_matched = true;
	uhd::time_spec_t mboard0_time = usrp->get_time_last_pps(0);
	for (size_t mboard = 1; mboard < num_mboards; mboard++) {
		uhd::time_spec_t mboard_time = usrp->get_time_last_pps(mboard);
	    if (mboard_time != mboard0_time) {
	      all_matched = false;
	      memset(buff,0x00, sizeof(char)*100);
	      sprintf(buff, "error: times are not aligned: USRP 0=%0.9f, USRP %d=%0.9f", mboard0_time.get_real_secs(), mboard, mboard_time.get_real_secs());
	      goto error;
	    }
	 }
	 if (all_matched) {
		 memset(buff,0x00, sizeof(char)*100);
		 sprintf(buff, "info: USRP times aligned", error_lvl, __FILE__, __LINE__);
		 vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	 } else {
		 memset(buff,0x00, sizeof(char)*100);
		 sprintf(buff, "info: USRP times aligned", error_lvl, __FILE__, __LINE__);
		 vipl_printf("error: USRP times are not aligned", error_lvl, __FILE__, __LINE__);
	 }
	}
	return true;
	error:
	vipl_printf(buff, error_lvl, __FILE__, __LINE__);
	return false;
}

void vipl_rf_interface::start_stream(double freq, int8_t mode, uint8_t channel){
	char buff[100] ={0x00};
	unsigned long long num_total_samps = 0;

	    /*
	     * create a receive streamer
	     */
	usrp->set_rx_subdev_spec(subdev, mboard);
	uhd::tune_request_t tune_request(freq, lo_offset);
	tune_request.rf_freq_policy = uhd::tune_request_t::POLICY_MANUAL;
	//std::cout<<freq<<" "<<lo_offset<<std::endl;
	if(mode==rx){
		usrp->set_rx_freq(tune_request, channel);
		if((usrp->get_rx_freq(channel))!=freq){
			memset(buff, 0x00, sizeof(char)*100);
			sprintf(buff,"error: unable to set rx frequency %f %f, channel %d", freq, usrp->get_rx_freq(channel), channel);
			goto error;
		}
		usrp->set_rx_gain(gain, channel);
		if(usrp->get_rx_gain(channel)!=gain){
			memset(buff, 0x00, sizeof(char)*100);
			sprintf(buff,"error: unable to set gain %u, channel %d", gain, channel);
			goto error;
		}
		usrp->set_rx_antenna("RX2", channel);
	}else if(mode==tx){
		uhd::tune_request_t tune_request(freq, lo_offset);
		usrp->set_tx_freq(tune_request, channel);
		if(usrp->get_tx_freq(channel)!=freq){
			memset(buff, 0x00, sizeof(char)*100);
			sprintf(buff,"error: unable to set tx frequency %f, channel %d", freq, channel);
			goto error;
		}
		usrp->set_tx_gain(gain, channel);
		if(usrp->get_tx_gain(channel)!=gain){
			memset(buff, 0x00, sizeof(char)*100);
			sprintf(buff,"error: unable to set gain %u, channel %d", gain, channel);
			goto error;
		}
		usrp->set_tx_antenna("TX/RX",channel);
		usrp->set_rx_antenna("RX2",channel);
	}
	lock_gps();
	char fifo_name[100]={0x00};
	sprintf(fifo_name,"/tmp/samples_write_%d",channel);
	fifo_read_write samples_read_write_init(fifo_name,true);
	std::cout<<"Test1"<<std::endl;
	uhd::stream_args_t stream_args("fc32","sc16");
	std::vector<size_t> channel_nums;
	channel_nums.push_back(channel);
	stream_args.channels = channel_nums;
	rx_stream = usrp->get_rx_stream(stream_args);
	uhd::rx_metadata_t md;
	bool overflow_message = true;
	uhd::stream_cmd_t stream_cmd(uhd::stream_cmd_t::STREAM_MODE_START_CONTINUOUS);
	stream_cmd.num_samps  = WIFI_SAMPLE_RATE;
	stream_cmd.stream_now = true;
	stream_cmd.time_spec  = uhd::time_spec_t();
	rx_stream->issue_stream_cmd(stream_cmd);
	std::vector<std::complex<float>> cb(TOTAL_BUFFER_SIZE);
	while(!stop_rx){
		size_t num_rx_samps = rx_stream->recv(&cb.front(), cb.size(), md, 3.0, false);
		if(error_lvl==3)
			fprintf(stderr,"Number of samples received %u\n",num_rx_samps);
		if (md.error_code == uhd::rx_metadata_t::ERROR_CODE_TIMEOUT) {
		   vipl_printf("error:timeout while streaming", error_lvl, __FILE__, __LINE__);
		   break;
		}
		if (md.error_code == uhd::rx_metadata_t::ERROR_CODE_OVERFLOW) {
			if (overflow_message) {
				overflow_message = false;
				vipl_printf("error: overflow detected", error_lvl, __FILE__, __LINE__);
			}
			continue;
		}
		if (md.error_code != uhd::rx_metadata_t::ERROR_CODE_NONE){
			char msg[100]={0x00};
			sprintf(msg,"error: %s",md.strerror());
		}
		//TODO: Write samples
		int32_t rtnval = samples_read_write_init.samplesWrite(&cb.front(),cb.size());
		if(rtnval==-1)
			vipl_printf("error: unable to read from USRP", error_lvl, __FILE__, __LINE__);
		if(rtnval!=cb.size()){
			char msg[100]={0x00};
			sprintf(msg,"warning: Improper write! have wrote %d Bytes should have wrote %d", rtnval, cb.size());
			vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		}
		cb.clear();
	}
	vipl_printf("warning: stopping streaming mode", error_lvl, __FILE__, __LINE__);
	uhd::stream_cmd_t stream_cmd_stop(uhd::stream_cmd_t::STREAM_MODE_STOP_CONTINUOUS);
	rx_stream->issue_stream_cmd(stream_cmd_stop);
	error:
		vipl_printf(buff, error_lvl, __FILE__, __LINE__);
}

vipl_rf_interface::~vipl_rf_interface() {

}

bool done = false;

void vipl_rf_interface::dequeue(void){
	int mboard_counter = 0x00;
	boost::thread t1[2];
	boost::thread t1_demod[2];
	int8_t count = 0x00, count_demod = 0x00;
	while(true){
		if(!command_queue.empty()){
			struct command_from_DSP command = command_queue.front();
			int8_t rtnval = 0x00;
			if(!done){
				std::string temp("addr=");
				std::string args = temp+command.mboard_addr;
				usrp = uhd::usrp::multi_usrp::make(args);
				if(usrp==NULL){
					vipl_printf("error: unable to create USRP!!", error_lvl, __FILE__, __LINE__);
				}
				done = true;
			}
			int rtnvalue = 0x00;
			if(strcmp(command.technology,"WIFI")==0x00){
				if(strcmp(command.band,"a")==0x00){
					load_map(command.band);
					t1_demod[count_demod++] = boost::thread (wifi_demod_band_a, command.db_board, command.channel_list, command.ntwrkscan);
					if(rtnvalue!=0x00)
						vipl_printf("error: unable for demodulate", error_lvl, __FILE__,__LINE__);
				}
				if(strcmp(command.band,"g")==0x00){
#if 0
					load_map(command.band);
					rtnvalue =  wifi_demod_band_g(command.db_board, command.channel_list,command.ntwrkscan);
					if(rtnvalue!=0x00)
						vipl_printf("error: unable for demodulate", error_lvl, __FILE__,__LINE__);
#endif
				}
				if(strcmp(command.band,"p")==0x00){
				#if 0
					load_map(command.band);
					rtnvalue =  wifi_demod_band_p(command.db_board, command.channel_list,command.ntwrkscan);
					if(rtnvalue!=0x00)
						vipl_printf("error: unable for demodulate", error_lvl, __FILE__,__LINE__);
				#endif
				}
				command.samp_rate = WIFI_SAMPLE_RATE;
			}

			if(command.init_board){
				switch(command.mode){
				case rx:sample_rate = command.samp_rate;
						mboard = command.mboard;
						stop_rx = false;
						stop_gps = false;
						switch(command.db_board){
						case 0: freq_rx_board_b = 0.00;
								freq_tx_board_a = 0.00;
								freq_tx_board_b = 0.00;
								freq_rx_board_a = command.freq*1e6;
								bandwidth = command.bandwidth*1e6;
								gain = command.gain;
								lo_offset = command.lo_offset*1e6;
								channel = 0x00;
								subdev = "A:0";
								t1[count++] = boost::thread (&vipl_rf_interface::start_stream, this,freq_rx_board_a, rx, channel);
								break;
						case 1: freq_rx_board_a = 0.00;
								freq_tx_board_a = 0.00;
								freq_tx_board_b = 0.00;
								freq_rx_board_b = command.freq*1e6;
								bandwidth = command.bandwidth*1e6;
								gain = command.gain;
								lo_offset = command.lo_offset*1e6;
								channel = 0x01;
								subdev = "B:0";
								t1[count++] = boost::thread (&vipl_rf_interface::start_stream, this,freq_rx_board_b, rx, channel);
								break;
						}
				break;
				case tx: switch(command.db_board){
						 case 0: freq_rx_board_a = 0.00;
						 	 	 freq_rx_board_b = 0.00;
								 freq_tx_board_b = 0.00;
								 freq_tx_board_a = command.freq*1e6;
								 bandwidth = command.bandwidth*1e6;
								 gain = command.gain;
								 lo_offset = command.lo_offset*1e6;
								 channel = 0x00;
								 subdev = "A:0";
								 t1[count++] = boost::thread (&vipl_rf_interface::start_stream, this, freq_tx_board_a, tx, channel);
								 break;
						 case 1: freq_rx_board_a = 0.00;
				 	 	 	 	 freq_rx_board_b = 0.00;
				 	 	 	 	 freq_tx_board_a = 0.00;
				 	 	 	 	 freq_tx_board_b = command.freq*106;
				 	 	 	 	 bandwidth = command.bandwidth*1e6;
				 	 	 	 	 gain = command.gain;
				 	 	 	 	 lo_offset = command.lo_offset*1e6;
				 	 	 	 	 channel = 0x01;
				 	 	 	 	 subdev = "B:0";
				 	 	 	 	t1[count++] = boost::thread (&vipl_rf_interface::start_stream, this,freq_tx_board_b, tx, channel);
						break;
				}
						break;
				case ntwrk_scan: switch(command.db_board){
				case 0: freq_rx_board_b = 0.00;
						freq_tx_board_a = 0.00;
						freq_tx_board_b = 0.00;
						freq_rx_board_a = command.freq*1e6;
						bandwidth = command.bandwidth*1e6;
						gain = command.gain;
						lo_offset = command.lo_offset*1e6;
						channel = 0x00;
						subdev = "A:1";
						t1[count++] = boost::thread (&vipl_rf_interface::start_stream, this,freq_rx_board_a, rx, channel);
						break;
				case 1: freq_rx_board_a = 0.00;
						freq_tx_board_a = 0.00;
						freq_tx_board_b = 0.00;
						freq_rx_board_b = command.freq*1e6;
						bandwidth = command.bandwidth*1e6;
						gain = command.gain;
						lo_offset = command.lo_offset*1e6;
						channel = 0x01;
						subdev = "B:0";
						t1[count++] = boost::thread (&vipl_rf_interface::start_stream, this,freq_rx_board_b, rx, channel);
						break;
				}
						break;
				}

			}else if(command.change_freq){
				uhd::stream_cmd_t stream_cmd_stop(uhd::stream_cmd_t::STREAM_MODE_STOP_CONTINUOUS);
				rx_stream->issue_stream_cmd(stream_cmd_stop);
				switch (command.mode){
				case rx:switch(command.db_board){
						case 0: if(set_rx_freq(command.freq*1e6, 0)!=0x00){
									vipl_printf("error: unable to change frequency", error_lvl, __FILE__, __LINE__);
								}
							break;
						case 1:if(set_rx_freq(command.freq*1e6, 1)!=0x00){
									vipl_printf("error: unable to change frequency", error_lvl, __FILE__, __LINE__);
								}
							break;
						}
						break;
				case tx:switch(command.db_board){
						case 0: if(set_rx_freq(command.freq*1e6, 0)!=0x00){
									vipl_printf("error: unable to change frequency", error_lvl, __FILE__, __LINE__);
								}
								break;
						case 1:	if(set_rx_freq(command.freq*1e6, 1)!=0x00){
									vipl_printf("error: unable to change frequency", error_lvl, __FILE__, __LINE__);
							   	}
							   	break;
						}
						break;
				}
				uhd::stream_cmd_t stream_cmd(uhd::stream_cmd_t::STREAM_MODE_START_CONTINUOUS);
				rx_stream->issue_stream_cmd(stream_cmd);
			}else if(command.change_gain){
				if(set_gain(command.gain, 0)!=0x00){
					vipl_printf("error: unable to change gain", error_lvl, __FILE__, __LINE__);
				}
			}else if(command.getgps){
				get_gps_val();
			}
			command_queue.pop();
		}else{
			if(sem_wait(&lock)==-1){
				vipl_printf("error: unable to lock semaphore..",error_lvl,__FILE__,__LINE__);
			}
		}
	}
}
