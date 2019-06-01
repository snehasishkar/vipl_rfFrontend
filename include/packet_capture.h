/*
 * packet_capture.h
 *
 *  Created on: 10-May-2019
 *      Author: saurabh
 */

#ifndef PACKET_CAPTURE_H_
#define PACKET_CAPTURE_H_

int parse_packets(struct vipl_rf_tap *rf_tap_db, char *handshake, char *offlinePcap, char *oui, int32_t error_lvl);

#endif /* PACKET_CAPTURE_H_ */
