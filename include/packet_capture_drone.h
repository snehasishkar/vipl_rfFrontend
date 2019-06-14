/*
 * packet_capture_drone.h
 *
 *  Created on: 07-Jun-2019
 *      Author: Saurabh
 */

#ifndef PACKET_CAPTURE_DRONE_H_
#define PACKET_CAPTURE_DRONE_H_

int8_t parse_packets_drone(struct vipl_rf_tap *rf_tap_db, char *offlinePcap, char *oui, uint32_t drone_dump_mode, uint32_t port_no, char *ip_addr, char *json_drone_path, int32_t error);

#endif /* PACKET_CAPTURE_DRONE_H_ */
