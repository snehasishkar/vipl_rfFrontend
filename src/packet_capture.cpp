#include <iostream>
#include <cstdlib>
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <net/ethernet.h>
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <signal.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "../include/defs.h"
#include "../include/uniqueiv.h"
#include "../include/mcs_index_rates.h"
#include "../include/verifyssid.h"
//#include "../lib/config4cpp/include/config4cpp/Configuration.h"

#define NULL_MAC (unsigned char *) "\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF"
// BSSID const. length of 6 bytes; can be together with all the other types
#define IVS2_BSSID 0x0001

using namespace std;

pcap_t *descr;
//struct globals G;
FILE *logfile;
struct sockaddr_in source,dest;
int total = 0;
int tcp=0, udp=0, icmp=0, others=0, igmp=0;
time_t start;
int ivs_only=1;
const unsigned char ZERO[33] = {0x00};
struct listFile{
	char filename[100];
	struct listFile *next;
}*head_file,*cur;
static int list_tail_free(struct pkt_buf ** list)
{
	struct pkt_buf ** pkts;
	struct pkt_buf * next;

	if (list == NULL) return 1;

	pkts = list;

	while (*pkts != NULL)
	{
		next = (*pkts)->next;
		if ((*pkts)->packet)
		{
			free((*pkts)->packet);
			(*pkts)->packet = NULL;
		}

		if (*pkts)
		{
			free(*pkts);
			*pkts = NULL;
		}
		*pkts = next;
	}

	*list = NULL;

	return 0;
}

static int
list_add_packet(struct pkt_buf ** list, int length, unsigned char * packet)
{
	struct pkt_buf * next;

	if (length <= 0) return 1;
	if (packet == NULL) return 1;
	if (list == NULL) return 1;

	next = *list;

	*list = (struct pkt_buf *) malloc(sizeof(struct pkt_buf));
	if (*list == NULL) return 1;
	(*list)->packet = (unsigned char *) malloc(length);
	if ((*list)->packet == NULL) return 1;

	memcpy((*list)->packet, packet, length);
	(*list)->next = next;
	(*list)->length = length;
	gettimeofday(&((*list)->ctime), NULL);

	return 0;
}
static int
list_check_decloak(struct pkt_buf ** list, int length, unsigned char * packet)
{
	struct pkt_buf * next;
	struct timeval tv1;
	int timediff;
	int i, correct;

	if (packet == NULL) return 1;
	if (list == NULL) return 1;
	if (*list == NULL) return 1;
	if (length <= 0) return 1;
	next = *list;

	gettimeofday(&tv1, NULL);

	timediff = (((tv1.tv_sec - ((*list)->ctime.tv_sec)) * 1000000UL)
				+ (tv1.tv_usec - ((*list)->ctime.tv_usec)))
			   / 1000;
	if (timediff > BUFFER_TIME)
	{
		list_tail_free(list);
		next = NULL;
	}

	while (next != NULL)
	{
		if (next->next != NULL)
		{
			timediff = (((tv1.tv_sec - (next->next->ctime.tv_sec)) * 1000000UL)
						+ (tv1.tv_usec - (next->next->ctime.tv_usec)))
					   / 1000;
			if (timediff > BUFFER_TIME)
			{
				list_tail_free(&(next->next));
				break;
			}
		}
		if ((next->length + 4) == length)
		{
			correct = 1;
			// check for 4 bytes added after the end
			for (i = 28; i < length - 28; i++) // check everything (in the old
			// packet) after the IV
			// (including crc32 at the end)
			{
				if (next->packet[i] != packet[i])
				{
					correct = 0;
					break;
				}
			}
			if (!correct)
			{
				correct = 1;
				// check for 4 bytes added at the beginning
				for (i = 28; i < length - 28; i++) // check everything (in the
				// old packet) after the IV
				// (including crc32 at the
				// end)
				{
					if (next->packet[i] != packet[4 + i])
					{
						correct = 0;
						break;
					}
				}
			}
			if (correct == 1) return 0; // found decloaking!
		}
		next = next->next;
	}

	return 1; // didn't find decloak
}

static int is_filtered_netmask(unsigned char * bssid)
{
	unsigned char mac1[6];
	unsigned char mac2[6];
	int i;

	for (i = 0; i < 6; i++)
	{
		mac1[i] = bssid[i] & G.f_netmask[i];
		mac2[i] = G.f_bssid[i] & G.f_netmask[i];
	}

	if (memcmp(mac1, mac2, 6) != 0)
	{
		return (1);
	}

	return 0;
}
static char * get_manufacturer_from_string(char * buffer)
{
	char * manuf = NULL;
	char * buffer_manuf;
	if (buffer != NULL && strlen(buffer) > 0)
	{
		buffer_manuf = strstr(buffer, "(hex)");
		if (buffer_manuf != NULL)
		{
			buffer_manuf += 6; // skip '(hex)' and one more character (there's
			// at least one 'space' character after that
			// string)
			while (*buffer_manuf == '\t' || *buffer_manuf == ' ')
			{
				++buffer_manuf;
			}

			// Did we stop at the manufacturer
			if (*buffer_manuf != '\0')
			{

				// First make sure there's no end of line
				if (buffer_manuf[strlen(buffer_manuf) - 1] == '\n'
					|| buffer_manuf[strlen(buffer_manuf) - 1] == '\r')
				{
					buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					if (*buffer_manuf != '\0'
						&& (buffer_manuf[strlen(buffer_manuf) - 1] == '\n'
							|| buffer[strlen(buffer_manuf) - 1] == '\r'))
					{
						buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					}
				}
				if (*buffer_manuf != '\0')
				{
					if ((manuf = (char *) malloc((strlen(buffer_manuf) + 1)
												 * sizeof(char)))
						== NULL)
					{
						perror("malloc failed");
						return NULL;
					}
					snprintf(
						manuf, strlen(buffer_manuf) + 1, "%s", buffer_manuf);
				}
			}
		}
	}

	return manuf;
}
#define OUI_STR_SIZE 8
#define MANUF_SIZE 128
char *get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2){
	char oui[OUI_STR_SIZE + 1];
	char *manuf, *rmanuf;
	// char *buffer_manuf;
	char * manuf_str;
	struct oui * ptr;
	FILE * fp;
	char buffer[BUFSIZ];
	char temp[OUI_STR_SIZE + 1];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	int found = 0;

	if ((manuf = (char *) calloc(1, MANUF_SIZE * sizeof(char))) == NULL)
	{
		perror("calloc failed");
		return NULL;
	}

	snprintf(oui, sizeof(oui), "%02X:%02X:%02X", mac0, mac1, mac2);
	if (G.manufList != NULL)
	{
		// Search in the list
		ptr = G.manufList;
		while (ptr != NULL)
		{
			found = !strncasecmp(ptr->id, oui, OUI_STR_SIZE);
			if (found)
			{
				memcpy(manuf, ptr->manuf, MANUF_SIZE);
				break;
			}
			ptr = ptr->next;
		}
	}
	else
	{
		// If the file exist, then query it each time we need to get a
		// manufacturer.
		fp = fopen("oui.txt", "r");

		if (fp != NULL)
		{

			memset(buffer, 0x00, sizeof(buffer));
			while (fgets(buffer, sizeof(buffer), fp) != NULL)
			{
				if (strstr(buffer, "(hex)") == NULL)
				{
					continue;
				}

				memset(a, 0x00, sizeof(a));
				memset(b, 0x00, sizeof(b));
				memset(c, 0x00, sizeof(c));
				if (sscanf(buffer, "%2c-%2c-%2c", a, b, c) == 3)
				{
					snprintf(temp,
							 sizeof(temp),
							 "%c%c:%c%c:%c%c",
							 a[0],
							 a[1],
							 b[0],
							 b[1],
							 c[0],
							 c[1]);
					found = !memcmp(temp, oui, strlen(oui));
					if (found)
					{
						manuf_str = get_manufacturer_from_string(buffer);
						if (manuf_str != NULL)
						{
							snprintf(manuf, MANUF_SIZE, "%s", manuf_str);
							free(manuf_str);
						}

						break;
					}
				}
				memset(buffer, 0x00, sizeof(buffer));
			}

			fclose(fp);
		}
	}
	// Not found, use "Unknown".
	if (!found || *manuf == '\0')
	{
		memcpy(manuf, "Unknown", 7);
		manuf[strlen(manuf)] = '\0';
	}

	// Going in a smaller buffer
	rmanuf = (char *) realloc(manuf, (strlen(manuf) + 1) * sizeof(char));

	return (rmanuf) ? rmanuf : manuf;
}
#undef OUI_STR_SIZE
#undef MANUF_SIZE

static int remove_namac(unsigned char * mac)
{
	struct NA_info * na_cur = NULL;
	struct NA_info * na_prv = NULL;

	if (mac == NULL) return (-1);

	na_cur = G.na_1st;
	na_prv = NULL;

	while (na_cur != NULL)
	{
		if (!memcmp(na_cur->namac, mac, 6)) break;

		na_prv = na_cur;
		na_cur = na_cur->next;
	}

	/* if it's known, remove it */
	if (na_cur != NULL)
	{
		/* first in linked list */
		if (na_cur == G.na_1st)
		{
			G.na_1st = na_cur->next;
		}
		else
		{
			na_prv->next = na_cur->next;
		}
		free(na_cur);
		na_cur = NULL;
	}

	return (0);
}

int is_filtered_essid(unsigned char * essid)
{
	//REQUIRE(essid != NULL);

	int ret = 0;
	int i;

	if (G.f_essid)
	{
		for (i = 0; i < G.f_essid_count; i++)
		{
			if (strncmp((char *) essid, G.f_essid[i], MAX_IE_ELEMENT_SIZE) == 0)
			{
				return (0);
			}
		}

		ret = 1;
	}

#ifdef HAVE_PCRE
	if (G.f_essid_regex)
	{
		return pcre_exec(G.f_essid_regex,
						 NULL,
						 (char *) essid,
						 strnlen((char *) essid, MAX_IE_ELEMENT_SIZE),
						 0,
						 0,
						 NULL,
						 0)
			   < 0;
	}
#endif

	return (ret);
}

float wifi_distance(int freq, int siglev)
{
  float exp = (27.55 - (20 * log10(freq)) + abs(siglev)) / 20.0;
  return pow(10.0, exp);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *pkh, const u_char *packet)
{
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
		uint8_t it_rev; // Revision: Version of RadioTap
		uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
		uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};
	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len;
	const u_char *h80211;
	h80211 = packet + offset;
	int i, n, seq, msd, dlen, clen, o;
	unsigned z;
	int type, length, numuni = 0, numauth = 0;
	struct timeval tv;
	struct ivs2_pkthdr ivs2;
	unsigned char *p, *org_p, c;
	unsigned char bssid[6];
	unsigned char stmac[6];
	unsigned char namac[6];
	unsigned char clear[2048];
	int weight[16];
	int num_xor = 0;

	struct AP_info * ap_cur = NULL;
	struct ST_info * st_cur = NULL;
	struct NA_info * na_cur = NULL;
	struct AP_info * ap_prv = NULL;
	struct ST_info * st_prv = NULL;
	struct NA_info * na_prv = NULL;
    int caplen = pkh->caplen;
	/* skip all non probe response frames in active scanning simulation mode */
	if (G.active_scan_sim > 0 && h80211[0] != 0x50) return;

	/* skip packets smaller than a 802.11 header */

	if (caplen < 24) goto write_packet;

	/* skip (uninteresting) control frames */

	if ((h80211[0] & 0x0C) == 0x04) goto write_packet;

	/* if it's a LLC null packet, just forget it (may change in the future) */

	if (caplen > 28)
		if (memcmp(h80211 + 24, llcnull, 4) == 0) return;

	/* grab the sequence number */
	seq = ((h80211[22] >> 4) + (h80211[23] << 4));

	/* locate the access point's MAC address */

	switch (h80211[1] & 3)
	{
		case 0:
			memcpy(bssid, h80211 + 16, 6);
			break; // Adhoc
		case 1:
			memcpy(bssid, h80211 + 4, 6);
			break; // ToDS
		case 2:
			memcpy(bssid, h80211 + 10, 6);
			break; // FromDS
		case 3:
			memcpy(bssid, h80211 + 10, 6);
			break; // WDS -> Transmitter taken as BSSID
	}

	if (memcmp(G.f_bssid, NULL_MAC, 6) != 0)
	{
		if (memcmp(G.f_netmask, NULL_MAC, 6) != 0)
		{
			if (is_filtered_netmask(bssid)) return;
		}
		else
		{
			if (memcmp(G.f_bssid, bssid, 6) != 0) return;
		}
	}

	/* update our chained list of access points */

	ap_cur = G.ap_1st;
	ap_prv = NULL;

	while (ap_cur != NULL)
	{
		if (!memcmp(ap_cur->bssid, bssid, 6)) break;

		ap_prv = ap_cur;
		ap_cur = ap_cur->next;
	}

	/* if it's a new access point, add it */

	if (ap_cur == NULL)
	{
		if (!(ap_cur = (struct AP_info *) malloc(sizeof(struct AP_info))))
		{
			perror("malloc failed");
			return;
		}

		/* if mac is listed as unknown, remove it */
		remove_namac(bssid);
		fprintf(stdout,"BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
		memset(ap_cur, 0, sizeof(struct AP_info));

		if (G.ap_1st == NULL)
			G.ap_1st = ap_cur;
		else
			ap_prv->next = ap_cur;

		memcpy(ap_cur->bssid, bssid, 6);
		if (ap_cur->manuf == NULL)
		{
			ap_cur->manuf = get_manufacturer(
				ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2]);
		}

		ap_cur->nb_pkt = 0;
		ap_cur->prev = ap_prv;

		ap_cur->tinit = time(NULL);
		ap_cur->tlast = time(NULL);

		ap_cur->avg_power = -1;
		ap_cur->best_power = -1;
		ap_cur->power_index = -1;

		for (i = 0; i < NB_PWR; i++) ap_cur->power_lvl[i] = -1;

		ap_cur->channel = -1;
		ap_cur->max_speed = -1;
		ap_cur->security = 0;

		ap_cur->uiv_root = uniqueiv_init();

		ap_cur->nb_data = 0;
		ap_cur->nb_dataps = 0;
		ap_cur->nb_data_old = 0;
		gettimeofday(&(ap_cur->tv), NULL);

		ap_cur->dict_started = 0;

		ap_cur->key = NULL;

		G.ap_end = ap_cur;

		ap_cur->nb_bcn = 0;

		ap_cur->rx_quality = 0;
		ap_cur->fcapt = 0;
		ap_cur->fmiss = 0;
		ap_cur->last_seq = 0;
		gettimeofday(&(ap_cur->ftimef), NULL);
		gettimeofday(&(ap_cur->ftimel), NULL);
		gettimeofday(&(ap_cur->ftimer), NULL);

		ap_cur->ssid_length = 0;
		ap_cur->essid_stored = 0;
		memset(ap_cur->essid, 0, MAX_IE_ELEMENT_SIZE);
		ap_cur->timestamp = 0;

		ap_cur->decloak_detect = G.decloak;
		ap_cur->is_decloak = 0;
		ap_cur->packets = NULL;

		ap_cur->marked = 0;
		ap_cur->marked_color = 1;

		ap_cur->data_root = NULL;
		ap_cur->EAP_detected = 0;
		memcpy(ap_cur->gps_loc_min, G.gps_loc, sizeof(float) * 5);
		memcpy(ap_cur->gps_loc_max, G.gps_loc, sizeof(float) * 5);
		memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float) * 5);

		/* 802.11n and ac */
		ap_cur->channel_width = CHANNEL_22MHZ; // 20MHz by default
		memset(ap_cur->standard, 0, 3);

		ap_cur->n_channel.sec_channel = -1;
		ap_cur->n_channel.short_gi_20 = 0;
		ap_cur->n_channel.short_gi_40 = 0;
		ap_cur->n_channel.any_chan_width = 0;
		ap_cur->n_channel.mcs_index = -1;

		ap_cur->ac_channel.center_sgmt[0] = 0;
		ap_cur->ac_channel.center_sgmt[1] = 0;
		ap_cur->ac_channel.mu_mimo = 0;
		ap_cur->ac_channel.short_gi_80 = 0;
		ap_cur->ac_channel.short_gi_160 = 0;
		ap_cur->ac_channel.split_chan = 0;
		ap_cur->ac_channel.mhz_160_chan = 0;
		ap_cur->ac_channel.wave_2 = 0;
		memset(ap_cur->ac_channel.mcs_index, 0, MAX_AC_MCS_INDEX);
	}

	/* update the last time seen */

	ap_cur->tlast = time(NULL);

	/* only update power if packets comes from
	 * the AP: either type == mgmt and SA == BSSID,
	 * or FromDS == 1 and ToDS == 0 */
        //syslog(LOG_INFO,"%d \n",h80211[1]);
	if (((h80211[1] & 3) == 0 && memcmp(h80211 + 10, bssid, 6) == 0)
		|| ((h80211[1] & 3) == 2))
	{
		ap_cur->power_index = (ap_cur->power_index + 1) % NB_PWR;
		//ap_cur->power_lvl[ap_cur->power_index] = ri->ri_power;

		ap_cur->avg_power = 0;

		for (i = 0, n = 0; i < NB_PWR; i++)
		{
			if (ap_cur->power_lvl[i] != -1)
			{
				ap_cur->avg_power += ap_cur->power_lvl[i];
				n++;
			}
		}

		if (n > 0)
		{
			ap_cur->avg_power /= n;
			if (ap_cur->avg_power > ap_cur->best_power)
			{
				ap_cur->best_power = ap_cur->avg_power;
				memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float) * 5);
			}
		}
		else
			ap_cur->avg_power = -1;

		/* every packet in here comes from the AP */

		if (G.gps_loc[0] > ap_cur->gps_loc_max[0])
			ap_cur->gps_loc_max[0] = G.gps_loc[0];
		if (G.gps_loc[1] > ap_cur->gps_loc_max[1])
			ap_cur->gps_loc_max[1] = G.gps_loc[1];
		if (G.gps_loc[2] > ap_cur->gps_loc_max[2])
			ap_cur->gps_loc_max[2] = G.gps_loc[2];

		if (G.gps_loc[0] < ap_cur->gps_loc_min[0])
			ap_cur->gps_loc_min[0] = G.gps_loc[0];
		if (G.gps_loc[1] < ap_cur->gps_loc_min[1])
			ap_cur->gps_loc_min[1] = G.gps_loc[1];
		if (G.gps_loc[2] < ap_cur->gps_loc_min[2])
			ap_cur->gps_loc_min[2] = G.gps_loc[2];
		//        printf("seqnum: %i\n", seq);

		if (ap_cur->fcapt == 0 && ap_cur->fmiss == 0)
			gettimeofday(&(ap_cur->ftimef), NULL);
		if (ap_cur->last_seq != 0)
			ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
		ap_cur->last_seq = seq;
		ap_cur->fcapt++;
		gettimeofday(&(ap_cur->ftimel), NULL);

		//         if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
	}

	switch (h80211[0])
	{
		case 0x80:
			ap_cur->nb_bcn++;
			break;
		case 0x50:
			/* reset the WPS state */
			ap_cur->wps.state = 0xFF;
			ap_cur->wps.ap_setup_locked = 0;
			break;
	}

	ap_cur->nb_pkt++;

	/* locate the station MAC in the 802.11 header */

	switch (h80211[1] & 3)
	{
		case 0:

			/* if management, check that SA != BSSID */

			if (memcmp(h80211 + 10, bssid, 6) == 0) goto skip_station;

			memcpy(stmac, h80211 + 10, 6);
			break;

		case 1:

			/* ToDS packet, must come from a client */

			memcpy(stmac, h80211 + 10, 6);
			break;

		case 2:

			/* FromDS packet, reject broadcast MACs */

			if ((h80211[4] % 2) != 0) goto skip_station;
			memcpy(stmac, h80211 + 4, 6);
			break;

		default:
			goto skip_station;
	}
	const u_char *rssi; // received signal strength
	rssi = packet + 30;
	signed int rssiDbm;
	rssiDbm = rssi[0] - 256;
	ap_cur->avg_power = rssiDbm;
	//ap_cur->distance = wifi_distance(2462, ap_cur->avg_power);
	fprintf(stdout, "power:%3d\n",rssiDbm);
	//ap_cur->distance = wifi_distance(freq, rssiDbm);
	/* update our chained list of wireless stations */

	st_cur = G.st_1st;
	st_prv = NULL;

	while (st_cur != NULL)
	{
		if (!memcmp(st_cur->stmac, stmac, 6)) break;

		st_prv = st_cur;
		st_cur = st_cur->next;
	}

	/* if it's a new client, add it */

	if (st_cur == NULL)
	{
		if (!(st_cur = (struct ST_info *) malloc(sizeof(struct ST_info))))
		{
			perror("malloc failed");
			return;
		}

		/* if mac is listed as unknown, remove it */
		remove_namac(stmac);

		memset(st_cur, 0, sizeof(struct ST_info));

		if (G.st_1st == NULL)
			G.st_1st = st_cur;
		else
			st_prv->next = st_cur;

		memcpy(st_cur->stmac, stmac, 6);

		if (st_cur->manuf == NULL)
		{
			st_cur->manuf = get_manufacturer(
				st_cur->stmac[0], st_cur->stmac[1], st_cur->stmac[2]);
		}

		st_cur->nb_pkt = 0;

		st_cur->prev = st_prv;

		st_cur->tinit = time(NULL);
		st_cur->tlast = time(NULL);

		st_cur->power = -1;
		st_cur->best_power = -1;
		st_cur->rate_to = -1;
		st_cur->rate_from = -1;

		st_cur->probe_index = -1;
		st_cur->missed = 0;
		st_cur->lastseq = 0;
		st_cur->qos_fr_ds = 0;
		st_cur->qos_to_ds = 0;
		st_cur->channel = 0;

		gettimeofday(&(st_cur->ftimer), NULL);

		memcpy(st_cur->gps_loc_min, G.gps_loc, sizeof(st_cur->gps_loc_min));
		memcpy(st_cur->gps_loc_max, G.gps_loc, sizeof(st_cur->gps_loc_max));
		memcpy(st_cur->gps_loc_best, G.gps_loc, sizeof(st_cur->gps_loc_best));

		for (i = 0; i < NB_PRB; i++)
		{
			memset(st_cur->probes[i], 0, sizeof(st_cur->probes[i]));
			st_cur->ssid_length[i] = 0;
		}

		G.st_end = st_cur;
	}

	if (st_cur->base == NULL || memcmp(ap_cur->bssid, BROADCAST, 6) != 0)
		st_cur->base = ap_cur;

	// update bitrate to station
	//if ((st_cur != NULL) && (h80211[1] & 3) == 2) st_cur->rate_to = ri->ri_rate;

	/* update the last time seen */

	st_cur->tlast = time(NULL);

	/* only update power if packets comes from the
	 * client: either type == Mgmt and SA != BSSID,
	 * or FromDS == 0 and ToDS == 1 */

	if (((h80211[1] & 3) == 0 && memcmp(h80211 + 10, bssid, 6) != 0)
		|| ((h80211[1] & 3) == 1))
	{
		/*st_cur->power = ri->ri_power;
		if (ri->ri_power > st_cur->best_power)
		{
			st_cur->best_power = ri->ri_power;
			memcpy(
				ap_cur->gps_loc_best, G.gps_loc, sizeof(st_cur->gps_loc_best));
		}

		st_cur->rate_from = ri->ri_rate;
		if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
			st_cur->channel = ri->ri_channel;
		else
			st_cur->channel = G.channel[cardnum];*/

		if (G.gps_loc[0] > st_cur->gps_loc_max[0])
			st_cur->gps_loc_max[0] = G.gps_loc[0];
		if (G.gps_loc[1] > st_cur->gps_loc_max[1])
			st_cur->gps_loc_max[1] = G.gps_loc[1];
		if (G.gps_loc[2] > st_cur->gps_loc_max[2])
			st_cur->gps_loc_max[2] = G.gps_loc[2];

		if (G.gps_loc[0] < st_cur->gps_loc_min[0])
			st_cur->gps_loc_min[0] = G.gps_loc[0];
		if (G.gps_loc[1] < st_cur->gps_loc_min[1])
			st_cur->gps_loc_min[1] = G.gps_loc[1];
		if (G.gps_loc[2] < st_cur->gps_loc_min[2])
			st_cur->gps_loc_min[2] = G.gps_loc[2];

		if (st_cur->lastseq != 0)
		{
			msd = seq - st_cur->lastseq - 1;
			if (msd > 0 && msd < 1000) st_cur->missed += msd;
		}
		st_cur->lastseq = seq;
	}

	st_cur->nb_pkt++;

skip_station:

	/* packet parsing: Probe Request */

	if (h80211[0] == 0x40 && st_cur != NULL)
	{
		p =(unsigned char*) h80211 + 24;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				//                n = ( p[1] > 32 ) ? 32 : p[1];
				n = p[1];

				for (i = 0; i < n; i++)
					if (p[2 + i] > 0 && p[2 + i] < ' ') goto skip_probe;

				/* got a valid ASCII probed ESSID, check if it's
				   already in the ring buffer */

				for (i = 0; i < NB_PRB; i++)
					if (memcmp(st_cur->probes[i], p + 2, n) == 0)
						goto skip_probe;

				st_cur->probe_index = (st_cur->probe_index + 1) % NB_PRB;
				memset(st_cur->probes[st_cur->probe_index], 0, 256);
				memcpy(
					st_cur->probes[st_cur->probe_index], p + 2, n); // twice?!
				st_cur->ssid_length[st_cur->probe_index] = n;

				if (verifyssid((const unsigned char *)
								   st_cur->probes[st_cur->probe_index])
					== 0)
					for (i = 0; i < n; i++)
					{
						c = p[2 + i];
						if (c == 0 || (c > 0 && c < 32) || (c > 126 && c < 160))
							c = '.';
						st_cur->probes[st_cur->probe_index][i] = c;
					}
			}

			p += 2 + p[1];
		}
	}

skip_probe:

	/* packet parsing: Beacon or Probe Response */

	if (h80211[0] == 0x80 || h80211[0] == 0x50)
	{
		if (!(ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)))
		{
			if ((h80211[34] & 0x10) >> 4)
				ap_cur->security |= STD_WEP | ENC_WEP;
			else
				ap_cur->security |= STD_OPN;
		}

		ap_cur->preamble = (h80211[34] & 0x20) >> 5;

		unsigned long long * tstamp = (unsigned long long *) (h80211 + 24);
		ap_cur->timestamp = (*tstamp);

		p =(unsigned char*) h80211 + 36;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			// only update the essid length if the new length is > the old one
			if (p[0] == 0x00 && (ap_cur->ssid_length < p[1]))
				ap_cur->ssid_length = p[1];

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				/* found a non-cloaked ESSID */

				//                n = ( p[1] > 32 ) ? 32 : p[1];
				n = p[1];

				memset(ap_cur->essid, 0, 256);
				memcpy(ap_cur->essid, p + 2, n);

				if (verifyssid(ap_cur->essid) == 0)
					for (i = 0; i < n; i++)
						if ((ap_cur->essid[i] > 0 && ap_cur->essid[i] < 32)
							|| (ap_cur->essid[i] > 126
								&& ap_cur->essid[i] < 160))
							ap_cur->essid[i] = '.';
			}

			/* get the maximum speed in Mb and the AP's channel */

			if (p[0] == 0x01 || p[0] == 0x32)
			{
				if (ap_cur->max_speed < (p[1 + p[1]] & 0x7F) / 2)
					ap_cur->max_speed = (p[1 + p[1]] & 0x7F) / 2;
			}

			if (p[0] == 0x03)
			{
				ap_cur->channel = p[2];
			}
			else if (p[0] == 0x3d)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				/* also get the channel from ht information->primary channel */
				ap_cur->channel = p[2];

				// Get channel width and secondary channel
				switch (p[3] % 4)
				{
					case 0:
						// 20MHz
						ap_cur->channel_width = CHANNEL_20MHZ;
						break;
					case 1:
						// Above
						ap_cur->n_channel.sec_channel = 1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
					case 2:
						// Reserved
						break;
					case 3:
						// Below
						ap_cur->n_channel.sec_channel = -1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
				}

				ap_cur->n_channel.any_chan_width = ((p[3] / 4) % 2);
			}

			// HT capabilities
			if (p[0] == 0x2d && p[1] > 18)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				// Short GI for 20/40MHz
				ap_cur->n_channel.short_gi_20 = (p[3] / 32) % 2;
				ap_cur->n_channel.short_gi_40 = (p[3] / 64) % 2;

				// Parse MCS rate
				/*
				 * XXX: Sometimes TX and RX spatial stream # differ and none of
				 * the beacon
				 * have that. If someone happens to have such AP, open an issue
				 * with it.
				 * Ref:
				 * https://www.wireshark.org/lists/wireshark-bugs/201307/msg00098.html
				 * See IEEE standard 802.11-2012 table 8.126
				 *
				 * For now, just figure out the highest MCS rate.
				 */
				if (ap_cur->n_channel.mcs_index == -1)
				{
					uint32_t rx_mcs_bitmask = 0;
					memcpy(&rx_mcs_bitmask, p + 5, sizeof(uint32_t));
					while (rx_mcs_bitmask)
					{
						++(ap_cur->n_channel.mcs_index);
						rx_mcs_bitmask /= 2;
					}
				}
			}

			// VHT Capabilities
			if (p[0] == 0xbf && p[1] >= 12)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				ap_cur->ac_channel.split_chan = (p[3] / 4) % 4;

				ap_cur->ac_channel.short_gi_80 = (p[3] / 32) % 2;
				ap_cur->ac_channel.short_gi_160 = (p[3] / 64) % 2;

				ap_cur->ac_channel.mu_mimo
					= ((p[3] / 524288) % 2) || ((p[3] / 1048576) % 2);

				// A few things indicate Wave 2: MU-MIMO, 80+80 Channels
				ap_cur->ac_channel.wave_2 = ap_cur->ac_channel.mu_mimo
											|| ap_cur->ac_channel.split_chan;

				// Maximum rates (16 bit)
				uint16_t tx_mcs = 0;
				memcpy(&tx_mcs, p + 10, sizeof(uint16_t));

				// Maximum of 8 SS, each uses 2 bits
				for (uint8_t stream_idx = 0; stream_idx < MAX_AC_MCS_INDEX;
					 ++stream_idx)
				{
					uint8_t mcs = (uint8_t)(tx_mcs % 4);

					// Unsupported -> No more spatial stream
					if (mcs == 3)
					{
						break;
					}
					switch (mcs)
					{
						case 0:
							// support of MCS 0-7
							ap_cur->ac_channel.mcs_index[stream_idx] = 7;
							break;
						case 1:
							// support of MCS 0-8
							ap_cur->ac_channel.mcs_index[stream_idx] = 8;
							break;
						case 2:
							// support of MCS 0-9
							ap_cur->ac_channel.mcs_index[stream_idx] = 9;
							break;
					}

					// Next spatial stream
					tx_mcs /= 4;
				}
			}

			// VHT Operations
			if (p[0] == 0xc0 && p[1] >= 3)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				// Channel width
				switch (p[2])
				{
					case 0:
						// 20 or 40MHz
						ap_cur->channel_width = CHANNEL_20_OR_40MHZ;
						break;
					case 1:
						ap_cur->channel_width = CHANNEL_80MHZ;
						break;
					case 2:
						ap_cur->channel_width = CHANNEL_160MHZ;
						break;
					case 3:
						// 80+80MHz
						ap_cur->channel_width = CHANNEL_80_80MHZ;
						ap_cur->ac_channel.split_chan = 1;
						break;
				}

				// 802.11ac channel center segments
				ap_cur->ac_channel.center_sgmt[0] = p[3];
				ap_cur->ac_channel.center_sgmt[1] = p[4];
			}

			// Next
			p += 2 + p[1];
		}

		// Now get max rate
		if (ap_cur->standard[0] == 'n' || strcmp(ap_cur->standard, "ac") == 0)
		{
			int sgi = 0;
			int width = 0;

			switch (ap_cur->channel_width)
			{
				case CHANNEL_20MHZ:
					width = 20;
					sgi = ap_cur->n_channel.short_gi_20;
					break;
				case CHANNEL_20_OR_40MHZ:
				case CHANNEL_40MHZ:
					width = 40;
					sgi = ap_cur->n_channel.short_gi_40;
					break;
				case CHANNEL_80MHZ:
					width = 80;
					sgi = ap_cur->ac_channel.short_gi_80;
					break;
				case CHANNEL_80_80MHZ:
				case CHANNEL_160MHZ:
					width = 160;
					sgi = ap_cur->ac_channel.short_gi_160;
					break;
				default:
					break;
			}

			if (width != 0)
			{
				// In case of ac, get the amount of spatial streams
				int amount_ss = 1;
				if (ap_cur->standard[0] != 'n')
				{
					for (amount_ss = 0;
						 amount_ss < MAX_AC_MCS_INDEX
						 && ap_cur->ac_channel.mcs_index[amount_ss] != 0;
						 ++amount_ss)
						;
				}

				// Get rate
				float max_rate
					= (ap_cur->standard[0] == 'n')
						  ? get_80211n_rate(
								width, sgi, ap_cur->n_channel.mcs_index)
						  : get_80211ac_rate(
								width,
								sgi,
								ap_cur->ac_channel.mcs_index[amount_ss - 1],
								amount_ss);

				// If no error, update rate
				if (max_rate > 0)
				{
					ap_cur->max_speed = (int) max_rate;
				}
			}
		}
	}

	/* packet parsing: Beacon & Probe response */
	/* TODO: Merge this if and the one above */
	if ((h80211[0] == 0x80 || h80211[0] == 0x50) && caplen > 38)
	{
		p =(unsigned char*) h80211 + 36; // ignore hdr + fixed params

		while (p < h80211 + caplen)
		{
			type = p[0];
			length = p[1];
			if (p + 2 + length > h80211 + caplen)
			{
				/*                printf("error parsing tags! %p vs. %p (tag:
				%i, length: %i,position: %i)\n", (p+2+length), (h80211+caplen),
				type, length, (p-h80211));
				exit(1);*/
				break;
			}

			// Find WPA and RSN tags
			if ((type == 0xDD && (length >= 8)
				 && (memcmp(p + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0))
				|| (type == 0x30))
			{
				ap_cur->security &= ~(STD_WEP | ENC_WEP | STD_WPA);

				org_p = p;
				offset = 0;

				if (type == 0xDD)
				{
					// WPA defined in vendor specific tag -> WPA1 support
					ap_cur->security |= STD_WPA;
					offset = 4;
				}

				// RSN => WPA2
				if (type == 0x30)
				{
					ap_cur->security |= STD_WPA2;
					offset = 0;
				}

				if (length < (18 + offset))
				{
					p += length + 2;
					continue;
				}

				// Number of pairwise cipher suites
				if (p + 9 + offset > h80211 + caplen) break;
				numuni = p[8 + offset] + (p[9 + offset] << 8);

				// Number of Authentication Key Managament suites
				if (p + (11 + offset) + 4 * numuni > h80211 + caplen) break;
				numauth = p[(10 + offset) + 4 * numuni]
						  + (p[(11 + offset) + 4 * numuni] << 8);

				p += (10 + offset);

				if (type != 0x30)
				{
					if (p + (4 * numuni) + (2 + 4 * numauth) > h80211 + caplen)
						break;
				}
				else
				{
					if (p + (4 * numuni) + (2 + 4 * numauth) + 2
						> h80211 + caplen)
						break;
				}

				// Get the list of cipher suites
				for (i = 0; i < numuni; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= ENC_WEP;
							break;
						case 0x02:
							ap_cur->security |= ENC_TKIP;
							break;
						case 0x03:
							ap_cur->security |= ENC_WRAP;
							break;
						case 0x0A:
						case 0x04:
							ap_cur->security |= ENC_CCMP;
							break;
						case 0x05:
							ap_cur->security |= ENC_WEP104;
							break;
						case 0x08:
						case 0x09:
							ap_cur->security |= ENC_GCMP;
							break;
						default:
							break;
					}
				}

				p += 2 + 4 * numuni;

				// Get the AKM suites
				for (i = 0; i < numauth; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= AUTH_MGT;
							break;
						case 0x02:
							ap_cur->security |= AUTH_PSK;
							break;
						default:
							break;
					}
				}

				p += 2 + 4 * numauth;

				if (type == 0x30) p += 2;

				p = org_p + length + 2;
			}
			else if ((type == 0xDD && (length >= 8)
					  && (memcmp(p + 2, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
			{
				// QoS IE
				ap_cur->security |= STD_QOS;
				p += length + 2;
			}
			else if ((type == 0xDD && (length >= 4)
					  && (memcmp(p + 2, "\x00\x50\xF2\x04", 4) == 0)))
			{
				// WPS IE
				org_p = p;
				p += 6;
				int len = length, subtype = 0, sublen = 0;
				while (len >= 4)
				{
					subtype = (p[0] << 8) + p[1];
					sublen = (p[2] << 8) + p[3];
					if (sublen > len) break;
					switch (subtype)
					{
						case 0x104a: // WPS Version
							ap_cur->wps.version = p[4];
							break;
						case 0x1011: // Device Name
						case 0x1012: // Device Password ID
						case 0x1021: // Manufacturer
						case 0x1023: // Model
						case 0x1024: // Model Number
						case 0x103b: // Response Type
						case 0x103c: // RF Bands
						case 0x1041: // Selected Registrar
						case 0x1042: // Serial Number
							break;
						case 0x1044: // WPS State
							ap_cur->wps.state = p[4];
							break;
						case 0x1047: // UUID Enrollee
						case 0x1049: // Vendor Extension
							if (memcmp(&p[4], "\x00\x37\x2A", 3) == 0)
							{
								unsigned char * pwfa = &p[7];
								int wfa_len = ntohs(*((short *) &p[2]));
								while (wfa_len > 0)
								{
									if (*pwfa == 0)
									{ // Version2
										ap_cur->wps.version = pwfa[2];
										break;
									}
									wfa_len -= pwfa[1] + 2;
									pwfa += pwfa[1] + 2;
								}
							}
							break;
						case 0x1054: // Primary Device Type
							break;
						case 0x1057: // AP Setup Locked
							ap_cur->wps.ap_setup_locked = p[4];
							break;
						case 0x1008: // Config Methods
						case 0x1053: // Selected Registrar Config Methods
							ap_cur->wps.meth = (p[4] << 8) + p[5];
							break;
						default: // Unknown type-length-value
							break;
					}
					p += sublen + 4;
					len -= sublen + 4;
				}
				p = org_p + length + 2;
			}
			else
				p += length + 2;
		}
	}

	/* packet parsing: Authentication Response */

	if (h80211[0] == 0xB0 && caplen >= 30)
	{
		if (ap_cur->security & STD_WEP)
		{
			// successful step 2 or 4 (coming from the AP)
			if (memcmp(h80211 + 28, "\x00\x00", 2) == 0
				&& (h80211[26] == 0x02 || h80211[26] == 0x04))
			{
				ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
				if (h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
				if (h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
			}
		}
	}

	/* packet parsing: Association Request */

	if (h80211[0] == 0x00 && caplen > 28)
	{
		p =(unsigned char*) h80211 + 28;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				/* found a non-cloaked ESSID */

				n = (p[1] > 32) ? 32 : p[1];

				memset(ap_cur->essid, 0, 33);
				memcpy(ap_cur->essid, p + 2, n);
				ap_cur->ssid_length = n;

				if (verifyssid(ap_cur->essid) == 0)
					for (i = 0; i < n; i++)
						if ((ap_cur->essid[i] > 0 && ap_cur->essid[i] < 32)
							|| (ap_cur->essid[i] > 126
								&& ap_cur->essid[i] < 160))
							ap_cur->essid[i] = '.';
			}

			p += 2 + p[1];
		}
		if (st_cur != NULL) st_cur->wpa.state = 0;
	}

	/* packet parsing: some data */

	if ((h80211[0] & 0x0C) == 0x08)
	{
		/* update the channel if we didn't get any beacon */

		if (ap_cur->channel == -1)
		{
			/*if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
				ap_cur->channel = ri->ri_channel;
			else
				ap_cur->channel = G.channel[cardnum];*/
		}

		/* check the SNAP header to see if data is encrypted */

		z = ((h80211[1] & 3) != 3) ? 24 : 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80)
		{
			z += 2;
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 1;
				else
					st_cur->qos_fr_ds = 1;
			}
		}
		else
		{
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 0;
				else
					st_cur->qos_fr_ds = 0;
			}
		}

		if (z == 24)
		{
			if (list_check_decloak(&(ap_cur->packets), caplen, (unsigned char*) h80211) != 0)
			{
				list_add_packet(&(ap_cur->packets), caplen, (unsigned char*) h80211);
			}
			else
			{
				ap_cur->is_decloak = 1;
				ap_cur->decloak_detect = 0;
				list_tail_free(&(ap_cur->packets));
				memset(G.message, '\x00', sizeof(G.message));
				snprintf(G.message,
						 sizeof(G.message) - 1,
						 "][ Decloak: %02X:%02X:%02X:%02X:%02X:%02X ",
						 ap_cur->bssid[0],
						 ap_cur->bssid[1],
						 ap_cur->bssid[2],
						 ap_cur->bssid[3],
						 ap_cur->bssid[4],
						 ap_cur->bssid[5]);
			}
		}

		if (z + 26 > (unsigned) caplen) goto write_packet;

		if (h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03)
		{
			//            if( ap_cur->encryption < 0 )
			//                ap_cur->encryption = 0;

			/* if ethertype == IPv4, find the LAN address */

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00
				&& (h80211[1] & 3) == 0x01)
				memcpy(ap_cur->lanip, &h80211[z + 20], 4);

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06)
				memcpy(ap_cur->lanip, &h80211[z + 22], 4);
		}
		//        else
		//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5
		//            );

		if (ap_cur->security == 0 || (ap_cur->security & STD_WEP))
		{
			if ((h80211[1] & 0x40) != 0x40)
			{
				ap_cur->security |= STD_OPN;
			}
			else
			{
				if ((h80211[z + 3] & 0x20) == 0x20)
				{
					ap_cur->security |= STD_WPA;
				}
				else
				{
					ap_cur->security |= STD_WEP;
					if ((h80211[z + 3] & 0xC0) != 0x00)
					{
						ap_cur->security |= ENC_WEP40;
					}
					else
					{
						ap_cur->security &= ~ENC_WEP40;
						ap_cur->security |= ENC_WEP;
					}
				}
			}
		}

		if (z + 10 > (unsigned) caplen) goto write_packet;

		if (ap_cur->security & STD_WEP)
		{
			/* WEP: check if we've already seen this IV */

			if (!uniqueiv_check(ap_cur->uiv_root, (unsigned char*)&h80211[z]))
			{
				/* first time seen IVs */
			}
		}
		else
		{
			ap_cur->nb_data++;
		}

		z = ((h80211[1] & 3) != 3) ? 24 : 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80) z += 2;

		if (z + 26 > (unsigned) caplen) goto write_packet;

		z += 6; // skip LLC header

		/* check ethertype == EAPOL */
		if (h80211[z] == 0x88 && h80211[z + 1] == 0x8E
			&& (h80211[1] & 0x40) != 0x40)
		{
			ap_cur->EAP_detected = 1;

			z += 2; // skip ethertype

			if (st_cur == NULL) goto write_packet;

			/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) == 0)
			{
				memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);
				st_cur->wpa.state = 1;
			}

			/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

			if (z + 17 + 32 > (unsigned) caplen) goto write_packet;

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) == 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					memcpy(st_cur->wpa.snonce, &h80211[z + 17], 32);
					st_cur->wpa.state |= 2;
				}

				if ((st_cur->wpa.state & 4) != 4)
				{
					st_cur->wpa.eapol_size
						= (h80211[z + 2] << 8) + h80211[z + 3] + 4;

					if (caplen - z < st_cur->wpa.eapol_size
						|| st_cur->wpa.eapol_size == 0
						|| caplen - z < 81 + 16
						|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
					{
						// Ignore the packet trying to crash us.
						st_cur->wpa.eapol_size = 0;
						goto write_packet;
					}

					memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
					memcpy(
						st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
					memset(st_cur->wpa.eapol + 81, 0, 16);
					st_cur->wpa.state |= 4;
					st_cur->wpa.keyver = h80211[z + 6] & 7;
				}
			}

			/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);
					st_cur->wpa.state |= 1;
				}

				if ((st_cur->wpa.state & 4) != 4)
				{
					st_cur->wpa.eapol_size
						= (h80211[z + 2] << 8) + h80211[z + 3] + 4;

					if (caplen - (unsigned) z < st_cur->wpa.eapol_size
						|| st_cur->wpa.eapol_size == 0
						|| caplen - (unsigned) z < 81 + 16
						|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
					{
						// Ignore the packet trying to crash us.
						st_cur->wpa.eapol_size = 0;
						goto write_packet;
					}

					memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
					memcpy(
						st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
					memset(st_cur->wpa.eapol + 81, 0, 16);
					st_cur->wpa.state |= 4;
					st_cur->wpa.keyver = h80211[z + 6] & 7;
				}
			}

			if (st_cur->wpa.state == 7 && !is_filtered_essid(ap_cur->essid))
			{
				memcpy(st_cur->wpa.stmac, st_cur->stmac, 6);
				memcpy(G.wpa_bssid, ap_cur->bssid, 6);
				memset(G.message, '\x00', sizeof(G.message));
				snprintf(G.message,
						 sizeof(G.message) - 1,
						 "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
						 G.wpa_bssid[0],
						 G.wpa_bssid[1],
						 G.wpa_bssid[2],
						 G.wpa_bssid[3],
						 G.wpa_bssid[4],
						 G.wpa_bssid[5]);

				if (ivs_only)
				{
					memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
					ivs2.flags = 0;
					ivs2.len = 0;

					ivs2.len = sizeof(struct WPA_hdsk);
					ivs2.flags |= IVS2_WPA;

					if (memcmp(G.prev_bssid, ap_cur->bssid, 6) != 0)
					{
						ivs2.flags |= IVS2_BSSID;
						ivs2.len += 6;
						memcpy(G.prev_bssid, ap_cur->bssid, 6);
					}
					char path[200];
                    char bssid[512];
                    snprintf(bssid, sizeof(bssid), "%02X%02X%02X%02X%02X%02X",
                    	         ap_cur->bssid[0],
                    	         ap_cur->bssid[1],
                    	         ap_cur->bssid[2],
                    	         ap_cur->bssid[3],
                    	         ap_cur->bssid[4],
                    	         ap_cur->bssid[5]);
                    sprintf(path, "/var/lib/wifi/handshake/ap-%s.%s", bssid, "ivs");
                    FILE *fp = fopen(path, "r");
                    if(!fp)
                    	fp = fopen(path, "w");
                    if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), fp) != (size_t) sizeof(struct ivs2_pkthdr)){
                 	    perror("fwrite(IV header) failed");
                 	    //return (1);
                 	}
                    if (ivs2.flags & IVS2_BSSID)
                   	{
                   	    if (fwrite(ap_cur->bssid, 1, 6, fp) != (size_t) 6)
                   	    {
                   		    perror("fwrite(IV bssid) failed");
                   		    //return (1);
                   	    }
                   	    ivs2.len -= 6;
                   	}
                    if (fwrite(&(st_cur->wpa), 1, sizeof(struct WPA_hdsk), fp) != (size_t) sizeof(struct WPA_hdsk))
                 	{
                 	   perror("fwrite(IV wpa_hdsk) failed");
                 	   //return (1);
                 	}
                 	fclose(fp);
				}
			}
		}
	}

write_packet:

	if (ap_cur != NULL)
	{
		if (h80211[0] == 0x80 && G.one_beacon)
		{
			if (!ap_cur->beacon_logged)
				ap_cur->beacon_logged = 1;
			else
				return;
		}
	}

	if (G.record_data)
	{
		if (((h80211[0] & 0x0C) == 0x00) && ((h80211[0] & 0xF0) == 0xB0))
		{
			/* authentication packet */
			//check_shared_key(h80211, caplen);
		}
	}

	if (ap_cur != NULL)
	{
		if (ap_cur->security != 0 && G.f_encrypt != 0
			&& ((ap_cur->security & G.f_encrypt) == 0))
		{
			return;
		}

		if (is_filtered_essid(ap_cur->essid))
		{
			return;
		}
	}

	/* this changes the local ap_cur, st_cur and na_cur variables and should be
	 * the last check before the actual write */
	if (caplen < 24 && caplen >= 10 && h80211[0])
	{
		/* RTS || CTS || ACK || CF-END || CF-END&CF-ACK*/
		//(h80211[0] == 0xB4 || h80211[0] == 0xC4 || h80211[0] == 0xD4 ||
		// h80211[0] == 0xE4 || h80211[0] == 0xF4)

		/* use general control frame detection, as the structure is always the
		 * same: mac(s) starting at [4] */
		if (h80211[0] & 0x04)
		{
			p =(unsigned char*) h80211 + 4;
			while (p <= h80211 + 16 && p <= h80211 + caplen)
			{
				memcpy(namac, p, 6);

				if (memcmp(namac, NULL_MAC, 6) == 0)
				{
					p += 6;
					continue;
				}

				if (memcmp(namac, BROADCAST, 6) == 0)
				{
					p += 6;
					continue;
				}

				if (G.hide_known)
				{
					/* check AP list */
					ap_cur = G.ap_1st;
					ap_prv = NULL;

					while (ap_cur != NULL)
					{
						if (!memcmp(ap_cur->bssid, namac, 6)) break;

						ap_prv = ap_cur;
						ap_cur = ap_cur->next;
					}

					/* if it's an AP, try next mac */

					if (ap_cur != NULL)
					{
						p += 6;
						continue;
					}

					/* check ST list */
					st_cur = G.st_1st;
					st_prv = NULL;

					while (st_cur != NULL)
					{
						if (!memcmp(st_cur->stmac, namac, 6)) break;

						st_prv = st_cur;
						st_cur = st_cur->next;
					}

					/* if it's a client, try next mac */

					if (st_cur != NULL)
					{
						p += 6;
						continue;
					}
				}

				/* not found in either AP list or ST list, look through NA list
				 */
				na_cur = G.na_1st;
				na_prv = NULL;

				while (na_cur != NULL)
				{
					if (!memcmp(na_cur->namac, namac, 6)) break;

					na_prv = na_cur;
					na_cur = na_cur->next;
				}

				/* update our chained list of unknown stations */
				/* if it's a new mac, add it */

				if (na_cur == NULL)
				{
					if (!(na_cur
						  = (struct NA_info *) malloc(sizeof(struct NA_info))))
					{
						perror("malloc failed");
						return;
					}

					memset(na_cur, 0, sizeof(struct NA_info));

					if (G.na_1st == NULL)
						G.na_1st = na_cur;
					else
						na_prv->next = na_cur;

					memcpy(na_cur->namac, namac, 6);

					na_cur->prev = na_prv;

					gettimeofday(&(na_cur->tv), NULL);
					na_cur->tinit = time(NULL);
					na_cur->tlast = time(NULL);

					na_cur->power = -1;
					na_cur->channel = -1;
					na_cur->ack = 0;
					na_cur->ack_old = 0;
					na_cur->ackps = 0;
					na_cur->cts = 0;
					na_cur->rts_r = 0;
					na_cur->rts_t = 0;
				}

				/* update the last time seen & power*/

				na_cur->tlast = time(NULL);
				//na_cur->power = ri->ri_power;
				//na_cur->channel = ri->ri_channel;

				switch (h80211[0] & 0xF0)
				{
					case 0xB0:
						if (p == h80211 + 4) na_cur->rts_r++;
						if (p == h80211 + 10) na_cur->rts_t++;
						break;

					case 0xC0:
						na_cur->cts++;
						break;

					case 0xD0:
						na_cur->ack++;
						break;

					default:
						na_cur->other++;
						break;
				}

				/*grab next mac (for rts frames)*/
				p += 6;
			}
		}
	}
	//pcap_dump(args, pkh, packet);
	return;
}

char * format_text_for_csv(const unsigned char * input, int len)
{
	// Unix style encoding
	char *ret, *rret;
	int i, pos, contains_space_end;
	const char * hex_table = "0123456789ABCDEF";

	if (len < 0)
	{
		return NULL;
	}

	if (len == 0 || input == NULL)
	{
		ret = (char *) malloc(1);
		ret[0] = 0;
		return ret;
	}

	pos = 0;
	contains_space_end = (input[0] == ' ') || input[len - 1] == ' ';

	// Make sure to have enough memory for all that stuff
	ret = (char *) malloc((len * 4) + 1 + 2);

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	for (i = 0; i < len; i++)
	{
		if (!isprint(input[i]) || input[i] == ',' || input[i] == '\\'
			|| input[i] == '"')
		{
			ret[pos++] = '\\';
		}

		if (isprint(input[i]))
		{
			ret[pos++] = input[i];
		}
		else if (input[i] == '\n' || input[i] == '\r' || input[i] == '\t')
		{
			ret[pos++]
				= (input[i] == '\n') ? 'n' : (input[i] == '\t') ? 't' : 'r';
		}
		else
		{
		        ret[pos++] = 'x';
			ret[pos++] = hex_table[input[i] / 16];
			ret[pos++] = hex_table[input[i] % 16];
		}
	}

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	ret[pos++] = '\0';

	rret =(char*) realloc(ret, pos);

	return (rret) ? rret : ret;
}

int dump_write_json(char *json_filename)
{
	printf("entered");
	    FILE *json = fopen(json_filename, "w");
        int i, n, probes_written;
        struct tm *ltime;
        struct AP_info *ap_cur;
        struct ST_info *st_cur;
        char * temp;

       // if (! G.record_data || !G.output_format_json)
    	//        return 0;

       //append
       // fseek( json, 0, SEEK_END );

        //append AP info
        ap_cur = G.ap_1st;
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        int count = 0x00;

        while( ap_cur != NULL )
        {
                if (time( NULL ) - ap_cur->tlast > G.berlin )
                {
                        ap_cur = ap_cur->next;
                        continue;
                }

                if( memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
                {
                        ap_cur = ap_cur->next;
                        continue;
                }

                if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
                {
                        ap_cur = ap_cur->next;
                        continue;
                }

                if(is_filtered_essid(ap_cur->essid))
                {
                        ap_cur = ap_cur->next;
                        continue;
                }
                if(count ==0x00){
                	fprintf(json,"{\"index\" : {\"_index\": \"vnfsdb-%d%d%d\", \"_type\": \"l4\", \"_id\": \"%02X%02X%02X%02X%02X%02X%lu\" } }\r\n",timeinfo->tm_year + 1900,timeinfo->tm_mon + 1,timeinfo->tm_mday,ap_cur->bssid[0], ap_cur->bssid[1],ap_cur->bssid[2], ap_cur->bssid[3],ap_cur->bssid[4], ap_cur->bssid[5],(unsigned long)time(NULL));
                	count++;
                }
                else{
                   		fprintf(json,"\r{\"index\" : {\"_index\": \"vnfsdb-%d%d%d\", \"_type\": \"l4\", \"_id\": \"%02X%02X%02X%02X%02X%02X%lu\" } }\r\n",timeinfo->tm_year + 1900,timeinfo->tm_mon + 1,timeinfo->tm_mday,ap_cur->bssid[0], ap_cur->bssid[1],ap_cur->bssid[2], ap_cur->bssid[3],ap_cur->bssid[4], ap_cur->bssid[5],(unsigned long)time(NULL));
                }
                struct timeval start;
                gettimeofday(&start,NULL);
                fprintf(json, "{\"session\" : {\"start_time\" : %lld, \"end_time\" : %lld},  \"BSSID\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ", (long long int)((start.tv_sec*1000)+(start.tv_usec/1000)),
                                     (long long int)((start.tv_sec*1000)+(start.tv_usec/1000)),
                                     ap_cur->bssid[0], ap_cur->bssid[1],
                                     ap_cur->bssid[2], ap_cur->bssid[3],
                                     ap_cur->bssid[4], ap_cur->bssid[5] );

	            ltime = localtime( &ap_cur->tinit );
	            fprintf( json, "\"FirstTimeSeen\":\"%04d-%02d-%02d %02d:%02d:%02d\", ",
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,
                        ltime->tm_mday, ltime->tm_hour,
                        ltime->tm_min,  ltime->tm_sec );

	            ltime = localtime( &ap_cur->tlast );

                fprintf( json, "\"LastTimeSeen\":\"%04d-%02d-%02d %02d:%02d:%02d\", ",
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,
                        ltime->tm_mday, ltime->tm_hour,
                        ltime->tm_min,  ltime->tm_sec );

	            fprintf( json, "\"channel\":%2d, \"max_speed\":\"%3d\",",
                        ap_cur->channel,
                        ap_cur->max_speed );

                fprintf( json, "\"Privacy\":");

	        if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0) fprintf( json, "\"\"" );
                else
                {
                        fprintf( json, "\"" );
                        if( ap_cur->security & STD_WPA2 ) fprintf( json, "WPA2" );
                        if( ap_cur->security & STD_WPA  ) fprintf( json, "WPA" );
                        if( ap_cur->security & STD_WEP  ) fprintf( json, "WEP" );
                        if( ap_cur->security & STD_OPN  ) fprintf( json, "OPN" );
                        fprintf( json, "\"" );
                }
                fprintf( json, ",");

	        if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) fprintf( json, "\"Cipher\":\"\" ");
                else
                {
                        fprintf( json, " \"Cipher\":\"" );
                        if( ap_cur->security & ENC_CCMP   ) fprintf( json, "CCMP ");
                        if( ap_cur->security & ENC_WRAP   ) fprintf( json, "WRAP ");
                        if( ap_cur->security & ENC_TKIP   ) fprintf( json, "TKIP ");
                        if( ap_cur->security & ENC_WEP104 ) fprintf( json, "WEP104 ");
                        if( ap_cur->security & ENC_WEP40  ) fprintf( json, "WEP40 ");
                        if( ap_cur->security & ENC_WEP    ) fprintf( json, "WEP ");
                       fprintf( json, "\"");
                }
                fprintf( json, ",");


                if( (ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ) fprintf( json, " \"Authentication\":\"\"");
                else
                {
                        if( ap_cur->security & AUTH_MGT   ) fprintf( json, " \"Authentication\":\"MGT\"");
                        if( ap_cur->security & AUTH_PSK   )
	                {
                                if( ap_cur->security & STD_WEP )
			                fprintf( json, "\"Authentication\":\"SKA\"");
			        else
		                        fprintf( json, "\"Authentication\":\"PSK\"");
		        }
                        if( ap_cur->security & AUTH_OPN   ) fprintf( json, " \"Authentication\":\"OPN\"");
                }

                fprintf( json, ", \"Signal strength\":%3d, \"#beacons\":%8ld,\"#IV\":%8ld, ",
                        ap_cur->avg_power,
                        ap_cur->nb_bcn,
                        ap_cur->nb_data );

                fprintf( json, "\"GATEWAY\":\"%3d.%3d.%3d.%3d\", ",
                        ap_cur->lanip[0], ap_cur->lanip[1],
                        ap_cur->lanip[2], ap_cur->lanip[3] );

                fprintf( json, "\"ID-length\":%3d, ", ap_cur->ssid_length);

	        temp = format_text_for_csv(ap_cur->essid, ap_cur->ssid_length);
                fprintf( json, "\"ESSID\":\"%s\", ", temp );
	        free(temp);

                if(ap_cur->key != NULL)
                {
                        fprintf( json, "\"Key\":\"");
                        for(i=0; i<(int)strlen(ap_cur->key); i++)
                        {
                                fprintf( json, "%02X", ap_cur->key[i]);
                                if(i<(int)(strlen(ap_cur->key)-1))
                                        fprintf( json, ":");
                        }
                        fprintf(json, "\",");
                }

	            fprintf(json,"\"Manufacturer\":\"%s\", ",ap_cur->manuf);
                double lt,ln;
                lt = ap_cur->gps_loc_best[0];
                ln = ap_cur->gps_loc_best[1];
                if(lt || ln){
                fprintf( json, "\"ap_geo_location\":{\"lat\":%.6f, ",
                                        ap_cur->gps_loc_best[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                        ap_cur->gps_loc_best[1] );

                fprintf( json, "\"ALTITUDE\":%.6f, ",
                                        ap_cur->gps_loc_best[2] );
                fprintf( json, "\"geo_location_max\":{\"lat\":%.6f, ",
                                        ap_cur->gps_loc_max[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                        ap_cur->gps_loc_max[1] );

                //fprintf( json, "\"ALTITUDE\":%.6f, ",
                                       // ap_cur->gps_loc_max[2] );
                }
                //terminate json AP data
                fprintf(json,"\"wlan_type\":\"AP\",\"timestamp\":\"%d\"}",(int)time(NULL));
	            fprintf(json, "\r\n");
                fflush( json);
                ap_cur = ap_cur->next;
        }

        //append STA info
       st_cur = G.st_1st;
        while( st_cur != NULL )
        {
                ap_cur = st_cur->base;

                if( ap_cur->nb_pkt < 2 )
                {
                        st_cur = st_cur->next;
                        continue;
                }

               if (time( NULL ) - st_cur->tlast > G.berlin )
                {
                        st_cur = st_cur->next;
                        continue;
               }
               if(count ==0x00){
              	        fprintf(json,"{\"index\" : {\"_index\": \"vnfsdb-%d%d%d\", \"_type\": \"l4\", \"_id\": \"%02X%02X%02X%02X%02X%02X%lu\" } }\r\n",timeinfo->tm_year + 1900,timeinfo->tm_mon + 1,timeinfo->tm_mday,ap_cur->bssid[0],st_cur->stmac[0], st_cur->stmac[1],st_cur->stmac[2], st_cur->stmac[3],st_cur->stmac[4], st_cur->stmac[5],(unsigned long)time(NULL));
              	        count++;
               }
               else
              	  fprintf(json,"\r{\"index\" : {\"_index\": \"vnfsdb-%d%d%d\", \"_type\": \"l4\", \"_id\": \"%02X%02X%02X%02X%02X%02X%lu\" } }\r\n",timeinfo->tm_year + 1900,timeinfo->tm_mon + 1,timeinfo->tm_mday,ap_cur->bssid[0],st_cur->stmac[0], st_cur->stmac[1],st_cur->stmac[2], st_cur->stmac[3],st_cur->stmac[4], st_cur->stmac[5],(unsigned long)time(NULL));
               struct timeval end;
               gettimeofday(&end,NULL);
               fprintf( json, "{\"session\" : {\"start_time\" : %lld, \"end_time\" : %lld}, \"StationMAC\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ", (end.tv_sec*1000)+(end.tv_usec/1000),(end.tv_sec*1000)+(end.tv_usec/1000)
                                      ,st_cur->stmac[0], st_cur->stmac[1],
                                      st_cur->stmac[2], st_cur->stmac[3],
                                      st_cur->stmac[4], st_cur->stmac[5] );

                ltime = localtime( &st_cur->tinit );

                fprintf( json, "\"FirstTimeSeen\":\"%04d-%02d-%02d %02d:%02d:%02d\", ",
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,
                        ltime->tm_mday, ltime->tm_hour,
                        ltime->tm_min,  ltime->tm_sec );

                ltime = localtime( &st_cur->tlast );

               fprintf( json, "\"LastTimeSeen\":\"%04d-%02d-%02d %02d:%02d:%02d\", ",
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,
                        ltime->tm_mday, ltime->tm_hour,
                        ltime->tm_min,  ltime->tm_sec );

               fprintf( json, "\"Signal strength\":%3d, \"#packets\":%8ld, ",
                        st_cur->power,
                        st_cur->nb_pkt );

                if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) )
                        fprintf( json, "\"BSSID\":\"(not associated)\" ," );
                else
                        fprintf( json, "\"BSSID\":\"%02X:%02X:%02X:%02X:%02X:%02X\",",
                                ap_cur->bssid[0], ap_cur->bssid[1],
                                ap_cur->bssid[2], ap_cur->bssid[3],
                                ap_cur->bssid[4], ap_cur->bssid[5] );

                //add ESSID
                fprintf(json,"\"ESSID\":\"%s\", ",ap_cur->essid);


	        probes_written = 0;
                fprintf( json, "\"ProbedESSIDs\":\"");
                int pnum = 0;
                for( i = 0, n = 0; i < NB_PRB; i++ )
                {
                        if( st_cur->ssid_length[i] == 0 )
                                continue;

	                temp = format_text_for_csv((const unsigned char*) st_cur->probes[i], st_cur->ssid_length[i]);

	                if( probes_written == 0)
	                {
		                fprintf( json, "%s", temp);
		                probes_written = 1;
	                }
	                else
                {
		                fprintf( json, ",%s", temp);
	                }
                        pnum=pnum+1;
	                free(temp);
                }
                fprintf(json, "\",");
                //add number of probes
                fprintf(json, "\"#probes\":%d,",pnum);



                //add manufacturer for STA

	            fprintf(json,"\"Manufacturer\":\"%s\", ",st_cur->manuf);
                srand(time(NULL));
                double lt,ln;
                lt = st_cur->gps_loc_best[0];
                ln = st_cur->gps_loc_best[1];
                if(lt || ln){
                fprintf( json, "\"equip_geo_location\":{\"lat\":%.6f, ",
                                                        st_cur->gps_loc_best[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                                      st_cur->gps_loc_best[1] );
                fprintf( json, "\"geo_location_max\":{\"lat\":%.6f, ",
                                        st_cur->gps_loc_max[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                        st_cur->gps_loc_max[1] );

                //fprintf( json, "\"ALTITUDE\":%.6f, ",
                                       // st_cur->gps_loc_max[2] );
                 }
                fprintf( json, "\"ALTITUDE\":%.6f, ",
                                                        st_cur->gps_loc_best[2] );

                //terminate json client data
                fprintf(json,"\"wlan_type\":\"CL\",\"timestamp\":\"%d\"}",(int)time(NULL));
                fprintf( json, "\r\n" );
                st_cur = st_cur->next;
        }
        fclose( json);

        return 1;
}

pthread_mutex_t lock_handler;
void *filehandler(void *arg){
	while(true){
		if(head_file!=NULL){
			char command[300];
			memset(command, 0x00, sizeof(char)*300);
			sprintf(command,"sshpass -p \"probe@PPPPKKKK\"  scp -o StrictHostKeyChecking=no %s.pcap admin1@192.168.2.117:/home/admin1/pcap_wifi ",head_file->filename);
			system(command);
			memset(command, 0x00, sizeof(char)*300);
			sprintf(command,"sshpass -p \"probe@PPPPKKKK\"  scp -o StrictHostKeyChecking=no %s.json admin1@192.168.2.117:/home/admin1/pcap_wifi ",head_file->filename);
			system(command);
			memset(command, 0x00, sizeof(char)*300);
			sprintf(command,"sshpass -p \"probe@PPPPKKKK\"  ssh -o StrictHostKeyChecking=no admin1@192.168.2.117 \"echo probe@PPPPKKKK | sudo -S mv /home/admin1/pcap_wifi/*.pcap /home/admin1/wpcap/\" ");
			system(command);
			memset(command, 0x00, sizeof(char)*300);
			sprintf(command,"sshpass -p \"probe@PPPPKKKK\"  ssh -o StrictHostKeyChecking=no admin1@192.168.2.117 \"echo probe@PPPPKKKK | sudo -S mv /home/admin1/pcap_wifi/*.json /var/lib/meta/\" ");
			system(command);
			memset(command,0x00, sizeof(char)*300);
			sprintf(command,"rm -rf %s.pcap", head_file->filename);
			//system(command);
			memset(command,0x00, sizeof(char)*300);
			sprintf(command,"rm -rf %s.json", head_file->filename);
			//system(command);
			pthread_mutex_lock(&lock_handler);
			head_file=head_file->next;
			pthread_mutex_unlock(&lock_handler);
		}
	}
}
void alarm_handler(int sig){
	pcap_breakloop(descr);
}
void init(){
	G.ap_1st = NULL;
	G.manufList = NULL;
	G.chanoption = 0;
	G.freqoption = 0;
	G.num_cards = 0;
	G.batt = NULL;
	G.chswitch = 0;
	G.usegpsd = 1;
	G.channels = abg_chans;
	G.one_beacon = 1;
	G.singlechan = 0;
	G.singlefreq = 0;
	G.dump_prefix = NULL;
	G.record_data = 1;
	G.f_cap = NULL;
	G.f_ivs = NULL;
	G.f_txt = NULL;
	G.f_kis = NULL;
	G.f_kis_xml = NULL;
	G.f_gps = NULL;
	G.keyout = NULL;
	G.f_xor = NULL;
	G.sk_len = 0;
	G.sk_len2 = 0;
	G.sk_start = 0;
	G.prefix = NULL;
	G.f_encrypt = 0;
	G.asso_client = 0;
	G.f_essid = NULL;
	G.f_essid_count = 0;
	G.active_scan_sim = 0;
	G.update_s = 0;
	G.decloak = 1;
	G.is_berlin = 0;
	G.numaps = 0;
	G.maxnumaps = 0;
	G.berlin = 120;
	G.show_ap = 1;
	G.show_sta = 1;
	G.show_ack = 0;
	G.hide_known = 0;
	G.maxsize_essid_seen = 5; // Initial value: length of "ESSID"
	G.show_manufacturer = 0x01;
	G.show_uptime = 0;
	G.hopfreq = DEFAULT_HOPFREQ;
	G.s_file = NULL;
	G.s_iface = NULL;
	G.f_cap_in = NULL;
	G.detect_anomaly = 0;
	G.airodump_start_time = NULL;
	G.manufList = NULL;

	G.output_format_pcap = 1;
	G.output_format_json = 1;
	G.output_format_csv = 0;
	G.output_format_kismet_csv = 0;
	G.output_format_kismet_netxml = 0;
	G.file_write_interval = 5; // Write file every 5 seconds by default
	G.maxsize_wps_seen = 6;
	G.show_wps = 0;
	G.background_mode = -1;
	#ifdef CONFIG_LIBNL
		G.htval = CHANNEL_NO_HT;
	#endif
	#ifdef HAVE_PCRE
		G.f_essid_regex = NULL;
	#endif
}

int parse_packets(){
  char filter[] = "";
  int fd_read =  open("/tmp/pipe_command_write", O_RDONLY);
  if(fd_read==-1)
  	fprintf(stderr, "error: uanble to open FIFO\n");
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];
  if(!(fp = pcap_open_offline("/home/saurabh/test1.pcap", errbuf))){
	  printf("Error in opening pcap file for reading\n");
	  exit(0);
  }
  pcap_loop(fp, 0, packet_handler, NULL);
  char json_filename[200];
  memset(json_filename, 0x00, 200);
  sprintf(json_filename, "/home/saurabh/dump1.json");
  if(dump_write_json(json_filename))
	  fprintf(stdout, "\njson file written successfully\n");
  return 0;
}
