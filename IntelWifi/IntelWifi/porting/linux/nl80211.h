#ifndef __LINUX_NL80211_H
#define __LINUX_NL80211_H
/*
 * 802.11 netlink interface public header
 *
 * Copyright 2006-2010 Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2008 Michael Wu <flamingice@sourmilk.net>
 * Copyright 2008 Luis Carlos Cobo <luisca@cozybit.com>
 * Copyright 2008 Michael Buesch <m@bues.ch>
 * Copyright 2008, 2009 Luis R. Rodriguez <lrodriguez@atheros.com>
 * Copyright 2008 Jouni Malinen <jouni.malinen@atheros.com>
 * Copyright 2008 Colin McCabe <colin@cozybit.com>
 * Copyright 2015-2017    Intel Deutschland GmbH
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/*
 * This header file defines the userspace API to the wireless stack. Please
 * be careful not to break things - i.e. don't move anything around or so
 * unless you can demonstrate that it breaks neither API nor ABI.
 *
 * Additions to the API should be accompanied by actual implementations in
 * an upstream driver, so that example implementations exist in case there
 * are ever concerns about the precise semantics of the API or changes are
 * needed, and to ensure that code for dead (no longer implemented) API
 * can actually be identified and removed.
 * Nonetheless, semantics should also be documented carefully in this file.
 */

#include "types.h"

#define NL80211_GENL_NAME "nl80211"

#define NL80211_MULTICAST_GROUP_CONFIG        "config"
#define NL80211_MULTICAST_GROUP_SCAN        "scan"
#define NL80211_MULTICAST_GROUP_REG        "regulatory"
#define NL80211_MULTICAST_GROUP_MLME        "mlme"
#define NL80211_MULTICAST_GROUP_VENDOR        "vendor"
#define NL80211_MULTICAST_GROUP_NAN        "nan"
#define NL80211_MULTICAST_GROUP_TESTMODE    "testmode"

/**
 * DOC: Station handling
 *
 * Stations are added per interface, but a special case exists with VLAN
 * interfaces. When a station is bound to an AP interface, it may be moved
 * into a VLAN identified by a VLAN interface index (%NL80211_ATTR_STA_VLAN).
 * The station is still assumed to belong to the AP interface it was added
 * to.
 *
 * Station handling varies per interface type and depending on the driver's
 * capabilities.
 *
 * For drivers supporting TDLS with external setup (WIPHY_FLAG_SUPPORTS_TDLS
 * and WIPHY_FLAG_TDLS_EXTERNAL_SETUP), the station lifetime is as follows:
 *  - a setup station entry is added, not yet authorized, without any rate
 *    or capability information, this just exists to avoid race conditions
 *  - when the TDLS setup is done, a single NL80211_CMD_SET_STATION is valid
 *    to add rate and capability information to the station and at the same
 *    time mark it authorized.
 *  - %NL80211_TDLS_ENABLE_LINK is then used
 *  - after this, the only valid operation is to remove it by tearing down
 *    the TDLS link (%NL80211_TDLS_DISABLE_LINK)
 *
 * TODO: need more info for other interface types
 */

/**
 * DOC: Frame transmission/registration support
 *
 * Frame transmission and registration support exists to allow userspace
 * management entities such as wpa_supplicant react to management frames
 * that are not being handled by the kernel. This includes, for example,
 * certain classes of action frames that cannot be handled in the kernel
 * for various reasons.
 *
 * Frame registration is done on a per-interface basis and registrations
 * cannot be removed other than by closing the socket. It is possible to
 * specify a registration filter to register, for example, only for a
 * certain type of action frame. In particular with action frames, those
 * that userspace registers for will not be returned as unhandled by the
 * driver, so that the registered application has to take responsibility
 * for doing that.
 *
 * The type of frame that can be registered for is also dependent on the
 * driver and interface type. The frame types are advertised in wiphy
 * attributes so applications know what to expect.
 *
 * NOTE: When an interface changes type while registrations are active,
 *       these registrations are ignored until the interface type is
 *       changed again. This means that changing the interface type can
 *       lead to a situation that couldn't otherwise be produced, but
 *       any such registrations will be dormant in the sense that they
 *       will not be serviced, i.e. they will not receive any frames.
 *
 * Frame transmission allows userspace to send for example the required
 * responses to action frames. It is subject to some sanity checking,
 * but many frames can be transmitted. When a frame was transmitted, its
 * status is indicated to the sending socket.
 *
 * For more technical details, see the corresponding command descriptions
 * below.
 */

/**
 * DOC: Virtual interface / concurrency capabilities
 *
 * Some devices are able to operate with virtual MACs, they can have
 * more than one virtual interface. The capability handling for this
 * is a bit complex though, as there may be a number of restrictions
 * on the types of concurrency that are supported.
 *
 * To start with, each device supports the interface types listed in
 * the %NL80211_ATTR_SUPPORTED_IFTYPES attribute, but by listing the
 * types there no concurrency is implied.
 *
 * Once concurrency is desired, more attributes must be observed:
 * To start with, since some interface types are purely managed in
 * software, like the AP-VLAN type in mac80211 for example, there's
 * an additional list of these, they can be added at any time and
 * are only restricted by some semantic restrictions (e.g. AP-VLAN
 * cannot be added without a corresponding AP interface). This list
 * is exported in the %NL80211_ATTR_SOFTWARE_IFTYPES attribute.
 *
 * Further, the list of supported combinations is exported. This is
 * in the %NL80211_ATTR_INTERFACE_COMBINATIONS attribute. Basically,
 * it exports a list of "groups", and at any point in time the
 * interfaces that are currently active must fall into any one of
 * the advertised groups. Within each group, there are restrictions
 * on the number of interfaces of different types that are supported
 * and also the number of different channels, along with potentially
 * some other restrictions. See &enum nl80211_if_combination_attrs.
 *
 * All together, these attributes define the concurrency of virtual
 * interfaces that a given device supports.
 */

/**
 * DOC: packet coalesce support
 *
 * In most cases, host that receives IPv4 and IPv6 multicast/broadcast
 * packets does not do anything with these packets. Therefore the
 * reception of these unwanted packets causes unnecessary processing
 * and power consumption.
 *
 * Packet coalesce feature helps to reduce number of received interrupts
 * to host by buffering these packets in firmware/hardware for some
 * predefined time. Received interrupt will be generated when one of the
 * following events occur.
 * a) Expiration of hardware timer whose expiration time is set to maximum
 * coalescing delay of matching coalesce rule.
 * b) Coalescing buffer in hardware reaches it's limit.
 * c) Packet doesn't match any of the configured coalesce rules.
 *
 * User needs to configure following parameters for creating a coalesce
 * rule.
 * a) Maximum coalescing delay
 * b) List of packet patterns which needs to be matched
 * c) Condition for coalescence. pattern 'match' or 'no match'
 * Multiple such rules can be created.
 */

/**
 * DOC: WPA/WPA2 EAPOL handshake offload
 *
 * By setting @NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK flag drivers
 * can indicate they support offloading EAPOL handshakes for WPA/WPA2
 * preshared key authentication. In %NL80211_CMD_CONNECT the preshared
 * key should be specified using %NL80211_ATTR_PMK. Drivers supporting
 * this offload may reject the %NL80211_CMD_CONNECT when no preshared
 * key material is provided, for example when that driver does not
 * support setting the temporal keys through %CMD_NEW_KEY.
 *
 * Similarly @NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X flag can be
 * set by drivers indicating offload support of the PTK/GTK EAPOL
 * handshakes during 802.1X authentication. In order to use the offload
 * the %NL80211_CMD_CONNECT should have %NL80211_ATTR_WANT_1X_4WAY_HS
 * attribute flag. Drivers supporting this offload may reject the
 * %NL80211_CMD_CONNECT when the attribute flag is not present.
 *
 * For 802.1X the PMK or PMK-R0 are set by providing %NL80211_ATTR_PMK
 * using %NL80211_CMD_SET_PMK. For offloaded FT support also
 * %NL80211_ATTR_PMKR0_NAME must be provided.
 */

/**
 * DOC: FILS shared key authentication offload
 *
 * FILS shared key authentication offload can be advertized by drivers by
 * setting @NL80211_EXT_FEATURE_FILS_SK_OFFLOAD flag. The drivers that support
 * FILS shared key authentication offload should be able to construct the
 * authentication and association frames for FILS shared key authentication and
 * eventually do a key derivation as per IEEE 802.11ai. The below additional
 * parameters should be given to driver in %NL80211_CMD_CONNECT.
 *    %NL80211_ATTR_FILS_ERP_USERNAME - used to construct keyname_nai
 *    %NL80211_ATTR_FILS_ERP_REALM - used to construct keyname_nai
 *    %NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM - used to construct erp message
 *    %NL80211_ATTR_FILS_ERP_RRK - used to generate the rIK and rMSK
 * rIK should be used to generate an authentication tag on the ERP message and
 * rMSK should be used to derive a PMKSA.
 * rIK, rMSK should be generated and keyname_nai, sequence number should be used
 * as specified in IETF RFC 6696.
 *
 * When FILS shared key authentication is completed, driver needs to provide the
 * below additional parameters to userspace.
 *    %NL80211_ATTR_FILS_KEK - used for key renewal
 *    %NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM - used in further EAP-RP exchanges
 *    %NL80211_ATTR_PMKID - used to identify the PMKSA used/generated
 *    %Nl80211_ATTR_PMK - used to update PMKSA cache in userspace
 * The PMKSA can be maintained in userspace persistently so that it can be used
 * later after reboots or wifi turn off/on also.
 *
 * %NL80211_ATTR_FILS_CACHE_ID is the cache identifier advertized by a FILS
 * capable AP supporting PMK caching. It specifies the scope within which the
 * PMKSAs are cached in an ESS. %NL80211_CMD_SET_PMKSA and
 * %NL80211_CMD_DEL_PMKSA are enhanced to allow support for PMKSA caching based
 * on FILS cache identifier. Additionally %NL80211_ATTR_PMK is used with
 * %NL80211_SET_PMKSA to specify the PMK corresponding to a PMKSA for driver to
 * use in a FILS shared key connection with PMKSA caching.
 */





#define NL80211_MAX_SUPP_RATES            32
#define NL80211_MAX_SUPP_HT_RATES        77
#define NL80211_MAX_SUPP_REG_RULES        64
#define NL80211_TKIP_DATA_OFFSET_ENCR_KEY    0
#define NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY    16
#define NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY    24
#define NL80211_HT_CAPABILITY_LEN        26
#define NL80211_VHT_CAPABILITY_LEN        12

#define NL80211_MAX_NR_CIPHER_SUITES        5
#define NL80211_MAX_NR_AKM_SUITES        2

#define NL80211_MIN_REMAIN_ON_CHANNEL_TIME    10

/* default RSSI threshold for scan results if none specified. */
#define NL80211_SCAN_RSSI_THOLD_OFF        -300

#define NL80211_CQM_TXE_MAX_INTVL        1800

/**
 * enum nl80211_iftype - (virtual) interface types
 *
 * @NL80211_IFTYPE_UNSPECIFIED: unspecified type, driver decides
 * @NL80211_IFTYPE_ADHOC: independent BSS member
 * @NL80211_IFTYPE_STATION: managed BSS member
 * @NL80211_IFTYPE_AP: access point
 * @NL80211_IFTYPE_AP_VLAN: VLAN interface for access points; VLAN interfaces
 *    are a bit special in that they must always be tied to a pre-existing
 *    AP type interface.
 * @NL80211_IFTYPE_WDS: wireless distribution interface
 * @NL80211_IFTYPE_MONITOR: monitor interface receiving all frames
 * @NL80211_IFTYPE_MESH_POINT: mesh point
 * @NL80211_IFTYPE_P2P_CLIENT: P2P client
 * @NL80211_IFTYPE_P2P_GO: P2P group owner
 * @NL80211_IFTYPE_P2P_DEVICE: P2P device interface type, this is not a netdev
 *    and therefore can't be created in the normal ways, use the
 *    %NL80211_CMD_START_P2P_DEVICE and %NL80211_CMD_STOP_P2P_DEVICE
 *    commands to create and destroy one
 * @NL80211_IF_TYPE_OCB: Outside Context of a BSS
 *    This mode corresponds to the MIB variable dot11OCBActivated=true
 * @NL80211_IFTYPE_NAN: NAN device interface type (not a netdev)
 * @NL80211_IFTYPE_MAX: highest interface type number currently defined
 * @NUM_NL80211_IFTYPES: number of defined interface types
 *
 * These values are used with the %NL80211_ATTR_IFTYPE
 * to set the type of an interface.
 *
 */
enum nl80211_iftype {
    NL80211_IFTYPE_UNSPECIFIED,
    NL80211_IFTYPE_ADHOC,
    NL80211_IFTYPE_STATION,
    NL80211_IFTYPE_AP,
    NL80211_IFTYPE_AP_VLAN,
    NL80211_IFTYPE_WDS,
    NL80211_IFTYPE_MONITOR,
    NL80211_IFTYPE_MESH_POINT,
    NL80211_IFTYPE_P2P_CLIENT,
    NL80211_IFTYPE_P2P_GO,
    NL80211_IFTYPE_P2P_DEVICE,
    NL80211_IFTYPE_OCB,
    NL80211_IFTYPE_NAN,
    
    /* keep last */
    NUM_NL80211_IFTYPES,
    NL80211_IFTYPE_MAX = NUM_NL80211_IFTYPES - 1
};

/**
 * enum nl80211_sta_p2p_ps_status - station support of P2P PS
 *
 * @NL80211_P2P_PS_UNSUPPORTED: station doesn't support P2P PS mechanism
 * @@NL80211_P2P_PS_SUPPORTED: station supports P2P PS mechanism
 * @NUM_NL80211_P2P_PS_STATUS: number of values
 */
enum nl80211_sta_p2p_ps_status {
    NL80211_P2P_PS_UNSUPPORTED = 0,
    NL80211_P2P_PS_SUPPORTED,
    
    NUM_NL80211_P2P_PS_STATUS,
};

#define NL80211_STA_FLAG_MAX_OLD_API    NL80211_STA_FLAG_TDLS_PEER



/**
 * enum nl80211_channel_type - channel type
 * @NL80211_CHAN_NO_HT: 20 MHz, non-HT channel
 * @NL80211_CHAN_HT20: 20 MHz HT channel
 * @NL80211_CHAN_HT40MINUS: HT40 channel, secondary channel
 *    below the control channel
 * @NL80211_CHAN_HT40PLUS: HT40 channel, secondary channel
 *    above the control channel
 */
enum nl80211_channel_type {
    NL80211_CHAN_NO_HT,
    NL80211_CHAN_HT20,
    NL80211_CHAN_HT40MINUS,
    NL80211_CHAN_HT40PLUS
};

/**
 * enum nl80211_chan_width - channel width definitions
 *
 * These values are used with the %NL80211_ATTR_CHANNEL_WIDTH
 * attribute.
 *
 * @NL80211_CHAN_WIDTH_20_NOHT: 20 MHz, non-HT channel
 * @NL80211_CHAN_WIDTH_20: 20 MHz HT channel
 * @NL80211_CHAN_WIDTH_40: 40 MHz channel, the %NL80211_ATTR_CENTER_FREQ1
 *    attribute must be provided as well
 * @NL80211_CHAN_WIDTH_80: 80 MHz channel, the %NL80211_ATTR_CENTER_FREQ1
 *    attribute must be provided as well
 * @NL80211_CHAN_WIDTH_80P80: 80+80 MHz channel, the %NL80211_ATTR_CENTER_FREQ1
 *    and %NL80211_ATTR_CENTER_FREQ2 attributes must be provided as well
 * @NL80211_CHAN_WIDTH_160: 160 MHz channel, the %NL80211_ATTR_CENTER_FREQ1
 *    attribute must be provided as well
 * @NL80211_CHAN_WIDTH_5: 5 MHz OFDM channel
 * @NL80211_CHAN_WIDTH_10: 10 MHz OFDM channel
 */
enum nl80211_chan_width {
    NL80211_CHAN_WIDTH_20_NOHT,
    NL80211_CHAN_WIDTH_20,
    NL80211_CHAN_WIDTH_40,
    NL80211_CHAN_WIDTH_80,
    NL80211_CHAN_WIDTH_80P80,
    NL80211_CHAN_WIDTH_160,
    NL80211_CHAN_WIDTH_5,
    NL80211_CHAN_WIDTH_10,
};

/**
 * enum nl80211_bss_scan_width - control channel width for a BSS
 *
 * These values are used with the %NL80211_BSS_CHAN_WIDTH attribute.
 *
 * @NL80211_BSS_CHAN_WIDTH_20: control channel is 20 MHz wide or compatible
 * @NL80211_BSS_CHAN_WIDTH_10: control channel is 10 MHz wide
 * @NL80211_BSS_CHAN_WIDTH_5: control channel is 5 MHz wide
 */
enum nl80211_bss_scan_width {
    NL80211_BSS_CHAN_WIDTH_20,
    NL80211_BSS_CHAN_WIDTH_10,
    NL80211_BSS_CHAN_WIDTH_5,
};



/**
 * enum nl80211_band - Frequency band
 * @NL80211_BAND_2GHZ: 2.4 GHz ISM band
 * @NL80211_BAND_5GHZ: around 5 GHz band (4.9 - 5.7 GHz)
 * @NL80211_BAND_60GHZ: around 60 GHz band (58.32 - 64.80 GHz)
 * @NUM_NL80211_BANDS: number of bands, avoid using this in userspace
 *    since newer kernel versions may support more bands
 */
enum nl80211_band {
    NL80211_BAND_2GHZ,
    NL80211_BAND_5GHZ,
    NL80211_BAND_60GHZ,
    
    NUM_NL80211_BANDS,
};

/**
 * enum nl80211_ps_state - powersave state
 * @NL80211_PS_DISABLED: powersave is disabled
 * @NL80211_PS_ENABLED: powersave is enabled
 */
enum nl80211_ps_state {
    NL80211_PS_DISABLED,
    NL80211_PS_ENABLED,
};

/**
 * enum nl80211_tx_power_setting - TX power adjustment
 * @NL80211_TX_POWER_AUTOMATIC: automatically determine transmit power
 * @NL80211_TX_POWER_LIMITED: limit TX power by the mBm parameter
 * @NL80211_TX_POWER_FIXED: fix TX power to the mBm parameter
 */
enum nl80211_tx_power_setting {
    NL80211_TX_POWER_AUTOMATIC,
    NL80211_TX_POWER_LIMITED,
    NL80211_TX_POWER_FIXED,
};



#define NL80211_KCK_LEN            16
#define NL80211_KEK_LEN            16
#define NL80211_REPLAY_CTR_LEN        8

/**
 * enum nl80211_rekey_data - attributes for GTK rekey offload
 * @__NL80211_REKEY_DATA_INVALID: invalid number for nested attributes
 * @NL80211_REKEY_DATA_KEK: key encryption key (binary)
 * @NL80211_REKEY_DATA_KCK: key confirmation key (binary)
 * @NL80211_REKEY_DATA_REPLAY_CTR: replay counter (binary)
 * @NUM_NL80211_REKEY_DATA: number of rekey attributes (internal)
 * @MAX_NL80211_REKEY_DATA: highest rekey attribute (internal)
 */
enum nl80211_rekey_data {
    __NL80211_REKEY_DATA_INVALID,
    NL80211_REKEY_DATA_KEK,
    NL80211_REKEY_DATA_KCK,
    NL80211_REKEY_DATA_REPLAY_CTR,
    
    /* keep last */
    NUM_NL80211_REKEY_DATA,
    MAX_NL80211_REKEY_DATA = NUM_NL80211_REKEY_DATA - 1
};




/**
 * enum nl80211_feature_flags - device/driver features
 * @NL80211_FEATURE_SK_TX_STATUS: This driver supports reflecting back
 *    TX status to the socket error queue when requested with the
 *    socket option.
 * @NL80211_FEATURE_HT_IBSS: This driver supports IBSS with HT datarates.
 * @NL80211_FEATURE_INACTIVITY_TIMER: This driver takes care of freeing up
 *    the connected inactive stations in AP mode.
 * @NL80211_FEATURE_CELL_BASE_REG_HINTS: This driver has been tested
 *    to work properly to suppport receiving regulatory hints from
 *    cellular base stations.
 * @NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL: (no longer available, only
 *    here to reserve the value for API/ABI compatibility)
 * @NL80211_FEATURE_SAE: This driver supports simultaneous authentication of
 *    equals (SAE) with user space SME (NL80211_CMD_AUTHENTICATE) in station
 *    mode
 * @NL80211_FEATURE_LOW_PRIORITY_SCAN: This driver supports low priority scan
 * @NL80211_FEATURE_SCAN_FLUSH: Scan flush is supported
 * @NL80211_FEATURE_AP_SCAN: Support scanning using an AP vif
 * @NL80211_FEATURE_VIF_TXPOWER: The driver supports per-vif TX power setting
 * @NL80211_FEATURE_NEED_OBSS_SCAN: The driver expects userspace to perform
 *    OBSS scans and generate 20/40 BSS coex reports. This flag is used only
 *    for drivers implementing the CONNECT API, for AUTH/ASSOC it is implied.
 * @NL80211_FEATURE_P2P_GO_CTWIN: P2P GO implementation supports CT Window
 *    setting
 * @NL80211_FEATURE_P2P_GO_OPPPS: P2P GO implementation supports opportunistic
 *    powersave
 * @NL80211_FEATURE_FULL_AP_CLIENT_STATE: The driver supports full state
 *    transitions for AP clients. Without this flag (and if the driver
 *    doesn't have the AP SME in the device) the driver supports adding
 *    stations only when they're associated and adds them in associated
 *    state (to later be transitioned into authorized), with this flag
 *    they should be added before even sending the authentication reply
 *    and then transitioned into authenticated, associated and authorized
 *    states using station flags.
 *    Note that even for drivers that support this, the default is to add
 *    stations in authenticated/associated state, so to add unauthenticated
 *    stations the authenticated/associated bits have to be set in the mask.
 * @NL80211_FEATURE_ADVERTISE_CHAN_LIMITS: cfg80211 advertises channel limits
 *    (HT40, VHT 80/160 MHz) if this flag is set
 * @NL80211_FEATURE_USERSPACE_MPM: This driver supports a userspace Mesh
 *    Peering Management entity which may be implemented by registering for
 *    beacons or NL80211_CMD_NEW_PEER_CANDIDATE events. The mesh beacon is
 *    still generated by the driver.
 * @NL80211_FEATURE_ACTIVE_MONITOR: This driver supports an active monitor
 *    interface. An active monitor interface behaves like a normal monitor
 *    interface, but gets added to the driver. It ensures that incoming
 *    unicast packets directed at the configured interface address get ACKed.
 * @NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE: This driver supports dynamic
 *    channel bandwidth change (e.g., HT 20 <-> 40 MHz channel) during the
 *    lifetime of a BSS.
 * @NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES: This device adds a DS Parameter
 *    Set IE to probe requests.
 * @NL80211_FEATURE_WFA_TPC_IE_IN_PROBES: This device adds a WFA TPC Report IE
 *    to probe requests.
 * @NL80211_FEATURE_QUIET: This device, in client mode, supports Quiet Period
 *    requests sent to it by an AP.
 * @NL80211_FEATURE_TX_POWER_INSERTION: This device is capable of inserting the
 *    current tx power value into the TPC Report IE in the spectrum
 *    management TPC Report action frame, and in the Radio Measurement Link
 *    Measurement Report action frame.
 * @NL80211_FEATURE_ACKTO_ESTIMATION: This driver supports dynamic ACK timeout
 *    estimation (dynack). %NL80211_ATTR_WIPHY_DYN_ACK flag attribute is used
 *    to enable dynack.
 * @NL80211_FEATURE_STATIC_SMPS: Device supports static spatial
 *    multiplexing powersave, ie. can turn off all but one chain
 *    even on HT connections that should be using more chains.
 * @NL80211_FEATURE_DYNAMIC_SMPS: Device supports dynamic spatial
 *    multiplexing powersave, ie. can turn off all but one chain
 *    and then wake the rest up as required after, for example,
 *    rts/cts handshake.
 * @NL80211_FEATURE_SUPPORTS_WMM_ADMISSION: the device supports setting up WMM
 *    TSPEC sessions (TID aka TSID 0-7) with the %NL80211_CMD_ADD_TX_TS
 *    command. Standard IEEE 802.11 TSPEC setup is not yet supported, it
 *    needs to be able to handle Block-Ack agreements and other things.
 * @NL80211_FEATURE_MAC_ON_CREATE: Device supports configuring
 *    the vif's MAC address upon creation.
 *    See 'macaddr' field in the vif_params (cfg80211.h).
 * @NL80211_FEATURE_TDLS_CHANNEL_SWITCH: Driver supports channel switching when
 *    operating as a TDLS peer.
 * @NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR: This device/driver supports using a
 *    random MAC address during scan (if the device is unassociated); the
 *    %NL80211_SCAN_FLAG_RANDOM_ADDR flag may be set for scans and the MAC
 *    address mask/value will be used.
 * @NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR: This device/driver supports
 *    using a random MAC address for every scan iteration during scheduled
 *    scan (while not associated), the %NL80211_SCAN_FLAG_RANDOM_ADDR may
 *    be set for scheduled scan and the MAC address mask/value will be used.
 * @NL80211_FEATURE_ND_RANDOM_MAC_ADDR: This device/driver supports using a
 *    random MAC address for every scan iteration during "net detect", i.e.
 *    scan in unassociated WoWLAN, the %NL80211_SCAN_FLAG_RANDOM_ADDR may
 *    be set for scheduled scan and the MAC address mask/value will be used.
 */
enum nl80211_feature_flags {
    NL80211_FEATURE_SK_TX_STATUS            = 1 << 0,
    NL80211_FEATURE_HT_IBSS                = 1 << 1,
    NL80211_FEATURE_INACTIVITY_TIMER        = 1 << 2,
    NL80211_FEATURE_CELL_BASE_REG_HINTS        = 1 << 3,
    NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL    = 1 << 4,
    NL80211_FEATURE_SAE                = 1 << 5,
    NL80211_FEATURE_LOW_PRIORITY_SCAN        = 1 << 6,
    NL80211_FEATURE_SCAN_FLUSH            = 1 << 7,
    NL80211_FEATURE_AP_SCAN                = 1 << 8,
    NL80211_FEATURE_VIF_TXPOWER            = 1 << 9,
    NL80211_FEATURE_NEED_OBSS_SCAN            = 1 << 10,
    NL80211_FEATURE_P2P_GO_CTWIN            = 1 << 11,
    NL80211_FEATURE_P2P_GO_OPPPS            = 1 << 12,
    /* bit 13 is reserved */
    NL80211_FEATURE_ADVERTISE_CHAN_LIMITS        = 1 << 14,
    NL80211_FEATURE_FULL_AP_CLIENT_STATE        = 1 << 15,
    NL80211_FEATURE_USERSPACE_MPM            = 1 << 16,
    NL80211_FEATURE_ACTIVE_MONITOR            = 1 << 17,
    NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE    = 1 << 18,
    NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES    = 1 << 19,
    NL80211_FEATURE_WFA_TPC_IE_IN_PROBES        = 1 << 20,
    NL80211_FEATURE_QUIET                = 1 << 21,
    NL80211_FEATURE_TX_POWER_INSERTION        = 1 << 22,
    NL80211_FEATURE_ACKTO_ESTIMATION        = 1 << 23,
    NL80211_FEATURE_STATIC_SMPS            = 1 << 24,
    NL80211_FEATURE_DYNAMIC_SMPS            = 1 << 25,
    NL80211_FEATURE_SUPPORTS_WMM_ADMISSION        = 1 << 26,
    NL80211_FEATURE_MAC_ON_CREATE            = 1 << 27,
    NL80211_FEATURE_TDLS_CHANNEL_SWITCH        = 1 << 28,
    NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR        = 1 << 29,
    NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR    = 1 << 30,
    NL80211_FEATURE_ND_RANDOM_MAC_ADDR        = 1 << 31,
};

/**
 * enum nl80211_ext_feature_index - bit index of extended features.
 * @NL80211_EXT_FEATURE_VHT_IBSS: This driver supports IBSS with VHT datarates.
 * @NL80211_EXT_FEATURE_RRM: This driver supports RRM. When featured, user can
 *    can request to use RRM (see %NL80211_ATTR_USE_RRM) with
 *    %NL80211_CMD_ASSOCIATE and %NL80211_CMD_CONNECT requests, which will set
 *    the ASSOC_REQ_USE_RRM flag in the association request even if
 *    NL80211_FEATURE_QUIET is not advertized.
 * @NL80211_EXT_FEATURE_MU_MIMO_AIR_SNIFFER: This device supports MU-MIMO air
 *    sniffer which means that it can be configured to hear packets from
 *    certain groups which can be configured by the
 *    %NL80211_ATTR_MU_MIMO_GROUP_DATA attribute,
 *    or can be configured to follow a station by configuring the
 *    %NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR attribute.
 * @NL80211_EXT_FEATURE_SCAN_START_TIME: This driver includes the actual
 *    time the scan started in scan results event. The time is the TSF of
 *    the BSS that the interface that requested the scan is connected to
 *    (if available).
 * @NL80211_EXT_FEATURE_BSS_PARENT_TSF: Per BSS, this driver reports the
 *    time the last beacon/probe was received. The time is the TSF of the
 *    BSS that the interface that requested the scan is connected to
 *    (if available).
 * @NL80211_EXT_FEATURE_SET_SCAN_DWELL: This driver supports configuration of
 *    channel dwell time.
 * @NL80211_EXT_FEATURE_BEACON_RATE_LEGACY: Driver supports beacon rate
 *    configuration (AP/mesh), supporting a legacy (non HT/VHT) rate.
 * @NL80211_EXT_FEATURE_BEACON_RATE_HT: Driver supports beacon rate
 *    configuration (AP/mesh) with HT rates.
 * @NL80211_EXT_FEATURE_BEACON_RATE_VHT: Driver supports beacon rate
 *    configuration (AP/mesh) with VHT rates.
 * @NL80211_EXT_FEATURE_FILS_STA: This driver supports Fast Initial Link Setup
 *    with user space SME (NL80211_CMD_AUTHENTICATE) in station mode.
 * @NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA: This driver supports randomized TA
 *    in @NL80211_CMD_FRAME while not associated.
 * @NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA_CONNECTED: This driver supports
 *    randomized TA in @NL80211_CMD_FRAME while associated.
 * @NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI: The driver supports sched_scan
 *    for reporting BSSs with better RSSI than the current connected BSS
 *    (%NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI).
 * @NL80211_EXT_FEATURE_CQM_RSSI_LIST: With this driver the
 *    %NL80211_ATTR_CQM_RSSI_THOLD attribute accepts a list of zero or more
 *    RSSI threshold values to monitor rather than exactly one threshold.
 * @NL80211_EXT_FEATURE_FILS_SK_OFFLOAD: Driver SME supports FILS shared key
 *    authentication with %NL80211_CMD_CONNECT.
 * @NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK: Device wants to do 4-way
 *    handshake with PSK in station mode (PSK is passed as part of the connect
 *    and associate commands), doing it in the host might not be supported.
 * @NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X: Device wants to do doing 4-way
 *    handshake with 802.1X in station mode (will pass EAP frames to the host
 *    and accept the set_pmk/del_pmk commands), doing it in the host might not
 *    be supported.
 *
 * @NUM_NL80211_EXT_FEATURES: number of extended features.
 * @MAX_NL80211_EXT_FEATURES: highest extended feature index.
 */
enum nl80211_ext_feature_index {
    NL80211_EXT_FEATURE_VHT_IBSS,
    NL80211_EXT_FEATURE_RRM,
    NL80211_EXT_FEATURE_MU_MIMO_AIR_SNIFFER,
    NL80211_EXT_FEATURE_SCAN_START_TIME,
    NL80211_EXT_FEATURE_BSS_PARENT_TSF,
    NL80211_EXT_FEATURE_SET_SCAN_DWELL,
    NL80211_EXT_FEATURE_BEACON_RATE_LEGACY,
    NL80211_EXT_FEATURE_BEACON_RATE_HT,
    NL80211_EXT_FEATURE_BEACON_RATE_VHT,
    NL80211_EXT_FEATURE_FILS_STA,
    NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA,
    NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA_CONNECTED,
    NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI,
    NL80211_EXT_FEATURE_CQM_RSSI_LIST,
    NL80211_EXT_FEATURE_FILS_SK_OFFLOAD,
    NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK,
    NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X,
    
    /* add new features before the definition below */
    NUM_NL80211_EXT_FEATURES,
    MAX_NL80211_EXT_FEATURES = NUM_NL80211_EXT_FEATURES - 1
};




#endif /* __LINUX_NL80211_H */

