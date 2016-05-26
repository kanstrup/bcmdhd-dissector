-- Copyright (C) 2014 Pontus Fuchs (pontus.fuchs@gmail.com)
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

--local bit = require("bit")
local bcmioctlout = Proto("bcmioctlout", "BCM WLAN dissector- IOCTLout")
local bcmioctlin = Proto("bcmioctlin", "BCM WLAN dissector- IOCTLin")
local f = bcmioctlout.fields
local cdc_ioctl_cmd_strings = {}
local band_strings = {}
local bss_type_strings = {}
local scan_type_strings = {}
local p2p_state_strings = {}
local event_msgs_strings = {}
local p2p_if_type_strings = {}
local last_get_var = ""

function bcmioctlout.init()
	local udp_table = DissectorTable.get("ethertype")
	local pattern = 0xBC02
	udp_table:add(pattern, bcmioctlout)
end

function bcmioctlin.init()
	local udp_table = DissectorTable.get("ethertype")
	local pattern = 0xBC03
	udp_table:add(pattern, bcmioctlin)
end

function is_int_var(wlc_var)
	local int_vars = {
		"allmulti", "ampdu_hostreorder", "apsta", "arpoe", "arp_ol",
		"assoc_listen", "bcn_timeout", "bcn_timeout", "btc_params",
		"bus:txglomalign", "bw_cap", "ccx_enable", "chanspec",
		"dtim_assoc", "fragthresh", "mimo_bw_cap", "mpc", "ndoe",
		"nmode", "obss_coex", "p2p_dev", "p2p_disc", "pfn",
		"pkt_filter_mode", "qtxpower", "roam_off", "rtsthresh",
		"rxchain", "tdls_enable", "tlv", "toe_ol", "txbf", "vhtmode",
		"wlfc_mode", "wowl", "wowl_activate", "wowl_cap", "wowl_clear",
		"wsec"
	}

	for i,v in pairs(int_vars) do
		if v == wlc_var then
			return true
		end
	end
	return false
end

function is_int_cmd(wlc_cmd)
	local int_cmds = {
		1,   -- GET_VERSION
		2,   -- UP
		3,   -- DOWN
		10,  -- SET_PROMISC
		12,  -- GET_RATE
		20,  -- SET_INFRA
		28,  -- TERMINATED
		29,  -- GET_CHANNEL
		30,  -- SET_CHANNEL
		32,  -- SET_SRL
		34,  -- SET_LRL
		38,  -- SET_RADIO
		46,  -- GET_REGULATORY
		47,  -- SET_REGULATORY
		49,  -- SET_PASSIVE_SCAN
		75,  -- GET_BCNPRD
		76,  -- SET_BCNPRD
		77,  -- GET_DTIMPRD
		78,  -- SET_DTIMPRD
		85,  -- GET_PM
		86,  -- SET_PM
		118, -- SET_AP
		158, -- SET_SCB_TIMEOUT
		185, -- SET_SCAN_CHANNEL_TIME
		187, -- SET_SCAN_UNASSOC_TIME
		258  -- SET_SCAN_PASSIVE_TIME
	}

	for i, cmd in pairs(int_cmds) do
		if cmd == wlc_cmd then
			return true
		end
	end
	return false
end

function parse_chanspec(bcm, buffer, pinfo, tree, use_subtree)
	local n = 0
	local subtree
	if (use_subtree == 1) then
		subtree = tree:add(bcm, buffer(n, 2), "chanspec")
	else
		subtree = tree
	end
	subtree:add_le(f.chanspec_chan, buffer(n, 1)); n = n + 1
	subtree:add_le(f.chanspec_other, buffer(n, 1)); n = n + 1
	return n
end

function parse_ssid(bcm, buffer, pinfo, tree)
	local n = 0
	tree:add_le(f.brcmf_ssid_len, buffer(n, 4)); n = n + 4
	tree:add(f.brcmf_ssid, buffer(n, 32)); n = n + 32
	return n
end

function parse_wl_scan(bcm, buffer, pinfo, tree)
	local n = 0
	n = n + parse_ssid(bcm, buffer(n), pinfo, tree)
	tree:add_le(f.brcmf_bssid, buffer(n, 6)); n = n + 6
	tree:add_le(f.wl_scan_bss_type, buffer(n, 1)); n = n + 1
	tree:add_le(f.wl_scan_scan_type, buffer(n, 1)); n = n + 1
	tree:add_le(f.wl_scan_nprobes, buffer(n, 4)); n = n + 4
	tree:add_le(f.wl_scan_active_time, buffer(n, 4)); n = n + 4
	tree:add_le(f.wl_scan_passive_time, buffer(n, 4)); n = n + 4
	tree:add_le(f.wl_scan_home_time, buffer(n, 4)); n = n + 4
	local channel_num = buffer(n, 2):le_uint()
	tree:add_le(f.wl_scan_channel_num, buffer(n, 4)); n = n + 4
	for i = 1, channel_num do
		n = n + parse_chanspec(bcm, buffer(n), pinfo, tree, 1)
	end
	return n
end

function parse_escan(bcm, buffer, pinfo, tree)
	local n = 0
	tree:add_le(f.escan_version, buffer(n, 4)); n = n + 4
	tree:add_le(f.escan_action, buffer(n, 2)); n = n + 2
	tree:add_le(f.escan_sync_id, buffer(n, 2)); n = n + 2
	n = n + parse_wl_scan(bcm, buffer(n), pinfo, tree)
	return n
end

function parse_event_msgs(buffer, pinfo, tree)
	local n = 0
	for i = 0, 127 do
		local by = math.floor(i / 8)
		local bi = (i % 8)
		local b = buffer(by, 1):uint()

		if (bit.band(b, bit.lshift(1, bi)) > 0) then
			tree:add(f.bcm_var_event_msgs_event, buffer(by, 1), i);
		end

	end
	return 16
end

function bcmioctlin.dissector(inbuffer, pinfo, tree)
	dissector(inbuffer, pinfo, tree, 0)
end

function bcmioctlout.dissector(inbuffer, pinfo, tree)
	dissector(inbuffer, pinfo, tree, 1)
end


function dissector(inbuffer, pinfo, tree, out)
	local n = 0
	local buffer = inbuffer
	pinfo.cols.info = ""

	local cmd = buffer(0, 4):le_uint();

	local bcm = bcmioctlin

	local proto_name = "bcmdhd_ioctl_in"
	pinfo.cols.protocol = "ioctl in"
	if (out == 1) then
		bcm = bcmioctlout
		proto_name = "bcmdhd_ioctl_out"
	pinfo.cols.protocol = "ioctl out"
	end


	local subtree = tree:add(bcm, buffer(), proto_name)
	local header = subtree:add(bcm, buffer(n, 8), "header")

	header:add_le(f.bcm_cdc_ioctl_cmd, buffer(n, 4)); n = n + 4
	header:add_le(f.bcm_cdc_ioctl_len, buffer(n, 4)); n = n + 4
	header:add_le(f.bcm_cdc_ioctl_flags, buffer(n, 4)); n = n + 4
	local status = buffer(n, 4):le_int()
	header:add_le(f.bcm_cdc_ioctl_status, buffer(n, 4)); n = n + 4

	local cmd_str
	if cdc_ioctl_cmd_strings[cmd] ~= nil then
		cmd_str = cdc_ioctl_cmd_strings[cmd]:lower()
	else
		cmd_str = cmd
	end
	pinfo.cols.info:append(cmd_str)

	-- data
	if buffer:len() > n then
		local par = subtree:add(bcm, buffer(n), cmd_str)

		if is_int_cmd(cmd) then
			local value = buffer(n, 4)
			pinfo.cols.info:append(" "..value:le_uint())
			par:add_le(f.value32, value); n = n + 4
			if buffer:len() > n then
				par:add(f.unused, buffer(n)); n = buffer:len()
			end
		elseif (cmd == 23) then
			-- WLC_GET_BSSID
			par:add_le(f.brcmf_bssid, buffer(n, 6)); n = n + 6
		elseif (cmd == 26) then
			-- WLC_SET_SSID
			n = n + parse_ssid(bcm, buffer(n), pinfo, par)
			par:add_le(f.brcmf_bssid, buffer(n, 6)); n = n + 6
			par:add_le(f.WLC_SET_SSID_chanspec_num, buffer(n, 4)); n = n + 4
			n = n + parse_chanspec(bcm, buffer(n), pinfo, par, 0)
		elseif (cmd == 50) then
			-- WLC_SCAN
			n = n + parse_wl_scan(bcm, buffer(n), pinfo, par)
		elseif (cmd == 52) then
			-- WLC_DISASSOC
			par:add_le(f.WLC_DISASSOC_val, buffer(n, 4)); n = n + 4
			par:add_le(f.WLC_DISASSOC_ea, buffer(n, 6)); n = n + 6
		elseif (cmd == 55) then
			-- WLC_SET_ROAM_TRIGGER
			par:add_le(f.WLC_SET_ROAM_TRIGGER_level, buffer(n, 4)); n = n + 4
			par:add_le(f.WLC_SET_ROAM_TRIGGER_band, buffer(n, 4)); n = n + 4
		elseif (cmd == 57) then
			-- WLC_SET_ROAM_DELTA
			par:add_le(f.WLC_SET_ROAM_DELTA_delta, buffer(n, 4)); n = n + 4
			par:add_le(f.WLC_SET_ROAM_DELTA_band, buffer(n, 4)); n = n + 4
		elseif (cmd == 127) then
			-- WLC_GET_RSSI
			par:add_le(f.WLC_GET_RSSI_val, buffer(n, 4)); n = n + 4
			par:add_le(f.WLC_GET_RSSI_ea, buffer(n, 6)); n = n + 6
		elseif (cmd == 136) then
			-- GET_BSS_INFO
			n = n + 4 -- unknown
			par:add_le(f.GET_BSS_INFO_version, buffer(n, 4)); n = n + 4
			par:add_le(f.GET_BSS_INFO_length, buffer(n, 4)); n = n + 4
			par:add_le(f.brcmf_bssid, buffer(n, 6)); n = n + 6
			par:add_le(f.GET_BSS_INFO_beacon_period, buffer(n, 2)); n = n + 2
			par:add_le(f.GET_BSS_INFO_capability, buffer(n, 2)); n = n + 2
			par:add_le(f.GET_BSS_INFO_SSID_len, buffer(n, 1)); n = n + 1
			par:add_le(f.GET_BSS_INFO_SSID, buffer(n, 32)); n = n + 32
			n = n + 1 -- padding in struct
			par:add_le(f.GET_BSS_INFO_rateset_count, buffer(n, 4)); n = n + 4
			par:add_le(f.GET_BSS_INFO_rateset_rates, buffer(n, 16)); n = n + 16
			n = n + parse_chanspec(bcm, buffer(n), pinfo, par, 1)
			par:add_le(f.GET_BSS_INFO_atim_window, buffer(n, 2)); n = n + 2
			par:add_le(f.GET_BSS_INFO_dtim_period, buffer(n, 1)); n = n + 1
			n = n + 1 -- padding in struct
			par:add_le(f.GET_BSS_INFO_RSSI, buffer(n, 2)); n = n + 2
			par:add_le(f.GET_BSS_INFO_phy_noise, buffer(n, 1)); n = n + 1
			par:add_le(f.GET_BSS_INFO_n_cap, buffer(n, 1)); n = n + 1
			n = n + 2 -- padding in struct
			par:add_le(f.GET_BSS_INFO_nbss_cap, buffer(n, 4)); n = n + 4
			par:add_le(f.GET_BSS_INFO_ctl_ch, buffer(n, 1)); n = n + 1
			n = n + 3 -- padding in struct
			par:add_le(f.GET_BSS_INFO_reserved32, buffer(n, 4)); n = n + 4
			par:add_le(f.GET_BSS_INFO_flags, buffer(n, 1)); n = n + 1
			par:add_le(f.GET_BSS_INFO_reserved, buffer(n, 3)); n = n + 3
			par:add_le(f.GET_BSS_INFO_basic_mcs, buffer(n, 16)); n = n + 16
			par:add_le(f.GET_BSS_INFO_ie_offset, buffer(n, 2)); n = n + 2
			n = n + 2 -- padding in struct
			par:add_le(f.GET_BSS_INFO_ie_length, buffer(n, 4)); n = n + 4
			par:add_le(f.GET_BSS_INFO_SNR, buffer(n, 2)); n = n + 2
		elseif (cmd == 217) then
			-- WLC_GET_VALID_CHANNELS
			local count = buffer(n, 4):le_uint()
			par:add_le(f.WLC_GET_VALID_CHANNELS_count, buffer(n, 4)); n = n + 4
			for i = 1, count do
				par:add_le(f.WLC_GET_VALID_CHANNELS_channel, buffer(n, 4)); n = n + 4
			end
		elseif (cmd == 262 and out == 1) then
			-- WLC_GET_VAR
			last_get_var = buffer(n):stringz()
			pinfo.cols.info:append(" "..buffer(n):stringz())
			par:add(f.bcm_var_name, buffer(n)); n = n + buffer(n):stringz():len() + 1
			if buffer:len() > n then
				par:add(f.unused, buffer(n)); n = buffer:len()
			end
		elseif (cmd == 262 and out == 0) then
			pinfo.cols.info:append(" <reply data>")
			if last_get_var == "event_msgs" then
				n = n + parse_event_msgs(buffer(n), pinfo, par)
			end
		elseif (cmd == 263 and out == 1) then
			-- WLC_SET_VAR
			local parsed = false
			local var_str = buffer(n):stringz()
			pinfo.cols.info:append(" "..var_str)
			par:add(f.bcm_var_name,  buffer(n)); n = n + var_str:len() + 1

			if is_int_var(var_str) then
				local value = buffer(n, 4)
				pinfo.cols.info:append(" "..value:le_uint())
				par:add_le(f.value32, value); n = n + 4
				parsed = true
			elseif var_str == "arp_hostip" then
				pinfo.cols.info:append(" "..tostring(buffer(n, 4):ipv4()))
				par:add(f.bcm_var_arp_hostip, buffer(n, 4)); n = n + 4
				parsed = true
			elseif var_str == "cur_etheraddr" then
				par:add_le(f.bcm_var_cur_etheraddr, buffer(n, 6)); n = n + 6
				parsed = true
			elseif var_str == "mcast_list" then
				local count = buffer(n, 4):le_uint()
				par:add_le(f.bcm_var_mcast_list_count, buffer(n, 4)); n = n + 4
				for i = 1, count do
					par:add_le(f.bcm_var_mcast_list_addr, buffer(n, 6)); n = n + 6
				end
				parsed = true
			elseif var_str == "escan" then
				n = n + parse_escan(bcm, buffer(n), pinfo, par)
			elseif var_str == "bsscfg:p2p_scan" then
				-- p2p_scan
				par:add_le(f.brcmf_bsscfgidx, buffer(n, 4)); n = n + 4
				local type = buffer(n, 1):le_uint()
				par:add_le(f.bcm_var_p2p_scan_type, buffer(n, 1)); n = n + 1
				par:add_le(f.bcm_var_p2p_scan_reserved, buffer(n, 3)); n = n + 3
				if (type == 0x45) then -- 'E' = escan
					n = n + parse_escan(bcm, buffer(n), pinfo, par)
				end
				parsed = true
			elseif var_str == "bsscfg:p2p_state" then
				par:add_le(f.brcmf_bsscfgidx, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_p2p_state_state, buffer(n, 1)); n = n + 1
				n = n + 1 -- unused padding in struct
				n = n + parse_chanspec(bcm, buffer(n), pinfo, par, 0)
				par:add_le(f.bcm_var_p2p_state_dwell, buffer(n, 2)); n = n + 2
				parsed = true
			elseif var_str == "event_msgs" then
				n = n + parse_event_msgs(buffer(n), pinfo, par)
				parsed = true
			elseif var_str == "p2p_ifadd" then
				par:add_le(f.bcm_var_p2p_ifadd_addr, buffer(n, 6)); n = n + 6
				par:add_le(f.bcm_var_p2p_ifadd_type, buffer(n, 1)); n = n + 1
				n = n + parse_chanspec(bcm, buffer(n), pinfo, par)
				parsed = true
			elseif var_str == "p2p_ifdel" then
				par:add_le(f.bcm_var_p2p_ifdel_addr, buffer(n, 6)); n = n + 6
				parsed = true
			elseif var_str == "join" then
				n = n + parse_ssid(bcm, buffer(n), pinfo, par)
				par:add_le(f.bcm_var_join_scan_type, buffer(n, 1)); n = n + 1
				n = n + 3 -- padding in struct
				par:add_le(f.bcm_var_join_nprobes, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_join_active_time, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_join_passive_time, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_join_home_time, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_join_bssid, buffer(n, 6)); n = n + 6
				n = n + 2 -- padding in struct
				local count = buffer(n, 4):le_uint()
				par:add_le(f.bcm_var_join_chanspec_num, buffer(n, 4)); n = n + 4
				for i = 1, count do
					n = n + parse_chanspec(bcm, buffer(n), pinfo, par, 1)
				end
			elseif var_str == "pkt_filter_enable" then
				par:add_le(f.bcm_var_pkt_filter_enable_id, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_pkt_filter_enable_enable, buffer(n, 4)); n = n + 4
				parsed = true;
			elseif var_str == "pkt_filter_add" then
				par:add_le(f.bcm_var_pkt_filter_add_id, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_pkt_filter_add_type, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_pkt_filter_add_negate_match, buffer(n, 4)); n = n + 4

				par:add_le(f.bcm_var_pkt_filter_pattern_offset, buffer(n, 4)); n = n + 4
				local size_bytes = buffer(n, 4):le_uint()
				par:add_le(f.bcm_var_pkt_filter_pattern_size_bytes, buffer(n, 4)); n = n + 4
				par:add_le(f.bcm_var_pkt_filter_pattern_mask, buffer(n, size_bytes)); n = n + size_bytes
				par:add_le(f.bcm_var_pkt_filter_pattern_pattern, buffer(n, size_bytes)); n = n + size_bytes
				parsed = true;
			end
			if parsed and buffer:len() > n then
				par:add(f.unused, buffer(n)); n = buffer:len()
			end
		elseif (cmd == 263 and out == 0) then
			pinfo.cols.info:append(" <reply data>")
		end

		-- add data not parsed above
		if (buffer:len() > n) then
			par:add(f.data, buffer(n))
		end

		if (out == 0) then
			if (status == 0) then
				pinfo.cols.info:append(" OK")
			else
				pinfo.cols.info:append(" FAILED ("..status..")")
			end
		end
	end
end

cdc_ioctl_cmd_strings[0] = "WLC_GET_MAGIC"
cdc_ioctl_cmd_strings[1] = "WLC_GET_VERSION"
cdc_ioctl_cmd_strings[2] = "WLC_UP"
cdc_ioctl_cmd_strings[3] = "WLC_DOWN"
cdc_ioctl_cmd_strings[4] = "WLC_GET_LOOP"
cdc_ioctl_cmd_strings[5] = "WLC_SET_LOOP"
cdc_ioctl_cmd_strings[6] = "WLC_DUMP"
cdc_ioctl_cmd_strings[7] = "WLC_GET_MSGLEVEL"
cdc_ioctl_cmd_strings[8] = "WLC_SET_MSGLEVEL"
cdc_ioctl_cmd_strings[9] = "WLC_GET_PROMISC"
cdc_ioctl_cmd_strings[10] = "WLC_SET_PROMISC"
cdc_ioctl_cmd_strings[11] = "WLC_OVERLAY_IOCTL"
cdc_ioctl_cmd_strings[12] = "WLC_GET_RATE"
cdc_ioctl_cmd_strings[13] = "WLC_GET_MAX_RATE"
cdc_ioctl_cmd_strings[14] = "WLC_GET_INSTANCE"
cdc_ioctl_cmd_strings[15] = "WLC_GET_FRAG"
cdc_ioctl_cmd_strings[16] = "WLC_SET_FRAG"
cdc_ioctl_cmd_strings[17] = "WLC_GET_RTS"
cdc_ioctl_cmd_strings[18] = "WLC_SET_RTS"
cdc_ioctl_cmd_strings[19] = "WLC_GET_INFRA"
cdc_ioctl_cmd_strings[20] = "WLC_SET_INFRA"
cdc_ioctl_cmd_strings[21] = "WLC_GET_AUTH"
cdc_ioctl_cmd_strings[22] = "WLC_SET_AUTH"
cdc_ioctl_cmd_strings[23] = "WLC_GET_BSSID"
cdc_ioctl_cmd_strings[24] = "WLC_SET_BSSID"
cdc_ioctl_cmd_strings[25] = "WLC_GET_SSID"
cdc_ioctl_cmd_strings[26] = "WLC_SET_SSID"
cdc_ioctl_cmd_strings[27] = "WLC_RESTART"
cdc_ioctl_cmd_strings[28] = "WLC_TERMINATED"
cdc_ioctl_cmd_strings[28] = "WLC_DUMP_SCB"
cdc_ioctl_cmd_strings[29] = "WLC_GET_CHANNEL"
cdc_ioctl_cmd_strings[30] = "WLC_SET_CHANNEL"
cdc_ioctl_cmd_strings[31] = "WLC_GET_SRL"
cdc_ioctl_cmd_strings[32] = "WLC_SET_SRL"
cdc_ioctl_cmd_strings[33] = "WLC_GET_LRL"
cdc_ioctl_cmd_strings[34] = "WLC_SET_LRL"
cdc_ioctl_cmd_strings[35] = "WLC_GET_PLCPHDR"
cdc_ioctl_cmd_strings[36] = "WLC_SET_PLCPHDR"
cdc_ioctl_cmd_strings[37] = "WLC_GET_RADIO"
cdc_ioctl_cmd_strings[38] = "WLC_SET_RADIO"
cdc_ioctl_cmd_strings[39] = "WLC_GET_PHYTYPE"
cdc_ioctl_cmd_strings[40] = "WLC_DUMP_RATE"
cdc_ioctl_cmd_strings[41] = "WLC_SET_RATE_PARAMS"
cdc_ioctl_cmd_strings[42] = "WLC_GET_FIXRATE"
cdc_ioctl_cmd_strings[43] = "WLC_SET_FIXRATE"
cdc_ioctl_cmd_strings[42] = "WLC_GET_WEP"
cdc_ioctl_cmd_strings[43] = "WLC_SET_WEP"
cdc_ioctl_cmd_strings[44] = "WLC_GET_KEY"
cdc_ioctl_cmd_strings[45] = "WLC_SET_KEY"
cdc_ioctl_cmd_strings[46] = "WLC_GET_REGULATORY"
cdc_ioctl_cmd_strings[47] = "WLC_SET_REGULATORY"
cdc_ioctl_cmd_strings[48] = "WLC_GET_PASSIVE_SCAN"
cdc_ioctl_cmd_strings[49] = "WLC_SET_PASSIVE_SCAN"
cdc_ioctl_cmd_strings[50] = "WLC_SCAN"
cdc_ioctl_cmd_strings[51] = "WLC_SCAN_RESULTS"
cdc_ioctl_cmd_strings[52] = "WLC_DISASSOC"
cdc_ioctl_cmd_strings[53] = "WLC_REASSOC"
cdc_ioctl_cmd_strings[54] = "WLC_GET_ROAM_TRIGGER"
cdc_ioctl_cmd_strings[55] = "WLC_SET_ROAM_TRIGGER"
cdc_ioctl_cmd_strings[56] = "WLC_GET_ROAM_DELTA"
cdc_ioctl_cmd_strings[57] = "WLC_SET_ROAM_DELTA"
cdc_ioctl_cmd_strings[58] = "WLC_GET_ROAM_SCAN_PERIOD"
cdc_ioctl_cmd_strings[59] = "WLC_SET_ROAM_SCAN_PERIOD"
cdc_ioctl_cmd_strings[60] = "WLC_EVM"
cdc_ioctl_cmd_strings[61] = "WLC_GET_TXANT"
cdc_ioctl_cmd_strings[62] = "WLC_SET_TXANT"
cdc_ioctl_cmd_strings[63] = "WLC_GET_ANTDIV"
cdc_ioctl_cmd_strings[64] = "WLC_SET_ANTDIV"
cdc_ioctl_cmd_strings[65] = "WLC_GET_TXPWR"
cdc_ioctl_cmd_strings[66] = "WLC_SET_TXPWR"
cdc_ioctl_cmd_strings[67] = "WLC_GET_CLOSED"
cdc_ioctl_cmd_strings[68] = "WLC_SET_CLOSED"
cdc_ioctl_cmd_strings[69] = "WLC_GET_MACLIST"
cdc_ioctl_cmd_strings[70] = "WLC_SET_MACLIST"
cdc_ioctl_cmd_strings[71] = "WLC_GET_RATESET"
cdc_ioctl_cmd_strings[72] = "WLC_SET_RATESET"
cdc_ioctl_cmd_strings[73] = "WLC_GET_LOCALE"
cdc_ioctl_cmd_strings[74] = "WLC_LONGTRAIN"
cdc_ioctl_cmd_strings[75] = "WLC_GET_BCNPRD"
cdc_ioctl_cmd_strings[76] = "WLC_SET_BCNPRD"
cdc_ioctl_cmd_strings[77] = "WLC_GET_DTIMPRD"
cdc_ioctl_cmd_strings[78] = "WLC_SET_DTIMPRD"
cdc_ioctl_cmd_strings[79] = "WLC_GET_SROM"
cdc_ioctl_cmd_strings[80] = "WLC_SET_SROM"
cdc_ioctl_cmd_strings[81] = "WLC_GET_WEP_RESTRICT"
cdc_ioctl_cmd_strings[82] = "WLC_SET_WEP_RESTRICT"
cdc_ioctl_cmd_strings[83] = "WLC_GET_COUNTRY"
cdc_ioctl_cmd_strings[84] = "WLC_SET_COUNTRY"
cdc_ioctl_cmd_strings[85] = "WLC_GET_PM"
cdc_ioctl_cmd_strings[86] = "WLC_SET_PM"
cdc_ioctl_cmd_strings[87] = "WLC_GET_WAKE"
cdc_ioctl_cmd_strings[88] = "WLC_SET_WAKE"
cdc_ioctl_cmd_strings[89] = "WLC_GET_D11CNTS"
cdc_ioctl_cmd_strings[90] = "WLC_GET_FORCELINK"
cdc_ioctl_cmd_strings[91] = "WLC_SET_FORCELINK"
cdc_ioctl_cmd_strings[92] = "WLC_FREQ_ACCURACY"
cdc_ioctl_cmd_strings[93] = "WLC_CARRIER_SUPPRESS"
cdc_ioctl_cmd_strings[94] = "WLC_GET_PHYREG"
cdc_ioctl_cmd_strings[95] = "WLC_SET_PHYREG"
cdc_ioctl_cmd_strings[96] = "WLC_GET_RADIOREG"
cdc_ioctl_cmd_strings[97] = "WLC_SET_RADIOREG"
cdc_ioctl_cmd_strings[98] = "WLC_GET_REVINFO"
cdc_ioctl_cmd_strings[99] = "WLC_GET_UCANTDIV"
cdc_ioctl_cmd_strings[100] = "WLC_SET_UCANTDIV"
cdc_ioctl_cmd_strings[101] = "WLC_R_REG"
cdc_ioctl_cmd_strings[102] = "WLC_W_REG"
cdc_ioctl_cmd_strings[103] = "WLC_DIAG_LOOPBACK"
cdc_ioctl_cmd_strings[104] = "WLC_RESET_D11CNTS"
cdc_ioctl_cmd_strings[105] = "WLC_GET_MACMODE"
cdc_ioctl_cmd_strings[106] = "WLC_SET_MACMODE"
cdc_ioctl_cmd_strings[107] = "WLC_GET_MONITOR"
cdc_ioctl_cmd_strings[108] = "WLC_SET_MONITOR"
cdc_ioctl_cmd_strings[109] = "WLC_GET_GMODE"
cdc_ioctl_cmd_strings[110] = "WLC_SET_GMODE"
cdc_ioctl_cmd_strings[111] = "WLC_GET_LEGACY_ERP"
cdc_ioctl_cmd_strings[112] = "WLC_SET_LEGACY_ERP"
cdc_ioctl_cmd_strings[113] = "WLC_GET_RX_ANT"
cdc_ioctl_cmd_strings[114] = "WLC_GET_CURR_RATESET"
cdc_ioctl_cmd_strings[115] = "WLC_GET_SCANSUPPRESS"
cdc_ioctl_cmd_strings[116] = "WLC_SET_SCANSUPPRESS"
cdc_ioctl_cmd_strings[117] = "WLC_GET_AP"
cdc_ioctl_cmd_strings[118] = "WLC_SET_AP"
cdc_ioctl_cmd_strings[119] = "WLC_GET_EAP_RESTRICT"
cdc_ioctl_cmd_strings[120] = "WLC_SET_EAP_RESTRICT"
cdc_ioctl_cmd_strings[121] = "WLC_SCB_AUTHORIZE"
cdc_ioctl_cmd_strings[122] = "WLC_SCB_DEAUTHORIZE"
cdc_ioctl_cmd_strings[123] = "WLC_GET_WDSLIST"
cdc_ioctl_cmd_strings[124] = "WLC_SET_WDSLIST"
cdc_ioctl_cmd_strings[125] = "WLC_GET_ATIM"
cdc_ioctl_cmd_strings[126] = "WLC_SET_ATIM"
cdc_ioctl_cmd_strings[127] = "WLC_GET_RSSI"
cdc_ioctl_cmd_strings[128] = "WLC_GET_PHYANTDIV"
cdc_ioctl_cmd_strings[129] = "WLC_SET_PHYANTDIV"
cdc_ioctl_cmd_strings[130] = "WLC_AP_RX_ONLY"
cdc_ioctl_cmd_strings[131] = "WLC_GET_TX_PATH_PWR"
cdc_ioctl_cmd_strings[132] = "WLC_SET_TX_PATH_PWR"
cdc_ioctl_cmd_strings[133] = "WLC_GET_WSEC"
cdc_ioctl_cmd_strings[134] = "WLC_SET_WSEC"
cdc_ioctl_cmd_strings[135] = "WLC_GET_PHY_NOISE"
cdc_ioctl_cmd_strings[136] = "WLC_GET_BSS_INFO"
cdc_ioctl_cmd_strings[137] = "WLC_GET_PKTCNTS"
cdc_ioctl_cmd_strings[138] = "WLC_GET_LAZYWDS"
cdc_ioctl_cmd_strings[139] = "WLC_SET_LAZYWDS"
cdc_ioctl_cmd_strings[140] = "WLC_GET_BANDLIST"
cdc_ioctl_cmd_strings[141] = "WLC_GET_BAND"
cdc_ioctl_cmd_strings[142] = "WLC_SET_BAND"
cdc_ioctl_cmd_strings[143] = "WLC_SCB_DEAUTHENTICATE"
cdc_ioctl_cmd_strings[144] = "WLC_GET_SHORTSLOT"
cdc_ioctl_cmd_strings[145] = "WLC_GET_SHORTSLOT_OVERRIDE"
cdc_ioctl_cmd_strings[146] = "WLC_SET_SHORTSLOT_OVERRIDE"
cdc_ioctl_cmd_strings[147] = "WLC_GET_SHORTSLOT_RESTRICT"
cdc_ioctl_cmd_strings[148] = "WLC_SET_SHORTSLOT_RESTRICT"
cdc_ioctl_cmd_strings[149] = "WLC_GET_GMODE_PROTECTION"
cdc_ioctl_cmd_strings[150] = "WLC_GET_GMODE_PROTECTION_OVERRIDE"
cdc_ioctl_cmd_strings[151] = "WLC_SET_GMODE_PROTECTION_OVERRIDE"
cdc_ioctl_cmd_strings[152] = "WLC_UPGRADE"
cdc_ioctl_cmd_strings[153] = "WLC_GET_MRATE"
cdc_ioctl_cmd_strings[154] = "WLC_SET_MRATE"
cdc_ioctl_cmd_strings[155] = "WLC_GET_IGNORE_BCNS"
cdc_ioctl_cmd_strings[156] = "WLC_SET_IGNORE_BCNS"
cdc_ioctl_cmd_strings[157] = "WLC_GET_SCB_TIMEOUT"
cdc_ioctl_cmd_strings[158] = "WLC_SET_SCB_TIMEOUT"
cdc_ioctl_cmd_strings[159] = "WLC_GET_ASSOCLIST"
cdc_ioctl_cmd_strings[160] = "WLC_GET_CLK"
cdc_ioctl_cmd_strings[161] = "WLC_SET_CLK"
cdc_ioctl_cmd_strings[162] = "WLC_GET_UP"
cdc_ioctl_cmd_strings[163] = "WLC_OUT"
cdc_ioctl_cmd_strings[164] = "WLC_GET_WPA_AUTH"
cdc_ioctl_cmd_strings[165] = "WLC_SET_WPA_AUTH"
cdc_ioctl_cmd_strings[166] = "WLC_GET_UCFLAGS"
cdc_ioctl_cmd_strings[167] = "WLC_SET_UCFLAGS"
cdc_ioctl_cmd_strings[168] = "WLC_GET_PWRIDX"
cdc_ioctl_cmd_strings[169] = "WLC_SET_PWRIDX"
cdc_ioctl_cmd_strings[170] = "WLC_GET_TSSI"
cdc_ioctl_cmd_strings[171] = "WLC_GET_SUP_RATESET_OVERRIDE"
cdc_ioctl_cmd_strings[172] = "WLC_SET_SUP_RATESET_OVERRIDE"
cdc_ioctl_cmd_strings[173] = "WLC_SET_FAST_TIMER"
cdc_ioctl_cmd_strings[174] = "WLC_GET_FAST_TIMER"
cdc_ioctl_cmd_strings[175] = "WLC_SET_SLOW_TIMER"
cdc_ioctl_cmd_strings[176] = "WLC_GET_SLOW_TIMER"
cdc_ioctl_cmd_strings[177] = "WLC_DUMP_PHYREGS"
cdc_ioctl_cmd_strings[178] = "WLC_GET_PROTECTION_CONTROL"
cdc_ioctl_cmd_strings[179] = "WLC_SET_PROTECTION_CONTROL"
cdc_ioctl_cmd_strings[180] = "WLC_GET_PHYLIST"
cdc_ioctl_cmd_strings[181] = "WLC_ENCRYPT_STRENGTH"
cdc_ioctl_cmd_strings[182] = "WLC_DECRYPT_STATUS"
cdc_ioctl_cmd_strings[183] = "WLC_GET_KEY_SEQ"
cdc_ioctl_cmd_strings[184] = "WLC_GET_SCAN_CHANNEL_TIME"
cdc_ioctl_cmd_strings[185] = "WLC_SET_SCAN_CHANNEL_TIME"
cdc_ioctl_cmd_strings[186] = "WLC_GET_SCAN_UNASSOC_TIME"
cdc_ioctl_cmd_strings[187] = "WLC_SET_SCAN_UNASSOC_TIME"
cdc_ioctl_cmd_strings[188] = "WLC_GET_SCAN_HOME_TIME"
cdc_ioctl_cmd_strings[189] = "WLC_SET_SCAN_HOME_TIME"
cdc_ioctl_cmd_strings[190] = "WLC_GET_SCAN_NPROBES"
cdc_ioctl_cmd_strings[191] = "WLC_SET_SCAN_NPROBES"
cdc_ioctl_cmd_strings[192] = "WLC_GET_PRB_RESP_TIMEOUT"
cdc_ioctl_cmd_strings[193] = "WLC_SET_PRB_RESP_TIMEOUT"
cdc_ioctl_cmd_strings[194] = "WLC_GET_ATTEN"
cdc_ioctl_cmd_strings[195] = "WLC_SET_ATTEN"
cdc_ioctl_cmd_strings[196] = "WLC_GET_SHMEM"
cdc_ioctl_cmd_strings[197] = "WLC_SET_SHMEM"
cdc_ioctl_cmd_strings[198] = "WLC_GET_GMODE_PROTECTION_CTS"
cdc_ioctl_cmd_strings[199] = "WLC_SET_GMODE_PROTECTION_CTS"
cdc_ioctl_cmd_strings[200] = "WLC_SET_WSEC_TEST"
cdc_ioctl_cmd_strings[201] = "WLC_SCB_DEAUTHENTICATE_FOR_REASON"
cdc_ioctl_cmd_strings[202] = "WLC_TKIP_COUNTERMEASURES"
cdc_ioctl_cmd_strings[203] = "WLC_GET_PIOMODE"
cdc_ioctl_cmd_strings[204] = "WLC_SET_PIOMODE"
cdc_ioctl_cmd_strings[205] = "WLC_SET_ASSOC_PREFER"
cdc_ioctl_cmd_strings[206] = "WLC_GET_ASSOC_PREFER"
cdc_ioctl_cmd_strings[207] = "WLC_SET_ROAM_PREFER"
cdc_ioctl_cmd_strings[208] = "WLC_GET_ROAM_PREFER"
cdc_ioctl_cmd_strings[209] = "WLC_SET_LED"
cdc_ioctl_cmd_strings[210] = "WLC_GET_LED"
cdc_ioctl_cmd_strings[211] = "WLC_GET_INTERFERENCE_MODE"
cdc_ioctl_cmd_strings[212] = "WLC_SET_INTERFERENCE_MODE"
cdc_ioctl_cmd_strings[213] = "WLC_GET_CHANNEL_QA"
cdc_ioctl_cmd_strings[214] = "WLC_START_CHANNEL_QA"
cdc_ioctl_cmd_strings[215] = "WLC_GET_CHANNEL_SEL"
cdc_ioctl_cmd_strings[216] = "WLC_START_CHANNEL_SEL"
cdc_ioctl_cmd_strings[217] = "WLC_GET_VALID_CHANNELS"
cdc_ioctl_cmd_strings[218] = "WLC_GET_FAKEFRAG"
cdc_ioctl_cmd_strings[219] = "WLC_SET_FAKEFRAG"
cdc_ioctl_cmd_strings[220] = "WLC_GET_PWROUT_PERCENTAGE"
cdc_ioctl_cmd_strings[221] = "WLC_SET_PWROUT_PERCENTAGE"
cdc_ioctl_cmd_strings[222] = "WLC_SET_BAD_FRAME_PREEMPT"
cdc_ioctl_cmd_strings[223] = "WLC_GET_BAD_FRAME_PREEMPT"
cdc_ioctl_cmd_strings[224] = "WLC_SET_LEAP_LIST"
cdc_ioctl_cmd_strings[225] = "WLC_GET_LEAP_LIST"
cdc_ioctl_cmd_strings[226] = "WLC_GET_CWMIN"
cdc_ioctl_cmd_strings[227] = "WLC_SET_CWMIN"
cdc_ioctl_cmd_strings[228] = "WLC_GET_CWMAX"
cdc_ioctl_cmd_strings[229] = "WLC_SET_CWMAX"
cdc_ioctl_cmd_strings[230] = "WLC_GET_WET"
cdc_ioctl_cmd_strings[231] = "WLC_SET_WET"
cdc_ioctl_cmd_strings[232] = "WLC_GET_PUB"
cdc_ioctl_cmd_strings[233] = "WLC_SET_GLACIAL_TIMER"
cdc_ioctl_cmd_strings[234] = "WLC_GET_GLACIAL_TIMER"
cdc_ioctl_cmd_strings[235] = "WLC_GET_KEY_PRIMARY"
cdc_ioctl_cmd_strings[236] = "WLC_SET_KEY_PRIMARY"
cdc_ioctl_cmd_strings[237] = "WLC_DUMP_RADIOREGS"
cdc_ioctl_cmd_strings[238] = "WLC_GET_ACI_ARGS"
cdc_ioctl_cmd_strings[239] = "WLC_SET_ACI_ARGS"
cdc_ioctl_cmd_strings[240] = "WLC_UNSET_CALLBACK"
cdc_ioctl_cmd_strings[241] = "WLC_SET_CALLBACK"
cdc_ioctl_cmd_strings[242] = "WLC_GET_RADAR"
cdc_ioctl_cmd_strings[243] = "WLC_SET_RADAR"
cdc_ioctl_cmd_strings[244] = "WLC_SET_SPECT_MANAGMENT"
cdc_ioctl_cmd_strings[245] = "WLC_GET_SPECT_MANAGMENT"
cdc_ioctl_cmd_strings[246] = "WLC_WDS_GET_REMOTE_HWADDR"
cdc_ioctl_cmd_strings[247] = "WLC_WDS_GET_WPA_SUP"
cdc_ioctl_cmd_strings[248] = "WLC_SET_CS_SCAN_TIMER"
cdc_ioctl_cmd_strings[249] = "WLC_GET_CS_SCAN_TIMER"
cdc_ioctl_cmd_strings[250] = "WLC_MEASURE_REQUEST"
cdc_ioctl_cmd_strings[251] = "WLC_INIT"
cdc_ioctl_cmd_strings[252] = "WLC_SEND_QUIET"
cdc_ioctl_cmd_strings[253] = "WLC_KEEPALIVE"
cdc_ioctl_cmd_strings[254] = "WLC_SEND_PWR_CONSTRAINT"
cdc_ioctl_cmd_strings[255] = "WLC_UPGRADE_STATUS"
cdc_ioctl_cmd_strings[256] = "WLC_CURRENT_PWR"
cdc_ioctl_cmd_strings[257] = "WLC_GET_SCAN_PASSIVE_TIME"
cdc_ioctl_cmd_strings[258] = "WLC_SET_SCAN_PASSIVE_TIME"
cdc_ioctl_cmd_strings[259] = "WLC_LEGACY_LINK_BEHAVIOR"
cdc_ioctl_cmd_strings[260] = "WLC_GET_CHANNELS_IN_COUNTRY"
cdc_ioctl_cmd_strings[261] = "WLC_GET_COUNTRY_LIST"
cdc_ioctl_cmd_strings[262] = "WLC_GET_VAR"
cdc_ioctl_cmd_strings[263] = "WLC_SET_VAR"
cdc_ioctl_cmd_strings[264] = "WLC_NVRAM_GET"
cdc_ioctl_cmd_strings[265] = "WLC_NVRAM_SET"
cdc_ioctl_cmd_strings[266] = "WLC_NVRAM_DUMP"
cdc_ioctl_cmd_strings[267] = "WLC_REBOOT"
cdc_ioctl_cmd_strings[268] = "WLC_SET_WSEC_PMK"
cdc_ioctl_cmd_strings[269] = "WLC_GET_AUTH_MODE"
cdc_ioctl_cmd_strings[270] = "WLC_SET_AUTH_MODE"
cdc_ioctl_cmd_strings[271] = "WLC_GET_WAKEENTRY"
cdc_ioctl_cmd_strings[272] = "WLC_SET_WAKEENTRY"
cdc_ioctl_cmd_strings[273] = "WLC_NDCONFIG_ITEM"
cdc_ioctl_cmd_strings[274] = "WLC_NVOTPW"
cdc_ioctl_cmd_strings[275] = "WLC_OTPW"
cdc_ioctl_cmd_strings[276] = "WLC_IOV_BLOCK_GET"
cdc_ioctl_cmd_strings[277] = "WLC_IOV_MODULES_GET"
cdc_ioctl_cmd_strings[278] = "WLC_SOFT_RESET"
cdc_ioctl_cmd_strings[279] = "WLC_GET_ALLOW_MODE"
cdc_ioctl_cmd_strings[280] = "WLC_SET_ALLOW_MODE"
cdc_ioctl_cmd_strings[281] = "WLC_GET_DESIRED_BSSID"
cdc_ioctl_cmd_strings[282] = "WLC_SET_DESIRED_BSSID"
cdc_ioctl_cmd_strings[284] = "WLC_GET_NBANDS"
cdc_ioctl_cmd_strings[285] = "WLC_GET_BANDSTATES"
cdc_ioctl_cmd_strings[286] = "WLC_GET_WLC_BSS_INFO"
cdc_ioctl_cmd_strings[287] = "WLC_GET_ASSOC_INFO"
cdc_ioctl_cmd_strings[288] = "WLC_GET_OID_PHY"
cdc_ioctl_cmd_strings[289] = "WLC_SET_OID_PHY"
cdc_ioctl_cmd_strings[290] = "WLC_SET_ASSOC_TIME"
cdc_ioctl_cmd_strings[291] = "WLC_GET_DESIRED_SSID"
cdc_ioctl_cmd_strings[292] = "WLC_GET_CHANSPEC"
cdc_ioctl_cmd_strings[293] = "WLC_GET_ASSOC_STATE"
cdc_ioctl_cmd_strings[294] = "WLC_SET_PHY_STATE"
cdc_ioctl_cmd_strings[295] = "WLC_GET_SCAN_PENDING"
cdc_ioctl_cmd_strings[296] = "WLC_GET_SCANREQ_PENDING"
cdc_ioctl_cmd_strings[297] = "WLC_GET_PREV_ROAM_REASON"
cdc_ioctl_cmd_strings[298] = "WLC_SET_PREV_ROAM_REASON"
cdc_ioctl_cmd_strings[299] = "WLC_GET_BANDSTATES_PI"
cdc_ioctl_cmd_strings[300] = "WLC_GET_PHY_STATE"
cdc_ioctl_cmd_strings[301] = "WLC_GET_BSS_WPA_RSN"
cdc_ioctl_cmd_strings[302] = "WLC_GET_BSS_WPA2_RSN"
cdc_ioctl_cmd_strings[303] = "WLC_GET_BSS_BCN_TS"
cdc_ioctl_cmd_strings[304] = "WLC_GET_INT_DISASSOC"
cdc_ioctl_cmd_strings[305] = "WLC_SET_NUM_PEERS"
cdc_ioctl_cmd_strings[306] = "WLC_GET_NUM_BSS"
cdc_ioctl_cmd_strings[307] = "WLC_PHY_SAMPLE_COLLECT"
cdc_ioctl_cmd_strings[308] = "WLC_UM_PRIV"
cdc_ioctl_cmd_strings[309] = "WLC_GET_CMD"
cdc_ioctl_cmd_strings[310] = "WLC_LAST"
cdc_ioctl_cmd_strings[311] = "WLC_SET_INTERFERENCE_OVERRIDE_MODE"
cdc_ioctl_cmd_strings[312] = "WLC_GET_INTERFERENCE_OVERRIDE_MODE"
cdc_ioctl_cmd_strings[313] = "WLC_GET_WAI_RESTRICT"
cdc_ioctl_cmd_strings[314] = "WLC_SET_WAI_RESTRICT"
cdc_ioctl_cmd_strings[315] = "WLC_SET_WAI_REKEY"
cdc_ioctl_cmd_strings[316] = "WLC_SET_NAT_CONFIG"
cdc_ioctl_cmd_strings[317] = "WLC_GET_NAT_STATE"
cdc_ioctl_cmd_strings[318] = "WLC_LAST"

band_strings[0] = "AUTO"
band_strings[1] = "5G"
band_strings[2] = "2G"
band_strings[3] = "ALL"

bss_type_strings[0] = "INFRASTRUCTURE"
bss_type_strings[1] = "INDEPENDENT"
bss_type_strings[2] = "ANY"

scan_type_strings[0] = "ACTIVE"
scan_type_strings[1] = "PASSIVE"

p2p_state_strings[0] = "SCAN"
p2p_state_strings[1] = "LISTEN"
p2p_state_strings[2] = "SEARCH"

event_msgs_strings[0] = "SET_SSID"
event_msgs_strings[1] = "JOIN"
event_msgs_strings[2] = "START"
event_msgs_strings[3] = "AUTH"
event_msgs_strings[4] = "AUTH_IND"
event_msgs_strings[5] = "DEAUTH"
event_msgs_strings[6] = "DEAUTH_IND"
event_msgs_strings[7] = "ASSOC"
event_msgs_strings[8] = "ASSOC_IND"
event_msgs_strings[9] = "REASSOC"
event_msgs_strings[10] = "REASSOC_IND"
event_msgs_strings[11] = "DISASSOC"
event_msgs_strings[12] = "DISASSOC_IND"
event_msgs_strings[13] = "QUIET_START"
event_msgs_strings[14] = "QUIET_END"
event_msgs_strings[15] = "BEACON_RX"
event_msgs_strings[16] = "LINK"
event_msgs_strings[17] = "MIC_ERROR"
event_msgs_strings[18] = "NDIS_LINK"
event_msgs_strings[19] = "ROAM"
event_msgs_strings[20] = "TXFAIL"
event_msgs_strings[21] = "PMKID_CACHE"
event_msgs_strings[22] = "RETROGRADE_TSF"
event_msgs_strings[23] = "PRUNE"
event_msgs_strings[24] = "AUTOAUTH"
event_msgs_strings[25] = "EAPOL_MSG"
event_msgs_strings[26] = "SCAN_COMPLETE"
event_msgs_strings[27] = "ADDTS_IND"
event_msgs_strings[28] = "DELTS_IND"
event_msgs_strings[29] = "BCNSENT_IND"
event_msgs_strings[30] = "BCNRX_MSG"
event_msgs_strings[31] = "BCNLOST_MSG"
event_msgs_strings[32] = "ROAM_PREP"
event_msgs_strings[33] = "PFN_NET_FOUND"
event_msgs_strings[34] = "PFN_NET_LOST"
event_msgs_strings[35] = "RESET_COMPLETE"
event_msgs_strings[36] = "JOIN_START"
event_msgs_strings[37] = "ROAM_START"
event_msgs_strings[38] = "ASSOC_START"
event_msgs_strings[39] = "IBSS_ASSOC"
event_msgs_strings[40] = "RADIO"
event_msgs_strings[41] = "PSM_WATCHDOG"
event_msgs_strings[44] = "PROBREQ_MSG"
event_msgs_strings[45] = "SCAN_CONFIRM_IND"
event_msgs_strings[46] = "PSK_SUP"
event_msgs_strings[47] = "COUNTRY_CODE_CHANGED"
event_msgs_strings[48] = "EXCEEDED_MEDIUM_TIME"
event_msgs_strings[49] = "ICV_ERROR"
event_msgs_strings[50] = "UNICAST_DECODE_ERROR"
event_msgs_strings[51] = "MULTICAST_DECODE_ERROR"
event_msgs_strings[52] = "TRACE"
event_msgs_strings[54] = "IF"
event_msgs_strings[55] = "P2P_DISC_LISTEN_COMPLETE"
event_msgs_strings[56] = "RSSI"
event_msgs_strings[57] = "PFN_SCAN_COMPLETE"
event_msgs_strings[58] = "EXTLOG_MSG"
event_msgs_strings[59] = "ACTION_FRAME"
event_msgs_strings[60] = "ACTION_FRAME_COMPLETE"
event_msgs_strings[61] = "PRE_ASSOC_IND"
event_msgs_strings[62] = "PRE_REASSOC_IND"
event_msgs_strings[63] = "CHANNEL_ADOPTED"
event_msgs_strings[64] = "AP_STARTED"
event_msgs_strings[65] = "DFS_AP_STOP"
event_msgs_strings[66] = "DFS_AP_RESUME"
event_msgs_strings[69] = "ESCAN_RESULT"
event_msgs_strings[70] = "ACTION_FRAME_OFF_CHAN_COMPLETE"
event_msgs_strings[71] = "PROBERESP_MSG"
event_msgs_strings[72] = "P2P_PROBEREQ_MSG"
event_msgs_strings[73] = "DCS_REQUEST"
event_msgs_strings[74] = "FIFO_CREDIT_MAP"
event_msgs_strings[75] = "ACTION_FRAME_RX"

p2p_if_type_strings[0] = "CLIENT"
p2p_if_type_strings[1] = "GO"
p2p_if_type_strings[2] = "DYNBCN_GO"
p2p_if_type_strings[3] = "DEV"

f.value32 = ProtoField.uint32("bcm_cdc_ioctl.value32", "value32", base.DEC)
f.unused = ProtoField.bytes("bcm_cdc_ioctl.data", "unused")

f.data = ProtoField.bytes("bcm_cdc_ioctl.data", "data")

f.bcm_cdc_ioctl_cmd = ProtoField.uint32("bcm_cdc_ioctl.cmd", "cmd", base.DEC, cdc_ioctl_cmd_strings)
f.bcm_cdc_ioctl_len = ProtoField.uint32("bcm_cdc_ioctl.len", "len", base.DEC)
f.bcm_cdc_ioctl_flags = ProtoField.uint32("bcm_cdc_ioctl.flags", "flags", base.HEX)
f.bcm_cdc_ioctl_status = ProtoField.uint32("bcm_cdc_ioctl.status", "status", base.DEC)


f.bcm_var_name = ProtoField.stringz("bcm_var_name", "var_name")

f.bcm_var_cur_etheraddr = ProtoField.ether("bcm_var_cur_etheraddr", "cur_etheraddr")

f.bcm_var_mcast_list_count = ProtoField.uint32("bcm_var_mcast_list.count", "count", base.DEC)
f.bcm_var_mcast_list_addr = ProtoField.ether("bcm_var_mcast_list.addr", "addr")

f.bcm_var_arp_hostip = ProtoField.ipv4("bcm_var_arp_hostip.ip", "ip")


f.bcm_var_p2p_scan_type = ProtoField.uint8("bcm_var_p2p_scan.type", "type")
f.bcm_var_p2p_scan_reserved = ProtoField.bytes("bcm_var_p2p_scan.reserved", "reserved")

f.bcm_var_p2p_state_state = ProtoField.uint8("bcm_var_p2p_state.state", "state", base.DEC, p2p_state_strings)
f.bcm_var_p2p_state_dwell = ProtoField.uint16("bcm_var_p2p_state.dwell", "dwell")

f.bcm_var_event_msgs_event = ProtoField.uint8("bcm_var_event_msgs.event", "event", base.DEC, event_msgs_strings	)

f.bcm_var_p2p_ifadd_addr = ProtoField.ether("bcm_var_p2p_ifadd.addr", "addr")
f.bcm_var_p2p_ifadd_type = ProtoField.uint8("bcm_var_p2p_ifadd.type", "type", base.DEC, p2p_if_type_strings)

f.bcm_var_p2p_ifdel_addr = ProtoField.ether("bcm_var_p2p_ifdel.addr", "addr")

f.bcm_var_join_scan_type = ProtoField.uint8("bcm_var_join.scan_type", "scan_type", base.DEC, scan_type_strings)
f.bcm_var_join_nprobes = ProtoField.uint32("bcm_var_join.scan_nprobes", "scan_nprobes")
f.bcm_var_join_active_time = ProtoField.uint32("bcm_var_join.scan_active_time", "scan_active_time")
f.bcm_var_join_passive_time = ProtoField.uint32("bcm_var_join.scan_passive_time", "scan_passive_time")
f.bcm_var_join_home_time = ProtoField.uint32("bcm_var_join.scan_home_time", "scan_home_time")
f.bcm_var_join_bssid = ProtoField.ether("bcm_cdc_ioctl.bcm_var_join_assoc_bssid", "assoc_bssid")
f.bcm_var_join_chanspec_num = ProtoField.uint32("bcm_cdc_ioctl.bcm_var_join_assoc_chanspec_num", "assoc_chanspec_num")

f.bcm_var_pkt_filter_enable_id = ProtoField.uint32("bcm_var_pkt_filter_enable.id", "id", base.DEC)
f.bcm_var_pkt_filter_enable_enable = ProtoField.bool("bcm_var_pkt_filter_enable.enable", "enable")

f.bcm_var_pkt_filter_add_id = ProtoField.uint32("bcm_var_pkt_filter_add.id", "id", base.DEC)
f.bcm_var_pkt_filter_add_type = ProtoField.uint32("bcm_var_pkt_filter_add.type", "type")
f.bcm_var_pkt_filter_add_negate_match = ProtoField.bool("bcm_var_pkt_filter_add.negate_match", "negate_match")

f.bcm_var_pkt_filter_pattern_offset = ProtoField.uint32("bcm_var_pkt_filter_pattern.offset", "offset")
f.bcm_var_pkt_filter_pattern_size_bytes = ProtoField.uint32("bcm_var_pkt_filter_pattern.size_bytes", "size_bytes")
f.bcm_var_pkt_filter_pattern_mask = ProtoField.bytes("bcm_var_pkt_filter_pattern.mask", "mask")
f.bcm_var_pkt_filter_pattern_pattern = ProtoField.bytes("bcm_var_pkt_filter_pattern.pattern", "pattern")

f.chanspec_chan = ProtoField.uint8("bcm_cdc_ioctl.chanspec.chan", "channel")
f.chanspec_other = ProtoField.uint8("bcm_cdc_ioctl.chanspec.other", "other")

f.escan_version = ProtoField.uint32("bcm_cdc_ioctl.escan.version", "version")
f.escan_action = ProtoField.uint16("bcm_cdc_ioctl.escan.action", "action")
f.escan_sync_id = ProtoField.uint16("bcm_cdc_ioctl.escan.sync_id", "sync_id")
f.escan_params = ProtoField.bytes("bcm_cdc_ioctl.escan.params", "params")

f.brcmf_ssid_len = ProtoField.uint32("cm_cdc_ioctl.brcmf_ssid.len", "ssid_len")
f.brcmf_ssid = ProtoField.stringz("cm_cdc_ioctl.brcmf_ssid.ssid", "ssid")

f.brcmf_bssid = ProtoField.ether("bcm_cdc_ioctl.brcmf_bssid", "bssid")

f.brcmf_bsscfgidx = ProtoField.uint32("bcm_cdc_ioctl.brcmf_bsscfgidx", "bsscfgidx")

f.wl_scan_bss_type = ProtoField.uint8("bcm_cdc_ioctl.wl_scan.bss_type", "bss_type", base.DEC, bss_type_strings)
f.wl_scan_scan_type = ProtoField.uint8("bcm_cdc_ioctl.wl_scan.scan_type", "scan_type", base.DEC, scan_type_strings)
f.wl_scan_nprobes = ProtoField.uint32("bcm_cdc_ioctl.wl_scan.nprobes", "nprobes")
f.wl_scan_active_time = ProtoField.uint32("bcm_cdc_ioctl.wl_scan.active_time", "active_time")
f.wl_scan_passive_time = ProtoField.uint32("bcm_cdc_ioctl.wl_scan.passive_time", "passive_time")
f.wl_scan_home_time = ProtoField.uint32("bcm_cdc_ioctl.wl_scan.home_time", "home_time")
f.wl_scan_channel_num = ProtoField.uint32("bcm_cdc_ioctl.wl_scan.channel_num", "channel_num")
f.wl_scan_channel_list = ProtoField.uint16("bcm_cdc_ioctl.wl_scan.channel_list", "channel_list")

f.WLC_SET_SSID_chanspec_num = ProtoField.uint32("bcm_cdc_ioctl.WLC_SET_SSID_chanspec_num", "chanspec_num")

f.WLC_DISASSOC_val = ProtoField.uint32("bcm_cdc_ioctl.WLC_DISASSOC_val", "val")
f.WLC_DISASSOC_ea = ProtoField.ether("bcm_cdc_ioctl.WLC_DISASSOC_ea", "ea")

f.WLC_SET_ROAM_TRIGGER_level = ProtoField.int32("bcm_cdc_ioctl.WLC_SET_ROAM_TRIGGER_level", "level")
f.WLC_SET_ROAM_TRIGGER_band = ProtoField.uint32("bcm_cdc_ioctl.WLC_SET_ROAM_TRIGGER_band", "band", base.DEC, band_strings)

f.WLC_SET_ROAM_DELTA_delta = ProtoField.int32("bcm_cdc_ioctl.WLC_SET_ROAM_DELTA_delta", "delta")
f.WLC_SET_ROAM_DELTA_band = ProtoField.uint32("bcm_cdc_ioctl.WLC_SET_ROAM_DELTA_band", "band", base.DEC, band_strings)

f.WLC_GET_RSSI_val = ProtoField.int32("bcm_cdc_ioctl.WLC_GET_RSSI_val", "val")
f.WLC_GET_RSSI_ea = ProtoField.ether("bcm_cdc_ioctl.WLC_GET_RSSI_ea", "ea")

f.WLC_GET_VALID_CHANNELS_count = ProtoField.int32("bcm_cdc_ioctl.WLC_GET_VALID_CHANNELS_count", "count")
f.WLC_GET_VALID_CHANNELS_channel = ProtoField.int32("bcm_cdc_ioctl.WLC_GET_VALID_CHANNELS_channel", "channel")

f.GET_BSS_INFO_version = ProtoField.uint32("bcm_cdc_ioctl.GET_BSS_INFO_version", "version")
f.GET_BSS_INFO_length = ProtoField.uint32("bcm_cdc_ioctl.GET_BSS_INFO_length", "length")
f.GET_BSS_INFO_beacon_period = ProtoField.uint16("bcm_cdc_ioctl.GET_BSS_INFO_beacon_period", "beacon_period")
f.GET_BSS_INFO_capability = ProtoField.uint16("bcm_cdc_ioctl.GET_BSS_INFO_capability", "capability")
f.GET_BSS_INFO_SSID_len = ProtoField.uint8("bcm_cdc_ioctl.GET_BSS_INFO_SSID_len", "SSID_len")
f.GET_BSS_INFO_SSID = ProtoField.stringz("bcm_cdc_ioctl.GET_BSS_INFO_SSID", "SSID")
f.GET_BSS_INFO_rateset_count = ProtoField.uint32("bcm_cdc_ioctl.GET_BSS_INFO_rateset_count", "rateset_count")
f.GET_BSS_INFO_rateset_rates = ProtoField.bytes("bcm_cdc_ioctl.GET_BSS_INFO_rateset_rates", "rateset_rates")
f.GET_BSS_INFO_atim_window = ProtoField.uint16("bcm_cdc_ioctl.GET_BSS_INFO_atim_window", "atim_window")
f.GET_BSS_INFO_dtim_period = ProtoField.uint8("bcm_cdc_ioctl.GET_BSS_INFO_dtim_period", "dtim_period")
f.GET_BSS_INFO_RSSI = ProtoField.int16("bcm_cdc_ioctl.GET_BSS_INFO_RSSI", "RSSI")
f.GET_BSS_INFO_phy_noise = ProtoField.uint8("bcm_cdc_ioctl.GET_BSS_INFO_phy_noise", "phy_noise")
f.GET_BSS_INFO_n_cap = ProtoField.uint8("bcm_cdc_ioctl.GET_BSS_INFO_n_cap", "n_cap")
f.GET_BSS_INFO_nbss_cap = ProtoField.uint32("bcm_cdc_ioctl.GET_BSS_INFO_nbss_cap", "nbss_cap")
f.GET_BSS_INFO_ctl_ch = ProtoField.uint8("bcm_cdc_ioctl.GET_BSS_INFO_ctl_ch", "ctl_ch")
f.GET_BSS_INFO_reserved32 = ProtoField.uint32("bcm_cdc_ioctl.GET_BSS_INFO_reserved32", "reserved32")
f.GET_BSS_INFO_flags = ProtoField.uint8("bcm_cdc_ioctl.GET_BSS_INFO_flags", "flags")
f.GET_BSS_INFO_reserved = ProtoField.bytes("bcm_cdc_ioctl.GET_BSS_INFO_reserved", "reserved")
f.GET_BSS_INFO_basic_mcs = ProtoField.bytes("bcm_cdc_ioctl.GET_BSS_INFO_basic_mcs", "basic_mcs")
f.GET_BSS_INFO_ie_offset = ProtoField.uint16("bcm_cdc_ioctl.GET_BSS_INFO_ie_offset", "ie_offset")
f.GET_BSS_INFO_ie_length = ProtoField.uint32("bcm_cdc_ioctl.GET_BSS_INFO_ie_length", "ie_length")
f.GET_BSS_INFO_SNR = ProtoField.uint16("bcm_cdc_ioctl.GET_BSS_INFO_SNR", "SNR")
