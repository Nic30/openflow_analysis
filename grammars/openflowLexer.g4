/*
 * Doc in parser grammar
 */
lexer grammar openflowLexer;

KW_in_port: 'in_port';
KW_dl_vlan: 'dl_vlan';
KW_dl_vlan_pcp: 'dl_vlan_pcp';
KW_dl_src: 'dl_src';
KW_dl_dst: 'dl_dst';
KW_dl_type: 'dl_type';
KW_nw_src: 'nw_src';
KW_nw_dst: 'nw_dst';
KW_nw_proto: 'nw_proto';
KW_ip_proto: 'ip_proto';
KW_nw_tos: 'nw_tos';
KW_ip_dscp: 'ip_dscp';
KW_nw_ecn: 'nw_ecn';
KW_ip_ecn: 'ip_ecn';
KW_nw_ttl: 'nw_ttl';
KW_nw_frag: 'nw_frag';

KW_tcp_src: 'tcp_src';
KW_tcp_dst: 'tcp_dst';
KW_udp_src: 'udp_src';
KW_udp_dst: 'udp_dst';
KW_sctp_src: 'sctp_src';
KW_sctp_dst: 'sctp_dst';
KW_tp_dst: 'tp_dst';
KW_tp_src: 'tp_src';

KW_tcp_flags: 'tcp_flags';
KW_TCP_FLAG_fin: 'fin';
KW_TCP_FLAG_syn: 'syn';
KW_TCP_FLAG_rst: 'rst';
KW_TCP_FLAG_psh: 'psh';
KW_TCP_FLAG_ack: 'ack';
KW_TCP_FLAG_urg: 'urg';
KW_TCP_FLAG_ece: 'ece';
KW_TCP_FLAG_cwr: 'cwr';
KW_TCP_FLAG_ns: 'ns';

KW_icmp_type: 'icmp_type';
KW_icmp_code: 'icmp_code';
KW_table: 'table';

// protocol shorcuts
KW_ip: 'ip';
KW_ipv6: 'ipv6';
KW_icmp: 'icmp';
KW_igmp: 'igmp';
KW_icmp6: 'icmp6';
KW_tcp: 'tcp';
KW_tcp6: 'tcp6';
KW_udp: 'udp';
KW_udp6: 'udp6';
KW_sctp: 'sctp';
KW_sctp6: 'sctp6';
KW_arp: 'arp';
KW_rarp: 'rarp';
KW_mpls: 'mpls';
KW_mplsm: 'mplsm';

KW_ip_frag: 'ip_frag';
// ip frag values
KW_no        : 'no';
KW_yes       : 'yes';
KW_first     : 'first';
KW_later     : 'later';
KW_not_later : 'not_later';

KW_eth_type: 'eth_type';

KW_arp_spa: 'arp_spa';
KW_arp_tpa: 'arp_tpa';
KW_arp_sha: 'arp_sha';
KW_arp_tha: 'arp_tha';
KW_arp_op: 'arp_op';

KW_ipv6_src: 'ipv6_src';
KW_ipv6_dst: 'ipv6_dst';
KW_ipv6_label: 'ipv6_label';
KW_nd_target: 'nd_target';
KW_nd_sll: 'nd_sll';
KW_nd_tll: 'nd_tll';
KW_mpls_bos: 'mpls_bos';
KW_mpls_label: 'mpls_label';
KW_mpls_tc: 'mpls_tc';
KW_tun_id   : 'tun_id';
KW_tunnel_id: 'tunnel_id';
KW_tun_flags: 'tun_flags';
KW_oam: 'oam';

KW_tun_src: 'tun_src';
KW_tun_dst: 'tun_dst';
KW_tun_gbp_id   : 'tun_gbp_id';
KW_tun_gbp_flags: 'tun_gbp_flags';
TUN_METADATA: 'tun_metadata' DEC_NUM;
REG_ID: 'reg' DEC_NUM;
XREG_ID: 'xreg' DEC_NUM;
KW_pkt_mark: 'pkt_mark';
KW_actset_output: 'actset_output';
KW_conj_id: 'conj_id';
KW_ct_state: 'ct_state';
// ct states
KW_new: 'new';
KW_est: 'est';
KW_rel: 'rel';
KW_rpl: 'rpl';
KW_inv: 'inv';
KW_trk: 'trk';

KW_ct_zone: 'ct_zone';
KW_ct_mark : 'ct_mark';
KW_ct_label: 'ct_label';

KW_actions: 'actions';

KW_clone: 'clone';
KW_ct_clear: 'ct_clear';

KW_output: 'output';
KW_flood: 'flood';
KW_all  : 'all';
KW_local: 'local';
// KW_in_port
KW_controller: 'controller';
KW_pause: 'pause';
KW_id: 'id';
KW_max_len: 'max_len';
KW_reason: 'reason';
// controller reason values
KW_action: 'action';
KW_default: 'default';
KW_no_match: 'no_match';
KW_invalid_ttl: 'invalid_ttl';

KW_enqueue: 'enqueue';
KW_drop: 'drop';
KW_mod_vlan_vid: 'mod_vlan_vid';
KW_mod_vlan_pcp: 'mod_vlan_pcp';
KW_strip_vlan: 'strip_vlan';
KW_push_vlan: 'push_vlan';
KW_push_mpls: 'push_mpls';
KW_pop_mpls: 'pop_mpls';
KW_mod_dl_src: 'mod_dl_src';
KW_mod_dl_dst: 'mod_dl_dst';
KW_mod_nw_src: 'mod_nw_src';
KW_mod_nw_dst: 'mod_nw_dst';
KW_mod_tp_src: 'mod_tp_src';
KW_mod_tp_dst: 'mod_tp_dst';
KW_mod_nw_tos: 'mod_nw_tos';
KW_mod_nw_ecn: 'mod_nw_ecn';
KW_mod_nw_ttl: 'mod_nw_ttl';
KW_resubmit: 'resubmit';
KW_set_tunnel: 'set_tunnel';
KW_set_tunnel64: 'set_tunnel64';
KW_set_queue: 'set_queue';
KW_pop_queue: 'pop_queue';
KW_delete_field: 'delete_field';

KW_ct: 'ct';
// ct arguments
KW_commit: 'commit';
KW_force: 'force';
// KW_table
KW_zone: 'zone';
KW_exec: 'exec';
// exec actions
KW_set_field: 'set_field';
KW_alg: 'alg';
// alg values
KW_ftp: 'ftp';
KW_tftp: 'tftp';

KW_dec_ttl: 'dec_ttl';
KW_set_mpls_label: 'set_mpls_label';
KW_set_mpls_tc: 'set_mpls_tc';
KW_set_mpls_ttl: 'set_mpls_ttl';
KW_dec_mpls_ttl: 'dec_mpls_ttl';
KW_note: 'note';
KW_move: 'move';
// KW_set_field
KW_load: 'load';
KW_push: 'push';
KW_pop: 'pop';
KW_multipath: 'multipath';
// [todo]
KW_bundle: 'bundle';
// [todo]
KW_bundle_load: 'bundle_load';
KW_learn: 'learn';
KW_fin_idle_timeout: 'fin_idle_timeout';
KW_fin_hard_timeout: 'fin_hard_timeout';
KW_delete_learned: 'delete_learned';
KW_write_metadata: 'write_metadata';
KW_meter: 'meter';
KW_meter_id: 'meter_id';
KW_goto_table: 'goto_table';
KW_fin_timeout: 'fin_timeout';
KW_sample: 'sample';
KW_exit: 'exit';
KW_conjunction: 'conjunction';
KW_cookie: 'cookie';
KW_priority: 'priority';

KW_clear_actions: 'clear_actions';
KW_write_actions: 'write_actions';
KW_idle_timeout: 'idle_timeout';
KW_hard_timeout: 'hard_timeout';

KW_importance: 'importance';
KW_send_flow_rem: 'send_flow_rem';
KW_check_overlap: 'check_overlap';
KW_out_port: 'out_port';
KW_out_group: 'out_group';

KW_duration: 'duration';
KW_n_packets: 'n_packets';
KW_n_bytes: 'n_bytes';
KW_hard_age: 'hard_age';
KW_idle_age: 'idle_age';


// bundle fiedls
KW_eth_src: 'eth_src';
//KW_nw_src
//KW_nw_dst
KW_symmetric_l4  : 'symmetric_l4';
KW_symmetric_l3l4: 'symmetric_l3l4';
KW_symmetric_l3l4_udp: 'symmetric_l3l4+udp';

// bundle algorithm
KW_active_backup: 'active_backup';
KW_hrw: 'hrw';


KW_slaves: 'slaves';
KW_ANY: 'ANY';
// bundle slave_type
KW_ofport: 'ofport';

KW_nat: 'nat';
KW_normal: 'NORMAL';

KW_group: 'group';
KW_vlan_tci: 'vlan_tci';
KW_metadata: 'metadata';
KW_userdata: 'userdata';


NXM_ID: 'NXM_' [a-zA-Z_0-9]+;
OXM_OF_METADATA: 'OXM_OF_METADATA';


// [0] added because of rulesets from 2015
KW_CONTROLLER: 'CONTROLLER';

//STRING_LITERAL:
// DBLQUOTE ( ANY_STR_CHARACTERS )* DBLQUOTE;

fragment COLON_SEPARATED_HEX_PART:
 (HEX_NUM COLON ( HEX_NUM )? ( COLON ( HEX_NUM )? )+ ( HEX_NUM )?)
 | COLON COLON BYTE_STRING // ipv4
 | COLON (COLON)+

;

COLON_SEPARATED_HEX_ADDR: COLON_SEPARATED_HEX_PART
 ('/' (DEC_NUM | COLON_SEPARATED_HEX_PART | '0' 'x' HEX_NUM) )?
;

PLUS: '+';
MINUS: '-';
DEC_NUM: [0-9]+;
HEX_NUM: [0-9a-fA-F]+;
TIME_NUM: DEC_NUM ('.' DEC_NUM)? 's';
BASED_HEX_NUM: '0' ('x' HEX_NUM)? ('/' '0' ('x' HEX_NUM) ?)?;
DEC_NUM_SLASH_DEC_NUM: DEC_NUM '/' DEC_NUM;

BYTE_STRING: HEX_NUM ('.' HEX_NUM)+ ('/' DEC_NUM )?;
LPAREN: '(';
RPAREN: ')';
LSQUARE_BR: '[';
RSQUARE_BR: ']';
COMMA: ',';
EQ: '=';
COLON: ':';
DDOT: '..';
ARROW_RIGHT: '->';

WHITE_SPACE: [ \t\r]+ -> skip;
NL: '\n';
// fallback for parser performance reasons
UNKNOWN_ID:  [a-zA-Z_][a-zA-Z_0-9]*;
ERROR_CHAR: .;