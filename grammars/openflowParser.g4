/*
 * This is the grammar for OpenFlow records printed by ovs-ofctl tool (ovs-ofctl dump-flows <swith>)  
 * 
 * Parser/Lexer grammar build from info on ovs doc[1] + added missign features
 * from newer/older version which I required (2015-2019).
 * 
 * [1] https://www.openvswitch.org/support/dist-docs-2.5/ovs-ofctl.8.txt
 */

parser grammar openflowParser;

options { tokenVocab=openflowLexer;}


openflow_dump_text: (
	 of_record 
	 | (OF_OVS_OFCTL_HEADER | OF_NXST_FLOW_HEADER)? NL
 )* EOF;

of_record: of_record_item (COMMA? of_record_item)* NL;

of_record_item:
 KW_duration EQ TIME_NUM
 | ( 
     KW_in_port
     | KW_dl_vlan
     | KW_dl_vlan_pcp
     | KW_dl_type
     | KW_nw_proto
     | KW_ip_proto
     | KW_nw_tos
     | KW_ip_dscp
     | KW_nw_ecn
     | KW_ip_ecn
     | KW_nw_ttl
     | KW_icmp_type
     | KW_icmp_code
     | KW_table
     | KW_ipv6_label
     | KW_mpls_bos
     | KW_mpls_tc
     | KW_ct_zone
     | KW_n_packets
     | KW_n_bytes
     | KW_idle_age
     | KW_hard_age
     | KW_priority
     | KW_arp_op
     | KW_idle_timeout
     | KW_hard_timeout
     | KW_importance
    ) EQ optionaly_masked_int
 | (
 	KW_cookie
    | KW_vlan_tci
 	| KW_tcp_src
    | KW_tcp_dst
    | KW_udp_src
    | KW_udp_dst
    | KW_sctp_src
    | KW_sctp_dst
    | KW_tp_dst
    | KW_tp_src
    | KW_mpls_label
    | KW_tun_id
    | KW_tunnel_id
    | KW_tun_gbp_id   
	| KW_tun_gbp_flags
    | REG_ID
    | XREG_ID
	| KW_pkt_mark
	| KW_actset_output
	| KW_conj_id
	| KW_ct_mark
	| KW_ct_label
    | KW_metadata
    ) EQ optionaly_masked_int
 | KW_ct_state EQ (optionaly_masked_int | (ct_state_item)+)
 | (
    KW_nw_src
    | KW_nw_dst
    | KW_arp_spa
    | KW_arp_tpa
    | KW_tun_src
    | KW_tun_dst
    ) EQ BYTE_STRING // ipv4
 | (KW_ipv6_src 
    | KW_ipv6_dst
    | KW_nd_target
    ) EQ COLON_SEPARATED_HEX_ADDR // ipv6
 | (KW_dl_src
    | KW_dl_dst
    | KW_arp_sha
    | KW_arp_tha
    | KW_nd_sll
	| KW_nd_tll
    ) EQ COLON_SEPARATED_HEX_ADDR // eth_mac
 | of_record_tcp_flags
 | of_record_protocol
 | of_actions
 | ( KW_ip_frag | KW_nw_frag ) EQ frag_type
 | KW_tun_flags EQ (PLUS | MINUS) KW_oam
 | TUN_METADATA (EQ optionaly_masked_int)
 | KW_send_flow_rem
 | KW_check_overlap
 | KW_out_port EQ optionaly_masked_int
 | KW_out_group EQ optionaly_masked_int
;

tcp_flag_item:
	(PLUS | MINUS)? (
	 KW_TCP_FLAG_fin
	 | KW_TCP_FLAG_syn
	 | KW_TCP_FLAG_rst
	 | KW_TCP_FLAG_psh
	 | KW_TCP_FLAG_ack
	 | KW_TCP_FLAG_urg
	 | KW_TCP_FLAG_ece
	 | KW_TCP_FLAG_cwr
	 | KW_TCP_FLAG_ns
	);
of_record_tcp_flags:
  KW_tcp_flags EQ (
     BASED_HEX_NUM
     | (tcp_flag_item)+
  );
of_record_protocol:
	KW_ip
	| KW_ipv6
	| KW_icmp
	| KW_icmp6
	| KW_tcp
	| KW_tcp6
	| KW_udp
	| KW_udp6
	| KW_sctp
	| KW_sctp6
	| KW_arp
	| KW_rarp
	| KW_mpls
	| KW_mplsm
;
ct_state_item:
  (PLUS | MINUS) ct_state_flag;

ct_state_flag: 
	KW_new
	| KW_est
	| KW_rel
	| KW_rpl
	| KW_inv
	| KW_trk
;

of_actions: KW_actions EQ of_action_item (COMMA of_action_item)*;
of_action_item:
  KW_normal
  | KW_flood
  | KW_all
  | KW_local
  | KW_in_port
  | KW_strip_vlan
  | KW_drop
  | KW_pop_queue
  | KW_clone LPAREN of_action_clone_arg ( COMMA of_action_clone_arg )*  RPAREN
  | (KW_group
     | KW_mod_vlan_vid
     | KW_mod_vlan_pcp
     | KW_push_vlan
     | KW_push_mpls
     | KW_pop_mpls
     | KW_mod_tp_src
     | KW_mod_tp_dst
     | KW_mod_nw_tos
     | KW_mod_nw_ecn
     | KW_mod_nw_ttl
     | KW_set_tunnel
     | KW_set_tunnel64
     | KW_set_queue
     | KW_set_mpls_label
     | KW_set_mpls_tc
     | KW_set_mpls_ttl
    ) COLON optionaly_masked_int
  | KW_output COLON (
  		    any_reg
            | optionaly_masked_int
        )
  | (KW_mod_dl_src | KW_mod_dl_dst) COLON COLON_SEPARATED_HEX_ADDR // eth_mac
  | ( KW_mod_nw_dst | KW_mod_nw_src) COLON BYTE_STRING // ipv4
  | KW_enqueue LPAREN optionaly_masked_int COMMA optionaly_masked_int RPAREN
  | KW_CONTROLLER COLON DEC_NUM // [0]
  | of_action_controller
  | of_action_load
  | of_action_resubmit
  | of_action_ct
  | KW_dec_ttl (LPAREN (DEC_NUM (COMMA DEC_NUM)*)? RPAREN)?
  | KW_dec_mpls_ttl
  | of_action_note
  | of_action_move
  | of_action_set_field
  | of_action_push
  | of_action_pop
  | KW_multipath LPAREN RPAREN // [TODO] body
  | KW_bundle      LPAREN bundle_field COMMA optionaly_masked_int COMMA bundle_algorithm
                          COMMA KW_ofport COMMA bundle_slaves_value RPAREN
  | KW_bundle_load LPAREN bundle_field COMMA optionaly_masked_int COMMA bundle_algorithm
                          COMMA KW_ofport COMMA  field_name COMMA  bundle_slaves_value RPAREN
  | KW_learn LPAREN of_action_learn_argument (COMMA of_action_learn_argument)* RPAREN // [TODO] body
  | KW_clear_actions
  | KW_write_actions LPAREN RPAREN // [TODO] body
  | KW_write_metadata COLON optionaly_masked_int
  | KW_meter COLON DEC_NUM
  | KW_goto_table COLON DEC_NUM
  | KW_fin_timeout LPAREN fin_timeout_arg (COMMA fin_timeout_arg)* RPAREN // [TODO] body
  | KW_sample LPAREN RPAREN // [TODO] body
  | KW_exit
  | of_action_conjunction
;

fin_timeout_arg:
(KW_idle_timeout | KW_hard_timeout) EQ DEC_NUM
;

bundle_slaves_value:
    KW_slaves COLON (KW_ANY | DEC_NUM (COMMA  DEC_NUM)*)
;

of_action_learn_argument:
	( KW_idle_timeout
	  | KW_hard_timeout
	  | KW_fin_idle_timeout
	  | KW_fin_hard_timeout
	  | KW_table
	) EQ DEC_NUM
	| ( 
	   KW_priority
	   | KW_cookie
	  ) EQ optionaly_masked_int
	| KW_send_flow_rem
	| KW_delete_learned
	| field_name (EQ (
	                field_name
	                | any_value 
	                ))?
	| of_action_load
	| KW_output COLON field_name
;
of_action_load:
 KW_load COLON value_or_reg
      ARROW_RIGHT any_reg
;
of_action_clone_arg:
 KW_ct_clear
 | of_action_item
;

of_action_move:
    KW_move COLON any_reg
      ARROW_RIGHT any_reg
;
of_action_set_field:
    KW_set_field COLON any_value ARROW_RIGHT field_name;
of_action_pop:
    KW_pop COLON any_reg
;

of_action_push:
    KW_push COLON any_reg
;

of_action_conjunction:
KW_conjunction LPAREN DEC_NUM COMMA DEC_NUM_SLASH_DEC_NUM  RPAREN
;

any_value:
	optionaly_masked_int
	| COLON_SEPARATED_HEX_ADDR // ipv6, eth_mac
	| BYTE_STRING // ipv4
;

frag_type:
 KW_no        
 | KW_yes       
 | KW_first     
 | KW_later     
 | KW_not_later 
;

of_action_controller:
  KW_controller
  (
    LPAREN of_action_controller_item (COMMA of_action_controller_item)* RPAREN
    | LSQUARE_BR COLON DEC_NUM RSQUARE_BR
  )
;

of_action_controller_item:
  (KW_max_len | KW_id | KW_meter_id) EQ DEC_NUM
  | KW_reason EQ reason_value
  | KW_userdata EQ BYTE_STRING
  | KW_pause
;

reason_value:
	KW_action
	| KW_no_match
	| KW_invalid_ttl
;
of_action_ct_item:
    KW_commit
    | KW_force
    | KW_table EQ DEC_NUM
    | KW_zone EQ (DEC_NUM | any_reg)
    | KW_nat
    | of_action_ct_exec
    | KW_alg EQ alg
;
of_action_ct_exec: 
  KW_exec LPAREN of_action_item (COMMA of_action_item)* RPAREN;
 
of_action_ct:
  KW_ct LPAREN (of_action_ct_item (COMMA of_action_ct_item)*) RPAREN;

constant_index:
  DEC_NUM ( DDOT DEC_NUM)?;

of_action_resubmit:
  KW_resubmit (COLON optionaly_masked_int
               | LPAREN (optionaly_masked_int)? COMMA (DEC_NUM)? (COMMA KW_ct)? RPAREN // ct added for ruleset from vmware
               )
 ;
of_action_note:
  KW_note COLON BYTE_STRING;

field_name: 
   // [todo] (can not find full list of field names)
   any_reg
   | REG_ID
   | XREG_ID
   | OXM_OF_METADATA
   | TUN_METADATA
   | KW_eth_type
   | KW_nw_proto
   | KW_icmp_type
   | KW_icmp_code
   | UNKNOWN_ID
;

any_reg:
   (NXM_ID | OXM_OF_METADATA) (LSQUARE_BR (constant_index)? RSQUARE_BR)?
;

value_or_reg:
    optionaly_masked_int
     | (NXM_ID | OXM_OF_METADATA) LSQUARE_BR (constant_index)? RSQUARE_BR
;

bundle_field:
	KW_eth_src
	| KW_nw_src
	| KW_nw_dst
	| KW_symmetric_l4  
	| KW_symmetric_l3l4
	| KW_symmetric_l3l4_udp
;
bundle_algorithm:
    KW_active_backup
    | KW_hrw
;

optionaly_masked_int:
  DEC_NUM
  | BASED_HEX_NUM
;

alg:
  KW_ftp
  | KW_tftp
;