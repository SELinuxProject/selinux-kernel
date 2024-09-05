/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _SELINUX_SS_H_
#define _SELINUX_SS_H_

/*
 * SELinux security server policy-dependent interfaces.
 * Most callers should use the corresponding security_*() interfaces
 * from security.h instead in order to transparently map to/from
 * global SIDs.
 */

void selinux_ss_compute_av(struct selinux_state *state, u32 ssid, u32 tsid,
			   u16 tclass, struct av_decision *avd,
			   struct extended_perms *xperms);

void selinux_ss_compute_xperms_decision(struct selinux_state *state, u32 ssid,
					u32 tsid, u16 tclass, u8 driver,
					u8 base_perm,
					struct extended_perms_decision *xpermd);

void selinux_ss_compute_av_user(struct selinux_state *state, u32 ssid, u32 tsid,
				u16 tclass, struct av_decision *avd);

int selinux_ss_transition_sid(struct selinux_state *state, u32 ssid, u32 tsid,
			      u16 tclass, const struct qstr *qstr,
			      u32 *out_sid);

int selinux_ss_transition_sid_user(struct selinux_state *state, u32 ssid,
				   u32 tsid, u16 tclass, const char *objname,
				   u32 *out_sid);

int selinux_ss_member_sid(struct selinux_state *state, u32 ssid, u32 tsid,
			  u16 tclass, u32 *out_sid);

int selinux_ss_change_sid(struct selinux_state *state, u32 ssid, u32 tsid,
			  u16 tclass, u32 *out_sid);

int selinux_ss_sid_to_context(struct selinux_state *state, u32 sid,
			      char **scontext, u32 *scontext_len);

int selinux_ss_sid_to_context_force(struct selinux_state *state, u32 sid,
				    char **scontext, u32 *scontext_len);

int selinux_ss_sid_to_context_inval(struct selinux_state *state, u32 sid,
				    char **scontext, u32 *scontext_len);

int selinux_ss_context_to_sid(struct selinux_state *state, const char *scontext,
			      u32 scontext_len, u32 *out_sid, gfp_t gfp);

int selinux_ss_context_str_to_sid(struct selinux_state *state,
				  const char *scontext, u32 *out_sid,
				  gfp_t gfp);

int selinux_ss_context_to_sid_default(struct selinux_state *state,
				      const char *scontext, u32 scontext_len,
				      u32 *out_sid, u32 def_sid,
				      gfp_t gfp_flags);

int selinux_ss_context_to_sid_force(struct selinux_state *state,
				    const char *scontext, u32 scontext_len,
				    u32 *sid, gfp_t gfp);

int selinux_ss_get_user_sids(struct selinux_state *state, u32 callsid,
			     const char *username, u32 **sids, u32 *nel);

int selinux_ss_port_sid(struct selinux_state *state, u8 protocol, u16 port,
			u32 *out_sid);

int selinux_ss_ib_pkey_sid(struct selinux_state *state, u64 subnet_prefix,
			   u16 pkey_num, u32 *out_sid);

int selinux_ss_ib_endport_sid(struct selinux_state *state, const char *dev_name,
			      u8 port_num, u32 *out_sid);

int selinux_ss_netif_sid(struct selinux_state *state, char *name, u32 *if_sid);

int selinux_ss_node_sid(struct selinux_state *state, u16 domain, void *addr,
			u32 addrlen, u32 *out_sid);

int selinux_ss_validate_transition(struct selinux_state *state, u32 oldsid,
				   u32 newsid, u32 tasksid, u16 tclass);

int selinux_ss_validate_transition_user(struct selinux_state *state, u32 oldsid,
					u32 newsid, u32 tasksid, u16 tclass);

int selinux_ss_bounded_transition(struct selinux_state *state, u32 oldsid,
				  u32 newsid);

int selinux_ss_sid_mls_copy(struct selinux_state *state, u32 sid, u32 mls_sid,
			    u32 *new_sid);

int selinux_ss_net_peersid_resolve(struct selinux_state *state, u32 nlbl_sid,
				   u32 nlbl_type, u32 xfrm_sid, u32 *peer_sid);

int selinux_ss_fs_use(struct selinux_state *state, struct super_block *sb);

int selinux_ss_genfs_sid(struct selinux_state *state, const char *fstype,
			 const char *path, u16 sclass, u32 *sid);

int selinux_ss_policy_genfs_sid(struct selinux_policy *policy,
				const char *fstype, const char *path,
				u16 sclass, u32 *sid);

int selinux_ss_audit_rule_match(struct lsm_prop *prop, u32 field, u32 op,
				void *rule);

#ifdef CONFIG_NETLABEL
int selinux_ss_netlbl_secattr_to_sid(struct selinux_state *state,
				     struct netlbl_lsm_secattr *secattr,
				     u32 *sid);

int selinux_ss_netlbl_sid_to_secattr(struct selinux_state *state, u32 sid,
				     struct netlbl_lsm_secattr *secattr);
#endif

#endif /* _SELINUX_SS_H_ */
