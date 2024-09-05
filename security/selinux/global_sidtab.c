// SPDX-License-Identifier: GPL-2.0
#include "global_sidtab.h"
#include "sidtab.h"
#include "selinux_ss.h"
#include "audit.h"

static struct sidtab global_sidtab;

int global_sidtab_init(void)
{
	struct context ctx;
	int rc, sid;

	rc = sidtab_init(&global_sidtab);
	if (rc)
		return rc;

	memset(&ctx, 0, sizeof(ctx));
	for (sid = 1; sid <= SECINITSID_NUM; sid++) {
		const char *str = security_get_initial_sid_context(sid);

		if (!str)
			continue;
		ctx.str = (char *)str;
		ctx.len = strlen(str)+1;
		rc = sidtab_set_initial(&global_sidtab, sid, &ctx);
		if (rc)
			return rc;
	}

	return 0;
}

int global_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
	struct context *ctx;

	rcu_read_lock();
	ctx = sidtab_search_force(&global_sidtab, sid);
	if (!ctx) {
		rcu_read_unlock();
		*scontext = NULL;
		*scontext_len = 0;
		return -EINVAL;
	}
	*scontext_len = ctx->len;
	/*
	 * Could eliminate allocation + copy if callers do not free
	 * since the global sidtab entries are never freed.
	 * This however would not match the current expectation
	 * of callers of security_sid_to_context().
	 * TODO: Update all callers and get rid of this copy.
	 */
	*scontext = kstrdup(ctx->str, GFP_ATOMIC);
	if (!(*scontext)) {
		rcu_read_unlock();
		*scontext_len = 0;
		return -ENOMEM;
	}

	rcu_read_unlock();
	return 0;
}

int global_context_to_sid(struct selinux_state *state, u32 ss_sid,
			  const char *scontext, u32 scontext_len,
			  u32 *out_sid, gfp_t gfp)
{
	char *str;
	struct context ctx;
	int rc;

	if (!scontext_len)
		return -EINVAL;

	/*
	 * Could eliminate allocation + copy if callers were required to
	 * pass in a NUL-terminated string or if the context_cmp/cpy()
	 * functions did not assume that ctx.str is NUL-terminated.
	 * This however would not match the current expectation of
	 * callers of security_context_to_sid, particularly contexts
	 * fetched from xattr values or provided by the xattr APIs.
	 * TODO: Change context_cmp/cpy() or update all callers and
	 * get rid of this copy.
	 */
	str = kmemdup_nul(scontext, scontext_len, gfp);
	if (!str)
		return -ENOMEM;

	ctx.str = str;
	ctx.len = strlen(str)+1;

retry:
	rcu_read_lock();
	rc = sidtab_context_ss_to_sid(&global_sidtab, &ctx, state, ss_sid,
				      out_sid);
	if (rc == -ESTALE) {
		rcu_read_unlock();
		goto retry;
	}
	rcu_read_unlock();
	kfree(str);
	return rc;
}

static int map_global_sid_to_ss(struct selinux_state *state, u32 sid,
				u32 *ss_sid, gfp_t gfp)
{
	struct sidtab_entry *entry;
	int rc;
	char *scontext;
	u32 scontext_len;

	if (sid <= SECINITSID_NUM) {
		*ss_sid = sid;
		return 0;
	}

	rcu_read_lock();
	entry = sidtab_search_entry_force(&global_sidtab, sid);
	if (!entry) {
		rcu_read_unlock();
		return -EINVAL;
	}
	if (entry->state == state && entry->ss_sid) {
		*ss_sid = entry->ss_sid;
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	rc = global_sid_to_context(sid, &scontext, &scontext_len);
	if (rc)
		return rc;

	rc = selinux_ss_context_to_sid_force(state, scontext,
					     scontext_len, ss_sid, gfp);
	kfree(scontext);
	return rc;
}

static int map_ss_sid_to_global(struct selinux_state *state, u32 ss_sid,
				u32 *out_sid, gfp_t gfp)
{
	char *scontext;
	u32 scontext_len;
	int rc;

	if (ss_sid <= SECINITSID_NUM) {
		*out_sid = ss_sid;
		return 0;
	}

	rc = selinux_ss_sid_to_context_force(state, ss_sid, &scontext,
					     &scontext_len);
	if (rc)
		return rc;

	rc = global_context_to_sid(state, ss_sid, scontext, scontext_len,
				   out_sid, GFP_ATOMIC);
	kfree(scontext);
	return rc;
}

int security_sid_to_context(struct selinux_state *state, u32 sid,
			    char **scontext, u32 *scontext_len)
{
	// initial SID contexts have to be obtained from the policy, if initialized
	if (sid <= SECINITSID_NUM && selinux_initialized(state))
		return selinux_ss_sid_to_context(state, sid, scontext, scontext_len);

	return global_sid_to_context(sid, scontext, scontext_len);
}

int security_sid_to_context_valid(struct selinux_state *state, u32 sid,
			    char **scontext, u32 *scontext_len)
{
	int rc;
	u32 ss_sid;

	// Valid SID contexts have to be obtained from the policy, if initialized
	if (selinux_initialized(state)) {
		rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
		if (rc)
			return rc;
		return selinux_ss_sid_to_context(state, ss_sid, scontext,
						 scontext_len);
	}

	return global_sid_to_context(sid, scontext, scontext_len);
}

int security_sid_to_context_force(struct selinux_state *state, u32 sid,
				  char **scontext, u32 *scontext_len)
{
	// initial SID contexts have to be obtained from the policy, if initialized
	if (sid <= SECINITSID_NUM && selinux_initialized(state))
		return selinux_ss_sid_to_context_force(state, sid, scontext, scontext_len);

	return global_sid_to_context(sid, scontext, scontext_len);
}

int security_sid_to_context_inval(struct selinux_state *state, u32 sid,
				  char **scontext, u32 *scontext_len)
{
	int rc;
	u32 ss_sid;

	// TODO Cache invalid bit in global SID table so we do not need
	// to lookup in the per-policy one each time.
	if (selinux_initialized(state)) {
		rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
		if (rc)
			return rc;
		return selinux_ss_sid_to_context_inval(state, ss_sid, scontext,
						       scontext_len);
	}
	return global_sid_to_context(sid, scontext, scontext_len);
}

int security_context_to_sid(struct selinux_state *state, const char *scontext,
			    u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
	int rc;
	u32 sid, ss_sid = 0;
	char *ctx = NULL;

	/*
	 * If initialized, validate and canonicalize the context against
	 * the policy.
	 */
	if (selinux_initialized(state)) {
		rc = selinux_ss_context_to_sid(state, scontext, scontext_len,
					       &ss_sid, gfp);
		if (rc)
			return rc;

		rc = selinux_ss_sid_to_context(state, ss_sid, &ctx,
					       &scontext_len);
		if (rc)
			return rc;
		scontext = ctx;
	}

	// allocate or lookup a SID in the global SID table
	rc = global_context_to_sid(state, ss_sid, scontext, scontext_len,
				   &sid, gfp);
	if (rc)
		goto out;

	*out_sid = sid;

out:
	kfree(ctx);
	return rc;
}

int security_context_str_to_sid(struct selinux_state *state,
				const char *scontext, u32 *out_sid, gfp_t gfp)
{
	size_t scontext_len = strlen(scontext) + 1;

	return security_context_to_sid(state, scontext, scontext_len, out_sid,
				       gfp);
}

int security_context_to_sid_default(struct selinux_state *state,
				    const char *scontext, u32 scontext_len,
				    u32 *out_sid, u32 def_sid, gfp_t gfp)
{
	int rc;
	u32 sid, ss_sid = 0;
	char *ctx = NULL;

	/*
	 * If initialized, validate and canonicalize the context against
	 * the policy.
	 */
	if (selinux_initialized(state)) {
		rc = selinux_ss_context_to_sid_default(state, scontext,
						       scontext_len, &ss_sid,
						       def_sid, gfp);
		if (rc)
			return rc;

		rc = selinux_ss_sid_to_context(state, ss_sid, &ctx,
					       &scontext_len);
		if (rc)
			return rc;
		scontext = ctx;
	}

	// allocate or lookup a SID in the global SID table
	rc = global_context_to_sid(state, ss_sid, scontext, scontext_len,
				   &sid, gfp);
	if (rc)
		goto out;

	*out_sid = sid;

out:
	kfree(ctx);
	return rc;
}

int security_context_to_sid_force(struct selinux_state *state,
				  const char *scontext, u32 scontext_len,
				  u32 *out_sid)
{
	int rc;
	u32 sid, ss_sid = 0;
	char *ctx = NULL;

	/*
	 * If initialized, validate and canonicalize the context against
	 * the policy.
	 */
	if (selinux_initialized(state)) {
		rc = selinux_ss_context_to_sid_force(state, scontext,
						     scontext_len, &ss_sid,
						     GFP_KERNEL);
		if (rc)
			return rc;

		rc = selinux_ss_sid_to_context_force(state, ss_sid, &ctx,
						     &scontext_len);
		if (rc)
			return rc;
		scontext = ctx;
	}

	// allocate or lookup a SID in the global SID table
	rc = global_context_to_sid(state, ss_sid, scontext, scontext_len,
				   &sid, GFP_KERNEL);
	if (rc)
		goto out;

	*out_sid = sid;

out:
	kfree(ctx);
	return rc;
}

void security_compute_av(struct selinux_state *state, u32 ssid, u32 tsid,
			 u16 tclass, struct av_decision *avd,
			 struct extended_perms *xperms)
{
	u32 ss_ssid, ss_tsid;
	int rc;

	if (!selinux_initialized(state))
		goto allow;

	rc = map_global_sid_to_ss(state, ssid, &ss_ssid, GFP_ATOMIC);
	if (rc)
		goto deny;
	rc = map_global_sid_to_ss(state, tsid, &ss_tsid, GFP_ATOMIC);
	if (rc)
		goto deny;
	selinux_ss_compute_av(state, ss_ssid, ss_tsid, tclass, avd, xperms);
	return;
allow:
	avd->allowed = ~0U;
	goto out;
deny:
	avd->allowed = 0;
out:
	avd->auditallow = 0;
	avd->auditdeny = ~0U;
	avd->seqno = 0;
	avd->flags = 0;
	xperms->len = 0;
}

void security_compute_xperms_decision(struct selinux_state *state, u32 ssid,
				      u32 tsid, u16 tclass, u8 driver,
				      u8 base_perm,
				      struct extended_perms_decision *xpermd)
{
	u32 ss_ssid, ss_tsid;
	int rc;

	if (!selinux_initialized(state))
		goto allow;

	rc = map_global_sid_to_ss(state, ssid, &ss_ssid, GFP_ATOMIC);
	if (rc)
		goto deny;
	rc = map_global_sid_to_ss(state, tsid, &ss_tsid, GFP_ATOMIC);
	if (rc)
		goto deny;
	selinux_ss_compute_xperms_decision(state, ss_ssid, ss_tsid, tclass,
					   driver, base_perm, xpermd);
	return;
allow:
	memset(xpermd->allowed->p, 0xff, sizeof(xpermd->allowed->p));
	goto out;
deny:
	memset(xpermd->allowed->p, 0, sizeof(xpermd->allowed->p));
out:
	xpermd->driver = driver;
	xpermd->used = 0;
	memset(xpermd->auditallow->p, 0, sizeof(xpermd->auditallow->p));
	memset(xpermd->dontaudit->p, 0, sizeof(xpermd->dontaudit->p));
}

int security_transition_sid(struct selinux_state *state, u32 ssid, u32 tsid,
			    u16 tclass, const struct qstr *qstr, u32 *out_sid)
{
	u32 ss_ssid, ss_tsid, ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		switch (tclass) {
		case SECCLASS_PROCESS:
			*out_sid = ssid;
			break;
		default:
			*out_sid = tsid;
			break;
		}
		return 0;
	}

	rc = map_global_sid_to_ss(state, ssid, &ss_ssid, GFP_ATOMIC);
	if (rc)
		return rc;
	rc = map_global_sid_to_ss(state, tsid, &ss_tsid, GFP_ATOMIC);
	if (rc)
		return rc;
	rc = selinux_ss_transition_sid(state, ss_ssid, ss_tsid, tclass, qstr,
				       &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_port_sid(struct selinux_state *state, u8 protocol, u16 port,
		      u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		*out_sid = SECINITSID_PORT;
		return 0;
	}

	rc = selinux_ss_port_sid(state, protocol, port, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_ib_pkey_sid(struct selinux_state *state, u64 subnet_prefix,
			 u16 pkey_num, u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		*out_sid = SECINITSID_UNLABELED;
		return 0;
	}

	rc = selinux_ss_ib_pkey_sid(state, subnet_prefix, pkey_num, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_ib_endport_sid(struct selinux_state *state, const char *dev_name,
			    u8 port_num, u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		*out_sid = SECINITSID_UNLABELED;
		return 0;
	}

	rc = selinux_ss_ib_endport_sid(state, dev_name, port_num, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_netif_sid(struct selinux_state *state, char *name, u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		*out_sid = SECINITSID_NETIF;
		return 0;
	}

	rc = selinux_ss_netif_sid(state, name, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_node_sid(struct selinux_state *state, u16 domain, void *addr,
		      u32 addrlen, u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		*out_sid = SECINITSID_NODE;
		return 0;
	}

	rc = selinux_ss_node_sid(state, domain, addr, addrlen, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_validate_transition(struct selinux_state *state, u32 oldsid,
				 u32 newsid, u32 tasksid, u16 tclass)
{
	u32 ss_oldsid, ss_newsid, ss_tasksid;
	int rc;

	if (!selinux_initialized(state))
		return 0;

	rc = map_global_sid_to_ss(state, oldsid, &ss_oldsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	rc = map_global_sid_to_ss(state, newsid, &ss_newsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	rc = map_global_sid_to_ss(state, tasksid, &ss_tasksid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	return selinux_ss_validate_transition(state, ss_oldsid, ss_newsid,
					      ss_tasksid, tclass);
}

int security_bounded_transition(struct selinux_state *state, u32 oldsid,
				u32 newsid)
{
	u32 ss_oldsid, ss_newsid;
	int rc;

	if (!selinux_initialized(state))
		return 0;

	rc = map_global_sid_to_ss(state, oldsid, &ss_oldsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	rc = map_global_sid_to_ss(state, newsid, &ss_newsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	return selinux_ss_bounded_transition(state, ss_oldsid, ss_newsid);
}

int security_sid_mls_copy(struct selinux_state *state, u32 sid, u32 mls_sid,
			  u32 *out_sid)
{
	u32 ss_sid, ss_mlssid, ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		*out_sid = sid;
		return 0;
	}

	rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
	if (rc)
		return rc;
	rc = map_global_sid_to_ss(state, mls_sid, &ss_mlssid, GFP_ATOMIC);
	if (rc)
		return rc;

	rc = selinux_ss_sid_mls_copy(state, ss_sid, ss_mlssid, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_net_peersid_resolve(struct selinux_state *state, u32 nlbl_sid,
				 u32 nlbl_type, u32 xfrm_sid, u32 *out_sid)
{
	u32 ss_nlblsid, ss_xfrmsid, ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		if (xfrm_sid == SECSID_NULL) {
			*out_sid = nlbl_sid;
			return 0;
		}
		if (nlbl_sid == SECSID_NULL || nlbl_type == NETLBL_NLTYPE_UNLABELED) {
			*out_sid = xfrm_sid;
			return 0;
		}
		*out_sid = SECSID_NULL;
		return 0;
	}

	rc = map_global_sid_to_ss(state, nlbl_sid, &ss_nlblsid, GFP_ATOMIC);
	if (rc)
		return rc;
	rc = map_global_sid_to_ss(state, xfrm_sid, &ss_xfrmsid, GFP_ATOMIC);
	if (rc)
		return rc;

	rc = selinux_ss_net_peersid_resolve(state, ss_nlblsid, nlbl_type, ss_xfrmsid, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

// only required for (mis)use of superblock_security_struct + selinux_superblock() below.
// TODO Remove when security_fs_use() interface is repaired
#include "objsec.h"

int security_fs_use(struct selinux_state *state, struct super_block *sb)
{
	int rc;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);

	if (!selinux_initialized(state)) {
		sbsec->behavior = SECURITY_FS_USE_NONE;
		sbsec->sid = SECINITSID_UNLABELED;
		return 0;
	}

	// TODO - it was a mistake to have pushed direct access to
	// sbsec into a security server function. Fix both that
	// interface and here to explicitly return the behavior and
	// SID via parameters to be set in the sbsec by the caller.
	rc = selinux_ss_fs_use(state, sb);
	if (rc)
		return rc;

	if (sbsec->sid <= SECINITSID_NUM)
		return 0;

	return map_ss_sid_to_global(state, sbsec->sid, &sbsec->sid, GFP_ATOMIC);
}

int security_genfs_sid(struct selinux_state *state, const char *fstype,
		       const char *path, u16 sclass, u32 *out_sid)
{
	int rc;
	u32 ss_outsid;

	if (!selinux_initialized(state)) {
		*out_sid = SECINITSID_UNLABELED;
		return 0;
	}

	rc = selinux_ss_genfs_sid(state, fstype, path, sclass, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int selinux_policy_genfs_sid(struct selinux_policy *policy, const char *fstype,
			     const char *path, u16 sclass, u32 *out_sid)
{
	int rc;
	u32 ss_outsid;

	rc = selinux_ss_policy_genfs_sid(policy, fstype, path, sclass, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(current_selinux_state, ss_outsid, out_sid,
				    GFP_ATOMIC);
}

int selinux_audit_rule_match(struct lsm_prop *prop, u32 field, u32 op, void *vrule)
{
	int rc;
	struct lsm_prop local_prop;
	struct selinux_state *state = current_selinux_state;

	if (!selinux_initialized(state))
		return 0;

	rc = map_global_sid_to_ss(state, prop->selinux.secid,
				  &local_prop.selinux.secid, GFP_ATOMIC);
	if (rc)
		return -ENOENT;
	return selinux_ss_audit_rule_match(&local_prop, field, op, vrule);
}

#ifdef CONFIG_NETLABEL
int security_netlbl_secattr_to_sid(struct selinux_state *state,
				   struct netlbl_lsm_secattr *secattr,
				   u32 *out_sid)
{
	int rc;
	u32 ss_outsid;

	if (!selinux_initialized(state)) {
		*out_sid = SECSID_NULL;
		return 0;
	}

	// The secattr secid is a global SID
	if (secattr->flags & NETLBL_SECATTR_SECID) {
		*out_sid = secattr->attr.secid;
		return 0;
	}

	rc = selinux_ss_netlbl_secattr_to_sid(state, secattr, &ss_outsid);
	if (rc)
		return rc;

	return map_ss_sid_to_global(state, ss_outsid, out_sid, GFP_ATOMIC);
}

int security_netlbl_sid_to_secattr(struct selinux_state *state, u32 sid,
				   struct netlbl_lsm_secattr *secattr)
{
	int rc;
	u32 ss_sid;

	if (!selinux_initialized(state))
		return 0;

	rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
	if (rc)
		return rc;
	rc = selinux_ss_netlbl_sid_to_secattr(state, ss_sid, secattr);
	if (rc)
		return rc;

	// The secattr secid is a global SID.
	secattr->attr.secid = sid;
	secattr->flags |= NETLBL_SECATTR_SECID;
	return 0;
}
#endif
