// SPDX-License-Identifier: GPL-2.0
#include "global_sidtab.h"
#include "sidtab.h"

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

int global_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid,
			gfp_t gfp)
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
	rc = sidtab_context_to_sid(&global_sidtab, &ctx, out_sid);
	if (rc == -ESTALE) {
		rcu_read_unlock();
		goto retry;
	}
	rcu_read_unlock();
	kfree(str);
	return rc;
}
