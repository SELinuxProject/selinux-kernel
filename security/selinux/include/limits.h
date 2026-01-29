/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Limits for various policy database elements.
 */

/*
 * Maximum supported depth of conditional expressions.
 */
#define COND_EXPR_MAXDEPTH 10

/*
 * Maximum supported depth for constraint expressions.
 */
#define CEXPR_MAXDEPTH 5

/*
 * Maximum supported identifier value.
 *
 * Reasoning: The most used symbols are types and they need to fit into
 *            an u16 for the avtab entries. Keep U16_MAX as special value
 *            and U16_MAX-1 to avoid accidental overflows into U16_MAX.
 */
#define IDENTIFIER_MAXVALUE (U16_MAX - 2)

/*
 * Maximum supported length of security context strings.
 *
 * Reasoning: The string must fir into a PAGE_SIZE.
 */
#define CONTEXT_MAXLENGTH 4000

/*
 * Maximum supported boolean name length.
 */
#define BOOLEAN_NAME_MAXLENGTH 64

/*
 * Maximum supported security class and common class name length.
 */
#define CLASS_NAME_MAXLENGTH 64

/*
 * Maximum supported permission name length.
 */
#define PERMISSION_NAME_MAXLENGTH 64

/*
 * Maximum supported user name length.
 */
#define USER_NAME_MAXLENGTH 64

/*
 * Maximum supported role name length.
 */
#define ROLE_NAME_MAXLENGTH 64

/*
 * Maximum supported type name length.
 */
#define TYPE_NAME_MAXLENGTH 1024

/*
 * Maximum supported sensitivity name length.
 */
#define SENSITIVITY_NAME_MAXLENGTH 32

/*
 * Maximum supported category name length.
 */
#define CATEGORY_NAME_MAXLENGTH 16

/*
 * Maximum supported path name length for keys in filename transitions.
 */
#define FILETRANSKEY_NAME_MAXLENGTH 1024

/*
 * Maximum supported filesystem name length.
 */
#define FILESYSTEM_NAME_MAXLENGTH 128

/*
 * Maximum supported path prefix length for genfs statements.
 */
#define GENFS_PATH_MAXLENGTH 1024

/*
 * Maximum supported Infiniband device name length.
 */
#define INFINIBAND_DEVNAME_MAXLENGTH 256
