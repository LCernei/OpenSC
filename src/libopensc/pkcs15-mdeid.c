/*
 * PKCS15 emulation layer for Moldova Identity card.
 *
 * Copyright (C) 2026, Liviu Cernei <cernei.liviu@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "internal.h"
#include "pkcs15.h"

static const struct sc_aid GENERIC_AID = {
		{0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x50, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63},
		14
};

static const struct sc_aid ESIGN_AID = {
		{0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E},
		15
};

/*
 * Fallback if EF.ODF (5031) cannot be read: the directory files it lists on
 * known cards (EF 7003 SKDF and EF 7006 DODF are empty there).
 */
static const struct {
	unsigned int type;
	unsigned int fid;
} mdeid_dfs[] = {
		{SC_PKCS15_AODF,	 0x7001},
		{SC_PKCS15_PRKDF, 0x7002},
		{SC_PKCS15_SKDF,	 0x7003},
		{SC_PKCS15_PUKDF, 0x7004},
		{SC_PKCS15_CDF,	0x7005},
		{SC_PKCS15_DODF,	 0x7006},
};

static int
mdeid_add_df(sc_pkcs15_card_t *p15card, unsigned int type, const u8 *fid)
{
	struct sc_path path;

	sc_path_set(&path, SC_PATH_TYPE_PATH, fid, 2, 0, -1);
	path.aid = GENERIC_AID;
	return sc_pkcs15_add_df(p15card, type, &path);
}

/*
 * EF.ODF entries are [type] { path { OCTET STRING fid } }, where the context
 * tag number equals the SC_PKCS15_*DF type.
 */
static int
mdeid_add_dfs_from_odf(sc_pkcs15_card_t *p15card)
{
	sc_context_t *ctx = p15card->card->ctx;
	struct sc_path path;
	u8 *buf = NULL;
	const u8 *p, *fid;
	size_t len = 0, left, fid_len;
	unsigned int cla, tag;
	int r, count = 0;

	sc_format_path("5031", &path);
	path.aid = GENERIC_AID;
	r = sc_pkcs15_read_file(p15card, &path, &buf, &len, 0);
	LOG_TEST_RET(ctx, r, "Could not read EF.ODF");

	p = buf;
	left = len;
	while (left > 0 && *p != 0x00) {
		const u8 *entry = p;
		size_t entry_len;

		r = sc_asn1_read_tag(&p, left, &cla, &tag, &entry_len);
		if (r != SC_SUCCESS || p == NULL || cla != (SC_ASN1_TAG_CONTEXT | SC_ASN1_TAG_CONSTRUCTED) ||
				tag > SC_PKCS15_AODF) {
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			break;
		}
		left -= (p - entry) + entry_len;
		fid = sc_asn1_find_tag(ctx, p, entry_len, 0x30, &fid_len);
		if (fid != NULL)
			fid = sc_asn1_find_tag(ctx, fid, fid_len, 0x04, &fid_len);
		p += entry_len;
		if (fid == NULL || fid_len != 2)
			continue;
		r = mdeid_add_df(p15card, tag, fid);
		if (r < 0)
			break;
		count++;
	}
	free(buf);
	if (r < 0)
		return r;
	return count > 0 ? SC_SUCCESS : SC_ERROR_OBJECT_NOT_FOUND;
}

/*
 * The AODF says min 6, but the card's PIN objects accept exactly
 * stored_length (8) bytes and the issuer's middleware only allows 8 digits,
 * so require 8. PIN QSCD (0A) is local to the eSIGN DF; the others work from
 * GENERIC.
 */
static void
mdeid_fix_pins(sc_pkcs15_card_t *p15card)
{
	struct sc_pkcs15_object *objs[8];
	int count, i;

	count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs,
			sizeof(objs) / sizeof(objs[0]));
	for (i = 0; i < count; i++) {
		struct sc_pkcs15_auth_info *info = objs[i]->data;

		if (info->attrs.pin.stored_length > info->attrs.pin.min_length)
			info->attrs.pin.min_length = info->attrs.pin.stored_length;
		if (info->attrs.pin.reference == 0x0A)
			sc_path_set(&info->path, SC_PATH_TYPE_DF_NAME,
					ESIGN_AID.value, ESIGN_AID.len, 0, 0);
	}
}

static int
mdeid_set_file_app(sc_pkcs15_card_t *p15card)
{
	sc_file_free(p15card->file_app);
	p15card->file_app = sc_file_new();
	if (p15card->file_app == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	return sc_path_set(&p15card->file_app->path, SC_PATH_TYPE_DF_NAME,
			GENERIC_AID.value, GENERIC_AID.len, 0, 0);
}

/*
 * The card's AODF sets each PIN's common authId to the PIN itself, while
 * sc_pkcs15_unblock_pin() looks up the PUK through that field. Point the
 * user PINs at the unblocking PIN instead.
 */
static int
mdeid_link_puk(sc_pkcs15_card_t *p15card)
{
	struct sc_pkcs15_object *objs[8];
	const struct sc_pkcs15_auth_info *puk = NULL;
	int count, i;

	count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs,
			sizeof(objs) / sizeof(objs[0]));
	if (count < 0)
		return count;

	for (i = 0; i < count; i++) {
		const struct sc_pkcs15_auth_info *info = objs[i]->data;

		if (info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN) {
			puk = info;
			break;
		}
	}
	if (puk == NULL)
		return SC_SUCCESS;

	for (i = 0; i < count; i++) {
		const struct sc_pkcs15_auth_info *info = objs[i]->data;

		if (info != puk)
			objs[i]->auth_id = puk->auth_id;
	}
	return SC_SUCCESS;
}

/*
 * EF 5032 is a PKCS#15 TokenInfo (manufacturer IDEMIA, label ASP_<serial>).
 * Use it for the version, flags and manufacturer; the label set before is
 * kept, and the serial is replaced by the ASCII value from EF D003 since the
 * parser hex-encodes the octet string.
 */
static int
mdeid_read_tokeninfo(sc_pkcs15_card_t *p15card)
{
	struct sc_path path;
	u8 *buf = NULL;
	size_t len = 0;
	int r;

	sc_format_path("5032", &path);
	path.aid = GENERIC_AID;
	r = sc_pkcs15_read_file(p15card, &path, &buf, &len, 0);
	if (r < 0)
		return r;
	r = sc_pkcs15_parse_tokeninfo(p15card->card->ctx, p15card->tokeninfo, buf, len);
	free(buf);
	return r;
}

/*
 * The PrKDF gives the key path as the certificate EF 0001, but the key is a
 * data object in the application. Keep only the AID so signing selects the
 * application instead of the certificate file.
 */
static void
mdeid_fix_prkey_paths(sc_pkcs15_card_t *p15card)
{
	struct sc_pkcs15_object *objs[8];
	int count, i;

	count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, objs,
			sizeof(objs) / sizeof(objs[0]));
	for (i = 0; i < count; i++) {
		struct sc_pkcs15_prkey_info *info = objs[i]->data;

		info->path.len = 0;
		info->path.type = SC_PATH_TYPE_DF_NAME;
	}
}

static int
mdeid_read_token_serial(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;
	struct sc_path path;
	u8 *serial_data = NULL;
	const u8 *serial_value;
	char *serial;
	size_t serial_data_len = 0;
	size_t serial_len = 0;
	int r;
	size_t i;

	sc_format_path("3F00", &path);
	LOG_TEST_RET(card->ctx, sc_select_file(card, &path, NULL), "SELECT MF for token serial");

	sc_format_path("D003", &path);
	r = sc_pkcs15_read_file(p15card, &path, &serial_data, &serial_data_len, 0);
	LOG_TEST_RET(card->ctx, r, "Could not read EF.D003");
	serial_value = sc_asn1_find_tag(card->ctx, serial_data, serial_data_len, 0x5A, &serial_len);
	if (serial_value == NULL || serial_len == 0) {
		free(serial_data);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	for (i = 0; i < serial_len; i++) {
		if (!isxdigit((unsigned char)serial_value[i])) {
			free(serial_data);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}
	}

	serial = malloc(serial_len + 1);
	if (serial == NULL) {
		free(serial_data);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(serial, serial_value, serial_len);
	serial[serial_len] = '\0';
	free(serial_data);
	free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = serial;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
sc_pkcs15emu_mdeid_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;
	struct sc_pkcs15_df *df;
	int r;
	size_t i;

	LOG_FUNC_CALLED(card->ctx);

	set_string(&p15card->tokeninfo->label, "Moldova eID");
	r = mdeid_read_tokeninfo(p15card);
	if (r < 0)
		sc_log(card->ctx, "Could not read MDeID TokenInfo: %s", sc_strerror(r));
	/* A TokenInfo parse error clears the label set above. */
	if (p15card->tokeninfo->label == NULL)
		set_string(&p15card->tokeninfo->label, "Moldova eID");
	r = mdeid_read_token_serial(p15card);
	if (r < 0)
		sc_log(card->ctx, "Could not read MDeID token serial: %s", sc_strerror(r));

	r = mdeid_set_file_app(p15card);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Could not set MDeID application path");

	r = mdeid_add_dfs_from_odf(p15card);
	if (r < 0)
		sc_log(card->ctx, "MDeID EF.ODF not usable: %s", sc_strerror(r));
	for (i = 0; p15card->df_list == NULL && i < sizeof(mdeid_dfs) / sizeof(mdeid_dfs[0]); i++) {
		u8 fid[2] = {mdeid_dfs[i].fid >> 8, mdeid_dfs[i].fid & 0xFF};

		r = mdeid_add_df(p15card, mdeid_dfs[i].type, fid);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not add MDeID DF");
	}

	for (df = p15card->df_list; df != NULL; df = df->next) {
		r = sc_pkcs15_parse_df(p15card, df);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not parse MDeID DF");
	}

	r = mdeid_link_puk(p15card);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Could not link MDeID PINs to PUK");

	mdeid_fix_prkey_paths(p15card);
	mdeid_fix_pins(p15card);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

err:
	sc_pkcs15_card_clear(p15card);
	LOG_FUNC_RETURN(card->ctx, r);
}

int
sc_pkcs15emu_mdeid_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	if (p15card->card->type == SC_CARD_TYPE_MDEID_2025) {
		return sc_pkcs15emu_mdeid_init(p15card);
	}
	return SC_ERROR_WRONG_CARD;
}
