/*
 * Driver for Moldova Identity Card.
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
#include "common/constant-time.h"
#include "gp.h"
#include "internal.h"
#include "pkcs15.h"

static const struct sc_atr_table mdeid_atrs[] = {
		{"3b:df:96:00:81:31:fe:45:80:73:84:21:e0:57:4d:44:41:5f:41:53:50:81:0f:78", NULL, "MDeID", SC_CARD_TYPE_MDEID_2025, 0, NULL},
		{NULL,								      NULL, NULL,	   0,			      0, NULL}
};

static const struct sc_aid INIT_AID = {
		{0xA0, 0x00, 0x00, 0x00, 0x77, 0x03, 0x0C, 0x60, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x05, 0x00},
		16
};

static const u8 GENERIC_DF[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x50, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63};
static const u8 ESIGN_DF[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E};

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations mdeid_ops;

static struct sc_card_driver mdeid_driver = {"MDeID 2025", "mdeid", &mdeid_ops, NULL, 0, NULL};

#define SC_TRANSMIT_TEST_RET(card, apdu, text) \
	do { \
		LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed"); \
		LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), text); \
	} while (0)

static int
mdeid_match_card(sc_card_t *card)
{
	LOG_FUNC_CALLED(card->ctx);

	int i = _sc_match_atr(card, mdeid_atrs, &card->type);

	if (i >= 0 && gp_select_aid(card, &INIT_AID) == SC_SUCCESS) {
		card->name = mdeid_atrs[i].name;
		LOG_FUNC_RETURN(card->ctx, 1);
	}

	LOG_FUNC_RETURN(card->ctx, 0);
}

static int
mdeid_process_fci(sc_card_t *card, const u8 *resp, size_t resplen, struct sc_file **file_out)
{
	struct sc_file *file;
	int r;

	if (file_out == NULL)
		return SC_SUCCESS;

	file = sc_file_new();
	if (file == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	r = iso_ops->process_fci(card, file, resp, resplen);
	if (r != SC_SUCCESS) {
		sc_file_free(file);
		return r;
	}
	*file_out = file;
	return SC_SUCCESS;
}

static int
mdeid_select_file(sc_card_t *card, const struct sc_path *in_path, struct sc_file **file_out)
{
	const u8 *path;
	u8 resp[SC_MAX_APDU_RESP_SIZE];
	size_t resplen = sizeof(resp);
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	if (in_path == NULL || in_path->len > SC_MAX_PATH_SIZE ||
			in_path->aid.len > sizeof(in_path->aid.value)) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	if (in_path->type != SC_PATH_TYPE_DF_NAME && (in_path->len % 2) != 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	path = in_path->value;

	if (in_path->aid.len > 0) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x04, 0x04,
				in_path->aid.value, in_path->aid.len, resp, sizeof(resp));
		SC_TRANSMIT_TEST_RET(card, apdu, "Application select failed");
		if (in_path->len == 0) {
			LOG_TEST_RET(card->ctx,
					mdeid_process_fci(card, resp, apdu.resplen, file_out),
					"Process application FCI failed");
			LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		}
	}

	if (in_path->len == 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (in_path->type == SC_PATH_TYPE_PATH && in_path->len == 2 &&
			memcmp(path, "\x3F\x00", 2) == 0) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x00, 0x0C, path, in_path->len, NULL, 0);
		SC_TRANSMIT_TEST_RET(card, apdu, "MF select failed");
		if (file_out != NULL) {
			struct sc_file *file = sc_file_new();
			if (file == NULL)
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
			file->id = 0x3F00;
			file->type = SC_FILE_TYPE_DF;
			*file_out = file;
		}
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	if (in_path->type == SC_PATH_TYPE_DF_NAME ||
			(in_path->type == SC_PATH_TYPE_PATH && in_path->len > 0 && path[0] == 0xE8)) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x04, 0x04, path, in_path->len, resp, resplen);
		SC_TRANSMIT_TEST_RET(card, apdu, "DF select failed");
		LOG_TEST_RET(card->ctx,
				mdeid_process_fci(card, resp, apdu.resplen, file_out),
				"Process DF FCI failed");
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	if (in_path->len == 2 && (in_path->type == SC_PATH_TYPE_PATH ||
						 in_path->type == SC_PATH_TYPE_FILE_ID)) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x02, 0x04, path, in_path->len, resp, resplen);
		SC_TRANSMIT_TEST_RET(card, apdu, "EF select failed");
		LOG_TEST_RET(card->ctx,
				mdeid_process_fci(card, resp, apdu.resplen, file_out),
				"Process EF FCI failed");
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	if (in_path->type == SC_PATH_TYPE_FROM_CURRENT) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x09, 0x04,
				path, in_path->len, resp, resplen);
		SC_TRANSMIT_TEST_RET(card, apdu, "Relative path select failed");
		LOG_TEST_RET(card->ctx,
				mdeid_process_fci(card, resp, apdu.resplen, file_out),
				"Process relative path FCI failed");
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	if (in_path->type == SC_PATH_TYPE_PATH) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4,
				in_path->aid.len > 0 ? 0x09 : 0x08, 0x04,
				path, in_path->len, resp, resplen);
		SC_TRANSMIT_TEST_RET(card, apdu, "Path select failed");
		LOG_TEST_RET(card->ctx,
				mdeid_process_fci(card, resp, apdu.resplen, file_out),
				"Process path FCI failed");
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

/*
 * PIN and PUK (03, 04) are global MF objects. PIN QSCD (0A) is local to the
 * eSIGN DF and PIN ENC (0B) to the GENERIC DF, so select those first.
 */
static int
mdeid_select_pin_df(sc_card_t *card, int pin_reference)
{
	struct sc_path path;

	if (pin_reference == 0x0A)
		sc_path_set(&path, SC_PATH_TYPE_DF_NAME, ESIGN_DF, sizeof(ESIGN_DF), 0, 0);
	else if (pin_reference == 0x0B)
		sc_path_set(&path, SC_PATH_TYPE_DF_NAME, GENERIC_DF, sizeof(GENERIC_DF), 0, 0);
	else if (pin_reference == 0x03 || pin_reference == 0x04)
		sc_format_path("3F00", &path);
	else
		return SC_ERROR_NOT_SUPPORTED;
	return sc_select_file(card, &path, NULL);
}

static int
mdeid_logout(sc_card_t *card)
{
	return gp_select_aid(card, &INIT_AID);
}

/*
 * A card reset deselects the main application, and selecting GENERIC or eSIGN
 * by name then fails with 6A86, so select it again.
 */
static int
mdeid_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	if (was_reset > 0)
		r = gp_select_aid(card, &INIT_AID);

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * GET DATA on the PIN data object (BF 81 <ref>) in the PIN's own DF:
 * tag 9A is the maximum and 9B the remaining number of tries.
 */
static int
mdeid_pin_get_info(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	u8 cmd[] = {0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, 0x00, 0x02, 0xA0, 0x80};
	u8 resp[SC_MAX_APDU_RESP_SIZE];
	const u8 *p;
	size_t len;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	LOG_TEST_RET(card->ctx, mdeid_select_pin_df(card, data->pin_reference),
			"PIN DF select failed");

	cmd[6] = (u8)data->pin_reference;
	sc_format_apdu_ex(&apdu, card->cla, 0xCB, 0x3F, 0xFF, cmd, sizeof(cmd), resp, sizeof(resp));
	SC_TRANSMIT_TEST_RET(card, apdu, "GET DATA PIN info failed");

	p = sc_asn1_find_tag(card->ctx, resp, apdu.resplen, 0x70, &len);
	if (p != NULL)
		p = sc_asn1_find_tag(card->ctx, p, len, 0xBF8100 | data->pin_reference, &len);
	if (p != NULL)
		p = sc_asn1_find_tag(card->ctx, p, len, 0xA0, &len);
	if (p == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	{
		size_t max_len = 0, left_len = 0;
		const u8 *max = sc_asn1_find_tag(card->ctx, p, len, 0x9A, &max_len);
		const u8 *left = sc_asn1_find_tag(card->ctx, p, len, 0x9B, &left_len);

		if (max == NULL || left == NULL || max_len != 1 || left_len != 1)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		data->pin1.max_tries = *max;
		data->pin1.tries_left = *left;
	}
	data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
mdeid_pin_cmd_one(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	int pin_reference = data->pin_reference;
	int r;

	/*
	 * Local PINs need their DF. CHANGE/RESET of the global PIN/PUK use the
	 * high-bit reference (83/84), which the card only resolves with the MF
	 * selected; VERIFY 03/04 works from any DF.
	 */
	if (pin_reference == 0x0A || pin_reference == 0x0B || data->cmd != SC_PIN_CMD_VERIFY)
		LOG_TEST_RET(card->ctx, mdeid_select_pin_df(card, pin_reference),
				"PIN DF select failed");

	data->pin1.encoding = SC_PIN_ENCODING_ASCII;
	data->pin2.encoding = SC_PIN_ENCODING_ASCII;

	/*
	 * Unblock by verifying the PUK first, then RESET RETRY COUNTER with the
	 * new PIN only (P1 = 02).
	 */
	if (data->cmd == SC_PIN_CMD_UNBLOCK && data->pin1.len > 0 && data->puk_reference > 0) {
		struct sc_pin_cmd_data verify = *data;

		verify.cmd = SC_PIN_CMD_VERIFY;
		verify.pin_reference = data->puk_reference;
		memset(&verify.pin2, 0, sizeof(verify.pin2));
		r = iso_ops->pin_cmd(card, &verify);
		data->pin1.tries_left = verify.pin1.tries_left;
		LOG_TEST_RET(card->ctx, r, "PUK verification failed");

		data->pin1.data = NULL;
		data->pin1.len = 0;
	}

	/* VERIFY uses 03/04 as is; local PINs and CHANGE/RESET use the high-bit
	 * form (83, 84, 8A, 8B). */
	if (data->cmd == SC_PIN_CMD_CHANGE || data->cmd == SC_PIN_CMD_UNBLOCK ||
			(data->cmd == SC_PIN_CMD_VERIFY &&
					(data->pin_reference == 0x0A || data->pin_reference == 0x0B)))
		data->pin_reference |= 0x80;

	r = iso_ops->pin_cmd(card, data);
	data->pin_reference = pin_reference;
	return r;
}

/*
 * The issuer's middleware keeps PIN, PIN QSCD and PIN ENC identical. Do the
 * same: a change or unblock of PIN (03) is applied to 0A, 0B and finally 03,
 * so a failure leaves the main PIN untouched.
 */
static int
mdeid_pin_cmd_all(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	static const int sync_refs[] = {0x0A, 0x0B, 0x03};
	size_t i;
	int r = SC_SUCCESS;

	for (i = 0; i < sizeof(sync_refs) / sizeof(sync_refs[0]); i++) {
		struct sc_pin_cmd_data one = *data;

		one.pin_reference = sync_refs[i];
		r = mdeid_pin_cmd_one(card, &one);
		data->pin1.tries_left = one.pin1.tries_left;
		if (r < 0) {
			sc_log(card->ctx, "PIN %s failed for reference 0x%02X",
					data->cmd == SC_PIN_CMD_CHANGE ? "change" : "unblock", sync_refs[i]);
			break;
		}
	}
	return r;
}

/* VERIFY without data reports the state of PIN (03) and does not use a try. */
static int
mdeid_pin_is_verified(sc_card_t *card)
{
	struct sc_apdu apdu;

	sc_format_apdu_ex(&apdu, card->cla, 0x20, 0x00, 0x03, NULL, 0, NULL, 0);
	return sc_transmit_apdu(card, &apdu) == SC_SUCCESS && apdu.sw1 == 0x90 && apdu.sw2 == 0x00;
}

/*
 * Check the old PIN on 03 first, so that a wrong one costs a try there and not
 * on PIN QSCD. Do not leave 03 verified if it was not verified before.
 */
static int
mdeid_change_pin(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	struct sc_pin_cmd_data verify = *data;
	int was_verified = mdeid_pin_is_verified(card);
	int r;

	verify.cmd = SC_PIN_CMD_VERIFY;
	memset(&verify.pin2, 0, sizeof(verify.pin2));
	r = mdeid_pin_cmd_one(card, &verify);
	data->pin1.tries_left = verify.pin1.tries_left;
	LOG_TEST_RET(card->ctx, r, "Old PIN verification failed");

	r = mdeid_pin_cmd_all(card, data);
	if (r < 0) {
		/* The old PIN is correct: this error and counter are not those of 03. */
		data->pin1.tries_left = -1;
		if (r == SC_ERROR_PIN_CODE_INCORRECT || r == SC_ERROR_AUTH_METHOD_BLOCKED)
			r = SC_ERROR_CARD_CMD_FAILED;
	}

	if (!was_verified && mdeid_logout(card) < 0)
		sc_log(card->ctx, "Logout after PIN change failed");

	return r;
}

static int
mdeid_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	size_t i;
	int r;

	if (data->cmd == SC_PIN_CMD_GET_INFO)
		return mdeid_pin_get_info(card, data);

	/*
	 * A change or unblock takes several commands and a pinpad would prompt for
	 * each, so use the given values or refuse.
	 */
	if ((data->cmd == SC_PIN_CMD_CHANGE || data->cmd == SC_PIN_CMD_UNBLOCK) &&
			(data->flags & SC_PIN_CMD_USE_PINPAD)) {
		if (data->pin1.len == 0 || data->pin2.len == 0)
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "PIN change and unblock need both values");
		data->flags &= ~SC_PIN_CMD_USE_PINPAD;
	}

	/*
	 * The issuer's middleware only accepts digits for the user PINs; do not
	 * set other values. The PUK (04) is alphanumeric.
	 */
	if ((data->cmd == SC_PIN_CMD_CHANGE || data->cmd == SC_PIN_CMD_UNBLOCK) &&
			data->pin_reference != 0x04 && data->pin2.data != NULL) {
		for (i = 0; i < data->pin2.len; i++) {
			if (!isdigit(data->pin2.data[i]))
				LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "New PIN must be digits only");
		}
	}

	if (data->cmd == SC_PIN_CMD_CHANGE && data->pin_reference == 0x03) {
		r = mdeid_change_pin(card, data);
	} else if (data->cmd == SC_PIN_CMD_UNBLOCK) {
		if (data->pin_reference == 0x03)
			r = mdeid_pin_cmd_all(card, data);
		else
			r = mdeid_pin_cmd_one(card, data);
		/* A verified PUK allows setting a new PIN, so never leave it verified. */
		if (mdeid_logout(card) < 0)
			sc_log(card->ctx, "Logout after PIN unblock failed");
	} else {
		r = mdeid_pin_cmd_one(card, data);
		if (data->cmd == SC_PIN_CMD_CHANGE && data->pin_reference == 0x04 && mdeid_logout(card) < 0)
			sc_log(card->ctx, "Logout after PUK change failed");
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * The PuKDF path points at the certificate EF, so read the key from the
 * public key data object instead: GET DATA BF A0 <ref> / 7F49 {81 n, 82 e}.
 */
static int
mdeid_read_public_key(sc_card_t *card, unsigned int algorithm, struct sc_path *path,
		unsigned int key_reference, unsigned int modulus_length, u8 **out, size_t *out_len)
{
	u8 cmd[] = {0x4D, 0x09, 0x70, 0x07, 0xBF, 0xA0, 0x00, 0x03, 0x7F, 0x49, 0x80};
	u8 resp[1024]; /* 70 { BF A0 xx { 7F49 { 81 n, 82 e } } } for RSA-4096 */
	struct sc_pkcs15_pubkey_rsa rsa = {0};
	struct sc_path app = {0};
	struct sc_apdu apdu;
	const u8 *p, *n = NULL, *e = NULL;
	size_t len, n_len = 0, e_len = 0;

	LOG_FUNC_CALLED(card->ctx);

	if (algorithm != SC_ALGORITHM_RSA || key_reference > 0x7F)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	if (path != NULL && path->aid.len > 0) {
		app.aid = path->aid;
		LOG_TEST_RET(card->ctx, sc_select_file(card, &app, NULL), "Application select failed");
	}

	cmd[6] = (u8)key_reference;
	sc_format_apdu_ex(&apdu, card->cla, 0xCB, 0x3F, 0xFF, cmd, sizeof(cmd), resp, sizeof(resp));
	apdu.le = 0x100;
	SC_TRANSMIT_TEST_RET(card, apdu, "GET DATA public key failed");

	p = sc_asn1_find_tag(card->ctx, resp, apdu.resplen, 0x70, &len);
	if (p != NULL)
		p = sc_asn1_find_tag(card->ctx, p, len, 0xBFA000 | key_reference, &len);
	if (p != NULL)
		p = sc_asn1_find_tag(card->ctx, p, len, 0x7F49, &len);
	if (p != NULL) {
		n = sc_asn1_find_tag(card->ctx, p, len, 0x81, &n_len);
		e = sc_asn1_find_tag(card->ctx, p, len, 0x82, &e_len);
	}
	if (p == NULL || n == NULL || e == NULL || n_len == 0 || e_len == 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	rsa.modulus.data = (u8 *)n;
	rsa.modulus.len = n_len;
	rsa.exponent.data = (u8 *)e;
	rsa.exponent.len = e_len;
	LOG_TEST_RET(card->ctx, sc_pkcs15_encode_pubkey_rsa(card->ctx, &rsa, out, out_len),
			"Encode RSA public key failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
mdeid_init(sc_card_t *card)
{
	/* RSA-4096 key; the card handles PKCS#1 padding for sign and decrypt. */
	_sc_card_add_rsa_alg(card, 4096,
			SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02 |
					SC_ALGORITHM_RSA_HASH_NONE,
			0);
	return SC_SUCCESS;
}

/*
 * Signing: MSE SET AT (41 A4) with key reference | 0x80 (local) and
 * algorithm 02 (RSA PKCS#1), then INTERNAL AUTHENTICATE over the DigestInfo.
 * Decryption: MSE SET CT (41 B8) with algorithm 1A, then PSO DECIPHER.
 */
static int
mdeid_set_security_env(sc_card_t *card, const struct sc_security_env *env, int se_num)
{
	u8 crt[] = {0x84, 0x01, 0x00, 0x80, 0x01, 0x02};
	u8 p2;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	if (env->operation == SC_SEC_OPERATION_SIGN ||
			env->operation == SC_SEC_OPERATION_AUTHENTICATE) {
		p2 = 0xA4;
	} else if (env->operation == SC_SEC_OPERATION_DECIPHER) {
		p2 = 0xB8;
		crt[5] = 0x1A;
	} else {
		return iso_ops->set_security_env(card, env, se_num);
	}

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || env->key_ref_len != 1)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Missing key reference");

	crt[2] = env->key_ref[0] | 0x80;
	sc_format_apdu_ex(&apdu, card->cla, 0x22, 0x41, p2, crt, sizeof(crt), NULL, 0);
	SC_TRANSMIT_TEST_RET(card, apdu, "MSE SET failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
mdeid_compute_signature(sc_card_t *card, const u8 *data, size_t datalen, u8 *out, size_t outlen)
{
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu_ex(&apdu, card->cla, 0x88, 0x00, 0x00, data, datalen, out, outlen);
	apdu.le = 0x100;
	SC_TRANSMIT_TEST_RET(card, apdu, "INTERNAL AUTHENTICATE failed");

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

/*
 * PSO DECIPHER with padding indicator 81, as in the IAS-ECC driver. The body
 * is sent with command chaining; the card strips the PKCS#1 padding, so any
 * failure other than 6982 (PIN not verified) is reported as wrong padding:
 * callers handle that in constant time. Do not log the result.
 */
static int
mdeid_decipher(sc_card_t *card, const u8 *crgram, size_t crgram_len, u8 *out, size_t outlen)
{
	u8 sbuf[1 + 512]; /* padding indicator + RSA-4096 cryptogram */
	struct sc_apdu apdu;
	unsigned int ok;

	LOG_FUNC_CALLED(card->ctx);

	if (crgram_len + 1 > sizeof(sbuf))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	sbuf[0] = 0x81;
	memcpy(sbuf + 1, crgram, crgram_len);

	sc_format_apdu_ex(&apdu, card->cla, 0x2A, 0x80, 0x86, sbuf, crgram_len + 1, out, outlen);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.le = 0x100;
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	if (apdu.sw1 == 0x69 && apdu.sw2 == 0x82)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);

	ok = constant_time_eq((apdu.sw1 << 8) | apdu.sw2, 0x9000);
	return (int)constant_time_select(ok, (unsigned int)apdu.resplen, (unsigned int)SC_ERROR_WRONG_PADDING);
}

struct sc_card_driver *
sc_get_mdeid_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	mdeid_ops = *iso_drv->ops;
	mdeid_ops.match_card = mdeid_match_card;
	mdeid_ops.init = mdeid_init;
	mdeid_ops.select_file = mdeid_select_file;
	mdeid_ops.set_security_env = mdeid_set_security_env;
	mdeid_ops.compute_signature = mdeid_compute_signature;
	mdeid_ops.decipher = mdeid_decipher;

	mdeid_ops.logout = mdeid_logout;
	mdeid_ops.card_reader_lock_obtained = mdeid_card_reader_lock_obtained;
	mdeid_ops.pin_cmd = mdeid_pin_cmd;
	mdeid_ops.read_public_key = mdeid_read_public_key;

	return &mdeid_driver;
}
