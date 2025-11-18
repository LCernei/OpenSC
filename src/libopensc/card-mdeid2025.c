/*
 * Driver for Moldova Identity Card issued from March 2025.
 *
 * Copyright (C) 2025, Liviu Cernei <cernei.liviu@gmail.com>
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

#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "gp.h"
#include "internal.h"

static const struct sc_atr_table mdeid_atrs[] = {
		{"3b:df:96:00:81:31:fe:45:80:73:84:21:e0:57:4d:44:41:5f:41:53:50:81:0f:78", NULL, "MDeID", SC_CARD_TYPE_MDEID_2025, 0, NULL},
		{NULL,								      NULL, NULL,	   0,			      0, NULL}
};

static const struct sc_aid INIT_AID = {
		{0xA0, 0x00, 0x00, 0x00, 0x77, 0x03, 0x0C, 0x60, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x05, 0x00},
		16
};

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations mdeid_ops;

static struct sc_card_driver mdeid_driver = {"MDeID 2025", "mdeid2025", &mdeid_ops, NULL, 0, NULL};

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
		return 1;
	}

	return 0;
}

static int
mdeid_select_file(sc_card_t *card, const struct sc_path *in_path, struct sc_file **file_out)
{
	const u8 *path = in_path->value;
	u8 resp[SC_MAX_APDU_RESP_SIZE];
	size_t resplen = sizeof(resp);
	int r;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	if (in_path->len % 2 != 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (in_path->len == 2 && memcmp(path, "\x3F\x00", 2) == 0) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x00, 0x0C, path, 0, NULL, 0);
		SC_TRANSMIT_TEST_RET(card, apdu, "MF select failed");
		return SC_SUCCESS;
	}

	if (path[0] == 0xE8 || path[0] == 0x87) {
		sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x04, 0x04, path, in_path->len, NULL, 0);
		SC_TRANSMIT_TEST_RET(card, apdu, "DF select failed");
		return SC_SUCCESS;
	}

	sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x02, 0x04, path, in_path->len, resp, resplen);
	SC_TRANSMIT_TEST_RET(card, apdu, "EF select failed");

	if (file_out != NULL) {
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		r = iso_ops->process_fci(card, file, resp, resplen);
		if (r != SC_SUCCESS) {
			sc_file_free(file);
		} else {
			*file_out = file;
		}
		LOG_TEST_RET(card->ctx, r, "Process fci failed");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
mdeid_logout(sc_card_t *card)
{
	return gp_select_aid(card, &INIT_AID);
}

struct sc_card_driver *
sc_get_mdeid2025_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	mdeid_ops = *iso_drv->ops;
	mdeid_ops.match_card = mdeid_match_card;
	mdeid_ops.select_file = mdeid_select_file;

	mdeid_ops.logout = mdeid_logout;

	return &mdeid_driver;
}
