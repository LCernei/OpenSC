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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "opensc.h"
#include "pkcs15.h"

static const struct sc_aid GENERIC_AID = {
		{0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x50, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63},
		14
};

static int
sc_pkcs15emu_mdeid_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;
	int r;

	r = iso7816_select_aid(card, GENERIC_AID.value, GENERIC_AID.len, NULL, NULL);
	LOG_TEST_RET(card->ctx, r, "SELECT GENERIC_AID");

	struct sc_pkcs15_cert_info cert_info = {
			.id = {.len = 1, .value[0] = 1}
	       };
	struct sc_pkcs15_object cert_obj = {0};

	strlcpy(cert_obj.label, "CertCetatean", sizeof(cert_obj.label));

	sc_format_path("00 01", &cert_info.path);
	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Could not add cert object");

	LOG_FUNC_RETURN(p15card->card->ctx, r);

err:
	sc_pkcs15_card_clear(p15card);
	LOG_FUNC_RETURN(p15card->card->ctx, r);
}

int sc_pkcs15emu_mdeid_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid) {
	if (p15card->card->type == SC_CARD_TYPE_MDEID_2025) {
		return sc_pkcs15emu_mdeid_init(p15card);
	}
	return SC_ERROR_WRONG_CARD;
}
