/* SPDX-License-Identifier: MIT */
#include "wr_err.h"

WR_FILE_LICENCE_MIT

typedef struct wri_err_row {
	wr_status status;
	const char *name;
	const char *text;
} wri_err_row;

static const wri_err_row wri_err_table[] = {
#define WR_X_ROW(name, code, text) {name, #name, text},
	WR_STATUS_LIST(WR_X_ROW)
#undef WR_X_ROW
};

#define WRI_ERR_ROWS (sizeof(wri_err_table) / sizeof(wri_err_table[0]))

static const wri_err_row *wri_err_find(wr_status st)
{
	size_t i;

	for (i = 0; i < WRI_ERR_ROWS; i++)
		if (wri_err_table[i].status == st)
			return &wri_err_table[i];
	return NULL;
}

const char *wr_strerror(wr_status st)
{
	const wri_err_row *r;

	if (st == WR_OK)
		return "success";
	r = wri_err_find(st);
	return r ? r->text : "unknown status";
}

const char *wr_status_name(wr_status st)
{
	const wri_err_row *r;

	if (st == WR_OK)
		return "WR_OK";
	r = wri_err_find(st);
	return r ? r->name : "WR_E_UNKNOWN";
}
