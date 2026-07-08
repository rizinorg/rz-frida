// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

RZ_IPI const char *rz_frida_method_string(RzFridaMethod method) {
	switch (method) {
	case RZ_FRIDA_METHOD_STATUS:
		return "status";
	case RZ_FRIDA_METHOD_DEVICES:
		return "devices";
	case RZ_FRIDA_METHOD_PROCESSES:
		return "processes";
	case RZ_FRIDA_METHOD_APPS:
		return "apps";
	case RZ_FRIDA_METHOD_ATTACH:
		return "attach";
	case RZ_FRIDA_METHOD_SPAWN:
		return "spawn";
	case RZ_FRIDA_METHOD_LAUNCH:
		return "launch";
	case RZ_FRIDA_METHOD_DETACH:
		return "detach";
	case RZ_FRIDA_METHOD_UNKNOWN:
	default:
		return "unknown";
	}
}

RZ_IPI RzFridaMethod rz_frida_method_from_string(const char *method) {
	if (!method) {
		return RZ_FRIDA_METHOD_UNKNOWN;
	}
	if (RZ_STR_EQ(method, "status")) {
		return RZ_FRIDA_METHOD_STATUS;
	} else if (RZ_STR_EQ(method, "devices")) {
		return RZ_FRIDA_METHOD_DEVICES;
	} else if (RZ_STR_EQ(method, "processes")) {
		return RZ_FRIDA_METHOD_PROCESSES;
	} else if (RZ_STR_EQ(method, "apps")) {
		return RZ_FRIDA_METHOD_APPS;
	} else if (RZ_STR_EQ(method, "attach")) {
		return RZ_FRIDA_METHOD_ATTACH;
	} else if (RZ_STR_EQ(method, "spawn")) {
		return RZ_FRIDA_METHOD_SPAWN;
	} else if (RZ_STR_EQ(method, "launch")) {
		return RZ_FRIDA_METHOD_LAUNCH;
	} else if (RZ_STR_EQ(method, "detach")) {
		return RZ_FRIDA_METHOD_DETACH;
	}
	return RZ_FRIDA_METHOD_UNKNOWN;
}

RZ_IPI bool rz_frida_method_parse(const char *method, RzFridaMethod *out, PJ *pj) {
	rz_return_val_if_fail(out, false);

	*out = rz_frida_method_from_string(method);
	if (*out != RZ_FRIDA_METHOD_UNKNOWN) {
		return true;
	}
	if (pj) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_NOT_IMPLEMENTED, method ? "unknown method" : "missing method");
	}
	return false;
}

RZ_IPI const char *rz_frida_error_string(RzFridaError error) {
	switch (error) {
	case RZ_FRIDA_ERROR_NONE:
		return "none";
	case RZ_FRIDA_ERROR_INVALID_URI:
		return "invalid_uri";
	case RZ_FRIDA_ERROR_INVALID_TARGET:
		return "invalid_target";
	case RZ_FRIDA_ERROR_TIMEOUT:
		return "timeout";
	case RZ_FRIDA_ERROR_CANCELLED:
		return "cancelled";
	case RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE:
		return "frida_unavailable";
	case RZ_FRIDA_ERROR_NOT_IMPLEMENTED:
		return "not_implemented";
	case RZ_FRIDA_ERROR_INTERNAL:
	default:
		return "internal_error";
	}
}

RZ_IPI void rz_frida_json_ok_begin(RZ_NONNULL PJ *pj) {
	rz_return_if_fail(pj);
	pj_o(pj);
	pj_kb(pj, "ok", true);
	pj_ko(pj, "result");
}

RZ_IPI void rz_frida_json_ok_end(RZ_NONNULL PJ *pj) {
	rz_return_if_fail(pj);
	pj_end(pj);
	pj_end(pj);
}

RZ_IPI void rz_frida_json_ok_empty(PJ *pj) {
	rz_return_if_fail(pj);
	rz_frida_json_ok_begin(pj);
	rz_frida_json_ok_end(pj);
}

RZ_IPI void rz_frida_json_error(RZ_NONNULL PJ *pj, RzFridaError error, RZ_NULLABLE const char *message) {
	rz_return_if_fail(pj);
	pj_o(pj);
	pj_kb(pj, "ok", false);
	pj_ko(pj, "error");
	pj_ks(pj, "code", rz_frida_error_string(error));
	pj_ks(pj, "message", message ? message : rz_frida_error_string(error));
	pj_end(pj);
	pj_end(pj);
}
