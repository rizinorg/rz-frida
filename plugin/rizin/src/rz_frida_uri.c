// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <string.h>

static bool assign_part(char **dst, const char **cursor, bool rest) {
	rz_return_val_if_fail(dst && cursor && *cursor, false);

	const char *start = *cursor;
	const char *slash = strchr(start, '/');
	size_t len = (!rest && slash) ? (size_t)(slash - start) : strlen(start);
	*dst = rz_str_ndup(start, (int)len);
	if (!*dst) {
		return false;
	}
	*cursor = (!rest && slash) ? slash + 1 : start + len;
	return true;
}

static bool uri_has_more_fields(const char *cursor) {
	return cursor && strchr(cursor, '/');
}

static bool target_action(RzFridaAction action) {
	return action == RZ_FRIDA_ACTION_ATTACH ||
		action == RZ_FRIDA_ACTION_SPAWN ||
		action == RZ_FRIDA_ACTION_LAUNCH;
}

RZ_IPI const char *rz_frida_action_string(RzFridaAction action) {
	switch (action) {
	case RZ_FRIDA_ACTION_LIST:
		return "list";
	case RZ_FRIDA_ACTION_APPS:
		return "apps";
	case RZ_FRIDA_ACTION_ATTACH:
		return "attach";
	case RZ_FRIDA_ACTION_SPAWN:
		return "spawn";
	case RZ_FRIDA_ACTION_LAUNCH:
		return "launch";
	case RZ_FRIDA_ACTION_UNKNOWN:
	default:
		return "unknown";
	}
}

RZ_IPI RzFridaAction rz_frida_action_from_string(const char *action) {
	if (!action) {
		return RZ_FRIDA_ACTION_UNKNOWN;
	}
	if (RZ_STR_EQ(action, "list")) {
		return RZ_FRIDA_ACTION_LIST;
	} else if (RZ_STR_EQ(action, "apps")) {
		return RZ_FRIDA_ACTION_APPS;
	} else if (RZ_STR_EQ(action, "attach")) {
		return RZ_FRIDA_ACTION_ATTACH;
	} else if (RZ_STR_EQ(action, "spawn")) {
		return RZ_FRIDA_ACTION_SPAWN;
	} else if (RZ_STR_EQ(action, "launch")) {
		return RZ_FRIDA_ACTION_LAUNCH;
	}
	return RZ_FRIDA_ACTION_UNKNOWN;
}

RZ_IPI const char *rz_frida_transport_string(RzFridaTransport transport) {
	switch (transport) {
	case RZ_FRIDA_TRANSPORT_LOCAL:
		return "local";
	case RZ_FRIDA_TRANSPORT_USB:
		return "usb";
	case RZ_FRIDA_TRANSPORT_REMOTE:
		return "remote";
	case RZ_FRIDA_TRANSPORT_UNKNOWN:
	default:
		return "unknown";
	}
}

RZ_IPI RzFridaTransport rz_frida_transport_from_string(const char *transport) {
	if (!transport) {
		return RZ_FRIDA_TRANSPORT_UNKNOWN;
	}
	if (RZ_STR_EQ(transport, "local")) {
		return RZ_FRIDA_TRANSPORT_LOCAL;
	} else if (RZ_STR_EQ(transport, "usb")) {
		return RZ_FRIDA_TRANSPORT_USB;
	} else if (RZ_STR_EQ(transport, "remote")) {
		return RZ_FRIDA_TRANSPORT_REMOTE;
	}
	return RZ_FRIDA_TRANSPORT_UNKNOWN;
}

RZ_IPI void rz_frida_uri_fini(RzFridaUri *uri) {
	if (!uri) {
		return;
	}
	free(uri->action);
	free(uri->transport);
	free(uri->device);
	free(uri->target);
	rz_mem_memzero(uri, sizeof(*uri));
}

/**
 * \brief Build a frida:// URI from its components.
 *
 * Validates the action and transport names, the target requirement for the
 * action, and the device rules per transport, then copies the parts into
 * \p out. Components are not URL encoded.
 *
 * \param action Action name (attach, spawn, launch, list, apps).
 * \param transport Transport name (local, usb, remote).
 * \param device Device selector, empty for local, host:port for remote.
 * \param target Target selector, required for attach, spawn, launch.
 * \param out Receives the owned URI on success.
 * \return true when the components form a valid URI, false otherwise.
 */
RZ_IPI bool rz_frida_uri_from_parts(const char *action, const char *transport,
	const char *device, const char *target, RzFridaUri *out) {
	rz_return_val_if_fail(action && transport && out, false);

	RzFridaAction action_type = rz_frida_action_from_string(action);
	RzFridaTransport transport_type = rz_frida_transport_from_string(transport);
	if (action_type == RZ_FRIDA_ACTION_UNKNOWN || transport_type == RZ_FRIDA_TRANSPORT_UNKNOWN) {
		return false;
	}
	if (target_action(action_type) && RZ_STR_ISEMPTY(target)) {
		return false;
	}
	if (!target_action(action_type) && RZ_STR_ISNOTEMPTY(target)) {
		return false;
	}
	if (transport_type == RZ_FRIDA_TRANSPORT_LOCAL && RZ_STR_ISNOTEMPTY(device)) {
		return false;
	}
	if (transport_type == RZ_FRIDA_TRANSPORT_REMOTE &&
		(RZ_STR_ISEMPTY(device) || !strchr(device, ':'))) {
		return false;
	}

	RzFridaUri uri = { 0 };
	uri.action_type = action_type;
	uri.transport_type = transport_type;
	uri.action = rz_str_dup(action);
	uri.transport = rz_str_dup(transport);
	uri.device = rz_str_dup(device ? device : "");
	uri.target = rz_str_dup(target ? target : "");
	if (!uri.action || !uri.transport || !uri.device || !uri.target) {
		rz_frida_uri_fini(&uri);
		return false;
	}
	*out = uri;
	return true;
}

RZ_IPI bool rz_frida_uri_copy(RzFridaUri *dst, const RzFridaUri *src) {
	rz_return_val_if_fail(dst && src, false);

	rz_mem_memzero(dst, sizeof(*dst));
	dst->action_type = src->action_type;
	dst->transport_type = src->transport_type;
	dst->action = rz_str_dup(src->action);
	dst->transport = rz_str_dup(src->transport);
	dst->device = rz_str_dup(src->device);
	dst->target = rz_str_dup(src->target);
	if (!dst->action || !dst->transport || !dst->device || !dst->target) {
		rz_frida_uri_fini(dst);
		return false;
	}
	return true;
}

RZ_IPI bool rz_frida_uri_parse(const char *uri, RzFridaUri *out) {
	rz_return_val_if_fail(uri && out, false);

	rz_mem_memzero(out, sizeof(*out));

	const char prefix[] = "frida://";
	if (!rz_str_startswith(uri, prefix)) {
		return false;
	}

	// sizeof(prefix) just keeps skip length tied to literal and -1 for trailing nul.
	const char *cursor = uri + sizeof(prefix) - 1;
	if (!assign_part(&out->action, &cursor, false) ||
		!assign_part(&out->transport, &cursor, false) ||
		!assign_part(&out->device, &cursor, false) ||
		!assign_part(&out->target, &cursor, true)) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (uri_has_more_fields(cursor) ||
		!RZ_STR_ISNOTEMPTY(out->action) || !RZ_STR_ISNOTEMPTY(out->transport) ||
		!out->device || !out->target) {
		rz_frida_uri_fini(out);
		return false;
	}

	out->action_type = rz_frida_action_from_string(out->action);
	out->transport_type = rz_frida_transport_from_string(out->transport);
	if (out->action_type == RZ_FRIDA_ACTION_UNKNOWN ||
		out->transport_type == RZ_FRIDA_TRANSPORT_UNKNOWN) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (target_action(out->action_type) && !RZ_STR_ISNOTEMPTY(out->target)) {
		rz_frida_uri_fini(out);
		return false;
	}
	if (!target_action(out->action_type) && RZ_STR_ISNOTEMPTY(out->target)) {
		rz_frida_uri_fini(out);
		return false;
	}

	// Local must not name a device. Remote must carry host:port. USB could omit
	// device id, which selects the single connected device.
	if (out->transport_type == RZ_FRIDA_TRANSPORT_LOCAL && RZ_STR_ISNOTEMPTY(out->device)) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (out->transport_type == RZ_FRIDA_TRANSPORT_REMOTE) {
		if (!RZ_STR_ISNOTEMPTY(out->device) || !strchr(out->device, ':')) {
			rz_frida_uri_fini(out);
			return false;
		}
	}

	return true;
}

/**
 * \brief Parse a decimal only target selector as a process id.
 */
RZ_IPI bool rz_frida_uri_target_pid(const char *target, ut32 *pid_out) {
	rz_return_val_if_fail(target && pid_out, false);

	if (RZ_STR_ISEMPTY(target)) {
		return false;
	}
	// decimal as pid only.
	ut64 value = 0;
	for (const char *p = target; *p; p++) {
		if (!IS_DIGIT(*p)) {
			return false;
		}
		value = value * 10 + (ut64)(*p - '0');
		if (value > UT32_MAX) {
			return false;
		}
	}
	*pid_out = (ut32)value;
	return true;
}
