// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_frida.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <cmd_descs.h>

extern RzCorePlugin rz_core_plugin_frida;

typedef struct rz_frida_core_context_t {
	RzCmdDesc *cmd_desc;
	RzFridaSession *session;
} RzFridaCoreContext;

static RzFridaCoreContext *frida_context(RzCore *core) {
	rz_return_val_if_fail(core, NULL);
	return (RzFridaCoreContext *)rz_core_plugin_context_get(core, &rz_core_plugin_frida);
}

static RzCmdStatus print_status(RzCore *core, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, RZ_CMD_STATUS_ERROR);

	RzFridaCoreContext *ctx = frida_context(core);
	const RzFridaSession *session = ctx ? ctx->session : NULL;
	const bool active = session != NULL;
	const char *state_string = session ? rz_frida_session_state_string(rz_frida_session_state(session)) : "closed";
	const RzFridaUri *uri = session ? rz_frida_session_uri(session) : NULL;

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("active: %s\n", rz_str_bool(active));
		rz_cons_printf("state: %s\n", state_string);
		if (session) {
			rz_cons_printf("pid: %u\n", rz_frida_session_target_pid(session));
			rz_cons_printf("action: %s\n", uri->action);
			rz_cons_printf("target: %s\n", uri->target);
		}
		return RZ_CMD_STATUS_OK;
	case RZ_OUTPUT_MODE_JSON:
		rz_frida_json_ok_begin(state->d.pj);
		pj_kb(state->d.pj, "active", active);
		pj_ks(state->d.pj, "state", state_string);
		if (session) {
			pj_kn(state->d.pj, "pid", rz_frida_session_target_pid(session));
			pj_ks(state->d.pj, "action", uri->action);
			pj_ks(state->d.pj, "target", uri->target);
		}
		rz_frida_json_ok_end(state->d.pj);
		return RZ_CMD_STATUS_OK;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
}

static RzCmdStatus print_uri(const char *uri_string, RzCmdStateOutput *state) {
	rz_return_val_if_fail(state, RZ_CMD_STATUS_ERROR);

	RzFridaUri uri = { 0 };

	// JSON replies accumulate in the state buffer, which RzCmd only prints when the
	// handler returns RZ_CMD_STATUS_OK. We return OK after writing an error envelope so
	// the ok:false reply still reaches the caller and plain text reports errors via the log.
	if (!RZ_STR_ISNOTEMPTY(uri_string)) {
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			rz_frida_json_error(state->d.pj, RZ_FRIDA_ERROR_INVALID_URI, "missing URI");
			return RZ_CMD_STATUS_OK;
		}
		RZ_LOG_ERROR("missing URI\n");
		return RZ_CMD_STATUS_INVALID;
	}

	if (!rz_frida_uri_parse(uri_string, &uri)) {
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			rz_frida_json_error(state->d.pj, RZ_FRIDA_ERROR_INVALID_URI, "invalid Frida URI");
			return RZ_CMD_STATUS_OK;
		}
		RZ_LOG_ERROR("invalid Frida URI\n");
		return RZ_CMD_STATUS_INVALID;
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("action: %s\n", uri.action);
		rz_cons_printf("transport: %s\n", uri.transport);
		rz_cons_printf("device: %s\n", uri.device);
		rz_cons_printf("target: %s\n", uri.target);
		break;
	case RZ_OUTPUT_MODE_JSON:
		rz_frida_json_ok_begin(state->d.pj);
		pj_ks(state->d.pj, "action", uri.action);
		pj_ks(state->d.pj, "transport", uri.transport);
		pj_ks(state->d.pj, "device", uri.device);
		pj_ks(state->d.pj, "target", uri.target);
		rz_frida_json_ok_end(state->d.pj);
		break;
	default:
		rz_frida_uri_fini(&uri);
		rz_warn_if_reached();
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	rz_frida_uri_fini(&uri);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridas_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return print_status(core, state);
}

RZ_IPI RzCmdStatus rz_cmd_fridau_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return print_uri(argv[1], state);
}

RZ_IPI RzCmdStatus rz_cmd_fridad_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	// rz_frida_devices_json always writes a JSON envelope (ok:true with devices, or
	// ok:false on failure). Return OK either way so RzCmd prints the envelope and the
	// ok flag inside carries the outcome to scripts and Cutter.
	rz_frida_devices_json(state->d.pj);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus run_device_listing(int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state,
	RzFridaAction action, RZ_NONNULL bool (*list)(const RzFridaUri *uri, PJ *pj)) {
	rz_return_val_if_fail(argv && state && list, RZ_CMD_STATUS_ERROR);

	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	const char *uri_string = (argc > 1) ? argv[1] : NULL;
	if (!RZ_STR_ISNOTEMPTY(uri_string)) {
		list(NULL, pj);
		return RZ_CMD_STATUS_OK;
	}

	RzFridaUri uri = { 0 };
	if (!rz_frida_uri_parse(uri_string, &uri)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "invalid Frida URI");
		return RZ_CMD_STATUS_OK;
	}
	if (uri.action_type != action) {
		rz_frida_uri_fini(&uri);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "URI action does not match the command");
		return RZ_CMD_STATUS_OK;
	}
	list(&uri, pj);
	rz_frida_uri_fini(&uri);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridap_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return run_device_listing(argc, argv, state, RZ_FRIDA_ACTION_LIST, rz_frida_processes_json);
}

RZ_IPI RzCmdStatus rz_cmd_fridaa_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return run_device_listing(argc, argv, state, RZ_FRIDA_ACTION_APPS, rz_frida_apps_json);
}

RZ_IPI RzCmdStatus rz_cmd_fridao_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "frida plugin context is unavailable");
		return RZ_CMD_STATUS_OK;
	}
	if (ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "a session is already open");
		return RZ_CMD_STATUS_OK;
	}

	RzFridaUri uri = { 0 };
	if (!rz_frida_uri_parse(argv[1], &uri)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "invalid Frida URI");
		return RZ_CMD_STATUS_OK;
	}

	RzFridaSession *session = rz_frida_session_new();
	if (!session) {
		rz_frida_uri_fini(&uri);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate session");
		return RZ_CMD_STATUS_OK;
	}

	ut64 timeout = rz_config_get_integer(core->config, "frida.timeout");
	if (timeout) {
		rz_frida_session_set_timeout(session, timeout);
	}

	bool stored = rz_frida_session_set_uri(session, &uri);
	rz_frida_uri_fini(&uri);
	if (!stored) {
		rz_frida_session_free(session);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot store the session URI");
		return RZ_CMD_STATUS_OK;
	}

	// backend_open writes the envelope either way. only keep the session if it opened.
	if (!rz_frida_backend_open(session, pj)) {
		rz_frida_session_free(session);
		return RZ_CMD_STATUS_OK;
	}

	ctx->session = session;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridar_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_frida_backend_resume(ctx->session, pj);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridac_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	// close writes reply, free releases backend state and clears slot
	if (rz_frida_backend_close(ctx->session, pj)) {
		rz_frida_session_free(ctx->session);
		ctx->session = NULL;
	}
	return RZ_CMD_STATUS_OK;
}

// cancel in-flight agent req after Ctrl-C.
static void frida_cancel_on_break(void *user) {
	rz_frida_session_request_cancel((RzFridaSession *)user);
}

RZ_IPI RzCmdStatus rz_cmd_fridae_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_eval(ctx->session, argv[1], pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridal_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	char *source = rz_file_slurp(argv[1], NULL);
	if (!source) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "cannot read the script file");
		return RZ_CMD_STATUS_OK;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_eval(ctx->session, source, pj);
	rz_cons_break_pop();
	free(source);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridai_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_ping(ctx->session, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridam_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_frida_backend_messages(ctx->session, pj);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridax_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	ut64 size = rz_num_math(core->num, argv[2]);
	ut64 maxbytes = rz_config_get_integer(core->config, "frida.mem.max");
	if (maxbytes && size > maxbytes) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "read size exceeds the frida.mem.max limit");
		return RZ_CMD_STATUS_OK;
	}
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	ut64 address = rz_num_math(core->num, argv[1]);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_mem_read(ctx->session, address, size, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaw_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	const char *hex = argv[2];
	int hexlen = strlen(hex);
	if (hexlen == 0 || (hexlen % 2)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "expected an even-length hex byte string");
		return RZ_CMD_STATUS_OK;
	}
	ut64 maxbytes = rz_config_get_integer(core->config, "frida.mem.max");
	if (maxbytes && (ut64)(hexlen / 2) > maxbytes) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "write size exceeds the frida.mem.max limit");
		return RZ_CMD_STATUS_OK;
	}
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	ut8 *bytes = malloc(hexlen / 2);
	if (!bytes) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the write buffer");
		return RZ_CMD_STATUS_OK;
	}
	int len = rz_hex_str2bin(hex, bytes);
	if (len < 1) {
		free(bytes);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "invalid hex byte string");
		return RZ_CMD_STATUS_OK;
	}
	ut64 address = rz_num_math(core->num, argv[1]);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_mem_write(ctx->session, address, bytes, (size_t)len, pj);
	rz_cons_break_pop();
	free(bytes);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaR_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	// any arg forces a fresh enumeration instead of cached ranges.
	bool refresh = (argc > 1) && RZ_STR_ISNOTEMPTY(argv[1]);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_ranges(ctx->session, refresh, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridat_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_threads(ctx->session, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaM_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	// any arg forces fresh enum instead of cached modules.
	bool refresh = (argc > 1) && RZ_STR_ISNOTEMPTY(argv[1]);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_modules(ctx->session, refresh, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaE_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_exports(ctx->session, argv[1], pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaI_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_imports(ctx->session, argv[1], pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaS_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_symbols(ctx->session, argv[1], pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridab_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	// an addr sets a breakpoint, no arg lists the current breakpoints.
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	if (argc > 1 && RZ_STR_ISNOTEMPTY(argv[1])) {
		ut64 address = rz_num_math(core->num, argv[1]);
		rz_frida_backend_bp_set(ctx->session, address, pj);
	} else {
		rz_frida_backend_bp_list(ctx->session, pj);
	}
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridab_minus_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	const char *target = argv[1];
	char address_str[32];
	if (!RZ_STR_EQ(target, "*")) {
		ut64 address = rz_num_math(core->num, target);
		rz_strf(address_str, "0x%" PFMT64x, address);
		target = address_str;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_bp_remove(ctx->session, target, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridag_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	// a thread id continues that thread, no arg continues most recent one.
	char tid[32];
	const char *thread_id = NULL;
	if (argc > 1 && RZ_STR_ISNOTEMPTY(argv[1])) {
		rz_strf(tid, "%" PFMT64u, rz_num_math(core->num, argv[1]));
		thread_id = tid;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_continue(ctx->session, thread_id, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaB_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	ut64 thread_id = rz_num_math(core->num, argv[1]);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	if (argc > 3) {
		char value_str[32];
		rz_strf(value_str, "0x%" PFMT64x, rz_num_math(core->num, argv[3]));
		rz_frida_backend_reg_write(ctx->session, thread_id, argv[2], value_str, pj);
	} else if (argc > 2) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "a register write needs a value");
	} else {
		rz_frida_backend_reg_read(ctx->session, thread_id, pj);
	}
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaW_handler(RZ_NONNULL RzCore *core, int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	// addr sets watchpoint, no arg lists current wps.
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	if (argc > 1 && RZ_STR_ISNOTEMPTY(argv[1])) {
		ut64 address = rz_num_math(core->num, argv[1]);
		ut64 size = (argc > 2) ? rz_num_math(core->num, argv[2]) : 0;
		const char *conditions = (argc > 3) ? argv[3] : NULL;
		ut64 slots = rz_config_get_integer(core->config, "frida.hw.watchpoints");
		rz_frida_backend_wp_set(ctx->session, address, size, conditions, slots, pj);
	} else {
		rz_frida_backend_wp_list(ctx->session, pj);
	}
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaW_minus_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	const char *target = argv[1];
	char address_str[32];
	if (!RZ_STR_EQ(target, "*")) {
		ut64 address = rz_num_math(core->num, target);
		rz_strf(address_str, "0x%" PFMT64x, address);
		target = address_str;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_wp_remove(ctx->session, target, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaJ_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_java_available(ctx->session, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaL_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc, RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_loaders(ctx->session, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaC_handler(RZ_NONNULL RzCore *core, int argc,
	RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	const char *prefix = (argc > 1 && RZ_STR_ISNOTEMPTY(argv[1])) ? argv[1] : NULL;
	ut64 max = rz_config_get_integer(core->config, "frida.java.max");
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_classes(ctx->session, prefix, max, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaN_handler(RZ_NONNULL RzCore *core, int argc,
	RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	bool enable = true;
	if (argc > 1 && RZ_STR_ISNOTEMPTY(argv[1])) {
		if (RZ_STR_EQ(argv[1], "start")) {
			enable = true;
		} else if (RZ_STR_EQ(argv[1], "stop")) {
			enable = false;
		} else {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET,
				"fridaNj expects start, stop, or no arguments to list");
			return RZ_CMD_STATUS_OK;
		}
		rz_cons_break_push(frida_cancel_on_break, ctx->session);
		rz_frida_backend_class_load_monitor(ctx->session, enable, pj);
		rz_cons_break_pop();
	} else {
		rz_cons_break_push(frida_cancel_on_break, ctx->session);
		rz_frida_backend_newly_loaded_classes(ctx->session, pj);
		rz_cons_break_pop();
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaRN_handler(RZ_NONNULL RzCore *core, int argc,
	RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	if (argc > 1 && RZ_STR_ISNOTEMPTY(argv[1])) {
		if (RZ_STR_EQ(argv[1], "on")) {
			rz_cons_break_push(frida_cancel_on_break, ctx->session);
			rz_frida_backend_rn_set(ctx->session, true, pj);
			rz_cons_break_pop();
		} else if (RZ_STR_EQ(argv[1], "off")) {
			rz_cons_break_push(frida_cancel_on_break, ctx->session);
			rz_frida_backend_rn_set(ctx->session, false, pj);
			rz_cons_break_pop();
		} else if (RZ_STR_EQ(argv[1], "import")) {
			rz_cons_break_push(frida_cancel_on_break, ctx->session);
			PJ *tmp = pj_new();
			if (!tmp) {
				rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the request");
				rz_cons_break_pop();
				return RZ_CMD_STATUS_OK;
			}
			rz_frida_backend_rn_list(ctx->session, tmp);
			char *raw = pj_drain(tmp);
			char *txt = raw ? rz_str_dup(raw) : NULL;
			free(raw);
			if (!txt) {
				rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot parse the reply");
				rz_cons_break_pop();
				return RZ_CMD_STATUS_OK;
			}
		RzJson *r = rz_json_parse(txt);
		if (!r) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot parse the reply");
			free(txt);
			rz_cons_break_pop();
			return RZ_CMD_STATUS_OK;
		}
		const RzJson *res = rz_json_get(r, "result");
		if (!res) {
			const RzJson *err = rz_json_get(r, "error");
			if (err && err->type == RZ_JSON_OBJECT) {
				const RzJson *msg = rz_json_get(err, "message");
				if (msg && msg->type == RZ_JSON_STRING && msg->str_value) {
					rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, msg->str_value);
				} else {
					rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "the agent returned an unexpected reply");
				}
			} else {
				rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "the agent returned an unexpected reply");
			}
			free(txt);
			rz_json_free(r);
			rz_cons_break_pop();
			return RZ_CMD_STATUS_OK;
		}
			const RzJson *inv = rz_json_get(res, "invocations");
			size_t total = 0;
			if (inv && inv->type == RZ_JSON_ARRAY) {
				const RzJson *entry = inv->children.first;
				while (entry) {
					const RzJson *cn = rz_json_get(entry, "className");
					const RzJson *methods = rz_json_get(entry, "methods");
					if (cn && cn->type == RZ_JSON_STRING && cn->str_value &&
						methods && methods->type == RZ_JSON_ARRAY) {
						const RzJson *m = methods->children.first;
						while (m) {
							const RzJson *mn = rz_json_get(m, "name");
							const RzJson *ma = rz_json_get(m, "address");
							if (mn && ma && mn->type == RZ_JSON_STRING && mn->str_value &&
								ma->type == RZ_JSON_STRING && ma->str_value) {
								rz_analysis_class_create(core->analysis, cn->str_value);
								RzAnalysisMethod meth = { .name = rz_str_dup(mn->str_value),
									.real_name = rz_str_dup(mn->str_value),
									.addr = rz_num_math(core->num, ma->str_value),
									.vtable_offset = -1,
									.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT };
								rz_analysis_class_method_set(core->analysis, cn->str_value, &meth);
								rz_analysis_class_method_fini(&meth);
								total++;
							}
							m = m->next;
						}
					}
					entry = entry->next;
				}
			}
			rz_frida_json_ok_begin(pj);
			pj_kb(pj, "imported", true);
			pj_kn(pj, "methods", (ut64)total);
			rz_frida_json_ok_end(pj);
			free(txt);
			rz_json_free(r);
			rz_cons_break_pop();
		} else {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET,
				"fridaRNj expects on, off, import, or no arguments to list");
			return RZ_CMD_STATUS_OK;
		}
	} else {
		rz_cons_break_push(frida_cancel_on_break, ctx->session);
		rz_frida_backend_rn_list(ctx->session, pj);
		rz_cons_break_pop();
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaf_handler(RZ_NONNULL RzCore *core, RZ_UNUSED int argc,
	RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	PJ *tmp = pj_new();
	if (!tmp) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the request");
		rz_cons_break_pop();
		return RZ_CMD_STATUS_OK;
	}
	rz_frida_backend_flag_modules(ctx->session, tmp);
	char *raw = pj_drain(tmp);
	char *txt = raw ? rz_str_dup(raw) : NULL;
	free(raw);
	if (!txt) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot parse the reply");
		rz_cons_break_pop();
		return RZ_CMD_STATUS_OK;
	}
	RzJson *r = rz_json_parse(txt);
	if (!r) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot parse the reply");
		free(txt);
		rz_cons_break_pop();
		return RZ_CMD_STATUS_OK;
	}
	const RzJson *res = rz_json_get(r, "result");
	if (!res) {
		const RzJson *err = rz_json_get(r, "error");
		if (err && err->type == RZ_JSON_OBJECT) {
			const RzJson *msg = rz_json_get(err, "message");
			if (msg && msg->type == RZ_JSON_STRING && msg->str_value) {
				rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, msg->str_value);
			} else {
				rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "the agent returned an unexpected reply");
			}
		} else {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "the agent returned an unexpected reply");
		}
		free(txt);
		rz_json_free(r);
		rz_cons_break_pop();
		return RZ_CMD_STATUS_OK;
	}
	const RzJson *mods = rz_json_get(res, "modules");
	size_t count = 0;
	if (mods && mods->type == RZ_JSON_ARRAY) {
		rz_flag_space_push(core->flags, "frida.libs");
		const RzJson *m = mods->children.first;
		while (m) {
			const RzJson *mn = rz_json_get(m, "name");
			const RzJson *mb = rz_json_get(m, "base");
			const RzJson *ms = rz_json_get(m, "size");
			if (mn && mb && mn->type == RZ_JSON_STRING && mn->str_value &&
				mb->type == RZ_JSON_STRING && mb->str_value) {
				ut64 base = rz_num_math(core->num, mb->str_value);
				ut32 size = (ms && ms->type == RZ_JSON_INTEGER) ? (ut32)ms->num.u_value : 1;
				rz_flag_set(core->flags, mn->str_value, base, size);
				count++;
			}
			m = m->next;
		}
		rz_flag_space_pop(core->flags);
	}
	rz_frida_json_ok_begin(pj);
	pj_kb(pj, "imported", true);
	pj_kn(pj, "modules", (ut64)count);
	rz_frida_json_ok_end(pj);
	free(txt);
	rz_json_free(r);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaD_handler(RZ_NONNULL RzCore *core, int argc,
	RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	const char *className = argv[1];
	if (!RZ_STR_ISNOTEMPTY(className)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "class name is required");
		return RZ_CMD_STATUS_OK;
	}
	ut64 loaderId = 0;
	if (argc > 2 && RZ_STR_ISNOTEMPTY(argv[2])) {
		loaderId = rz_num_math(core->num, argv[2]);
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_class_describe(ctx->session, className, loaderId, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaIm_handler(RZ_NONNULL RzCore *core, int argc,
	RZ_NONNULL const char **argv, RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}
	const char *className = argv[1];
	if (!RZ_STR_ISNOTEMPTY(className)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "class name is required");
		return RZ_CMD_STATUS_OK;
	}
	ut64 loaderId = 0;
	if (argc > 2 && RZ_STR_ISNOTEMPTY(argv[2])) {
		loaderId = rz_num_math(core->num, argv[2]);
	}

	bool has_dot = (strchr(className, '.') != NULL);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	if (has_dot) {
		rz_frida_backend_import_class(ctx->session, core, className, loaderId, pj);
	} else {
		ut64 max = rz_config_get_integer(core->config, "frida.java.max");
		size_t count = 0;
		char **names = rz_frida_backend_class_list(ctx->session, className, max, &count);

		if (!count) {
			if (names) {
				free(names);
			}
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET,
				"no matching classes found for the given prefix");
			rz_cons_break_pop();
			return RZ_CMD_STATUS_OK;
		}

		size_t total_m = 0, total_f = 0, total_c = 0;
		for (size_t i = 0; i < count; i++) {
			PJ *one = pj_new();
			if (!one) {
				continue;
			}
			rz_frida_backend_import_class(ctx->session, core, names[i], 0, one);
			char *raw = pj_drain(one); /* pj_drain frees one */
			char *txt = raw ? rz_str_dup(raw) : NULL;
			free(raw);
			if (!txt) {
				continue;
			}
			RzJson *r = rz_json_parse(txt);
			if (r) {
				const RzJson *res = rz_json_get(r, "result");
				if (res) {
					const RzJson *j = rz_json_get(res, "methods");
					total_m += (j && j->type == RZ_JSON_INTEGER) ? (size_t)j->num.u_value : 0;
					j = rz_json_get(res, "fields");
					total_f += (j && j->type == RZ_JSON_INTEGER) ? (size_t)j->num.u_value : 0;
					j = rz_json_get(res, "constructors");
					total_c += (j && j->type == RZ_JSON_INTEGER) ? (size_t)j->num.u_value : 0;
				}
				rz_json_free(r);
			}
			free(txt);
		}
		for (size_t i = 0; i < count; i++) free(names[i]);
		free(names);

		rz_frida_json_ok_begin(pj);
		pj_kb(pj, "batch", true);
		pj_kn(pj, "classes", (ut64)count);
		pj_kn(pj, "methods", (ut64)total_m);
		pj_kn(pj, "fields", (ut64)total_f);
		pj_kn(pj, "constructors", (ut64)total_c);
		rz_frida_json_ok_end(pj);
	}
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

static const char *extract_prefix(const char *line) {
	if (!line) {
		return NULL;
	}
	int len = (int)strlen(line);
	while (len > 0 && line[len - 1] == ' ') len--;
	int start = len;
	while (start > 0 && line[start - 1] != ' ') start--;
	if (start == 0) {
		return NULL;
	}
	if (start >= len) {
		return NULL;
	}
	return line + start;
}

/**
 * \brief Returns loaded Java class names for fridaDj Tab-completion.
 *
 * Reads the current line buffer to extract the partially typed class name,
 * guards against no-session and too-few-characters via the frida.ac.min config,
 * queries the agent for matching class names (capped at frida.ac.max), and
 * returns a freshly allocated NULL-terminated array suitable for rizin's
 * RZ_CMD_ARG_TYPE_CHOICES autocomplete mechanism.
 *
 * \param core The active RzCore (must have an open frida session).
 * \return NULL-terminated array of individually allocated class name strings,
 *         or NULL when autocomplete should not offer anything.
 */
RZ_IPI RZ_OWN char **rz_frida_autocomplete_class(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core, NULL);

	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		return NULL;
	}

	const char *line = core->cons->line->buffer.data;
	const char *prefix = extract_prefix(line);
	if (!prefix) {
		return NULL;
	}
	size_t plen = strlen(prefix);

	ut64 min = rz_config_get_integer(core->config, "frida.ac.min");
	if (min && plen < (size_t)min) {
		return NULL;
	}

	ut64 max = rz_config_get_integer(core->config, "frida.ac.max");
	if (!max) {
		max = 12;
	}

	size_t count = 0;
	char **result = rz_frida_backend_class_list(ctx->session, prefix, max, &count);
	if (!result) {
		return NULL;
	}

	if (count == 0) {
		free(result);
		return NULL;
	}
	return result;
}

static RzFridaCoreContext *frida_context_new(void) {
	return RZ_NEW0(RzFridaCoreContext);
}

static void frida_context_free(RzFridaCoreContext *ctx) {
	if (!ctx) {
		return;
	}
	rz_frida_session_free(ctx->session);
	RZ_FREE(ctx);
}

static bool rz_frida_plugin_init(RzCore *core, void **user) {
	rz_return_val_if_fail(core && core->rcmd && user, false);

	RzFridaCoreContext *ctx = frida_context_new();
	if (!ctx) {
		return false;
	}

	// The cmd tree is there in src/cmd_descs/cmd_descs.yaml and emitted by
	// Rizin's cmd_descs_generate.py into cmd_descs.c. rzshell_cmddescs_init registers
	// the frida group and its subcmds under the cmd root, and we keep the group
	// descriptor so fini can detach the whole subtree.
	rzshell_cmddescs_init(core);
	ctx->cmd_desc = rz_cmd_get_desc(core->rcmd, "frida");
	if (!ctx->cmd_desc) {
		frida_context_free(ctx);
		rz_warn_if_reached();
		return false;
	}

	// register the configurable limits the cmds read.
	rz_config_add_integer(core->config, "frida.mem.max", "Maximum bytes per frida memory read or write, 0 for no limit", RZ_FRIDA_MEM_MAX_DEFAULT);
	rz_config_add_integer(core->config, "frida.timeout", "Frida session and agent request timeout in milliseconds", RZ_FRIDA_DEFAULT_TIMEOUT_MS);
	rz_config_add_integer(core->config, "frida.hw.watchpoints", "Maximum hardware watchpoint slots fridaW may use, capped by the CPU", RZ_FRIDA_HW_WATCHPOINTS_DEFAULT);
	rz_config_add_integer(core->config, "frida.java.max", "Maximum loaded classes fridaC returns per request, 0 for unlimited", RZ_FRIDA_JAVA_MAX_DEFAULT);
	rz_config_add_integer(core->config, "frida.ac.min", "Minimum characters typed before class autocomplete triggers", 2);
	rz_config_add_integer(core->config, "frida.ac.max", "Maximum class autocomplete suggestions shown", 12);

	rz_frida_backend_init();

	*user = ctx;
	return true;
}

static bool rz_frida_plugin_fini(RzCore *core, void *user) {
	RzFridaCoreContext *ctx = user;
	rz_return_val_if_fail(core && ctx, false);
	bool ok = rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc);
	ctx->cmd_desc = NULL;
	frida_context_free(ctx);
	rz_frida_backend_deinit();
	return ok;
}

RzCorePlugin rz_core_plugin_frida = {
	.name = "rz_frida",
	.desc = "Frida integration for Rizin",
	.license = "LGPL-3.0",
	.author = "Alok Kumar Mishra",
	.version = "0.1.0",
	.init = rz_frida_plugin_init,
	.fini = rz_frida_plugin_fini,
};

#ifdef _MSC_VER
#define RZ_EXPORT __declspec(dllexport)
#else
#define RZ_EXPORT
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_EXPORT RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_frida,
	.version = RZ_VERSION,
};
#endif
