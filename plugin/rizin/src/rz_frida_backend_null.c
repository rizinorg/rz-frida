// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Frida-less device backend. meson compiles this in place of
// rz_frida_backend.c when frida-core is unavailable, so the backend entry
// points stay linkable and report that Frida support is not enabled.

#include <rz_frida.h>

RZ_IPI void rz_frida_backend_init(void) {
}

RZ_IPI void rz_frida_backend_deinit(void) {
}

RZ_IPI bool rz_frida_devices_json(PJ *pj) {
	rz_return_val_if_fail(pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_processes_json(RZ_UNUSED const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_apps_json(RZ_UNUSED const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_open(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_resume(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_close(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_eval(RzFridaSession *session, RZ_UNUSED const char *source, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_mem_read(RZ_NONNULL RzFridaSession *session, RZ_UNUSED ut64 address, RZ_UNUSED ut64 size, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_mem_write(RZ_NONNULL RzFridaSession *session, RZ_UNUSED ut64 address, RZ_NONNULL RZ_UNUSED const ut8 *bytes, RZ_UNUSED size_t len, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_ranges(RZ_NONNULL RzFridaSession *session, RZ_UNUSED bool refresh, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_threads(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_modules(RZ_NONNULL RzFridaSession *session, RZ_UNUSED bool refresh, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_exports(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RZ_UNUSED const char *module, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_imports(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RZ_UNUSED const char *module, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_symbols(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RZ_UNUSED const char *module, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_bp_set(RZ_NONNULL RzFridaSession *session, RZ_UNUSED ut64 address, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_bp_list(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_bp_remove(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RZ_UNUSED const char *address, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && address && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_continue(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE RZ_UNUSED const char *thread_id, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_reg_read(RZ_NONNULL RzFridaSession *session, RZ_UNUSED ut64 thread_id, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_reg_write(RZ_NONNULL RzFridaSession *session, RZ_UNUSED ut64 thread_id, RZ_NONNULL RZ_UNUSED const char *reg, RZ_NONNULL RZ_UNUSED const char *value, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && reg && value && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_wp_set(RZ_NONNULL RzFridaSession *session, RZ_UNUSED ut64 address, RZ_UNUSED ut64 size, RZ_NULLABLE RZ_UNUSED const char *conditions, RZ_UNUSED ut64 slots, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_wp_list(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_wp_remove(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RZ_UNUSED const char *address, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && address && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_java_available(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_loaders(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_classes(RZ_NONNULL RzFridaSession *session, RZ_UNUSED RZ_NULLABLE const char *prefix, RZ_UNUSED ut64 max, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_class_describe(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RZ_UNUSED const char *className, RZ_UNUSED ut64 loaderId, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && className && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI RZ_OWN char **rz_frida_backend_class_list(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE RZ_UNUSED const char *prefix, RZ_UNUSED ut64 max, RZ_NONNULL RZ_UNUSED size_t *count_out) {
	rz_return_val_if_fail(session && count_out, NULL);
	*count_out = 0;
	return NULL;
}

RZ_IPI bool rz_frida_backend_import_class(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RZ_UNUSED RzCore *core, RZ_NONNULL RZ_UNUSED const char *className, RZ_UNUSED ut64 loaderId, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && core && className && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_ping(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_messages(RZ_NONNULL RZ_BORROW RzFridaSession *session, RZ_NONNULL RZ_BORROW PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}
