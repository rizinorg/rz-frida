// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Frida-backed device backend. meson compiles this translation unit only when
// frida-core is available and linkable, builds without frida-core compile
// rz_frida_backend_null.c in its place.

#include <rz_frida.h>

#include <frida-core.h>

#include <rz_analysis.h>
#include <rz_core.h>

#include <rzfrida_agent.h>

#define RZ_FRIDA_DRAIN_POLL_MS 50

static int frida_runtime_refs = 0;

/**
 * \brief Start the Frida runtime used by the plugin backend.
 */
RZ_IPI void rz_frida_backend_init(void) {
	if (frida_runtime_refs++ == 0) {
		frida_init();
	}
}

/**
 * \brief Stop the Frida runtime used by the plugin backend.
 */
RZ_IPI void rz_frida_backend_deinit(void) {
	rz_return_if_fail(frida_runtime_refs > 0);
	if (--frida_runtime_refs == 0) {
		frida_deinit();
	}
}

static const char *device_type_string(FridaDeviceType type) {
	switch (type) {
	case FRIDA_DEVICE_TYPE_LOCAL:
		return "local";
	case FRIDA_DEVICE_TYPE_REMOTE:
		return "remote";
	case FRIDA_DEVICE_TYPE_USB:
		return "usb";
	default:
		return "unknown";
	}
}

static RzFridaError backend_error_code(GCancellable *cancellable, GError *error);

static FridaDevice *backend_resolve_device(FridaDeviceManager *manager, const RzFridaUri *uri, gint timeout, GCancellable *cancellable, GError **error) {
	rz_return_val_if_fail(manager, NULL);

	RzFridaTransport transport = uri ? uri->transport_type : RZ_FRIDA_TRANSPORT_LOCAL;
	switch (transport) {
	case RZ_FRIDA_TRANSPORT_USB:
		if (uri && RZ_STR_ISNOTEMPTY(uri->device)) {
			return frida_device_manager_get_device_by_id_sync(manager, uri->device, timeout, cancellable, error);
		}
		return frida_device_manager_get_device_by_type_sync(manager, FRIDA_DEVICE_TYPE_USB, timeout, cancellable, error);
	case RZ_FRIDA_TRANSPORT_REMOTE: {
		FridaRemoteDeviceOptions *options = frida_remote_device_options_new();
		if (!options) {
			return NULL;
		}
		FridaDevice *device = frida_device_manager_add_remote_device_sync(manager, uri ? uri->device : "", options, cancellable, error);
		frida_unref(options);
		return device;
	}
	case RZ_FRIDA_TRANSPORT_LOCAL:
		return frida_device_manager_get_device_by_type_sync(manager, FRIDA_DEVICE_TYPE_LOCAL, timeout, cancellable, error);
	case RZ_FRIDA_TRANSPORT_UNKNOWN:
	default:
		return NULL;
	}
}

/**
 * \brief Enumerate the available Frida devices into a JSON envelope.
 *
 * Writes an ok:true envelope carrying a "devices" array on success, or an
 * ok:false error envelope on failure. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the device list was emitted, false on any error.
 */
RZ_IPI bool rz_frida_devices_json(PJ *pj) {
	rz_return_val_if_fail(pj, false);

	bool ok = false;
	GError *error = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDeviceList *devices = NULL;

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	devices = frida_device_manager_enumerate_devices_sync(manager, NULL, &error);
	if (!devices) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL,
			error ? error->message : "cannot enumerate Frida devices");
		goto cleanup;
	}

	rz_frida_json_ok_begin(pj);
	pj_ka(pj, "devices");
	const gint count = frida_device_list_size(devices);
	for (gint i = 0; i < count; i++) {
		FridaDevice *device = frida_device_list_get(devices, i);
		if (!device) {
			continue;
		}
		pj_o(pj);
		pj_ks(pj, "id", frida_device_get_id(device));
		pj_ks(pj, "name", frida_device_get_name(device));
		pj_ks(pj, "type", device_type_string(frida_device_get_dtype(device)));
		pj_kb(pj, "lost", frida_device_is_lost(device));
		pj_end(pj);
		g_object_unref(device);
	}
	pj_end(pj);
	rz_frida_json_ok_end(pj);
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (devices) {
		frida_unref(devices);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	return ok;
}

/**
 * \brief Enumerate the processes on a device into a JSON envelope.
 *
 * Resolves the device selected by \p uri, NULL or the local transport selects
 * the local device, then writes an ok:true envelope carrying a "processes"
 * array on success, or an ok:false error envelope on failure. When the plugin
 * is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param uri Parsed URI whose transport and device select the device, or NULL for local.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the process list was emitted, false on any error.
 */
RZ_IPI bool rz_frida_processes_json(const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);

	bool ok = false;
	GError *error = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDevice *device = NULL;
	FridaProcessQueryOptions *options = NULL;
	FridaProcessList *processes = NULL;

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	device = backend_resolve_device(manager, uri, RZ_FRIDA_DEFAULT_TIMEOUT_MS, NULL, &error);
	if (!device) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot open the Frida device");
		goto cleanup;
	}

	options = frida_process_query_options_new();
	if (!options) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida process query options");
		goto cleanup;
	}

	processes = frida_device_enumerate_processes_sync(device, options, NULL, &error);
	if (!processes) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot enumerate processes");
		goto cleanup;
	}

	rz_frida_json_ok_begin(pj);
	pj_ka(pj, "processes");
	const gint count = frida_process_list_size(processes);
	for (gint i = 0; i < count; i++) {
		FridaProcess *process = frida_process_list_get(processes, i);
		if (!process) {
			continue;
		}
		pj_o(pj);
		pj_kn(pj, "pid", frida_process_get_pid(process));
		pj_ks(pj, "name", frida_process_get_name(process));
		pj_end(pj);
		g_object_unref(process);
	}
	pj_end(pj);
	rz_frida_json_ok_end(pj);
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (processes) {
		frida_unref(processes);
	}
	if (options) {
		frida_unref(options);
	}
	if (device) {
		frida_unref(device);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	return ok;
}

/**
 * \brief Enumerate the applications on a device into a JSON envelope.
 *
 * Resolves the device selected by \p uri, NULL or the local transport selects
 * the local device, then writes an ok:true envelope carrying an "apps" array on
 * success, or an ok:false error envelope on failure. Application listing is most
 * useful for Android and iOS targets reached over USB. When the plugin is built
 * without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param uri Parsed URI whose transport and device select the device, or NULL for local.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the application list was emitted, false on any error.
 */
RZ_IPI bool rz_frida_apps_json(const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);

	bool ok = false;
	GError *error = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDevice *device = NULL;
	FridaApplicationQueryOptions *options = NULL;
	FridaApplicationList *apps = NULL;

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	device = backend_resolve_device(manager, uri, RZ_FRIDA_DEFAULT_TIMEOUT_MS, NULL, &error);
	if (!device) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot open the Frida device");
		goto cleanup;
	}

	options = frida_application_query_options_new();
	if (!options) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida application query options");
		goto cleanup;
	}

	apps = frida_device_enumerate_applications_sync(device, options, NULL, &error);
	if (!apps) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot enumerate applications");
		goto cleanup;
	}

	rz_frida_json_ok_begin(pj);
	pj_ka(pj, "apps");
	const gint count = frida_application_list_size(apps);
	for (gint i = 0; i < count; i++) {
		FridaApplication *app = frida_application_list_get(apps, i);
		if (!app) {
			continue;
		}
		pj_o(pj);
		pj_ks(pj, "identifier", frida_application_get_identifier(app));
		pj_ks(pj, "name", frida_application_get_name(app));
		pj_kn(pj, "pid", frida_application_get_pid(app));
		pj_end(pj);
		g_object_unref(app);
	}
	pj_end(pj);
	rz_frida_json_ok_end(pj);
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (apps) {
		frida_unref(apps);
	}
	if (options) {
		frida_unref(options);
	}
	if (device) {
		frida_unref(device);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	return ok;
}

typedef struct rz_frida_backend_session_t {
	FridaDeviceManager *manager;
	FridaDevice *device;
	FridaSession *session;
	GCancellable *cancellable;
	guint pid;
	bool spawned;
	bool resumed;
	FridaScript *script; ///< Loaded agent script, or NULL until first use.
	gulong message_handler; ///< Handler id for the script message signal, or 0.
	RzFridaPending *pending; ///< Ids of requests still awaiting a reply.
	ut64 await_id; ///< Request id the active drain waits for, 0 when idle.
	bool reply_ready; ///< Set when the awaited reply has been captured.
	RzFridaResponse reply; ///< Captured reply, owned while reply_ready is set.
	RzFridaMsgBuf *messages; ///< Async agent output not tied to a request.
	GMutex lock; ///< Guards reply state and the async message buffer.
	GCond reply_cond; ///< Signaled when reply_ready becomes true.
} RzFridaBackendSession;

static void backend_script_teardown(RzFridaBackendSession *backend);

static void backend_session_dispose(RzFridaSession *session) {
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		return;
	}
	rz_frida_session_set_cancel_hook(session, NULL, NULL);
	// unload the agent while the session is still attached, then free the registry.
	backend_script_teardown(backend);
	rz_frida_pending_free(backend->pending);
	rz_frida_msgbuf_free(backend->messages);
	if (backend->session) {
		if (!frida_session_is_detached(backend->session)) {
			frida_session_detach_sync(backend->session, NULL, NULL);
		}
		frida_unref(backend->session);
	}
	if (backend->device) {
		// kill a spawned target we never resumed, else it stays suspended.
		if (backend->spawned && !backend->resumed) {
			frida_device_kill_sync(backend->device, backend->pid, NULL, NULL);
		}
		frida_unref(backend->device);
	}
	if (backend->manager) {
		frida_device_manager_close_sync(backend->manager, NULL, NULL);
		frida_unref(backend->manager);
	}
	if (backend->cancellable) {
		g_object_unref(backend->cancellable);
	}
	g_cond_clear(&backend->reply_cond);
	g_mutex_clear(&backend->lock);
	RZ_FREE(backend);
}

static void backend_cancel_hook(void *user) {
	if (user) {
		g_cancellable_cancel((GCancellable *)user);
	}
}

static RzFridaError backend_error_code(GCancellable *cancellable, GError *error) {
	if (cancellable && g_cancellable_is_cancelled(cancellable)) {
		return RZ_FRIDA_ERROR_CANCELLED;
	}
	if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		return RZ_FRIDA_ERROR_CANCELLED;
	}
	if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT)) {
		return RZ_FRIDA_ERROR_TIMEOUT;
	}
	if (error && g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_TIMED_OUT)) {
		return RZ_FRIDA_ERROR_TIMEOUT;
	}
	if (error && (g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_PROCESS_NOT_FOUND) ||
			g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_EXECUTABLE_NOT_FOUND) ||
			g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED))) {
		return RZ_FRIDA_ERROR_INVALID_TARGET;
	}
	return RZ_FRIDA_ERROR_INTERNAL;
}

static bool backend_resolve_pid(FridaDevice *device, const RzFridaUri *uri, GCancellable *cancellable, guint *pid, GError **error) {
	rz_return_val_if_fail(device && uri && pid, false);

	ut32 numeric = 0;
	if (rz_frida_uri_target_pid(uri->target, &numeric)) {
		*pid = numeric;
		return true;
	}
	FridaProcessMatchOptions *options = frida_process_match_options_new();
	if (!options) {
		return false;
	}
	// 0 match timeout, unknown names fail directly
	frida_process_match_options_set_timeout(options, 0);
	FridaProcess *process = frida_device_get_process_by_name_sync(device, uri->target, options, cancellable, error);
	frida_unref(options);
	if (!process) {
		return false;
	}
	*pid = frida_process_get_pid(process);
	g_object_unref(process);
	return true;
}

/**
 * \brief Open a session for the target described by the session URI.
 *
 * Resolves the local device, then attaches to a pid, or spawns or launches the
 * target before attaching. On success the live Frida handles are stored on the
 * session and an ok:true envelope carrying the action, pid, and state is
 * written, and on failure an ok:false envelope is written. When the plugin is built
 * without frida-core, a self contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session that owns the resolved URI and receives the backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the session was opened, false on any error.
 */
RZ_IPI bool rz_frida_backend_open(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	const RzFridaUri *uri = rz_frida_session_uri(session);
	if (!uri) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "session has no URI");
		return false;
	}
	switch (uri->action_type) {
	case RZ_FRIDA_ACTION_ATTACH:
	case RZ_FRIDA_ACTION_SPAWN:
	case RZ_FRIDA_ACTION_LAUNCH:
		break;
	default:
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "URI action cannot open a session");
		return false;
	}

	bool ok = false;
	GError *error = NULL;
	GCancellable *cancellable = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDevice *device = NULL;
	FridaSession *frida_session = NULL;
	FridaSpawnOptions *spawn_options = NULL;
	RzFridaBackendSession *backend = NULL;
	guint pid = 0;
	bool spawned = false;
	bool resumed = false;

	cancellable = g_cancellable_new();
	if (!cancellable) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create the cancellable");
		goto cleanup;
	}

	rz_frida_session_set_cancel_hook(session, cancellable, backend_cancel_hook);
	if (rz_frida_session_is_cancelled(session)) {
		g_cancellable_cancel(cancellable);
	}

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	device = backend_resolve_device(manager, uri, (gint)rz_frida_session_timeout(session), cancellable, &error);
	if (!device) {
		rz_frida_json_error(pj, backend_error_code(cancellable, error),
			error ? error->message : "cannot open the Frida device");
		goto cleanup;
	}

	if (uri->action_type == RZ_FRIDA_ACTION_ATTACH) {
		if (!backend_resolve_pid(device, uri, cancellable, &pid, &error)) {
			rz_frida_json_error(pj, backend_error_code(cancellable, error),
				error ? error->message : "cannot resolve the attach target");
			goto cleanup;
		}
	} else {
		spawn_options = frida_spawn_options_new();
		if (!spawn_options) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida spawn options");
			goto cleanup;
		}
		pid = frida_device_spawn_sync(device, uri->target, spawn_options, cancellable, &error);
		if (error) {
			rz_frida_json_error(pj, backend_error_code(cancellable, error),
				error->message ? error->message : "cannot spawn the target");
			goto cleanup;
		}
		spawned = true;
	}

	frida_session = frida_device_attach_sync(device, pid, NULL, cancellable, &error);
	if (!frida_session) {
		rz_frida_json_error(pj, backend_error_code(cancellable, error),
			error ? error->message : "cannot attach to the target");
		goto cleanup;
	}

	if (uri->action_type == RZ_FRIDA_ACTION_LAUNCH) {
		frida_device_resume_sync(device, pid, cancellable, &error);
		if (error) {
			rz_frida_json_error(pj, backend_error_code(cancellable, error),
				error->message ? error->message : "cannot resume the launched target");
			goto cleanup;
		}
		resumed = true;
	}

	backend = RZ_NEW0(RzFridaBackendSession);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate backend session state");
		goto cleanup;
	}
	g_mutex_init(&backend->lock);
	g_cond_init(&backend->reply_cond);
	backend->manager = manager;
	backend->device = device;
	backend->session = frida_session;
	backend->cancellable = cancellable;
	backend->pid = pid;
	backend->spawned = spawned;
	backend->resumed = resumed;

	rz_frida_session_set_backend_state(session, backend, backend_session_dispose);
	rz_frida_session_set_target_pid(session, (ut32)pid);
	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_ATTACHED);

	rz_frida_json_ok_begin(pj);
	pj_ks(pj, "action", uri->action);
	pj_kn(pj, "pid", pid);
	pj_kb(pj, "resumed", resumed);
	pj_ks(pj, "state", rz_frida_session_state_string(rz_frida_session_state(session)));
	rz_frida_json_ok_end(pj);

	// the session owns these now, so the cleanup path shouldnt touch them.
	manager = NULL;
	device = NULL;
	frida_session = NULL;
	cancellable = NULL;
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (spawn_options) {
		frida_unref(spawn_options);
	}
	if (frida_session) {
		frida_session_detach_sync(frida_session, NULL, NULL);
		frida_unref(frida_session);
	}
	if (!ok && spawned && device) {
		frida_device_kill_sync(device, pid, NULL, NULL);
	}
	if (device) {
		frida_unref(device);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	if (cancellable) {
		// failed open, clear hook before releasing cancellable
		rz_frida_session_set_cancel_hook(session, NULL, NULL);
		g_object_unref(cancellable);
	}
	return ok;
}

/**
 * \brief Resume a target that was spawned suspended by \ref rz_frida_backend_open.
 *
 * Writes an ok:true envelope on success, or an ok:false envelope when the
 * session has nothing to resume or the backend is unavailable.
 *
 * \param session Session holding the backend handles to resume.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the target was resumed, false on any error.
 */
RZ_IPI bool rz_frida_backend_resume(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "session has no backend state");
		return false;
	}
	if (!backend->spawned) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "session was attached and has nothing to resume");
		return false;
	}
	if (backend->resumed) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "session has already been resumed");
		return false;
	}

	if (backend->cancellable) {
		g_cancellable_reset(backend->cancellable);
	}
	GError *error = NULL;
	frida_device_resume_sync(backend->device, backend->pid, backend->cancellable, &error);
	if (error) {
		rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
			error->message ? error->message : "cannot resume the target");
		g_error_free(error);
		return false;
	}
	backend->resumed = true;

	rz_frida_json_ok_begin(pj);
	pj_kn(pj, "pid", backend->pid);
	pj_kb(pj, "resumed", true);
	pj_ks(pj, "state", rz_frida_session_state_string(rz_frida_session_state(session)));
	rz_frida_json_ok_end(pj);
	return true;
}

/**
 * \brief Detach the open session and report it as closed.
 *
 * Detaches from the target and writes an ok:true envelope carrying the pid and
 * final state. The caller frees the session afterwards, which kills a target
 * that was spawned but never resumed and releases the remaining handles. When
 * the plugin is built without frida-core, a self-contained implementation
 * reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the backend handles to detach.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the session was closed, false on any error.
 */
RZ_IPI bool rz_frida_backend_close(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "session has no backend state");
		return false;
	}

	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_DETACHING);
	if (backend->cancellable) {
		g_cancellable_reset(backend->cancellable);
	}
	GError *error = NULL;
	if (backend->session && !frida_session_is_detached(backend->session)) {
		frida_session_detach_sync(backend->session, backend->cancellable, &error);
		if (error) {
			rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_ERROR);
			rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
				error->message ? error->message : "cannot detach from the target");
			g_error_free(error);
			return false;
		}
	}
	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_CLOSED);

	rz_frida_json_ok_begin(pj);
	pj_kn(pj, "pid", backend->pid);
	pj_ks(pj, "state", rz_frida_session_state_string(rz_frida_session_state(session)));
	rz_frida_json_ok_end(pj);
	return true;
}

static void backend_script_teardown(RzFridaBackendSession *backend) {
	if (!backend) {
		return;
	}
	if (backend->script && backend->message_handler) {
		g_signal_handler_disconnect(backend->script, backend->message_handler);
	}
	backend->message_handler = 0;
	g_mutex_lock(&backend->lock);
	backend->await_id = 0;
	backend->reply_ready = false;
	rz_frida_response_fini(&backend->reply);
	g_cond_broadcast(&backend->reply_cond);
	g_mutex_unlock(&backend->lock);
	if (backend->script) {
		if (!frida_script_is_destroyed(backend->script)) {
			frida_script_unload_sync(backend->script, NULL, NULL);
		}
		frida_unref(backend->script);
		backend->script = NULL;
	}
}

// match an agent msg to the in-flight req or buffer it as async output.
static void backend_on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user) {
	(void)script;
	RzFridaBackendSession *backend = user;
	if (!backend || !message) {
		return;
	}
	RzFridaAgentMessage parsed = { 0 };
	if (!rz_frida_agent_message_parse(message, &parsed)) {
		return;
	}
	g_mutex_lock(&backend->lock);
	// send may answer in-flight req, capture it as reply.
	if (parsed.kind == RZ_FRIDA_AGENT_MESSAGE_SEND && parsed.payload) {
		RzFridaResponse response = { 0 };
		if (rz_frida_response_parse(parsed.payload, &response)) {
			if (response.id == backend->await_id && rz_frida_pending_take(backend->pending, response.id)) {
				rz_frida_response_fini(&backend->reply);
				backend->reply = response;
				backend->reply_ready = true;
				rz_mem_memzero(&response, sizeof(response));
				g_cond_signal(&backend->reply_cond);
				g_mutex_unlock(&backend->lock);
				rz_frida_agent_message_fini(&parsed);
				return;
			}
			rz_frida_response_fini(&response);
		}
	}
	// anything else is async script output, keep it with its binary data.
	if (data) {
		gsize size = 0;
		gconstpointer bytes = g_bytes_get_data(data, &size);
		if (bytes && size > 0) {
			parsed.data = rz_buf_new_with_bytes(bytes, size);
		}
	}
	if (!backend->messages || !rz_frida_msgbuf_push(backend->messages, &parsed)) {
		rz_frida_agent_message_fini(&parsed);
	}
	g_mutex_unlock(&backend->lock);
}

typedef enum {
	BACKEND_DRAIN_REPLY = 0,
	BACKEND_DRAIN_TIMEOUT,
	BACKEND_DRAIN_CANCELLED,
	BACKEND_DRAIN_GONE,
} BackendDrainResult;

// wait until reply lands, deadline passes, or caller cancels.
static BackendDrainResult backend_drain_reply(RzFridaBackendSession *backend, RzFridaSession *session, ut64 timeout_ms) {
	const gint64 deadline = g_get_monotonic_time() + (gint64)timeout_ms * 1000;
	BackendDrainResult result = BACKEND_DRAIN_TIMEOUT;

	g_mutex_lock(&backend->lock);
	while (!backend->reply_ready) {
		if (rz_frida_session_is_cancelled(session) ||
			(backend->cancellable && g_cancellable_is_cancelled(backend->cancellable))) {
			result = BACKEND_DRAIN_CANCELLED;
			goto beach;
		}
		if (!backend->script || frida_script_is_destroyed(backend->script)) {
			result = BACKEND_DRAIN_GONE;
			goto beach;
		}
		const gint64 now = g_get_monotonic_time();
		if (now >= deadline) {
			result = BACKEND_DRAIN_TIMEOUT;
			goto beach;
		}
		// wake atleast every poll interval so cancel & destroyed script are seen before deadline.
		gint64 wake = now + (gint64)RZ_FRIDA_DRAIN_POLL_MS * 1000;
		if (wake > deadline) {
			wake = deadline;
		}
		g_cond_wait_until(&backend->reply_cond, &backend->lock, wake);
	}
	result = BACKEND_DRAIN_REPLY;

beach:
	g_mutex_unlock(&backend->lock);
	return result;
}

// post a {id, type, params} req and block for the matching reply, moved into *out on success.
static bool backend_request(RzFridaBackendSession *backend, RzFridaSession *session,
	const char *type, const char *params_json, RzFridaResponse *out, RzFridaError *fail_code, const char **fail_msg) {
	ut64 id = rz_frida_pending_next_id(backend->pending);

	PJ *request = pj_new();
	if (!request) {
		*fail_code = RZ_FRIDA_ERROR_INTERNAL;
		*fail_msg = "cannot build the request";
		return false;
	}
	pj_o(request);
	pj_kn(request, "id", id);
	pj_ks(request, "type", type);
	if (RZ_STR_ISNOTEMPTY(params_json)) {
		pj_k(request, "params");
		pj_raw(request, params_json);
	}
	pj_end(request);
	char *request_json = pj_drain(request);
	if (!request_json) {
		*fail_code = RZ_FRIDA_ERROR_INTERNAL;
		*fail_msg = "cannot build the request";
		return false;
	}

	g_mutex_lock(&backend->lock);
	if (!rz_frida_pending_add(backend->pending, id)) {
		g_mutex_unlock(&backend->lock);
		free(request_json);
		*fail_code = RZ_FRIDA_ERROR_INTERNAL;
		*fail_msg = "cannot track the request";
		return false;
	}
	backend->await_id = id;
	backend->reply_ready = false;
	rz_frida_response_fini(&backend->reply);
	g_mutex_unlock(&backend->lock);

	frida_script_post(backend->script, request_json, NULL);
	free(request_json);

	BackendDrainResult drained = backend_drain_reply(backend, session, rz_frida_session_timeout(session));

	g_mutex_lock(&backend->lock);
	backend->await_id = 0;
	if (drained != BACKEND_DRAIN_REPLY) {
		// drop the in-flight id, a late reply for it is ignored after this.
		rz_frida_pending_take(backend->pending, id);
		backend->reply_ready = false;
		g_mutex_unlock(&backend->lock);
		switch (drained) {
		case BACKEND_DRAIN_CANCELLED:
			*fail_code = RZ_FRIDA_ERROR_CANCELLED;
			*fail_msg = "the request was cancelled";
			break;
		case BACKEND_DRAIN_GONE:
			*fail_code = RZ_FRIDA_ERROR_INTERNAL;
			*fail_msg = "the agent script is no longer loaded";
			break;
		case BACKEND_DRAIN_TIMEOUT:
		default:
			*fail_code = RZ_FRIDA_ERROR_TIMEOUT;
			*fail_msg = "the request timed out";
			break;
		}
		return false;
	}

	*out = backend->reply;
	rz_mem_memzero(&backend->reply, sizeof(backend->reply));
	backend->reply_ready = false;
	g_mutex_unlock(&backend->lock);
	return true;
}

// fwd the agent reply as our envelope, the agent's obj becomes the result body as is.
static bool backend_emit_response(PJ *pj, const RzFridaResponse *response) {
	if (!response->ok) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL,
			response->error ? response->error : "the agent reported an error");
		return false;
	}
	pj_o(pj);
	pj_kb(pj, "ok", true);
	pj_k(pj, "result");
	if (response->result) {
		pj_raw(pj, response->result);
	} else {
		pj_o(pj);
		pj_end(pj);
	}
	pj_end(pj);
	return true;
}

// create and load the agent script once per session, reload if died.
static bool backend_ensure_script(RzFridaBackendSession *backend, RzFridaSession *session, PJ *pj) {
	// start each req with a clean cancellation state.
	if (backend->cancellable) {
		g_cancellable_reset(backend->cancellable);
	}
	rz_frida_session_reset_cancel(session);
	if (backend->script && !frida_script_is_destroyed(backend->script)) {
		return true;
	}
	if (backend->script) {
		// died, so drop before reload.
		backend_script_teardown(backend);
	}
	if (!backend->session || frida_session_is_detached(backend->session)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "the session is not attached");
		return false;
	}
	if (!backend->pending) {
		backend->pending = rz_frida_pending_new();
		if (!backend->pending) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the request registry");
			return false;
		}
	}
	if (!backend->messages) {
		backend->messages = rz_frida_msgbuf_new(0);
		if (!backend->messages) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the message buffer");
			return false;
		}
	}
	GError *error = NULL;
	FridaScriptOptions *options = frida_script_options_new();
	if (!options) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create the script options");
		return false;
	}
	frida_script_options_set_name(options, "rzfrida");
	// embedded agent is unsigned byte array, frida needs c string.
	FridaScript *script = frida_session_create_script_sync(backend->session, (const char *)rz_frida_agent_source, options, backend->cancellable, &error);
	frida_unref(options);
	if (!script) {
		rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
			error ? error->message : "cannot create the agent script");
		if (error) {
			g_error_free(error);
		}
		return false;
	}

	gulong handler = g_signal_connect(script, "message", G_CALLBACK(backend_on_message), backend);
	frida_script_load_sync(script, backend->cancellable, &error);
	if (error) {
		rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
			error->message ? error->message : "cannot load the agent script");
		g_signal_handler_disconnect(script, handler);
		frida_unref(script);
		g_error_free(error);
		return false;
	}

	backend->script = script;
	backend->message_handler = handler;
	return true;
}

/**
 * \brief Evaluate a JavaScript snippet inside the target through the agent.
 *
 * Loads the agent on first use, sends an eval request, and writes an ok:true
 * envelope carrying the value and its type, or an ok:false envelope on
 * timeout, cancel, or an agent error. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param source JavaScript expression to evaluate.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with a result, false on any error.
 */
RZ_IPI bool rz_frida_backend_eval(RzFridaSession *session, const char *source, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	if (!RZ_STR_ISNOTEMPTY(source)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "missing script source");
		return false;
	}
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_ks(params, "source", source);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "eval", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Read a block of target memory through the agent.
 *
 * Loads the agent on first use, sends a memRead request, and writes an ok:true
 * envelope carrying the address, byte count, and the bytes as a hex string, or
 * an ok:false envelope on timeout, cancel, or an agent error. When the plugin
 * is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param address Target address to read from.
 * \param size Number of bytes to read.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the bytes, false on any error.
 */
RZ_IPI bool rz_frida_backend_mem_read(RZ_NONNULL RzFridaSession *session, ut64 address, ut64 size, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	if (size == 0) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "read size must be non-zero");
		return false;
	}
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	// addrs can exceed what json num holds, so pass them as txt.
	char address_str[32];
	rz_strf(address_str, "0x%" PFMT64x, address);
	pj_o(params);
	pj_ks(params, "address", address_str);
	pj_kn(params, "size", size);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "memRead", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Write a block of bytes into target memory through the agent.
 *
 * Loads the agent on first use, sends a memWrite request carrying the bytes as
 * a hex string, and writes an ok:true envelope with the address and byte count,
 * or an ok:false envelope on timeout, cancel, or an agent error. When the
 * plugin is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param address Target address to write to.
 * \param bytes Bytes to write.
 * \param len Number of bytes to write.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent confirmed the write, false on any error.
 */
RZ_IPI bool rz_frida_backend_mem_write(RZ_NONNULL RzFridaSession *session, ut64 address, RZ_NONNULL const ut8 *bytes, size_t len, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj && bytes, false);

	if (len == 0) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no bytes to write");
		return false;
	}
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	char *hex = malloc(len * 2 + 1);
	if (!hex) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	if (rz_hex_bin2str(bytes, (int)len, hex) < 1) {
		free(hex);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot encode the bytes to write");
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		free(hex);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	char address_str[32];
	rz_strf(address_str, "0x%" PFMT64x, address);
	pj_o(params);
	pj_ks(params, "address", address_str);
	pj_ks(params, "bytes", hex);
	pj_end(params);
	free(hex);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "memWrite", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief List the target memory ranges through the agent.
 *
 * Loads the agent on first use and sends a ranges request. The agent caches the
 * range list and re-enumerates when \p refresh is set or after code runs in the
 * target, so the reply stays fresh without re-scanning on every call. Writes an
 * ok:true envelope carrying the ranges and whether they came from the cache, or
 * an ok:false envelope on timeout, cancel, or an agent error. When the plugin is
 * built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param refresh Re-enumerate instead of serving the cached range list.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the ranges, false on any error.
 */
RZ_IPI bool rz_frida_backend_ranges(RZ_NONNULL RzFridaSession *session, bool refresh, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	char *params_json = NULL;
	if (refresh) {
		PJ *params = pj_new();
		if (!params) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
			return false;
		}
		pj_o(params);
		pj_kb(params, "refresh", true);
		pj_end(params);
		params_json = pj_drain(params);
		if (!params_json) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
			return false;
		}
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "ranges", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief List the target threads through the agent.
 *
 * Loads the agent on first use, sends a threads request, and writes an ok:true
 * envelope carrying the thread ids and states, or an ok:false envelope on
 * timeout, cancel, or an agent error. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the threads, false on any error.
 */
RZ_IPI bool rz_frida_backend_threads(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "threads", NULL, &response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief List the target modules through the agent.
 *
 * Loads the agent on first use and sends a modules request. The agent caches the
 * module list and re-enumerates when \p refresh is set or after code runs in the
 * target. Writes an ok:true envelope carrying the modules and whether they came
 * from the cache, or an ok:false envelope on timeout, cancel, or an agent error.
 * When the plugin is built without frida-core, a self-contained implementation
 * reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param refresh Re-enumerate instead of serving the cached module list.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the modules, false on any error.
 */
RZ_IPI bool rz_frida_backend_modules(RZ_NONNULL RzFridaSession *session, bool refresh, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	char *params_json = NULL;
	if (refresh) {
		PJ *params = pj_new();
		if (!params) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
			return false;
		}
		pj_o(params);
		pj_kb(params, "refresh", true);
		pj_end(params);
		params_json = pj_drain(params);
		if (!params_json) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
			return false;
		}
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "modules", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

static bool backend_module_query(RzFridaSession *session, const char *kind, const char *module, PJ *pj) {
	if (!RZ_STR_ISNOTEMPTY(module)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "missing module name");
		return false;
	}
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_ks(params, "module", module);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, kind, params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief List the exports of a target module through the agent.
 *
 * Loads the agent on first use and lists the named module's exports, each with
 * its type, name, and address. Writes an ok:false envelope on a missing module
 * name, timeout, cancel, or an agent error, and reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE when built without frida-core.
 *
 * \param session Session holding the attached backend handles.
 * \param module Name of the module whose exports are listed.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the exports, false on any error.
 */
RZ_IPI bool rz_frida_backend_exports(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *module, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && module && pj, false);
	return backend_module_query(session, "exports", module, pj);
}

/**
 * \brief List the imports of a target module through the agent.
 *
 * Like \ref rz_frida_backend_exports, listing the named module's imports, each
 * with its type, name, source module, and address.
 *
 * \param session Session holding the attached backend handles.
 * \param module Name of the module whose imports are listed.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the imports, false on any error.
 */
RZ_IPI bool rz_frida_backend_imports(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *module, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && module && pj, false);
	return backend_module_query(session, "imports", module, pj);
}

/**
 * \brief List the symbols of a target module through the agent.
 *
 * Like \ref rz_frida_backend_exports, listing the named module's symbols. The
 * result is empty for a module that carries no symbol table.
 *
 * \param session Session holding the attached backend handles.
 * \param module Name of the module whose symbols are listed.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the symbols, false on any error.
 */
RZ_IPI bool rz_frida_backend_symbols(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *module, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && module && pj, false);
	return backend_module_query(session, "symbols", module, pj);
}

/**
 * \brief Set a native breakpoint at an address through the agent.
 *
 * Loads the agent on first use and attaches a breakpoint. A hit later arrives as
 * an asynchronous frida.bp message in the buffer drained by \ref rz_frida_backend_messages,
 * carrying the thread id and register context, and the thread stays parked until
 * \ref rz_frida_backend_continue. Writes an ok:true envelope with the address and
 * breakpoint id, or an ok:false envelope on timeout, cancel, or an agent error. When
 * the plugin is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param address Target address to break on.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent confirmed the breakpoint, false on any error.
 */
RZ_IPI bool rz_frida_backend_bp_set(RZ_NONNULL RzFridaSession *session, ut64 address, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	char address_str[32];
	rz_strf(address_str, "0x%" PFMT64x, address);
	pj_o(params);
	pj_ks(params, "address", address_str);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "bpSet", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief List the native breakpoints set through the agent.
 *
 * Loads the agent on first use, sends a bpList request, and writes an ok:true
 * envelope carrying the breakpoints with their ids and addresses, or an ok:false
 * envelope on timeout, cancel, or an agent error. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the breakpoints, false on any error.
 */
RZ_IPI bool rz_frida_backend_bp_list(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "bpList", NULL, &response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Remove a native breakpoint set through the agent.
 *
 * Loads the agent on first use and removes the breakpoint at \p address, or every
 * breakpoint when \p address is "*". Writes an ok:true envelope carrying the number
 * removed, or an ok:false envelope on timeout, cancel, or an agent error. When the
 * plugin is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param address Canonical address string to remove, or "*" for all.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent confirmed the removal, false on any error.
 */
RZ_IPI bool rz_frida_backend_bp_remove(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *address, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && address && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_ks(params, "address", address);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "bpRemove", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

// read the most recently parked thread id from a bpParked reply, as the decimal
// str the agent keys its per-thread continue channel on.
static bool backend_recent_parked(const char *result_json, char *out, size_t out_size) {
	if (!result_json) {
		return false;
	}
	char *text = rz_str_dup(result_json);
	if (!text) {
		return false;
	}
	bool ok = false;
	RzJson *json = rz_json_parse(text);
	if (json && json->type == RZ_JSON_OBJECT) {
		const RzJson *recent = rz_json_get(json, "recent");
		if (recent && recent->type == RZ_JSON_INTEGER) {
			snprintf(out, out_size, "%" PFMT64u, (ut64)recent->num.u_value);
			ok = true;
		}
	}
	rz_json_free(json);
	free(text);
	return ok;
}

// post a targeted continue to one parked thread's channel and fwd the reply.
static bool backend_continue_thread(RzFridaBackendSession *backend, RzFridaSession *session, const char *thread_id, PJ *pj) {
	char type[64];
	rz_strf(type, "frida.cont.%s", thread_id);
	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	if (!backend_request(backend, session, type, NULL, &response, &fail_code, &fail_msg)) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Continue a thread parked at a breakpoint through the agent.
 *
 * Loads the agent on first use. With \p thread_id it continues that exact parked
 * thread, with NULL it continues the most recently parked thread, resolved by
 * asking the agent which threads are parked. Writes an ok:true envelope reporting
 * whether a thread was released, or an ok:false envelope on timeout, cancel, or an
 * agent error. When the plugin is built without frida-core, a self-contained
 * implementation reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param thread_id Decimal id of the parked thread to continue, or NULL for the most recent.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent acknowledged the continue, false on any error.
 */
RZ_IPI bool rz_frida_backend_continue(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE const char *thread_id, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	if (RZ_STR_ISNOTEMPTY(thread_id)) {
		return backend_continue_thread(backend, session, thread_id, pj);
	}

	// no thread named, ask which threads are parked and continue most recent one.
	RzFridaResponse parked = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	if (!backend_request(backend, session, "bpParked", NULL, &parked, &fail_code, &fail_msg)) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	char recent[32];
	bool has_recent = parked.ok && backend_recent_parked(parked.result, recent, sizeof(recent));
	rz_frida_response_fini(&parked);
	if (!has_recent) {
		rz_frida_json_ok_begin(pj);
		pj_kb(pj, "resumed", false);
		rz_frida_json_ok_end(pj);
		return true;
	}
	return backend_continue_thread(backend, session, recent, pj);
}

/**
 * \brief Read the register context of a thread parked at a breakpoint through the agent.
 *
 * Loads the agent on first use and asks for the saved register context of the
 * thread stopped at a breakpoint. Writes an ok:true envelope carrying the thread
 * id, the breakpoint it stopped at, and the registers, or an ok:false envelope
 * when the thread is not parked, on timeout, cancel, or an agent error. When the
 * plugin is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param thread_id Id of the parked thread whose registers are read.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the registers, false on any error.
 */
RZ_IPI bool rz_frida_backend_reg_read(RZ_NONNULL RzFridaSession *session, ut64 thread_id, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_kn(params, "threadId", thread_id);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "regRead", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Write a register of a thread parked at a breakpoint through the agent.
 *
 * Loads the agent on first use and sets \p reg to \p value on the thread stopped
 * at a breakpoint. The write lands on the saved register context and takes effect
 * when the thread is continued. Writes an ok:true envelope carrying the thread id,
 * register, and new value, or an ok:false envelope when the thread is not parked,
 * the register is unknown, on timeout, cancel, or an agent error. When the plugin
 * is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param thread_id Id of the parked thread whose register is written.
 * \param reg Name of the register to set.
 * \param value Canonical value string to set the register to.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent confirmed the write, false on any error.
 */
RZ_IPI bool rz_frida_backend_reg_write(RZ_NONNULL RzFridaSession *session, ut64 thread_id, RZ_NONNULL const char *reg, RZ_NONNULL const char *value, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && reg && value && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_kn(params, "threadId", thread_id);
	pj_ks(params, "register", reg);
	pj_ks(params, "value", value);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "regWrite", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Set a hardware watchpoint on a target address through the agent.
 *
 * Loads the agent on first use and arms a hardware watchpoint on every target
 * thread, covering the access in \p conditions ("r", "w", or "rw"). An access
 * later arrives as an asynchronous frida.wp message in the buffer drained by
 * \ref rz_frida_backend_messages, carrying the faulting thread, program counter,
 * and register context, and the watchpoint disarms itself on that hit. Writes an
 * ok:true envelope with the slot, address, size, and conditions, or an ok:false
 * envelope on timeout, cancel, or an agent error. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param address Target address to watch.
 * \param size Number of bytes to watch, 0 to default to the pointer size.
 * \param conditions Access to trap on as "r", "w", or "rw", or NULL for "rw".
 * \param slots Maximum hardware slots the agent may use, 0 for its default.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent confirmed the watchpoint, false on any error.
 */
RZ_IPI bool rz_frida_backend_wp_set(RZ_NONNULL RzFridaSession *session, ut64 address, ut64 size, RZ_NULLABLE const char *conditions, ut64 slots, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	char address_str[32];
	rz_strf(address_str, "0x%" PFMT64x, address);
	pj_o(params);
	pj_ks(params, "address", address_str);
	if (size) {
		pj_kn(params, "size", size);
	}
	if (RZ_STR_ISNOTEMPTY(conditions)) {
		pj_ks(params, "conditions", conditions);
	}
	if (slots) {
		pj_kn(params, "slots", slots);
	}
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "wpSet", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief List the hardware watchpoints set through the agent.
 *
 * Loads the agent on first use, sends a wpList request, and writes an ok:true
 * envelope carrying the watchpoints with their slot, address, size, and
 * conditions, or an ok:false envelope on timeout, cancel, or an agent error.
 * When the plugin is built without frida-core, a self-contained implementation
 * reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with the watchpoints, false on any error.
 */
RZ_IPI bool rz_frida_backend_wp_list(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "wpList", NULL, &response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Remove a hardware watchpoint set through the agent.
 *
 * Loads the agent on first use and disarms the watchpoint at \p address on every
 * thread, or every watchpoint when \p address is "*". Writes an ok:true envelope
 * carrying the number removed, or an ok:false envelope on timeout, cancel, or an
 * agent error. When the plugin is built without frida-core, a self-contained
 * implementation reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param address Canonical address string to remove, or "*" for all.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent confirmed the removal, false on any error.
 */
RZ_IPI bool rz_frida_backend_wp_remove(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *address, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && address && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_ks(params, "address", address);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "wpRemove", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Check whether the Android Java VM is reachable in the target.
 *
 * Loads the agent on first use, sends a javaAvailable request, and writes an
 * ok:true envelope carrying whether Java is available, or an ok:false envelope
 * on timeout, cancel, or an agent error. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied, false on any error.
 */
RZ_IPI bool rz_frida_backend_java_available(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "isJavaAvailable", NULL,
		&response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Enumerate the Java classloaders in the target through the agent.
 *
 * Loads the agent on first use, sends a loaderList request, and writes an
 * ok:true envelope carrying the classloaders with stable integer ids, or an
 * ok:false envelope on timeout, cancel, or an agent error. When the plugin is
 * built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied, false on any error.
 */
RZ_IPI bool rz_frida_backend_loaders(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "loaderList", NULL,
		&response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Enumerate loaded Java classes in the target through the agent.
 *
 * Loads the agent on first use, sends a classList request with an optional
 * prefix filter and a max cap from the frida.java.max config, and writes an
 * ok:true envelope carrying the matching class names together with the count
 * and a truncated flag, or an ok:false envelope on timeout, cancel, or an
 * agent error. When the plugin is built without frida-core, a self-contained
 * implementation reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param prefix Package or class name prefix to filter by, or NULL for all.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied, false on any error.
 */
RZ_IPI bool rz_frida_backend_classes(RZ_NONNULL RzFridaSession *session,
	RZ_NULLABLE const char *prefix, ut64 max, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	if (RZ_STR_ISNOTEMPTY(prefix)) {
		pj_ks(params, "prefix", prefix);
	}
	if (max) {
		pj_kn(params, "max", max);
	}
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "classList", params_json,
		&response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

RZ_IPI bool rz_frida_backend_class_load_monitor(RZ_NONNULL RzFridaSession *session, bool enable, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_kb(params, "enable", enable);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "classLoadMonitor", params_json,
		&response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

RZ_IPI bool rz_frida_backend_newly_loaded_classes(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "newlyLoadedClasses", NULL,
		&response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

RZ_IPI bool rz_frida_backend_rn_set(RZ_NONNULL RzFridaSession *session, bool enable, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_kb(params, "enable", enable);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "rnSet", params_json,
		&response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

RZ_IPI bool rz_frida_backend_rn_list(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "rnList", NULL,
		&response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

RZ_IPI bool rz_frida_backend_flag_modules(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "flagModules", NULL,
		&response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

static int strptr_cmp(const void *a, const void *b) {
	const char *sa = *(const char **)a;
	const char *sb = *(const char **)b;
	if (!sa) {
		return sb ? -1 : 0;
	}
	if (!sb) {
		return 1;
	}
	return strcmp(sa, sb);
}

/**
 * @return caller-owned sorted array of static class names from the loaded binary, or NULL.
 * \p count_out is set to the number of names (may be 0).
 */
static RZ_OWN char **collect_static_class_names(RZ_NULLABLE RzBinObject *o, RZ_NONNULL size_t *count_out) {
	rz_return_val_if_fail(count_out, NULL);
	*count_out = 0;
	if (!o) {
		return NULL;
	}
	const RzPVector *classes = rz_bin_object_get_classes(o);
	if (!classes) {
		return NULL;
	}
	size_t n = rz_pvector_len(classes);
	if (!n) {
		return NULL;
	}
	char **names = RZ_NEWS0(char *, n);
	if (!names) {
		return NULL;
	}
	void **iter;
	size_t idx = 0;
	rz_pvector_foreach (classes, iter) {
		RzBinClass *cls = *iter;
		if (cls && cls->name && idx < n) {
			names[idx++] = cls->name;
		}
	}
	*count_out = idx;
	if (*count_out > 1) {
		qsort(names, *count_out, sizeof(char *), strptr_cmp);
	}
	return names;
}

RZ_IPI bool rz_frida_backend_dex_diff(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prefix, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && core && pj, false);

	ut64 dex_max = rz_config_get_integer(core->config, "frida.dex.max");
	if (!dex_max) {
		dex_max = (ut64)UINT32_MAX;
	}
	size_t count = 0;
	char **names = rz_frida_backend_class_list(session, prefix, dex_max, &count);

	// sort for binary search
	if (names && count > 1) {
		qsort(names, count, sizeof(char *), strptr_cmp);
	}

	size_t static_count = 0;
	char **static_names = collect_static_class_names(core->bin && core->bin->cur ? core->bin->cur->o : NULL, &static_count);

	bool got_static = (static_names != NULL);
	size_t only_static_c = 0, only_runtime_c = 0, both_c = 0;

	// static count
	for (size_t i = 0; i < static_count; i++) {
		bool found = (names && count && bsearch(&static_names[i], names, count, sizeof(char *), strptr_cmp));
		if (found) {
			both_c++;
		} else {
			only_static_c++;
		}
	}

	// runtime count
	if (names) {
		for (size_t i = 0; i < count; i++) {
			bool found = (static_names && bsearch(&names[i], static_names, static_count, sizeof(char *), strptr_cmp));
			if (!found) {
				only_runtime_c++;
			}
		}
	} else {
		only_runtime_c = count;
	}

	rz_frida_json_ok_begin(pj);
	pj_kb(pj, "loaded_bin", got_static);
	pj_kn(pj, "only_static", (ut64)only_static_c);
	pj_kn(pj, "only_runtime", (ut64)only_runtime_c);
	pj_kn(pj, "both", (ut64)both_c);

	if (names) {
		for (size_t i = 0; i < count; i++) { free(names[i]); }
		free(names);
	}
	free(static_names);

	rz_frida_json_ok_end(pj);
	return true;
}

/**
 * \brief Describe a Java class in the target through the agent.
 *
 * Loads the agent on first use, sends a classDescribe request with the fully
 * qualified class name and an optional loader id, and writes an ok:true envelope
 * carrying the structured class description (name, superclass, interfaces,
 * fields, methods, constructors, modifiers, and Kotlin metadata when present),
 * or an ok:false envelope on timeout, cancel, or an agent error.  When the
 * plugin is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param className Fully qualified class name to describe.
 * \param loaderId Stable loader id from a previous loaderList reply, or 0
 *        for the default system loader.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied, false on any error.
 */
RZ_IPI bool rz_frida_backend_class_describe(RZ_NONNULL RzFridaSession *session,
	RZ_NONNULL const char *className, ut64 loaderId, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && className && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_ks(params, "className", className);
	if (loaderId) {
		pj_kn(params, "loaderId", loaderId);
	}
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "classDescribe", params_json,
		&response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Fetch a filtered list of loaded Java class names from the agent.
 *
 * Loads the agent on first use, sends a classList request with a prefix filter
 * and a max cap, parses the agent reply, and returns a freshly allocated
 * NULL-terminated array of class name strings together with the loaded count.
 * Returns NULL on any error (session missing, script not loaded, timeout,
 * cancel, or agent-side failure) and sets *count_out to zero.
 *
 * \param session Session holding the attached backend handles.
 * \param prefix  Class name prefix to send to the agent, or NULL for all.
 * \param max     Max number of classes the agent should return, or 0 for unlimited.
 * \param count_out Receives the number of strings in the returned array.
 * \return NULL-terminated array of individually allocated class name strings,
 *         or NULL on failure.
 */
RZ_IPI RZ_OWN char **rz_frida_backend_class_list(RZ_NONNULL RzFridaSession *session,
	RZ_NULLABLE const char *prefix, ut64 max, RZ_NONNULL size_t *count_out) {
	rz_return_val_if_fail(session && count_out, NULL);
	*count_out = 0;

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		return NULL;
	}

	// capture ensure_script errors in throwaway pj.
	PJ *err_pj = pj_new();
	bool script_ok = backend_ensure_script(backend, session, err_pj);
	if (!script_ok) {
		pj_free(err_pj);
		return NULL;
	}
	pj_free(err_pj);

	PJ *params = pj_new();
	if (!params) {
		return NULL;
	}
	pj_o(params);
	if (RZ_STR_ISNOTEMPTY(prefix)) {
		pj_ks(params, "prefix", prefix);
	}
	if (max) {
		pj_kn(params, "max", max);
	}
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		return NULL;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "classList", params_json,
		&response, &fail_code, &fail_msg);
	free(params_json);
	if (!got || !response.ok || !RZ_STR_ISNOTEMPTY(response.result)) {
		rz_frida_response_fini(&response);
		return NULL;
	}

	// args modified in place, so just dup beforehand.
	char *json_copy = rz_str_dup(response.result);
	rz_frida_response_fini(&response);
	if (!json_copy) {
		return NULL;
	}

	RzJson *root = rz_json_parse(json_copy);
	if (!root || root->type != RZ_JSON_OBJECT) {
		free(json_copy);
		rz_json_free(root);
		return NULL;
	}

	const RzJson *classes_node = rz_json_get(root, "classes");
	if (!classes_node || classes_node->type != RZ_JSON_ARRAY) {
		free(json_copy);
		rz_json_free(root);
		return NULL;
	}

	size_t count = classes_node->children.count;
	char **result = RZ_NEWS0(char *, count + 1);
	if (!result) {
		free(json_copy);
		rz_json_free(root);
		return NULL;
	}

	size_t i = 0;
	const RzJson *child = classes_node->children.first;
	while (child && i < count) {
		const RzJson *name_node = rz_json_get(child, "name");
		if (name_node && name_node->type == RZ_JSON_STRING && name_node->str_value) {
			result[i++] = rz_str_dup(name_node->str_value);
		}
		child = child->next;
	}
	result[i] = NULL;
	*count_out = i;

	free(json_copy);
	rz_json_free(root);
	return result;
}

/**
 * \brief Ping the agent loaded in the target and report what it sees.
 *
 * Loads the agent on first use, sends a ping request, and writes an ok:true
 * envelope carrying the agent version and the target platform, architecture,
 * and pointer size, or an ok:false envelope on timeout, cancel, or an agent
 * error. This doubles as a round-trip check of the host-agent message channel.
 * When the plugin is built without frida-core, a self-contained implementation
 * reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied, false on any error.
 */
RZ_IPI bool rz_frida_backend_ping(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "ping", NULL, &response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

static const char *java_type_to_c(RZ_NONNULL const char *jtype) {
	rz_return_val_if_fail(jtype, NULL);
	static const char *map[][2] = {
		{ "int",              "int"        },
		{ "long",             "long long"  },
		{ "boolean",          "bool"       },
		{ "double",           "double"     },
		{ "float",            "float"      },
		{ "byte",             "int8_t"     },
		{ "short",            "int16_t"    },
		{ "char",             "uint16_t"   },
		{ "java.lang.String", "char *"     },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(map); i++) {
		if (RZ_STR_EQ(jtype, map[i][0])) {
			return map[i][1];
		}
	}
	return "void *";
}

static size_t import_class_fields(RZ_NONNULL RzCore *core, RZ_NONNULL const RzJson *root, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(core && root && name, 0);
	size_t field_count = 0;
	const RzJson *fields_node = rz_json_get(root, "fields");
	size_t slen = strlen(name);
	if (!fields_node || fields_node->type != RZ_JSON_ARRAY || !fields_node->children.count || slen >= 512) {
		return 0;
	}
	char struct_name[512];
	for (size_t j = 0; j < slen; j++) {
		char c = name[j];
		struct_name[j] = (c == '.' || c == '$') ? '_' : c;
	}
	struct_name[slen] = '\0';

	bool struct_exists = rz_type_db_get_base_type(
		rz_analysis_get_type_db(core->analysis), struct_name) != NULL;
	RzStrBuf *decl = struct_exists ? NULL : rz_strbuf_new(NULL);
	if (decl) {
		rz_strbuf_appendf(decl, "struct %s { ", struct_name);
	}

	const RzJson *f = fields_node->children.first;
	while (f) {
		const RzJson *fn = rz_json_get(f, "name");
		const RzJson *ft = rz_json_get(f, "type");
		if (fn && ft && fn->type == RZ_JSON_STRING && fn->str_value &&
			ft->type == RZ_JSON_STRING && ft->str_value) {
			const char *ctype = java_type_to_c(ft->str_value);
			char fname[256];
			size_t flen = strlen(fn->str_value);
			for (size_t k = 0; k < flen && k < sizeof(fname) - 1; k++) {
				char c = fn->str_value[k];
				fname[k] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
					(c >= '0' && c <= '9') || c == '_' ? c : '_';
				fname[k + 1] = '\0';
			}
			if (decl) {
				rz_strbuf_appendf(decl, "%s %s; ", ctype, fname);
			}
			field_count++;
		}
		f = f->next;
	}

	if (decl && field_count > 0) {
		rz_strbuf_append(decl, "};");
		char *decl_c = rz_strbuf_drain(decl);
		if (decl_c) {
			rz_type_parse_string(rz_analysis_get_type_db(core->analysis), decl_c, NULL);
			free(decl_c);
		}
	} else {
		rz_strbuf_free(decl);
	}
	return field_count;
}

/**
 * \brief Import a Java class into the rizin analysis database.
 *
 * Describes the class through the agent, creates its analysis-class node via
 * \ref rz_analysis_class_create, sets the superclass relation via
 * \ref rz_analysis_class_base_set, registers each declared method and
 * constructor via \ref rz_analysis_class_method_set, exports field types into
 * the type database via \ref import_class_fields, and writes an import
 * summary as the ok:true reply envelope (or ok:false on any error).
 *
 * \param session  Session holding the attached backend handles.
 * \param core     Active RzCore, providing the analysis and type database.
 * \param className Fully qualified class name to import.
 * \param loaderId Stable loader id from a prior loaderList reply, or 0
 *                 for the default system loader.
 * \param pj       JSON builder that receives the reply envelope.
 * \return true on success, false on any error.
 */

RZ_IPI bool rz_frida_backend_import_class(RZ_NONNULL RzFridaSession *session,
	RZ_NONNULL RzCore *core, RZ_NONNULL const char *className, ut64 loaderId, RZ_NONNULL PJ *pj) {
	rz_return_val_if_fail(session && core && className && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_ks(params, "className", className);
	if (loaderId) {
		pj_kn(params, "loaderId", loaderId);
	}
	pj_end(params);
	char *pp = pj_drain(params);
	if (!pp) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "classDescribe", pp,
		&response, &fail_code, &fail_msg);
	free(pp);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	if (!response.ok || !RZ_STR_ISNOTEMPTY(response.result)) {
		rz_frida_json_error(pj, fail_code,
			response.error ? response.error : "the agent could not describe the class");
		rz_frida_response_fini(&response);
		return false;
	}

	char *json_copy = rz_str_dup(response.result);
	rz_frida_response_fini(&response);
	if (!json_copy) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "out of memory");
		return false;
	}

	RzJson *root = rz_json_parse(json_copy);
	if (!root || root->type != RZ_JSON_OBJECT) {
		free(json_copy); rz_json_free(root);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "the agent returned an unexpected reply");
		return false;
	}

	const RzJson *name_node = rz_json_get(root, "name");
	const RzJson *super_node = rz_json_get(root, "super");
	const RzJson *methods_node = rz_json_get(root, "methods");
	const RzJson *ctors_node = rz_json_get(root, "constructors");

	if (!name_node || name_node->type != RZ_JSON_STRING || !name_node->str_value) {
		free(json_copy); rz_json_free(root);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "class description has no name");
		return false;
	}

	RzAnalysis *analysis = core->analysis;
	const char *name = name_node->str_value;

	rz_analysis_class_create(analysis, name);

	if (super_node && super_node->type == RZ_JSON_STRING && super_node->str_value) {
		const char *super = super_node->str_value;
		if (!RZ_STR_EQ(super, "java.lang.Object")) {
			RzAnalysisBaseClass base = { .id = NULL, .offset = 0, .class_name = rz_str_dup(super) };
			rz_analysis_class_base_set(analysis, name, &base);
			rz_analysis_class_base_fini(&base);
		}
	}

	size_t method_count = 0;
	if (methods_node && methods_node->type == RZ_JSON_ARRAY) {
		const RzJson *m = methods_node->children.first;
		while (m) {
			const RzJson *mn = rz_json_get(m, "name");
			if (mn && mn->type == RZ_JSON_STRING && mn->str_value) {
				RzAnalysisMethod meth = { .name = rz_str_dup(mn->str_value),
					.real_name = rz_str_dup(mn->str_value),
					.addr = UT64_MAX, .vtable_offset = -1,
					.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT };
				rz_analysis_class_method_set(analysis, name, &meth);
				rz_analysis_class_method_fini(&meth);
				method_count++;
			}
			m = m->next;
		}
	}

	size_t ctor_count = 0;
	if (ctors_node && ctors_node->type == RZ_JSON_ARRAY) {
		const RzJson *c = ctors_node->children.first;
		while (c) {
			RzAnalysisMethod meth = { .name = rz_str_dup(name),
				.real_name = rz_str_dup(name),
				.addr = UT64_MAX, .vtable_offset = -1,
				.method_type = RZ_ANALYSIS_CLASS_METHOD_CONSTRUCTOR };
			rz_analysis_class_method_set(analysis, name, &meth);
			rz_analysis_class_method_fini(&meth);
			ctor_count++;
			c = c->next;
		}
	}

	size_t field_count = import_class_fields(core, root, name);

	rz_frida_json_ok_begin(pj);
	pj_kb(pj, "imported", true);
	pj_ks(pj, "class", name);
	pj_kn(pj, "loader", loaderId);
	pj_kn(pj, "methods", method_count);
	pj_kn(pj, "constructors", ctor_count);
	pj_kn(pj, "fields", field_count);
	rz_frida_json_ok_end(pj);

	free(json_copy);
	rz_json_free(root);
	return true;
}

/**
 * \brief Drain the asynchronous messages captured from the injected agent.
 *
 * Writes the buffered console output, script errors, and unsolicited send()
 * notifications as a JSON array and clears the buffer. When the plugin is built
 * without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the buffer was drained into an ok envelope.
 */
RZ_IPI bool rz_frida_backend_messages(RZ_NONNULL RZ_BORROW RzFridaSession *session, RZ_NONNULL RZ_BORROW PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	rz_frida_json_ok_begin(pj);
	g_mutex_lock(&backend->lock);
	if (backend->messages) {
		rz_frida_msgbuf_drain_json(backend->messages, pj);
	} else {
		pj_ka(pj, "messages");
		pj_end(pj);
		pj_kn(pj, "dropped", 0);
	}
	g_mutex_unlock(&backend->lock);
	rz_frida_json_ok_end(pj);
	return true;
}
