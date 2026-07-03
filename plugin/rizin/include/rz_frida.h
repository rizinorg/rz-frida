// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FRIDA_H
#define RZ_FRIDA_H

#include <rz_types.h>
#include <rz_util.h>

#define RZ_FRIDA_DEFAULT_TIMEOUT_MS 5000
#define RZ_FRIDA_MSGBUF_CAPACITY 256
#define RZ_FRIDA_MEM_MAX_DEFAULT 0x100000
#define RZ_FRIDA_HW_WATCHPOINTS_DEFAULT 4
#define RZ_FRIDA_JAVA_MAX_DEFAULT 512

/**
 * \brief URI operation requested by the frontend or command layer.
 */
typedef enum rz_frida_action_t {
	RZ_FRIDA_ACTION_UNKNOWN = 0, ///< Unknown or unsupported action.
	RZ_FRIDA_ACTION_LIST, ///< List devices for a transport.
	RZ_FRIDA_ACTION_APPS, ///< List applications of a target device.
	RZ_FRIDA_ACTION_ATTACH, ///< Attach to an existing process.
	RZ_FRIDA_ACTION_SPAWN, ///< Spawn a new process without resuming it yet.
	RZ_FRIDA_ACTION_LAUNCH, ///< Launch a process and prepare a session.
} RzFridaAction;

/**
 * \brief Transport used to reach the Frida target.
 */
typedef enum rz_frida_transport_t {
	RZ_FRIDA_TRANSPORT_UNKNOWN = 0, ///< Unknown or unsupported transport.
	RZ_FRIDA_TRANSPORT_LOCAL, ///< Local Frida device.
	RZ_FRIDA_TRANSPORT_USB, ///< USB-connected Frida device.
	RZ_FRIDA_TRANSPORT_REMOTE, ///< Remote Frida endpoint.
} RzFridaTransport;

/**
 * \brief Internal lifecycle state for an rz-frida session.
 */
typedef enum rz_frida_session_state_t {
	RZ_FRIDA_SESSION_STATE_NEW = 0, ///< Session was allocated but no target is resolved.
	RZ_FRIDA_SESSION_STATE_RESOLVED, ///< Target URI was copied into the session.
	RZ_FRIDA_SESSION_STATE_CONNECTING, ///< Backend connection is in progress.
	RZ_FRIDA_SESSION_STATE_ATTACHED, ///< Session is attached to a target.
	RZ_FRIDA_SESSION_STATE_DETACHING, ///< Detach is in progress.
	RZ_FRIDA_SESSION_STATE_CLOSED, ///< Session is closed.
	RZ_FRIDA_SESSION_STATE_ERROR, ///< Session entered an error state.
} RzFridaSessionState;

/**
 * \brief Structured backend request method.
 */
typedef enum rz_frida_method_t {
	RZ_FRIDA_METHOD_UNKNOWN = 0, ///< Unknown or unsupported method.
	RZ_FRIDA_METHOD_STATUS, ///< Query plugin/session status.
	RZ_FRIDA_METHOD_DEVICES, ///< Enumerate Frida devices.
	RZ_FRIDA_METHOD_PROCESSES, ///< Enumerate processes.
	RZ_FRIDA_METHOD_APPS, ///< Enumerate applications.
	RZ_FRIDA_METHOD_ATTACH, ///< Attach to a target.
	RZ_FRIDA_METHOD_SPAWN, ///< Spawn a target.
	RZ_FRIDA_METHOD_LAUNCH, ///< Launch a target.
	RZ_FRIDA_METHOD_DETACH, ///< Detach from the active target.
} RzFridaMethod;

/**
 * \brief Stable structured error code for rz-frida replies.
 */
typedef enum rz_frida_error_t {
	RZ_FRIDA_ERROR_NONE = 0, ///< No error.
	RZ_FRIDA_ERROR_INVALID_URI, ///< URI grammar or validation failed.
	RZ_FRIDA_ERROR_INVALID_TARGET, ///< Target selection is missing or invalid.
	RZ_FRIDA_ERROR_TIMEOUT, ///< Operation timed out.
	RZ_FRIDA_ERROR_CANCELLED, ///< Operation was cancelled.
	RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, ///< Frida backend support is unavailable.
	RZ_FRIDA_ERROR_NOT_IMPLEMENTED, ///< Requested method is not implemented.
	RZ_FRIDA_ERROR_INTERNAL, ///< Internal failure.
} RzFridaError;

/**
 * \brief Class of message delivered by the injected agent.
 */
typedef enum rz_frida_agent_message_kind_t {
	RZ_FRIDA_AGENT_MESSAGE_UNKNOWN = 0, ///< Unrecognized or malformed message.
	RZ_FRIDA_AGENT_MESSAGE_SEND, ///< Payload from the agent send() call.
	RZ_FRIDA_AGENT_MESSAGE_ERROR, ///< Uncaught error raised by the script.
	RZ_FRIDA_AGENT_MESSAGE_LOG, ///< Console output forwarded by the runtime.
} RzFridaAgentMessageKind;

/**
 * \brief Decoded message delivered by the injected agent.
 *
 * Owns the text it carries. Release the fields with \ref rz_frida_agent_message_fini.
 */
typedef struct rz_frida_agent_message_t {
	RzFridaAgentMessageKind kind; ///< Message class.
	char *payload; ///< send() payload as JSON text, or NULL.
	char *description; ///< Error description, or NULL.
	char *stack; ///< Error stack trace, or NULL.
	char *level; ///< Log level, or NULL.
	char *text; ///< Log text, or NULL.
	RzBuffer *data; ///< Optional binary blob from a send message, or NULL.
} RzFridaAgentMessage;

/**
 * \brief Reply to a host request decoded from an agent send() payload.
 *
 * Owns the text it carries. Release the fields with \ref rz_frida_response_fini.
 */
typedef struct rz_frida_response_t {
	ut64 id; ///< Request id the reply answers.
	bool ok; ///< True when the request succeeded.
	char *result; ///< Result as JSON text on success, or NULL.
	char *error; ///< Error message on failure, or NULL.
} RzFridaResponse;

/**
 * \brief Tracks the ids of host requests still awaiting a reply.
 */
typedef struct rz_frida_pending_t RzFridaPending;

/**
 * \brief Bounded buffer of asynchronous messages from the injected agent.
 */
typedef struct rz_frida_msgbuf_t RzFridaMsgBuf;

/**
 * \brief Parsed and validated frida:// URI.
 */
typedef struct rz_frida_uri_t {
	RzFridaAction action_type; ///< Action parsed from the URI.
	RzFridaTransport transport_type; ///< Transport parsed from the URI.
	char *action; ///< Action component as text.
	char *transport; ///< Transport component as text.
	char *device; ///< Device selector (empty, device id, or host:port).
	char *target; ///< Target selector (pid, process name, package, or path).
} RzFridaUri;

/**
 * \brief Opaque handle for an rz-frida session.
 */
typedef struct rz_frida_session_t RzFridaSession;

/**
 * \brief Backend cleanup callback run once when a session is freed.
 */
typedef void (*RzFridaBackendDispose)(RZ_NONNULL RzFridaSession *session);

/**
 * \brief Callback used to cancel a running backend operation.
 */
typedef void (*RzFridaCancelHook)(RZ_NULLABLE void *user);

RZ_IPI const char *rz_frida_action_string(RzFridaAction action);
RZ_IPI RzFridaAction rz_frida_action_from_string(RZ_NULLABLE const char *action);
RZ_IPI const char *rz_frida_transport_string(RzFridaTransport transport);
RZ_IPI RzFridaTransport rz_frida_transport_from_string(RZ_NULLABLE const char *transport);

RZ_IPI bool rz_frida_uri_parse(RZ_NONNULL const char *uri, RZ_NONNULL RzFridaUri *out);
RZ_IPI bool rz_frida_uri_copy(RZ_NONNULL RzFridaUri *dst, RZ_NONNULL const RzFridaUri *src);
RZ_IPI void rz_frida_uri_fini(RZ_NULLABLE RzFridaUri *uri);

RZ_IPI bool rz_frida_uri_target_pid(RZ_NONNULL const char *target, RZ_NONNULL ut32 *pid_out);

RZ_IPI RzFridaSession *rz_frida_session_new(void);
RZ_IPI void rz_frida_session_free(RZ_NULLABLE RzFridaSession *session);
RZ_IPI bool rz_frida_session_set_uri(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const RzFridaUri *uri);
RZ_IPI const RzFridaUri *rz_frida_session_uri(RZ_NONNULL const RzFridaSession *session);
RZ_IPI RzFridaSessionState rz_frida_session_state(RZ_NONNULL const RzFridaSession *session);
RZ_IPI const char *rz_frida_session_state_string(RzFridaSessionState state);
RZ_IPI void rz_frida_session_set_timeout(RZ_NONNULL RzFridaSession *session, ut64 timeout_ms);
RZ_IPI ut64 rz_frida_session_timeout(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_request_cancel(RZ_NONNULL RzFridaSession *session);
RZ_IPI bool rz_frida_session_is_cancelled(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_reset_cancel(RZ_NONNULL RzFridaSession *session);
RZ_IPI void rz_frida_session_set_error(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE const char *message);
RZ_IPI const char *rz_frida_session_error(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_set_state(RZ_NONNULL RzFridaSession *session, RzFridaSessionState state);
RZ_IPI void rz_frida_session_set_target_pid(RZ_NONNULL RzFridaSession *session, ut32 pid);
RZ_IPI ut32 rz_frida_session_target_pid(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_set_backend_state(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE void *backend_state, RZ_NULLABLE RzFridaBackendDispose dispose);
RZ_IPI void *rz_frida_session_backend_state(RZ_NONNULL const RzFridaSession *session);

RZ_IPI void rz_frida_session_set_cancel_hook(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE void *user, RZ_NULLABLE RzFridaCancelHook hook);

RZ_IPI const char *rz_frida_method_string(RzFridaMethod method);
RZ_IPI RzFridaMethod rz_frida_method_from_string(RZ_NULLABLE const char *method);
RZ_IPI bool rz_frida_method_parse(RZ_NULLABLE const char *method, RZ_NONNULL RzFridaMethod *out, RZ_NULLABLE PJ *pj);
RZ_IPI const char *rz_frida_error_string(RzFridaError error);
RZ_IPI void rz_frida_json_ok_begin(RZ_NONNULL PJ *pj);
RZ_IPI void rz_frida_json_ok_end(RZ_NONNULL PJ *pj);
RZ_IPI void rz_frida_json_ok_empty(RZ_NONNULL PJ *pj);
RZ_IPI void rz_frida_json_error(RZ_NONNULL PJ *pj, RzFridaError error, RZ_NULLABLE const char *message);

RZ_IPI bool rz_frida_agent_message_parse(RZ_NONNULL RZ_BORROW const char *message, RZ_NONNULL RZ_BORROW RZ_OUT RzFridaAgentMessage *out);
RZ_IPI void rz_frida_agent_message_fini(RZ_NULLABLE RZ_BORROW RzFridaAgentMessage *message);
RZ_IPI void rz_frida_agent_message_to_json(RZ_NONNULL RZ_BORROW const RzFridaAgentMessage *message, RZ_NONNULL RZ_BORROW PJ *pj);
RZ_IPI bool rz_frida_response_parse(RZ_NONNULL const char *payload, RZ_NONNULL RZ_OUT RzFridaResponse *out);
RZ_IPI void rz_frida_response_fini(RZ_NULLABLE RZ_BORROW RzFridaResponse *response);

RZ_IPI RZ_OWN RzFridaPending *rz_frida_pending_new(void);
RZ_IPI void rz_frida_pending_free(RZ_NULLABLE RZ_OWN RzFridaPending *pending);
RZ_IPI ut64 rz_frida_pending_next_id(RZ_NONNULL RZ_BORROW RzFridaPending *pending);
RZ_IPI bool rz_frida_pending_add(RZ_NONNULL RZ_BORROW RzFridaPending *pending, ut64 id);
RZ_IPI bool rz_frida_pending_contains(RZ_NONNULL const RzFridaPending *pending, ut64 id);
RZ_IPI bool rz_frida_pending_take(RZ_NONNULL RZ_BORROW RzFridaPending *pending, ut64 id);
RZ_IPI size_t rz_frida_pending_count(RZ_NONNULL const RzFridaPending *pending);
RZ_IPI void rz_frida_pending_clear(RZ_NONNULL RZ_BORROW RzFridaPending *pending);

RZ_IPI RZ_OWN RzFridaMsgBuf *rz_frida_msgbuf_new(size_t capacity);
RZ_IPI void rz_frida_msgbuf_free(RZ_NULLABLE RZ_OWN RzFridaMsgBuf *buf);
RZ_IPI bool rz_frida_msgbuf_push(RZ_NONNULL RZ_BORROW RzFridaMsgBuf *buf, RZ_NONNULL RZ_BORROW RZ_INOUT RzFridaAgentMessage *message);
RZ_IPI size_t rz_frida_msgbuf_count(RZ_NONNULL RZ_BORROW const RzFridaMsgBuf *buf);
RZ_IPI ut64 rz_frida_msgbuf_dropped(RZ_NONNULL RZ_BORROW const RzFridaMsgBuf *buf);
RZ_IPI void rz_frida_msgbuf_drain_json(RZ_NONNULL RZ_BORROW RzFridaMsgBuf *buf, RZ_NONNULL RZ_BORROW PJ *pj);
RZ_IPI void rz_frida_msgbuf_clear(RZ_NONNULL RZ_BORROW RzFridaMsgBuf *buf);

RZ_IPI void rz_frida_backend_init(void);
RZ_IPI void rz_frida_backend_deinit(void);
RZ_IPI bool rz_frida_devices_json(RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_processes_json(RZ_NULLABLE const RzFridaUri *uri, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_apps_json(RZ_NULLABLE const RzFridaUri *uri, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_open(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_resume(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_close(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_eval(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE const char *source, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_mem_read(RZ_NONNULL RzFridaSession *session, ut64 address, ut64 size, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_mem_write(RZ_NONNULL RzFridaSession *session, ut64 address, RZ_NONNULL const ut8 *bytes, size_t len, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_ranges(RZ_NONNULL RzFridaSession *session, bool refresh, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_threads(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_modules(RZ_NONNULL RzFridaSession *session, bool refresh, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_exports(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *module, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_imports(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *module, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_symbols(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *module, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_bp_set(RZ_NONNULL RzFridaSession *session, ut64 address, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_bp_list(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_bp_remove(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *address, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_continue(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE const char *thread_id, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_reg_read(RZ_NONNULL RzFridaSession *session, ut64 thread_id, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_reg_write(RZ_NONNULL RzFridaSession *session, ut64 thread_id, RZ_NONNULL const char *reg, RZ_NONNULL const char *value, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_wp_set(RZ_NONNULL RzFridaSession *session, ut64 address, ut64 size, RZ_NULLABLE const char *conditions, ut64 slots, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_wp_list(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_wp_remove(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *address, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_java_available(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_loaders(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_classes(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE const char *prefix, ut64 max, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_class_describe(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const char *className, ut64 loaderId, RZ_NONNULL PJ *pj);
RZ_IPI RZ_OWN char **rz_frida_backend_class_list(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE const char *prefix, ut64 max, RZ_NONNULL size_t *count_out);
RZ_IPI bool rz_frida_backend_import_class(RZ_NONNULL RzFridaSession *session, RZ_NONNULL RzCore *core, RZ_NONNULL const char *className, ut64 loaderId, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_ping(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);
RZ_IPI bool rz_frida_backend_messages(RZ_NONNULL RZ_BORROW RzFridaSession *session, RZ_NONNULL RZ_BORROW PJ *pj);

RZ_IPI RZ_OWN char **rz_frida_autocomplete_class(RZ_NONNULL RzCore *core);

#endif
