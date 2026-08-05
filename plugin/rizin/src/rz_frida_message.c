// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Host side of agent message protocol. Decodes messages the injected
// script gives and tracks ids of requests still waiting for reply.

#include <rz_frida.h>

#include <rz_util/rz_json.h>
#include <rz_util/rz_base64.h>

struct rz_frida_pending_t {
	RzSetU *ids; ///< Ids of requests still awaiting a reply.
	ut64 next_id; ///< Next id handed out, increases by one each time.
};

static char *dup_str_field(const RzJson *object, const char *key) {
	const RzJson *field = rz_json_get(object, key);
	if (!field || field->type != RZ_JSON_STRING) {
		return NULL;
	}
	return rz_str_dup(field->str_value);
}

RZ_IPI bool rz_frida_agent_message_parse(RZ_NONNULL const char *message, RZ_NONNULL RZ_OUT RzFridaAgentMessage *out) {
	rz_return_val_if_fail(message && out, false);

	rz_mem_memzero(out, sizeof(*out));

	char *text = rz_str_dup(message);
	if (!text) {
		return false;
	}

	bool ok = false;
	RzJson *json = rz_json_parse(text);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto beach;
	}

	const RzJson *type = rz_json_get(json, "type");
	if (!type || type->type != RZ_JSON_STRING) {
		goto beach;
	}

	if (RZ_STR_EQ(type->str_value, "send")) {
		out->kind = RZ_FRIDA_AGENT_MESSAGE_SEND;
		const RzJson *payload = rz_json_get(json, "payload");
		if (payload) {
			out->payload = rz_json_as_string(payload, false);
		}
		ok = true;
	} else if (RZ_STR_EQ(type->str_value, "error")) {
		out->kind = RZ_FRIDA_AGENT_MESSAGE_ERROR;
		out->description = dup_str_field(json, "description");
		out->stack = dup_str_field(json, "stack");
		ok = true;
	} else if (RZ_STR_EQ(type->str_value, "log")) {
		out->kind = RZ_FRIDA_AGENT_MESSAGE_LOG;
		out->level = dup_str_field(json, "level");
		out->text = dup_str_field(json, "payload");
		ok = true;
	}

beach:
	rz_json_free(json);
	free(text);
	if (!ok) {
		rz_frida_agent_message_fini(out);
	}
	return ok;
}

RZ_IPI void rz_frida_agent_message_fini(RZ_NULLABLE RZ_BORROW RzFridaAgentMessage *message) {
	if (!message) {
		return;
	}
	free(message->payload);
	free(message->description);
	free(message->stack);
	free(message->level);
	free(message->text);
	rz_buf_free(message->data);
	rz_mem_memzero(message, sizeof(*message));
}

RZ_IPI void rz_frida_agent_message_to_json(RZ_NONNULL const RzFridaAgentMessage *message, RZ_NONNULL RZ_BORROW PJ *pj) {
	rz_return_if_fail(message && pj);

	pj_o(pj);
	switch (message->kind) {
	case RZ_FRIDA_AGENT_MESSAGE_SEND:
		pj_ks(pj, "kind", "send");
		if (message->payload) {
			// pj_k + pj_raw leaves pj internal is_key flag set,
			// which suppresses separator before next element and
			// emits invalid JSON. Thus, we write the pair raw, "kind" is
			// always preceding, so comma is deterministic.
			pj_raw(pj, ",\"payload\":");
			pj_raw(pj, message->payload);
		}
		break;
	case RZ_FRIDA_AGENT_MESSAGE_ERROR:
		pj_ks(pj, "kind", "error");
		if (message->description) {
			pj_ks(pj, "description", message->description);
		}
		if (message->stack) {
			pj_ks(pj, "stack", message->stack);
		}
		break;
	case RZ_FRIDA_AGENT_MESSAGE_LOG:
		pj_ks(pj, "kind", "log");
		if (message->level) {
			pj_ks(pj, "level", message->level);
		}
		if (message->text) {
			pj_ks(pj, "text", message->text);
		}
		break;
	default:
		pj_ks(pj, "kind", "unknown");
		break;
	}
	if (message->data) {
		ut64 data_size = rz_buf_size(message->data);
		char *encoded = NULL;
		if (data_size && data_size <= (ut64)ST64_MAX && data_size <= (ut64)SIZE_MAX) {
			ut8 *data = RZ_NEWS(ut8, (size_t)data_size);
			if (data && rz_buf_read_at(message->data, 0, data, data_size) == (st64)data_size) {
				encoded = rz_base64_encode_dyn(data, (size_t)data_size);
			}
			free(data);
		}
		if (encoded) {
			pj_ks(pj, "data", encoded);
			free(encoded);
		}
		pj_kn(pj, "dataSize", data_size);
	}
	pj_end(pj);
}

RZ_IPI bool rz_frida_response_parse(RZ_NONNULL const char *payload, RZ_NONNULL RZ_OUT RzFridaResponse *out) {
	rz_return_val_if_fail(payload && out, false);

	rz_mem_memzero(out, sizeof(*out));

	char *text = rz_str_dup(payload);
	if (!text) {
		return false;
	}

	bool ok = false;
	RzJson *json = rz_json_parse(text);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto beach;
	}

	// a reply has to carry id it answers, anything else is a plain
	// notification and is not our concern here.
	const RzJson *id = rz_json_get(json, "id");
	if (!id || id->type != RZ_JSON_INTEGER) {
		goto beach;
	}
	out->id = id->num.u_value;

	const RzJson *status = rz_json_get(json, "ok");
	out->ok = status && status->type == RZ_JSON_BOOLEAN && status->num.u_value;

	if (out->ok) {
		const RzJson *result = rz_json_get(json, "result");
		if (result) {
			out->result = rz_json_as_string(result, false);
		}
	} else {
		const RzJson *error = rz_json_get(json, "error");
		if (error) {
			out->error = rz_json_as_string(error, false);
		}
	}
	ok = true;

beach:
	rz_json_free(json);
	free(text);
	if (!ok) {
		rz_frida_response_fini(out);
	}
	return ok;
}

RZ_IPI void rz_frida_response_fini(RZ_NULLABLE RZ_BORROW RzFridaResponse *response) {
	if (!response) {
		return;
	}
	free(response->result);
	free(response->error);
	rz_mem_memzero(response, sizeof(*response));
}

RZ_IPI RZ_OWN RzFridaPending *rz_frida_pending_new(void) {
	RzFridaPending *pending = RZ_NEW0(RzFridaPending);
	if (!pending) {
		return NULL;
	}
	pending->ids = rz_set_u_new();
	if (!pending->ids) {
		free(pending);
		return NULL;
	}
	// 0 for invalid req, so here start with 1.
	pending->next_id = 1;
	return pending;
}

RZ_IPI void rz_frida_pending_free(RZ_NULLABLE RZ_OWN RzFridaPending *pending) {
	if (!pending) {
		return;
	}
	rz_set_u_free(pending->ids);
	free(pending);
}

RZ_IPI ut64 rz_frida_pending_next_id(RZ_NONNULL RZ_BORROW RzFridaPending *pending) {
	rz_return_val_if_fail(pending, 0);
	return pending->next_id++;
}

RZ_IPI bool rz_frida_pending_add(RZ_NONNULL RZ_BORROW RzFridaPending *pending, ut64 id) {
	rz_return_val_if_fail(pending && pending->ids, false);
	if (rz_set_u_contains(pending->ids, id)) {
		return false;
	}
	rz_set_u_add(pending->ids, id);
	return true;
}

RZ_IPI bool rz_frida_pending_contains(RZ_NONNULL const RzFridaPending *pending, ut64 id) {
	rz_return_val_if_fail(pending && pending->ids, false);
	return rz_set_u_contains(pending->ids, id);
}

RZ_IPI bool rz_frida_pending_take(RZ_NONNULL RZ_BORROW RzFridaPending *pending, ut64 id) {
	rz_return_val_if_fail(pending && pending->ids, false);
	if (!rz_set_u_contains(pending->ids, id)) {
		return false;
	}
	rz_set_u_delete(pending->ids, id);
	return true;
}

RZ_IPI size_t rz_frida_pending_count(RZ_NONNULL const RzFridaPending *pending) {
	rz_return_val_if_fail(pending && pending->ids, 0);
	return rz_set_u_size(pending->ids);
}

RZ_IPI void rz_frida_pending_clear(RZ_NONNULL RZ_BORROW RzFridaPending *pending) {
	rz_return_if_fail(pending && pending->ids);
	rz_set_u_clear(pending->ids);
}

struct rz_frida_msgbuf_t {
	RzList /*<RzFridaAgentMessage *>*/ *items; ///< Buffered messages, oldest first.
	size_t capacity; ///< Most messages kept before the oldest is dropped.
	ut64 dropped; ///< Count of messages dropped because the buffer was full.
};

static void msgbuf_item_free(void *p) {
	RzFridaAgentMessage *message = p;
	if (!message) {
		return;
	}
	rz_frida_agent_message_fini(message);
	free(message);
}

RZ_IPI RZ_OWN RzFridaMsgBuf *rz_frida_msgbuf_new(size_t capacity) {
	RzFridaMsgBuf *buf = RZ_NEW0(RzFridaMsgBuf);
	if (!buf) {
		return NULL;
	}
	buf->items = rz_list_newf(msgbuf_item_free);
	if (!buf->items) {
		free(buf);
		return NULL;
	}
	buf->capacity = capacity ? capacity : RZ_FRIDA_MSGBUF_CAPACITY;
	return buf;
}

RZ_IPI void rz_frida_msgbuf_free(RZ_NULLABLE RZ_OWN RzFridaMsgBuf *buf) {
	if (!buf) {
		return;
	}
	rz_list_free(buf->items);
	free(buf);
}

RZ_IPI bool rz_frida_msgbuf_push(RZ_NONNULL RZ_BORROW RzFridaMsgBuf *buf, RZ_NONNULL RZ_BORROW RZ_INOUT RzFridaAgentMessage *message) {
	rz_return_val_if_fail(buf && buf->items && message, false);

	RzFridaAgentMessage *kept = RZ_NEW0(RzFridaAgentMessage);
	if (!kept) {
		return false;
	}
	*kept = *message;
	rz_mem_memzero(message, sizeof(*message));
	if (!rz_list_append(buf->items, kept)) {
		msgbuf_item_free(kept);
		return false;
	}
	// drop oldest while over capacity so buff remains bounded.
	while (rz_list_length(buf->items) > buf->capacity) {
		RzFridaAgentMessage *oldest = rz_list_pop_head(buf->items);
		msgbuf_item_free(oldest);
		buf->dropped++;
	}
	return true;
}

RZ_IPI size_t rz_frida_msgbuf_count(RZ_NONNULL const RzFridaMsgBuf *buf) {
	rz_return_val_if_fail(buf && buf->items, 0);
	return rz_list_length(buf->items);
}

RZ_IPI ut64 rz_frida_msgbuf_dropped(RZ_NONNULL const RzFridaMsgBuf *buf) {
	rz_return_val_if_fail(buf, 0);
	return buf->dropped;
}

RZ_IPI void rz_frida_msgbuf_drain_json(RZ_NONNULL RZ_BORROW RzFridaMsgBuf *buf, RZ_NONNULL RZ_BORROW PJ *pj) {
	rz_return_if_fail(buf && buf->items && pj);

	pj_ka(pj, "messages");
	RzListIter *it;
	RzFridaAgentMessage *message;
	rz_list_foreach (buf->items, it, message) {
		rz_frida_agent_message_to_json(message, pj);
	}
	pj_end(pj);
	pj_kn(pj, "dropped", buf->dropped);
	rz_frida_msgbuf_clear(buf);
}

RZ_IPI void rz_frida_msgbuf_clear(RZ_NONNULL RZ_BORROW RzFridaMsgBuf *buf) {
	rz_return_if_fail(buf && buf->items);
	RzFridaAgentMessage *message;
	while ((message = rz_list_pop_head(buf->items))) {
		msgbuf_item_free(message);
	}
	buf->dropped = 0;
}
