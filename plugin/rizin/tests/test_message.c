// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static bool test_parse_send_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"send\",\"payload\":{\"type\":\"agent.ready\",\"version\":1}}", &msg),
		"send message parses");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_SEND, "kind is send");
	mu_assert_streq(msg.payload, "{\"type\":\"agent.ready\",\"version\":1}", "payload round-trips as JSON text");
	mu_assert_null(msg.description, "send carries no description");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_send_string_payload(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"send\",\"payload\":\"binary-payload\"}", &msg),
		"send with a string payload parses");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_SEND, "kind is send");
	mu_assert_streq(msg.payload, "\"binary-payload\"", "string payload is stored as quoted JSON text");
	rz_frida_agent_message_fini(&msg);

	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"send\",\"payload\":\"\"}", &msg),
		"send with an empty string payload parses");
	mu_assert_streq(msg.payload, "\"\"", "empty string payload is stored as quoted JSON text");
	rz_frida_agent_message_fini(&msg);

	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"send\",\"payload\":\"quote\\\"and\\\\slash\"}", &msg),
		"send with an escaped string payload parses");
	mu_assert_streq(msg.payload, "\"quote\\\"and\\\\slash\"", "escapes survive as JSON text");
	rz_frida_agent_message_fini(&msg);

	mu_assert_true(rz_frida_agent_message_parse("{\"type\":\"send\",\"payload\":42}", &msg),
		"send with a number payload parses");
	mu_assert_streq(msg.payload, "42", "number payload stays unquoted JSON");
	rz_frida_agent_message_fini(&msg);

	mu_assert_true(rz_frida_agent_message_parse("{\"type\":\"send\",\"payload\":[1,2,3,255]}", &msg),
		"send with an array payload parses");
	mu_assert_streq(msg.payload, "[1,2,3,255]", "array payload stays JSON text");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_error_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"error\",\"description\":\"boom\",\"stack\":\"at agent.js\"}", &msg),
		"error message parses");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_ERROR, "kind is error");
	mu_assert_streq(msg.description, "boom", "description is captured");
	mu_assert_streq(msg.stack, "at agent.js", "stack is captured");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_log_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"log\",\"level\":\"warning\",\"payload\":\"heads up\"}", &msg),
		"log message parses");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_LOG, "kind is log");
	mu_assert_streq(msg.level, "warning", "level is captured");
	mu_assert_streq(msg.text, "heads up", "log text is captured");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_unknown_type(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_false(rz_frida_agent_message_parse("{\"type\":\"frobnicate\"}", &msg), "unknown type is rejected");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_UNKNOWN, "kind stays unknown on rejection");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_malformed_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_false(rz_frida_agent_message_parse("{ this is not json", &msg), "broken json is rejected");
	mu_assert_false(rz_frida_agent_message_parse("[1,2,3]", &msg), "a non-object is rejected");
	mu_assert_false(rz_frida_agent_message_parse("{\"type\":42}", &msg), "a non-string type is rejected");
	mu_assert_false(rz_frida_agent_message_parse("{\"payload\":1}", &msg), "a missing type is rejected");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_response_ok(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_true(rz_frida_response_parse("{\"id\":7,\"ok\":true,\"result\":{\"version\":1}}", &resp),
		"ok response parses");
	mu_assert_eq(resp.id, 7, "response id is read");
	mu_assert_true(resp.ok, "response is marked ok");
	mu_assert_streq(resp.result, "{\"version\":1}", "result round-trips as JSON text");
	mu_assert_null(resp.error, "ok response carries no error");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_response_error_string(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_true(rz_frida_response_parse("{\"id\":8,\"ok\":false,\"error\":\"bad request\"}", &resp),
		"error response parses");
	mu_assert_eq(resp.id, 8, "response id is read");
	mu_assert_false(resp.ok, "response is marked not ok");
	mu_assert_streq(resp.error, "bad request", "string error is captured");
	mu_assert_null(resp.result, "error response carries no result");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_response_error_object(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_true(rz_frida_response_parse(
			       "{\"id\":9,\"ok\":false,\"error\":{\"code\":\"internal_error\",\"message\":\"boom\"}}", &resp),
		"object error response parses");
	mu_assert_streq(resp.error, "{\"code\":\"internal_error\",\"message\":\"boom\"}", "object error round-trips as JSON text");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_response_rejects_non_reply(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_false(rz_frida_response_parse("{\"ok\":true,\"result\":1}", &resp), "a payload without id is not a reply");
	mu_assert_false(rz_frida_response_parse("{\"id\":\"oops\"}", &resp), "a non-integer id is rejected");
	mu_assert_false(rz_frida_response_parse("{ broken", &resp), "broken json is rejected");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_pending_lifecycle(void) {
	RzFridaPending *pending = rz_frida_pending_new();
	mu_assert_notnull(pending, "allocate pending registry");

	mu_assert_eq(rz_frida_pending_next_id(pending), 1, "ids start at one");
	mu_assert_eq(rz_frida_pending_next_id(pending), 2, "ids increase by one");
	mu_assert_eq(rz_frida_pending_next_id(pending), 3, "ids keep increasing");

	mu_assert_true(rz_frida_pending_add(pending, 1), "add a request id");
	mu_assert_true(rz_frida_pending_add(pending, 2), "add another request id");
	mu_assert_false(rz_frida_pending_add(pending, 1), "adding a duplicate id fails");
	mu_assert_eq(rz_frida_pending_count(pending), 2, "two ids are tracked");

	mu_assert_true(rz_frida_pending_contains(pending, 1), "tracked id is present");
	mu_assert_false(rz_frida_pending_contains(pending, 9), "untracked id is absent");

	mu_assert_true(rz_frida_pending_take(pending, 1), "take a tracked id");
	mu_assert_false(rz_frida_pending_take(pending, 1), "taking it again fails");
	mu_assert_eq(rz_frida_pending_count(pending), 1, "one id remains");

	rz_frida_pending_clear(pending);
	mu_assert_eq(rz_frida_pending_count(pending), 0, "clear empties the registry");

	rz_frida_pending_free(pending);
	mu_end;
}

static bool test_message_to_json_send(void) {
	RzFridaAgentMessage msg = { 0 };
	msg.kind = RZ_FRIDA_AGENT_MESSAGE_SEND;
	msg.payload = rz_str_dup("{\"type\":\"hit\"}");
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	rz_frida_agent_message_to_json(&msg, pj);
	mu_assert_streq(pj_string(pj), "{\"kind\":\"send\",\"payload\":{\"type\":\"hit\"}}", "send serializes with its payload");
	pj_free(pj);
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_message_to_json_log(void) {
	RzFridaAgentMessage msg = { 0 };
	msg.kind = RZ_FRIDA_AGENT_MESSAGE_LOG;
	msg.level = rz_str_dup("info");
	msg.text = rz_str_dup("hello");
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	rz_frida_agent_message_to_json(&msg, pj);
	mu_assert_streq(pj_string(pj), "{\"kind\":\"log\",\"level\":\"info\",\"text\":\"hello\"}", "log serializes with level and text");
	pj_free(pj);
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_message_to_json_error(void) {
	RzFridaAgentMessage msg = { 0 };
	msg.kind = RZ_FRIDA_AGENT_MESSAGE_ERROR;
	msg.description = rz_str_dup("boom");
	msg.stack = rz_str_dup("at agent.js");
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	rz_frida_agent_message_to_json(&msg, pj);
	mu_assert_streq(pj_string(pj), "{\"kind\":\"error\",\"description\":\"boom\",\"stack\":\"at agent.js\"}", "error serializes with description and stack");
	pj_free(pj);
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_message_to_json_send_string(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"send\",\"payload\":\"binary-payload\"}", &msg),
		"parse a string payload");
	const ut8 raw[] = { 1, 2, 3, 255 };
	msg.data = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(msg.data, "allocate the data blob");
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	rz_frida_agent_message_to_json(&msg, pj);
	mu_assert_streq(pj_string(pj),
		"{\"kind\":\"send\",\"payload\":\"binary-payload\",\"data\":\"AQID/w==\",\"dataSize\":4}",
		"string send payload is quoted JSON, with base64 data");
	pj_free(pj);
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_message_to_json_binary(void) {
	RzFridaAgentMessage msg = { 0 };
	msg.kind = RZ_FRIDA_AGENT_MESSAGE_SEND;
	msg.payload = rz_str_dup("{\"hooked\":true}");
	const ut8 raw[] = { 0xde, 0xad, 0xbe, 0xef };
	msg.data = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(msg.data, "allocate the data blob");
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	rz_frida_agent_message_to_json(&msg, pj);
	mu_assert_streq(pj_string(pj),
		"{\"kind\":\"send\",\"payload\":{\"hooked\":true},\"data\":\"3q2+7w==\",\"dataSize\":4}",
		"send with binary data base64-encodes the blob and reports its size");
	pj_free(pj);
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_msgbuf_lifecycle(void) {
	RzFridaMsgBuf *buf = rz_frida_msgbuf_new(0);
	mu_assert_notnull(buf, "allocate message buffer");
	mu_assert_eq(rz_frida_msgbuf_count(buf), 0, "buffer starts empty");

	RzFridaAgentMessage log = { 0 };
	log.kind = RZ_FRIDA_AGENT_MESSAGE_LOG;
	log.level = rz_str_dup("info");
	log.text = rz_str_dup("first");
	mu_assert_true(rz_frida_msgbuf_push(buf, &log), "push a log message");
	mu_assert_null(log.text, "push takes ownership and clears the source");
	mu_assert_eq(rz_frida_msgbuf_count(buf), 1, "one message buffered");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	pj_o(pj);
	rz_frida_msgbuf_drain_json(buf, pj);
	pj_end(pj);
	mu_assert_streq(pj_string(pj),
		"{\"messages\":[{\"kind\":\"log\",\"level\":\"info\",\"text\":\"first\"}],\"dropped\":0}",
		"drain emits the buffered message inside the result object");
	mu_assert_eq(rz_frida_msgbuf_count(buf), 0, "drain clears the buffer");
	pj_free(pj);
	rz_frida_msgbuf_free(buf);
	mu_end;
}

static bool test_msgbuf_capacity(void) {
	RzFridaMsgBuf *buf = rz_frida_msgbuf_new(2);
	mu_assert_notnull(buf, "allocate a small buffer");

	const char *texts[] = { "a", "b", "c" };
	for (int i = 0; i < 3; i++) {
		RzFridaAgentMessage m = { 0 };
		m.kind = RZ_FRIDA_AGENT_MESSAGE_LOG;
		m.text = rz_str_dup(texts[i]);
		mu_assert_true(rz_frida_msgbuf_push(buf, &m), "push within and over capacity");
	}
	mu_assert_eq(rz_frida_msgbuf_count(buf), 2, "capacity caps the buffer");
	mu_assert_eq(rz_frida_msgbuf_dropped(buf), 1, "the oldest message was dropped");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	pj_o(pj);
	rz_frida_msgbuf_drain_json(buf, pj);
	pj_end(pj);
	mu_assert_streq(pj_string(pj),
		"{\"messages\":[{\"kind\":\"log\",\"text\":\"b\"},{\"kind\":\"log\",\"text\":\"c\"}],\"dropped\":1}",
		"oldest is evicted, newest two remain, and the drop count is reported");
	pj_free(pj);
	rz_frida_msgbuf_free(buf);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_parse_send_message);
	mu_run_test(test_parse_send_string_payload);
	mu_run_test(test_parse_error_message);
	mu_run_test(test_parse_log_message);
	mu_run_test(test_parse_unknown_type);
	mu_run_test(test_parse_malformed_message);
	mu_run_test(test_response_ok);
	mu_run_test(test_response_error_string);
	mu_run_test(test_response_error_object);
	mu_run_test(test_response_rejects_non_reply);
	mu_run_test(test_pending_lifecycle);
	mu_run_test(test_message_to_json_send);
	mu_run_test(test_message_to_json_send_string);
	mu_run_test(test_message_to_json_log);
	mu_run_test(test_message_to_json_error);
	mu_run_test(test_message_to_json_binary);
	mu_run_test(test_msgbuf_lifecycle);
	mu_run_test(test_msgbuf_capacity);
	return tests_passed != tests_run;
}

mu_main(all_tests)
