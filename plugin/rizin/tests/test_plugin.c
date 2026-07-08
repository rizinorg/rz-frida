// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_frida.h>
#include "minunit.h"

extern RzCorePlugin rz_core_plugin_frida;

static bool test_plugin_registration(RzCore *core) {
	mu_assert_true(rz_core_plugin_add(core, &rz_core_plugin_frida), "register the frida plugin");
	mu_assert_notnull(rz_core_plugin_context_get(core, &rz_core_plugin_frida), "plugin context is created on registration");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "frida"), "frida group command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridas"), "fridas command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridau"), "fridau command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridad"), "fridad command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridap"), "fridap command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaa"), "fridaa command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridao"), "fridao command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridar"), "fridar command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridac"), "fridac command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridae"), "fridae command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridal"), "fridal command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridai"), "fridai command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridam"), "fridam command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridax"), "fridax command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaw"), "fridaw command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaR"), "fridaR command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridat"), "fridat command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaM"), "fridaM command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaE"), "fridaE command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaI"), "fridaI command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaS"), "fridaS command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridab"), "fridab command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridab-"), "fridab- command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridag"), "fridag command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaB"), "fridaB command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaW"), "fridaW command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaW-"), "fridaW- command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaJ"), "fridaJ command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaL"), "fridaL command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaC"), "fridaC command is registered");
	mu_end;
}

static bool test_config_defaults(RzCore *core) {
	mu_assert_true(rz_config_get_i(core->config, "frida.mem.max") == RZ_FRIDA_MEM_MAX_DEFAULT, "frida.mem.max default is registered");
	mu_assert_true(rz_config_get_i(core->config, "frida.timeout") == RZ_FRIDA_DEFAULT_TIMEOUT_MS, "frida.timeout default is registered");
	mu_assert_true(rz_config_get_i(core->config, "frida.hw.watchpoints") == RZ_FRIDA_HW_WATCHPOINTS_DEFAULT, "frida.hw.watchpoints default is registered");
	mu_assert_true(rz_config_get_i(core->config, "frida.java.max") == RZ_FRIDA_JAVA_MAX_DEFAULT, "frida.java.max default is registered");
	mu_end;
}

static bool test_mem_read_size_limit(RzCore *core) {
	rz_config_set_i(core->config, "frida.mem.max", 8);
	char *read = rz_core_cmd_str(core, "fridaxj 0x1000 16");
	rz_config_set_i(core->config, "frida.mem.max", RZ_FRIDA_MEM_MAX_DEFAULT);
	mu_assert_notnull(read, "memory read command returns output");
	mu_assert_streq(read,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"read size exceeds the frida.mem.max limit\"}}\n",
		"a read larger than frida.mem.max is rejected");
	RZ_FREE(read);
	mu_end;
}

static bool test_mem_write_size_limit(RzCore *core) {
	rz_config_set_i(core->config, "frida.mem.max", 2);
	char *write = rz_core_cmd_str(core, "fridawj 0x1000 deadbeef");
	rz_config_set_i(core->config, "frida.mem.max", RZ_FRIDA_MEM_MAX_DEFAULT);
	mu_assert_notnull(write, "memory write command returns output");
	mu_assert_streq(write,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"write size exceeds the frida.mem.max limit\"}}\n",
		"a write larger than frida.mem.max is rejected");
	RZ_FREE(write);
	mu_end;
}

static bool test_status_command(RzCore *core) {
	char *status = rz_core_cmd_str(core, "fridasj");
	mu_assert_notnull(status, "status command returns output");
	mu_assert_streq(status, "{\"ok\":true,\"result\":{\"active\":false,\"state\":\"closed\"}}\n", "status reports an inactive session");
	RZ_FREE(status);
	mu_end;
}

static bool test_uri_command(RzCore *core) {
	char *uri = rz_core_cmd_str(core, "fridauj frida://attach/local//1234");
	mu_assert_notnull(uri, "uri command returns output");
	mu_assert_streq(uri,
		"{\"ok\":true,\"result\":{\"action\":\"attach\",\"transport\":\"local\",\"device\":\"\",\"target\":\"1234\"}}\n",
		"uri command echoes the parsed components");
	RZ_FREE(uri);
	mu_end;
}

static bool test_invalid_uri_command(RzCore *core) {
	char *uri = rz_core_cmd_str(core, "fridauj gdb://attach/local//1234");
	mu_assert_notnull(uri, "uri command returns output");
	mu_assert_streq(uri,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"invalid Frida URI\"}}\n",
		"uri command rejects a non-frida scheme");
	RZ_FREE(uri);
	mu_end;
}

static bool test_devices_command(RzCore *core) {
	char *devices = rz_core_cmd_str(core, "fridadj");
	mu_assert_notnull(devices, "devices command returns output");
	mu_assert_true(rz_str_startswith(devices, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(devices, "{\"ok\":true,\"result\":{\"devices\":["),
		"devices command emits an ok or error envelope");
	RZ_FREE(devices);
	mu_end;
}

static bool test_processes_command(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj");
	mu_assert_notnull(processes, "processes command returns output");
	mu_assert_true(rz_str_startswith(processes, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(processes, "{\"ok\":true,\"result\":{\"processes\":["),
		"processes command emits an ok or error envelope");
	RZ_FREE(processes);
	mu_end;
}

static bool test_processes_device_command(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj frida://list/usb//");
	mu_assert_notnull(processes, "device-scoped processes command returns output");
	mu_assert_true(rz_str_startswith(processes, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(processes, "{\"ok\":true,\"result\":{\"processes\":["),
		"device-scoped processes command emits an ok or error envelope");
	RZ_FREE(processes);
	mu_end;
}

static bool test_apps_command(RzCore *core) {
	char *apps = rz_core_cmd_str(core, "fridaaj");
	mu_assert_notnull(apps, "apps command returns output");
	mu_assert_true(rz_str_startswith(apps, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(apps, "{\"ok\":true,\"result\":{\"apps\":["),
		"apps command emits an ok or error envelope");
	RZ_FREE(apps);
	mu_end;
}

static bool test_invalid_listing_uri(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj gdb://list/local//");
	mu_assert_notnull(processes, "listing command returns output");
	mu_assert_streq(processes,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"invalid Frida URI\"}}\n",
		"a non-frida selector is rejected before touching the backend");
	RZ_FREE(processes);
	mu_end;
}

static bool test_mismatched_listing_uri(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj frida://apps/usb//");
	mu_assert_notnull(processes, "listing command returns output");
	mu_assert_streq(processes,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"URI action does not match the command\"}}\n",
		"a listing command rejects a URI with the wrong action");
	RZ_FREE(processes);
	mu_end;
}

static bool test_resume_without_session(RzCore *core) {
	char *resume = rz_core_cmd_str(core, "fridarj");
	mu_assert_notnull(resume, "resume command returns output");
	mu_assert_streq(resume,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"resume without an open session reports the precondition failure");
	RZ_FREE(resume);
	mu_end;
}

static bool test_close_without_session(RzCore *core) {
	char *close = rz_core_cmd_str(core, "fridacj");
	mu_assert_notnull(close, "close command returns output");
	mu_assert_streq(close,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"close without an open session reports the precondition failure");
	RZ_FREE(close);
	mu_end;
}

static bool test_eval_without_session(RzCore *core) {
	char *eval = rz_core_cmd_str(core, "fridaej Process.arch");
	mu_assert_notnull(eval, "eval command returns output");
	mu_assert_streq(eval,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"eval without an open session reports the precondition failure");
	RZ_FREE(eval);
	mu_end;
}

static bool test_load_without_session(RzCore *core) {
	char *load = rz_core_cmd_str(core, "fridalj hook.js");
	mu_assert_notnull(load, "load command returns output");
	mu_assert_streq(load,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"load without an open session reports the precondition failure");
	RZ_FREE(load);
	mu_end;
}

static bool test_ping_without_session(RzCore *core) {
	char *ping = rz_core_cmd_str(core, "fridaij");
	mu_assert_notnull(ping, "ping command returns output");
	mu_assert_streq(ping,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"ping without an open session reports the precondition failure");
	RZ_FREE(ping);
	mu_end;
}

static bool test_messages_without_session(RzCore *core) {
	char *messages = rz_core_cmd_str(core, "fridamj");
	mu_assert_notnull(messages, "messages command returns output");
	mu_assert_streq(messages,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"messages without an open session reports the precondition failure");
	RZ_FREE(messages);
	mu_end;
}

static bool test_mem_read_without_session(RzCore *core) {
	char *read = rz_core_cmd_str(core, "fridaxj 0x1000 16");
	mu_assert_notnull(read, "memory read command returns output");
	mu_assert_streq(read,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"memory read without an open session reports the precondition failure");
	RZ_FREE(read);
	mu_end;
}

static bool test_mem_write_without_session(RzCore *core) {
	char *write = rz_core_cmd_str(core, "fridawj 0x1000 deadbeef");
	mu_assert_notnull(write, "memory write command returns output");
	mu_assert_streq(write,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"memory write without an open session reports the precondition failure");
	RZ_FREE(write);
	mu_end;
}

static bool test_ranges_without_session(RzCore *core) {
	char *ranges = rz_core_cmd_str(core, "fridaRj");
	mu_assert_notnull(ranges, "ranges command returns output");
	mu_assert_streq(ranges,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"ranges without an open session reports the precondition failure");
	RZ_FREE(ranges);
	mu_end;
}

static bool test_threads_without_session(RzCore *core) {
	char *threads = rz_core_cmd_str(core, "fridatj");
	mu_assert_notnull(threads, "threads command returns output");
	mu_assert_streq(threads,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"threads without an open session reports the precondition failure");
	RZ_FREE(threads);
	mu_end;
}

static bool test_modules_without_session(RzCore *core) {
	char *modules = rz_core_cmd_str(core, "fridaMj");
	mu_assert_notnull(modules, "modules command returns output");
	mu_assert_streq(modules,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"modules without an open session reports the precondition failure");
	RZ_FREE(modules);
	mu_end;
}

static bool test_exports_without_session(RzCore *core) {
	char *exports = rz_core_cmd_str(core, "fridaEj libc.so");
	mu_assert_notnull(exports, "exports command returns output");
	mu_assert_streq(exports,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"exports without an open session reports the precondition failure");
	RZ_FREE(exports);
	mu_end;
}

static bool test_imports_without_session(RzCore *core) {
	char *imports = rz_core_cmd_str(core, "fridaIj libc.so");
	mu_assert_notnull(imports, "imports command returns output");
	mu_assert_streq(imports,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"imports without an open session reports the precondition failure");
	RZ_FREE(imports);
	mu_end;
}

static bool test_symbols_without_session(RzCore *core) {
	char *symbols = rz_core_cmd_str(core, "fridaSj libc.so");
	mu_assert_notnull(symbols, "symbols command returns output");
	mu_assert_streq(symbols,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"symbols without an open session reports the precondition failure");
	RZ_FREE(symbols);
	mu_end;
}

static bool test_bp_set_without_session(RzCore *core) {
	char *bp = rz_core_cmd_str(core, "fridabj 0x1000");
	mu_assert_notnull(bp, "breakpoint set command returns output");
	mu_assert_streq(bp,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"breakpoint set without an open session reports the precondition failure");
	RZ_FREE(bp);
	mu_end;
}

static bool test_bp_list_without_session(RzCore *core) {
	char *bp = rz_core_cmd_str(core, "fridabj");
	mu_assert_notnull(bp, "breakpoint list command returns output");
	mu_assert_streq(bp,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"breakpoint list without an open session reports the precondition failure");
	RZ_FREE(bp);
	mu_end;
}

static bool test_bp_remove_without_session(RzCore *core) {
	char *bp = rz_core_cmd_str(core, "fridab-j 0x1000");
	mu_assert_notnull(bp, "breakpoint remove command returns output");
	mu_assert_streq(bp,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"breakpoint remove without an open session reports the precondition failure");
	RZ_FREE(bp);
	mu_end;
}

static bool test_continue_without_session(RzCore *core) {
	char *cont = rz_core_cmd_str(core, "fridagj");
	mu_assert_notnull(cont, "continue command returns output");
	mu_assert_streq(cont,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"continue without an open session reports the precondition failure");
	RZ_FREE(cont);
	mu_end;
}

static bool test_reg_read_without_session(RzCore *core) {
	char *reg = rz_core_cmd_str(core, "fridaBj 4242");
	mu_assert_notnull(reg, "register read command returns output");
	mu_assert_streq(reg,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"register read without an open session reports the precondition failure");
	RZ_FREE(reg);
	mu_end;
}

static bool test_reg_write_without_session(RzCore *core) {
	char *reg = rz_core_cmd_str(core, "fridaBj 4242 pc 0x401000");
	mu_assert_notnull(reg, "register write command returns output");
	mu_assert_streq(reg,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"register write without an open session reports the precondition failure");
	RZ_FREE(reg);
	mu_end;
}

static bool test_wp_set_without_session(RzCore *core) {
	char *wp = rz_core_cmd_str(core, "fridaWj 0x1000 8 w");
	mu_assert_notnull(wp, "watchpoint set command returns output");
	mu_assert_streq(wp,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"watchpoint set without an open session reports the precondition failure");
	RZ_FREE(wp);
	mu_end;
}

static bool test_wp_list_without_session(RzCore *core) {
	char *wp = rz_core_cmd_str(core, "fridaWj");
	mu_assert_notnull(wp, "watchpoint list command returns output");
	mu_assert_streq(wp,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"watchpoint list without an open session reports the precondition failure");
	RZ_FREE(wp);
	mu_end;
}

static bool test_wp_remove_without_session(RzCore *core) {
	char *wp = rz_core_cmd_str(core, "fridaW-j 0x1000");
	mu_assert_notnull(wp, "watchpoint remove command returns output");
	mu_assert_streq(wp,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"watchpoint remove without an open session reports the precondition failure");
	RZ_FREE(wp);
	mu_end;
}

static bool test_java_available_without_session(RzCore *core) {
	char *j = rz_core_cmd_str(core, "fridaJj");
	mu_assert_notnull(j, "java available command returns output");
	mu_assert_streq(j,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"java available without an open session reports the precondition failure");
	RZ_FREE(j);
	mu_end;
}

static bool test_loaders_without_session(RzCore *core) {
	char *l = rz_core_cmd_str(core, "fridaLj");
	mu_assert_notnull(l, "loader list command returns output");
	mu_assert_streq(l,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"loader list without an open session reports the precondition failure");
	RZ_FREE(l);
	mu_end;
}

static bool test_classes_without_session(RzCore *core) {
	char *c = rz_core_cmd_str(core, "fridaCj");
	mu_assert_notnull(c, "class list command returns output");
	mu_assert_streq(c,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"class list without an open session reports the precondition failure");
	RZ_FREE(c);
	mu_end;
}

static bool test_describe_without_session(RzCore *core) {
	char *d = rz_core_cmd_str(core, "fridaDj java.lang.String");
	mu_assert_notnull(d, "describe command returns output");
	mu_assert_streq(d,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"describe without an open session reports the precondition failure");
	RZ_FREE(d);
	mu_end;
}

static bool test_import_without_session(RzCore *core) {
	char *i = rz_core_cmd_str(core, "fridaImj java.lang.String");
	mu_assert_notnull(i, "import command returns output");
	mu_assert_streq(i,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"import without an open session reports the precondition failure");
	RZ_FREE(i);
	mu_end;
}

static bool test_import_batch_without_session(RzCore *core) {
	char *b = rz_core_cmd_str(core, "fridaImj re.frida");
	mu_assert_notnull(b, "batch import returns output");
	mu_assert_streq(b,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"batch import without an open session reports the precondition failure");
	RZ_FREE(b);
	mu_end;
}

static bool test_invalid_open_uri(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj gdb://attach/local//1234");
	mu_assert_notnull(open, "open command returns output");
	mu_assert_streq(open,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"invalid Frida URI\"}}\n",
		"open rejects a non-frida scheme before touching the backend");
	RZ_FREE(open);
	mu_end;
}

static bool test_open_command(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj frida://attach/local//1234");
	mu_assert_notnull(open, "open command returns output");
	mu_assert_true(rz_str_startswith(open, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(open, "{\"ok\":true,\"result\":{\"action\":"),
		"open command emits an ok or error envelope");
	RZ_FREE(open);
	mu_end;
}

static bool test_open_usb_command(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj frida://attach/usb//com.example.app");
	mu_assert_notnull(open, "usb open command returns output");
	mu_assert_true(rz_str_startswith(open, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(open, "{\"ok\":true,\"result\":{\"action\":"),
		"usb open routes a process-name target to the backend");
	RZ_FREE(open);
	mu_end;
}

static bool test_open_remote_command(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj frida://attach/remote/127.0.0.1:27042/1234");
	mu_assert_notnull(open, "remote open command returns output");
	mu_assert_true(rz_str_startswith(open, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(open, "{\"ok\":true,\"result\":{\"action\":"),
		"remote open routes to the backend");
	RZ_FREE(open);
	mu_end;
}

static bool test_close_command(RzCore *core) {
	char *close = rz_core_cmd_str(core, "fridacj");
	mu_assert_notnull(close, "close command returns output");
	mu_assert_true(rz_str_startswith(close, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(close, "{\"ok\":true,\"result\":{\"pid\":"),
		"close emits an ok or error envelope depending on whether open established a session");
	RZ_FREE(close);
	mu_end;
}

static bool test_plugin_unregistration(RzCore *core) {
	mu_assert_true(rz_core_plugin_del(core, &rz_core_plugin_frida), "unregister the frida plugin");
	mu_assert_null(rz_core_plugin_context_get(core, &rz_core_plugin_frida), "plugin context is released on unregistration");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "frida"), "frida group command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridas"), "fridas command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridau"), "fridau command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridad"), "fridad command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridap"), "fridap command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaa"), "fridaa command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridao"), "fridao command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridar"), "fridar command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridac"), "fridac command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridae"), "fridae command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridal"), "fridal command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridai"), "fridai command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridam"), "fridam command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridax"), "fridax command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaw"), "fridaw command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaR"), "fridaR command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridat"), "fridat command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaM"), "fridaM command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaE"), "fridaE command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaI"), "fridaI command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaS"), "fridaS command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridab"), "fridab command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridab-"), "fridab- command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridag"), "fridag command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaB"), "fridaB command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaW"), "fridaW command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaW-"), "fridaW- command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaJ"), "fridaJ command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaL"), "fridaL command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaC"), "fridaC command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaD"), "fridaD command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaIm"), "fridaIm command is removed");
	mu_end;
}

int all_tests(void) {
	RzCore *core = rz_core_new();
	if (!core) {
		printf("Cannot create RzCore\n");
		return 1;
	}

	mu_run_test(test_plugin_registration, core);
	mu_run_test(test_config_defaults, core);
	mu_run_test(test_mem_read_size_limit, core);
	mu_run_test(test_mem_write_size_limit, core);
	mu_run_test(test_status_command, core);
	mu_run_test(test_uri_command, core);
	mu_run_test(test_invalid_uri_command, core);
	mu_run_test(test_devices_command, core);
	mu_run_test(test_processes_command, core);
	mu_run_test(test_processes_device_command, core);
	mu_run_test(test_apps_command, core);
	mu_run_test(test_invalid_listing_uri, core);
	mu_run_test(test_mismatched_listing_uri, core);
	mu_run_test(test_resume_without_session, core);
	mu_run_test(test_close_without_session, core);
	mu_run_test(test_eval_without_session, core);
	mu_run_test(test_load_without_session, core);
	mu_run_test(test_ping_without_session, core);
	mu_run_test(test_messages_without_session, core);
	mu_run_test(test_mem_read_without_session, core);
	mu_run_test(test_mem_write_without_session, core);
	mu_run_test(test_ranges_without_session, core);
	mu_run_test(test_threads_without_session, core);
	mu_run_test(test_modules_without_session, core);
	mu_run_test(test_exports_without_session, core);
	mu_run_test(test_imports_without_session, core);
	mu_run_test(test_symbols_without_session, core);
	mu_run_test(test_bp_set_without_session, core);
	mu_run_test(test_bp_list_without_session, core);
	mu_run_test(test_bp_remove_without_session, core);
	mu_run_test(test_continue_without_session, core);
	mu_run_test(test_reg_read_without_session, core);
	mu_run_test(test_reg_write_without_session, core);
	mu_run_test(test_wp_set_without_session, core);
	mu_run_test(test_wp_list_without_session, core);
	mu_run_test(test_wp_remove_without_session, core);
	mu_run_test(test_java_available_without_session, core);
	mu_run_test(test_loaders_without_session, core);
	mu_run_test(test_classes_without_session, core);
	mu_run_test(test_describe_without_session, core);
	mu_run_test(test_import_without_session, core);
	mu_run_test(test_import_batch_without_session, core);
	mu_run_test(test_invalid_open_uri, core);
	mu_run_test(test_open_command, core);
	mu_run_test(test_open_usb_command, core);
	mu_run_test(test_open_remote_command, core);
	mu_run_test(test_close_command, core);
	mu_run_test(test_plugin_unregistration, core);

	rz_core_free(core);
	return tests_passed != tests_run;
}

mu_main(all_tests)
