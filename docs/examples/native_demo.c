// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// native_demo -- a small demo crackme for rz-frida.
// with an arg, it checks the key once and exits, without one it serves
// the interactive license gate.

#include <stdio.h>
#include <string.h>

#define MAX_KEY 128

// writable in memory secret, fridawj patch target
static char g_secret[] = "N4T1V3-D3M0-K3Y";

// attempt counter, the bump_counter trace target
static int g_attempts = 0;

static int check_key(const char *key) {
	return strcmp(key, g_secret) == 0;
}

static int bump_counter(void) {
	return ++g_attempts;
}

int main(int argc, char **argv) {
	if (argc > 1) {
		printf("License %s\n", check_key(argv[1]) ? "ACCEPTED" : "DENIED");
		return 0;
	}

	char line[MAX_KEY];
	printf("Native Demo -- license gate\n");
	printf("Find the key, or patch the gate\n");
	for (;;) {
		printf("attempts: %d\n", bump_counter());
		printf("Enter license key (q to quit): ");
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin)) {
			break;
		}
		line[strcspn(line, "\n")] = '\0';
		if (strcmp(line, "q") == 0) {
			break;
		}
		printf("License %s\n", check_key(line) ? "ACCEPTED" : "DENIED");
	}
	return 0;
}
