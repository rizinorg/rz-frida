// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// runs injected agent (rzfrida_agent.js) in mocked frida runtime and
// checks host-agent req/response protocol without a live target. meson
// runs this when node is available, else skipped.

'use strict';

const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const agentPath = process.argv[2];
if (!agentPath) {
	console.error('usage: test_agent.js <path to rzfrida_agent.js>');
	process.exit(2);
}
const source = fs.readFileSync(agentPath, 'utf8');

const sent = [];
let pendingRecv = null;
const interceptors = new Map();
let continueDeliverId = 0;
const parkedActions = [];
let exceptionHandler = null;
const hwWatch = new Map();
let javaGetEnvCalls = 0;

// fake target memory region, backs a known byte pattern at MEM_BASE, addressed through ptr().
const MEM_BASE = 0x1000;
const memory = new Uint8Array(256);
for (let i = 0; i < memory.length; i++) {
	memory[i] = i;
}
function FakePtr(value) {
	this.value = (typeof value === 'string') ? Number(value) : value;
}
FakePtr.prototype.toString = function () {
	return '0x' + this.value.toString(16);
};
FakePtr.prototype.compare = function (other) {
	if (this.value < other.value) { return -1; }
	return this.value > other.value ? 1 : 0;
};
FakePtr.prototype.add = function (n) {
	return new FakePtr(this.value + n);
};
FakePtr.prototype.readPointer = function () {
	return new FakePtr(this.value + 0x100);
};
FakePtr.prototype.isNull = function () {
	return this.value === 0;
};
FakePtr.prototype.readS32 = function () {
	return this.value | 0;
};
FakePtr.prototype.readInt = function () {
	return this.readS32();
};
FakePtr.prototype.toInt32 = function () {
	return this.value & 0xffffffff;
};
FakePtr.prototype.readUtf8String = function () {
	return 'nativeMethod';
};
FakePtr.prototype.toJSON = function () {
	return this.toString();
};
FakePtr.prototype.readByteArray = function (size) {
	const off = this.value - MEM_BASE;
	if (off < 0 || off + size > memory.length) {
		return null;
	}
	return memory.slice(off, off + size).buffer;
};
FakePtr.prototype.writeByteArray = function (bytes) {
	const off = this.value - MEM_BASE;
	if (off < 0 || off + bytes.length > memory.length) {
		throw new Error('access violation');
	}
	for (let i = 0; i < bytes.length; i++) {
		memory[off + i] = bytes[i];
	}
};

// fake enumerations, counters so the range & module caches can be checked.
let rangesEnumerated = 0;
let modulesEnumerated = 0;
const fakeRanges = [
	{ base: new FakePtr(0x1000), size: 0x1000, protection: 'r-x', file: { path: '/bin/app', offset: 0, size: 0x1000 } },
	{ base: new FakePtr(0x8000), size: 0x2000, protection: 'rw-' }
];
const fakeThreads = [
	{ id: 1, state: 'waiting', context: { pc: new FakePtr(0x401000), sp: new FakePtr(0x7000) } },
	{ id: 2, state: 'running', context: { pc: new FakePtr(0x402000), sp: new FakePtr(0x8000) }, entrypoint: { routine: new FakePtr(0x400000), parameter: new FakePtr(0) } }
];
fakeThreads.forEach(function (t) {
	t.setHardwareWatchpoint = function (slot, addr, size, conditions) {
		hwWatch.set(slot, { address: addr.toString(), size: size, conditions: conditions });
	};
	t.unsetHardwareWatchpoint = function (slot) { hwWatch.delete(slot); };
});
const fakeExports = [
	{ type: 'function', name: 'main', address: new FakePtr(0x401000) },
	{ type: 'variable', name: 'global', address: new FakePtr(0x402000) }
];
const fakeImports = [
	{ type: 'function', name: 'printf', module: 'libc.so', address: new FakePtr(0x7f0000001000) }
];
const fakeSymbols = [
	{ isGlobal: true, type: 'function', name: 'start', address: new FakePtr(0x401000), size: 32 }
];
const fakeModules = [
	{
		name: 'app', base: new FakePtr(0x400000), size: 0x20000, path: '/data/app/app',
		enumerateExports: function () { return fakeExports; },
		enumerateImports: function () { return fakeImports; },
		enumerateSymbols: function () { return fakeSymbols; }
	},
	{
		name: 'libc.so', base: new FakePtr(0x7f0000000000), size: 0x100000, path: '/system/lib/libc.so',
		enumerateExports: function () { return []; },
		enumerateImports: function () { return []; },
		enumerateSymbols: function () { return []; }
	}
];

const KNOWN_JAVA_CLASSES = [
	're.frida.minapp.MainActivity', 're.frida.minapp.SampleModel',
	're.frida.minapp.DerivedModel', 're.frida.minapp.NativeLib',
	're.frida.minapp.ReflectionTarget', 're.frida.minapp.BaseModel',
	'java.lang.String', 'java.lang.System',
	'android.app.Activity', 'android.os.Bundle',
	'kotlin.Metadata'
];

let dynamicJavaClasses = [];

// dynamic class tracking in mock
function makeClassLoaderObj() {
	let originalImpl = function (name, resolve) {
		return null;
	};
	let hookedImpl = null;
	let inHook = false;
	const obj = {};
	obj.loadClass = function (name, resolve) {
		if (inHook) {
			return originalImpl.call(this, name, resolve);
		}
		if (hookedImpl) {
			inHook = true;
			const r = hookedImpl.call(this, name, resolve);
			inHook = false;
			return r;
		}
		return originalImpl.call(this, name, resolve);
	};
	obj.loadClass.overload = function () {
		return {
			set implementation(fn) { hookedImpl = fn; },
			detach: function () { hookedImpl = null; },
		};
	};
	obj.$init = {
		overload: function () {
			return {
				set implementation(fn) { /* nop in mock */ },
			};
		},
	};
	return obj;
}

const fakeFields = {
	're.frida.minapp.SampleModel': [
		{ getName: function () { return 'id'; }, getType: function () { return { getName: function () { return 'int'; } }; }, getModifiers: function () { return 0x0002; } },
		{ getName: function () { return 'name'; }, getType: function () { return { getName: function () { return 'java.lang.String'; } }; }, getModifiers: function () { return 0x0002; } },
		{ getName: function () { return 'active'; }, getType: function () { return { getName: function () { return 'boolean'; } }; }, getModifiers: function () { return 0x0002; } },
		{ getName: function () { return 'tags'; }, getType: function () { return { getName: function () { return '[I'; } }; }, getModifiers: function () { return 0x0002; } },
		{ getName: function () { return 'parent'; }, getType: function () { return { getName: function () { return 're.frida.minapp.SampleModel'; } }; }, getModifiers: function () { return 0x0002; } }],
	're.frida.minapp.DerivedModel': [
		{ getName: function () { return 'count'; }, getType: function () { return { getName: function () { return 'int'; } }; }, getModifiers: function () { return 0x0002; } }],
	're.frida.minapp.ReflectionTarget': [
		{ getName: function () { return 'publicField'; }, getType: function () { return { getName: function () { return 'int'; } }; }, getModifiers: function () { return 0x0001; } },
		{ getName: function () { return 'privateField'; }, getType: function () { return { getName: function () { return 'java.lang.String'; } }; }, getModifiers: function () { return 0x0002; } },
		{ getName: function () { return 'protectedField'; }, getType: function () { return { getName: function () { return 'boolean'; } }; }, getModifiers: function () { return 0x0004; } },
		{ getName: function () { return 'packageField'; }, getType: function () { return { getName: function () { return 'double'; } }; }, getModifiers: function () { return 0; } }]
};

function fakeMethods(name) {
	if (name === 're.frida.minapp.SampleModel') {
		return [
			{ getName: function () { return 'getId'; }, getReturnType: function () { return { getName: function () { return 'int'; } }; },
				getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0001; } },
			{ getName: function () { return 'getName'; }, getReturnType: function () { return { getName: function () { return 'java.lang.String'; } }; },
				getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0001; } },
			{ getName: function () { return 'isActive'; }, getReturnType: function () { return { getName: function () { return 'boolean'; } }; },
				getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0001; } },
			{ getName: function () { return 'setActive'; }, getReturnType: function () { return { getName: function () { return 'void'; } }; },
				getParameterTypes: function () { return [{ getName: function () { return 'boolean'; } }]; }, getModifiers: function () { return 0x0001; } }];
	}
	if (name === 're.frida.minapp.NativeLib') {
		return [
			{ getName: function () { return 'nativeInit'; }, getReturnType: function () { return { getName: function () { return 'void'; } }; },
				getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0109; } },
			{ getName: function () { return 'processBytes'; }, getReturnType: function () { return { getName: function () { return 'int'; } }; },
				getParameterTypes: function () { return [{ getName: function () { return '[B'; } }]; }, getModifiers: function () { return 0x0101; } },
			{ getName: function () { return 'getNativeVersion'; }, getReturnType: function () { return { getName: function () { return 'java.lang.String'; } }; },
				getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0101; } }];
	}
	if (name === 're.frida.minapp.DerivedModel') {
		return [
			{ getName: function () { return 'getCount'; }, getReturnType: function () { return { getName: function () { return 'int'; } }; },
				getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0001; } },
			{ getName: function () { return 'setCount'; }, getReturnType: function () { return { getName: function () { return 'void'; } }; },
				getParameterTypes: function () { return [{ getName: function () { return 'int'; } }]; }, getModifiers: function () { return 0x0001; } },
			{ getName: function () { return 'getCount'; }, getReturnType: function () { return { getName: function () { return 'int'; } }; },
				getParameterTypes: function () { return [{ getName: function () { return 'int'; } }]; }, getModifiers: function () { return 0x0001; } },
			{ getName: function () { return 'compute'; }, getReturnType: function () { return { getName: function () { return 'int'; } }; },
				getParameterTypes: function () { return [{ getName: function () { return 'int'; } }, { getName: function () { return 'int'; } }, { getName: function () { return 'int'; } }]; },
				getModifiers: function () { return 0x0001; } },
			{ getName: function () { return 'compute'; }, getReturnType: function () { return { getName: function () { return 'double'; } }; },
				getParameterTypes: function () { return [{ getName: function () { return 'double'; } }, { getName: function () { return 'double'; } }]; },
				getModifiers: function () { return 0x0001; } }];
	}
	return [];
}

function fakeCtors(name) {
	if (name === 're.frida.minapp.SampleModel') {
		return [
			{ getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0001; } },
			{ getParameterTypes: function () { return [{ getName: function () { return 'int'; } }]; }, getModifiers: function () { return 0x0001; } },
			{ getParameterTypes: function () { return [{ getName: function () { return 'int'; } }, { getName: function () { return 'java.lang.String'; } }]; }, getModifiers: function () { return 0x0001; } }];
	}
	if (name === 're.frida.minapp.DerivedModel') {
		return [
			{ getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0001; } },
			{ getParameterTypes: function () { return [{ getName: function () { return 'int'; } }]; }, getModifiers: function () { return 0x0001; } }];
	}
	return [{ getParameterTypes: function () { return []; }, getModifiers: function () { return 0x0001; } }];
}

function fakeSuper(name) {
	if (name === 're.frida.minapp.DerivedModel') {
		return fakeKlass('re.frida.minapp.BaseModel');
	}
	if (name === 're.frida.minapp.MainActivity') {
		return fakeKlass('android.app.Activity');
	}
	if (name === 'java.lang.Object') {
		return null;
	}
	return fakeKlass('java.lang.Object');
}

function fakeInterfaces(name) {
	if (name === 're.frida.minapp.DerivedModel') {
		return [fakeKlass('re.frida.minapp.ModelInterface')];
	}
	return [];
}

const kotlinAnnotatedClasses = new Set(['re.frida.minapp.SampleModel']);
function makeKotlinMeta() {
	return {
		k: function () { return 1; },
		mv: function () { return [1, 4]; },
		xi: function () { return 0; },
		bv: function () { return [1, 0]; },
		d1: function () { return [0xca, 0xfe, 0xba, 0xbe]; },
		d2: function () { return [0xde, 0xad]; }
	};
}

function fakeKlass(name) {
	var cachedFields = (fakeFields[name] || []);
	return {
		getName: function () { return name; },
		getSuperclass: function () { return fakeSuper(name); },
		getInterfaces: function () { return fakeInterfaces(name); },
		getModifiers: function () { return name === 're.frida.minapp.BaseModel' ? 0x0401 : 0x0001; },
		getDeclaredFields: function () { return cachedFields; },
		getDeclaredMethods: function () { return fakeMethods(name); },
		getDeclaredConstructors: function () { return fakeCtors(name); },
		getAnnotation: function (annotationKlass) {
			if (annotationKlass && annotationKlass.getName && annotationKlass.getName() === 'kotlin.Metadata' && kotlinAnnotatedClasses.has(name)) {
				return makeKotlinMeta();
			}
			return null;
		}
	};
}

function findClass(name) {
	if (name === 'java.lang.ClassLoader') {
		return makeClassLoaderObj();
	}
	if (KNOWN_JAVA_CLASSES.indexOf(name) < 0) {
		throw new Error('java.lang.ClassNotFoundException: ' + name);
	}
	return { class: fakeKlass(name) };
}

const sandbox = {
	Process: {
		platform: 'linux',
		arch: 'x64',
		pointerSize: 8,
		enumerateRanges: function () { rangesEnumerated++; return fakeRanges; },
		enumerateThreads: function () { return fakeThreads; },
		enumerateModules: function () { modulesEnumerated++; return fakeModules; },
		getCurrentThreadId: function () { return 4242; },
		setExceptionHandler: function (cb) { exceptionHandler = cb; },
		findModuleByName: function (name) { return null; }
	},
	Java: {
		available: true,
		ACC_PUBLIC: 0x0001,
		ACC_PRIVATE: 0x0002,
		ACC_PROTECTED: 0x0004,
		ACC_STATIC: 0x0008,
		ACC_FINAL: 0x0010,
		ACC_SYNCHRONIZED: 0x0020,
		ACC_BRIDGE: 0x0040,
		ACC_VARARGS: 0x0080,
		ACC_NATIVE: 0x0100,
		ACC_ABSTRACT: 0x0400,
		ACC_STRICT: 0x0800,
		ACC_SYNTHETIC: 0x1000,
		performNow: function (fn) { return fn(); },
		perform: function (fn) { return fn(); },
		enumerateClassLoadersSync: function () {
			return [
				{ getClass: function () { return { getName: function () { return 'dalvik.system.PathClassLoader'; } }; },
					toString: function () { return 'dalvik.system.PathClassLoader[DexPathList[...]]'; } },
				{ getClass: function () { return { getName: function () { return 'java.lang.BootClassLoader'; } }; },
					toString: function () { return 'java.lang.BootClassLoader@abc'; } }
			];
		},
		enumerateLoadedClassesSync: function () {
			return KNOWN_JAVA_CLASSES.concat(dynamicJavaClasses);
		},
		use: function (name) { return findClass(name); },
		ClassFactory: { get: function (loader) { return { use: function (name) { return findClass(name); } }; } },
		vm: {
			getEnv: function () {
				javaGetEnvCalls++;
				const tablePtr = new FakePtr(0xcafe0000);
				return {
					handle: {
						readPointer: function () { return tablePtr; }
					},
					newGlobalRef: function (cls) { return cls; },
					deleteGlobalRef: function () {},
					getClassName: function (cls) { return 'com.example.TestClass'; }
				};
			}
		}
	},
	recv: function (type, cb) {
		// untyped recv stores the handler, typed recv(type, cb) is a parked thread waiter.
		if (typeof type === 'function') {
			pendingRecv = type;
			return { wait: function () {} };
		}
		return { wait: function () {
			while (parkedActions.length) {
				pendingRecv(parkedActions.shift());
			}
			cb({ id: continueDeliverId, type: type });
		} };
	},
	// frida marshals send() to json over the wire, so capture that form (it also
	// drops vm realm prototype, letting deepStrictEqual compare plain objs).
	send: function (message, data) { sent.push({ message: JSON.parse(JSON.stringify(message)), data: data }); },
	ptr: function (value) { return new FakePtr(value); },
	Memory: {
		alloc: function (n) { return new FakePtr(0x9000); }
	},
	NativeFunction: function (addr, ret) {
		return function () {
			if (ret === 'int') {
				return 0;
			}
			if (ret === 'pointer') {
				return arguments[1] || new FakePtr(0);
			}
			return undefined;
		};
	},
	Interceptor: {
		attach: function (addr, callbacks) {
			const key = addr.toString();
			const listener = { detach: function () { interceptors.delete(key); } };
			interceptors.set(key, { onEnter: callbacks.onEnter, onLeave: callbacks.onLeave, listener: listener });
			return listener;
		}
	},
	Module: {
		findExportByName: function (mod, name) { return null; }
	},
	rpc: {},
	console: console
};
sandbox.dynamicJavaClasses = [];
sandbox.kotlinAnnotatedClasses = kotlinAnnotatedClasses;
vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: 'rzfrida_agent.js' });

// send one req, return reply, or null when agent stays silent.
function roundtrip(request) {
	const before = sent.length;
	assert.ok(typeof pendingRecv === 'function', 'agent keeps a recv callback registered');
	pendingRecv(request);
	if (sent.length === before) {
		return null;
	}
	const reply = sent.slice(before).find(function (s) {
		return s.message && s.message.id === request.id;
	});
	assert.ok(reply, 'agent sends a reply for the request');
	return reply.message;
}

function fireRn(key, args) {
	const ctx = {};
	interceptors.get(key).onEnter.call(ctx, args);
	interceptors.get(key).onLeave.call(ctx);
	return ctx;
}

assert.deepStrictEqual(sent[0].message, { type: 'agent.ready', version: 1 },
	'agent.ready is emitted on load');

assert.deepStrictEqual(roundtrip({ id: 1, type: 'ping' }),
	{ id: 1, ok: true, result: { version: 1, platform: 'linux', arch: 'x64', pointerSize: 8 } },
	'ping replies with agent info');

assert.deepStrictEqual(roundtrip({ id: 2, type: 'eval', params: { source: '1 + 1' } }),
	{ id: 2, ok: true, result: { value: 2, type: 'number' } },
	'eval of a number');

assert.deepStrictEqual(roundtrip({ id: 3, type: 'eval', params: { source: '"a" + "b"' } }),
	{ id: 3, ok: true, result: { value: 'ab', type: 'string' } },
	'eval of a string');

assert.deepStrictEqual(roundtrip({ id: 4, type: 'eval', params: { source: 'undefined' } }),
	{ id: 4, ok: true, result: { value: null, type: 'undefined' } },
	'eval of undefined keeps its type');

assert.deepStrictEqual(roundtrip({ id: 5, type: 'eval', params: { source: 'Process.arch' } }),
	{ id: 5, ok: true, result: { value: 'x64', type: 'string' } },
	'eval can read the frida globals');

const evalError = roundtrip({ id: 6, type: 'eval', params: { source: 'nope.nope' } });
assert.strictEqual(evalError.id, 6, 'error reply keeps the id');
assert.strictEqual(evalError.ok, false, 'error reply is not ok');
assert.strictEqual(evalError.error, 'nope is not defined', 'error message is forwarded');

const evalBadSource = roundtrip({ id: 7, type: 'eval', params: {} });
assert.strictEqual(evalBadSource.ok, false, 'a missing source is rejected');
assert.strictEqual(evalBadSource.error, 'eval requires a string source', 'the source type is reported');

const unknown = roundtrip({ id: 8, type: 'frobnicate' });
assert.strictEqual(unknown.ok, false, 'an unknown type is rejected');
assert.strictEqual(unknown.error, 'unknown request type: frobnicate', 'the unknown type is named');

assert.strictEqual(roundtrip({ type: 'ping' }), null, 'a request without an id draws no reply');

assert.deepStrictEqual(JSON.parse(JSON.stringify(sandbox.rpc.exports.ping())),
	{ version: 1, platform: 'linux', arch: 'x64', pointerSize: 8 },
	'rpc.exports.ping returns the agent info');

assert.deepStrictEqual(roundtrip({ id: 9, type: 'memRead', params: { address: '0x1000', size: 4 } }),
	{ id: 9, ok: true, result: { address: '0x1000', size: 4, bytes: '00010203' } },
	'memRead returns the requested bytes as hex');

assert.deepStrictEqual(roundtrip({ id: 10, type: 'memRead', params: { address: 0x1004, size: 2 } }),
	{ id: 10, ok: true, result: { address: '0x1004', size: 2, bytes: '0405' } },
	'memRead accepts a numeric address');

const readOob = roundtrip({ id: 11, type: 'memRead', params: { address: '0x1000', size: 4096 } });
assert.strictEqual(readOob.ok, false, 'an unreadable range is rejected');
assert.ok(/cannot read/.test(readOob.error), 'the unreadable range is reported');

const readNoAddr = roundtrip({ id: 12, type: 'memRead', params: { size: 4 } });
assert.strictEqual(readNoAddr.error, 'a memory request requires an address', 'a missing address is rejected');

const readBadSize = roundtrip({ id: 13, type: 'memRead', params: { address: '0x1000', size: 0 } });
assert.strictEqual(readBadSize.error, 'memRead requires a positive integer size', 'a non-positive size is rejected');

assert.deepStrictEqual(roundtrip({ id: 14, type: 'memWrite', params: { address: '0x1018', bytes: '0xcafe' } }),
	{ id: 14, ok: true, result: { address: '0x1018', size: 2 } },
	'memWrite strips a 0x prefix from the hex bytes');

const writeNoString = roundtrip({ id: 142, type: 'memWrite', params: { address: '0x1018', bytes: 123 } });
assert.strictEqual(writeNoString.error, 'memWrite requires a hex byte string', 'a non-string hex payload is rejected');

const fromHexType = roundtrip({ id: 143, type: 'eval', params: { source: "try { fromHex(1); 'no'; } catch (e) { e.message; }" } });
assert.strictEqual(fromHexType.result.value, 'hex input must be a string', 'fromHex rejects a non-string with a distinct error');

assert.deepStrictEqual(roundtrip({ id: 15, type: 'memWrite', params: { address: '0x1010', bytes: 'deadbeef' } }),
	{ id: 15, ok: true, result: { address: '0x1010', size: 4 } },
	'memWrite reports the number of bytes written');

assert.deepStrictEqual(roundtrip({ id: 16, type: 'memRead', params: { address: '0x1010', size: 4 } }),
	{ id: 16, ok: true, result: { address: '0x1010', size: 4, bytes: 'deadbeef' } },
	'memRead sees the bytes memWrite stored');

const writeOddHex = roundtrip({ id: 17, type: 'memWrite', params: { address: '0x1010', bytes: 'abc' } });
assert.strictEqual(writeOddHex.error, 'hex input must have an even length', 'odd-length hex is rejected');

const writeBadHex = roundtrip({ id: 18, type: 'memWrite', params: { address: '0x1010', bytes: 'zz' } });
assert.strictEqual(writeBadHex.error, 'hex input has a non-hex character', 'non-hex input is rejected');

const writeOob = roundtrip({ id: 19, type: 'memWrite', params: { address: '0x10f8', bytes: 'deadbeefdeadbeefdeadbeef' } });
assert.strictEqual(writeOob.ok, false, 'a write past the region is rejected');

// memRead/memWrite above filled range cache to validate addrs, clear it
// so cache assertions below start from a known state.
roundtrip({ id: 100, type: 'eval', params: { source: '0' } });
rangesEnumerated = 0;

const firstRanges = roundtrip({ id: 20, type: 'ranges' });
assert.strictEqual(firstRanges.result.cached, false, 'the first ranges call enumerates');
assert.deepStrictEqual(firstRanges.result.ranges, [
	{ base: '0x1000', size: 0x1000, protection: 'r-x', file: { path: '/bin/app', offset: 0, size: 0x1000 } },
	{ base: '0x8000', size: 0x2000, protection: 'rw-' }
], 'ranges returns the mapped range details');

assert.strictEqual(roundtrip({ id: 21, type: 'ranges' }).result.cached, true, 'a second call serves the cache');
assert.strictEqual(roundtrip({ id: 22, type: 'ranges', params: { refresh: true } }).result.cached, false, 'refresh re-enumerates');
assert.strictEqual(roundtrip({ id: 23, type: 'ranges' }).result.cached, true, 'the refreshed list is cached again');

roundtrip({ id: 24, type: 'eval', params: { source: '1 + 1' } });
assert.strictEqual(roundtrip({ id: 25, type: 'ranges' }).result.cached, false, 'running code drops the cached ranges');
assert.strictEqual(rangesEnumerated, 3, 'the cache avoided redundant enumeration');

assert.deepStrictEqual(roundtrip({ id: 26, type: 'threads' }),
	{ id: 26, ok: true, result: { threads: [
		{ id: 1, state: 'waiting', context: { pc: '0x401000', sp: '0x7000' } },
		{ id: 2, state: 'running', context: { pc: '0x402000', sp: '0x8000' }, entrypoint: { routine: '0x400000', parameter: '0x0' } }
	] } },
	'threads returns id, state, register context, and entrypoint');

const readUnmapped = roundtrip({ id: 27, type: 'memRead', params: { address: '0x50000', size: 16 } });
assert.strictEqual(readUnmapped.ok, false, 'a read of unmapped memory is rejected');
assert.ok(/not mapped/.test(readUnmapped.error), 'the unmapped read address is reported');

const writeUnmapped = roundtrip({ id: 28, type: 'memWrite', params: { address: '0x50000', bytes: 'deadbeef' } });
assert.strictEqual(writeUnmapped.ok, false, 'a write to unmapped memory is rejected');
assert.ok(/not mapped/.test(writeUnmapped.error), 'the unmapped write address is reported');

const firstModules = roundtrip({ id: 29, type: 'modules' });
assert.strictEqual(firstModules.result.cached, false, 'the first modules call enumerates');
assert.deepStrictEqual(firstModules.result.modules, [
	{ name: 'app', base: '0x400000', size: 0x20000, path: '/data/app/app' },
	{ name: 'libc.so', base: '0x7f0000000000', size: 0x100000, path: '/system/lib/libc.so' }
], 'modules returns the mapped module details');

assert.strictEqual(roundtrip({ id: 30, type: 'modules' }).result.cached, true, 'a second modules call serves the cache');
roundtrip({ id: 31, type: 'eval', params: { source: '0' } });
assert.strictEqual(roundtrip({ id: 32, type: 'modules' }).result.cached, false, 'running code drops the cached modules');
assert.strictEqual(modulesEnumerated, 2, 'the cache avoided redundant module enumeration');

assert.deepStrictEqual(roundtrip({ id: 33, type: 'exports', params: { module: 'app' } }),
	{ id: 33, ok: true, result: { module: 'app', exports: [
		{ type: 'function', name: 'main', address: '0x401000' },
		{ type: 'variable', name: 'global', address: '0x402000' }
	] } },
	'exports lists the module exports');

const exportsMissing = roundtrip({ id: 34, type: 'exports', params: { module: 'nope' } });
assert.strictEqual(exportsMissing.error, 'no module named nope', 'an unknown module is rejected');

const exportsNoName = roundtrip({ id: 35, type: 'exports', params: {} });
assert.strictEqual(exportsNoName.error, 'exports requires a module name', 'a missing module name is rejected');

assert.deepStrictEqual(roundtrip({ id: 36, type: 'imports', params: { module: 'app' } }),
	{ id: 36, ok: true, result: { module: 'app', imports: [
		{ type: 'function', name: 'printf', module: 'libc.so', address: '0x7f0000001000' }
	] } },
	'imports lists the module imports');

const importsNoName = roundtrip({ id: 37, type: 'imports', params: {} });
assert.strictEqual(importsNoName.error, 'imports requires a module name', 'imports needs a module name');

assert.deepStrictEqual(roundtrip({ id: 38, type: 'symbols', params: { module: 'app' } }),
	{ id: 38, ok: true, result: { module: 'app', symbols: [
		{ isGlobal: true, type: 'function', name: 'start', address: '0x401000', size: 32 }
	] } },
	'symbols lists the module symbols');

const symbolsMissing = roundtrip({ id: 39, type: 'symbols', params: { module: 'nope' } });
assert.strictEqual(symbolsMissing.error, 'no module named nope', 'symbols rejects an unknown module');

assert.deepStrictEqual(roundtrip({ id: 40, type: 'bpSet', params: { address: '0x1000' } }),
	{ id: 40, ok: true, result: { address: '0x1000', bp: 1 } },
	'bpSet attaches a breakpoint and returns its id');

const bpDup = roundtrip({ id: 41, type: 'bpSet', params: { address: '0x1000' } });
assert.strictEqual(bpDup.error, 'a breakpoint already exists at 0x1000', 'a duplicate breakpoint is rejected');

assert.deepStrictEqual(roundtrip({ id: 42, type: 'bpList' }),
	{ id: 42, ok: true, result: { breakpoints: [{ bp: 1, address: '0x1000' }] } },
	'bpList reports the breakpoints that are set');

// fire the captured onEnter: it emits the async Fr.bp event, then parks on
// its own per-thread channel until the typed continue from the recv mock frees it.
const beforeHit = sent.length;
continueDeliverId = 500;
interceptors.get('0x1000').onEnter.call({ context: { pc: new FakePtr(0x1000), sp: new FakePtr(0x7000) } });
const hit = sent[beforeHit].message;
assert.strictEqual(hit.type, 'Fr.bp', 'a hit emits a Fr.bp event');
assert.strictEqual(hit.bp, 1, 'the hit event names the breakpoint id under bp, not id');
assert.strictEqual(hit.id, undefined, 'the hit event has no top-level id so it is never read as a reply');
assert.strictEqual(hit.address, '0x1000', 'the hit event names the address');
assert.strictEqual(hit.threadId, 4242, 'the hit event carries the thread id');
assert.deepStrictEqual(hit.context, {}, 'the hit event carries an empty context placeholder');
assert.deepStrictEqual(sent[beforeHit + 1].message, { id: 500, ok: true, result: { resumed: true, threadId: 4242 } },
	'the parked thread answers the continue that released it, naming its thread');

assert.deepStrictEqual(roundtrip({ id: 43, type: 'bpParked' }),
	{ id: 43, ok: true, result: { parked: [], recent: null } },
	'bpParked reports no parked threads once the hit has been continued');

assert.deepStrictEqual(roundtrip({ id: 44, type: 'bpRemove', params: { address: '0x1000' } }),
	{ id: 44, ok: true, result: { address: '0x1000', removed: 1 } },
	'bpRemove detaches a breakpoint');

const bpGone = roundtrip({ id: 45, type: 'bpRemove', params: { address: '0x1000' } });
assert.strictEqual(bpGone.error, 'no breakpoint at 0x1000', 'removing a missing breakpoint is rejected');

roundtrip({ id: 46, type: 'bpSet', params: { address: '0x2000' } });
roundtrip({ id: 47, type: 'bpSet', params: { address: '0x3000' } });
assert.deepStrictEqual(roundtrip({ id: 48, type: 'bpRemove', params: { address: '*' } }),
	{ id: 48, ok: true, result: { removed: 2 } },
	'bpRemove * clears every breakpoint');
assert.deepStrictEqual(roundtrip({ id: 49, type: 'bpList' }),
	{ id: 49, ok: true, result: { breakpoints: [] } },
	'bpList is empty after removing every breakpoint');

const regBp = roundtrip({ id: 50, type: 'bpSet', params: { address: '0x4000' } }).result.bp;

const regReadMiss = roundtrip({ id: 51, type: 'regRead', params: { threadId: 4242 } });
assert.strictEqual(regReadMiss.error, 'thread 4242 is not stopped at a breakpoint',
	'a register read of a thread that is not stopped is rejected');

parkedActions.push({ id: 52, type: 'regRead', params: { threadId: 4242 } });
parkedActions.push({ id: 53, type: 'regWrite', params: { threadId: 4242, register: 'pc', value: '0xdead' } });
parkedActions.push({ id: 531, type: 'regWrite', params: { threadId: 4242, register: '\u0016pc', value: '0xbeef' } });
parkedActions.push({ id: 54, type: 'regWrite', params: { threadId: 4242, register: 'nope', value: '0x1' } });
parkedActions.push({ id: 55, type: 'regRead', params: { threadId: 4242 } });
const beforeReg = sent.length;
continueDeliverId = 501;
interceptors.get('0x4000').onEnter.call({ context: { pc: new FakePtr(0x4000), sp: new FakePtr(0x9000) } });

assert.strictEqual(sent[beforeReg].message.type, 'Fr.bp', 'the register hit emits a Fr.bp event');
assert.deepStrictEqual(sent[beforeReg + 1].message,
	{ id: 52, ok: true, result: { threadId: 4242, bp: regBp, address: '0x4000' } },
	'regRead returns the stop identity of the parked thread');
assert.deepStrictEqual(sent[beforeReg + 2].message,
	{ id: 53, ok: true, result: { threadId: 4242, register: 'pc', value: '0xdead' } },
	'regWrite sets a register and echoes the new value');
assert.deepStrictEqual(sent[beforeReg + 3].message,
	{ id: 531, ok: true, result: { threadId: 4242, register: 'pc', value: '0xbeef' } },
	'regWrite strips a leading Ctrl-V from the register name');
assert.strictEqual(sent[beforeReg + 4].message.error, 'no register named nope',
	'a write to an unknown register is rejected');
assert.deepStrictEqual(sent[beforeReg + 5].message,
	{ id: 55, ok: true, result: { threadId: 4242, bp: regBp, address: '0x4000' } },
	'a later read returns the parked thread info');
assert.deepStrictEqual(sent[beforeReg + 6].message, { id: 501, ok: true, result: { resumed: true, threadId: 4242 } },
	'the parked thread is freed after the register window');

const regReadGone = roundtrip({ id: 56, type: 'regRead', params: { threadId: 4242 } });
assert.strictEqual(regReadGone.error, 'thread 4242 is not stopped at a breakpoint',
	'a continued thread is no longer stopped');

const regNoThread = roundtrip({ id: 57, type: 'regRead', params: {} });
assert.strictEqual(regNoThread.error, 'a register request requires a thread id', 'a register read needs a thread id');

const regNoValue = roundtrip({ id: 58, type: 'regWrite', params: { threadId: 4242, register: 'pc' } });
assert.strictEqual(regNoValue.error, 'thread 4242 is not stopped at a breakpoint',
	'a register write to a thread that is not stopped is rejected');

roundtrip({ id: 59, type: 'bpRemove', params: { address: '0x4000' } });

// hardware watchpoints armed on every thread, access reported as Fr.wp event.
assert.deepStrictEqual(roundtrip({ id: 60, type: 'wpSet', params: { address: '0x8000', size: 8, conditions: 'w' } }),
	{ id: 60, ok: true, result: { slot: 0, address: '0x8000', size: 8, conditions: 'w' } },
	'wpSet arms a watchpoint and returns its slot');
assert.strictEqual(hwWatch.size, 1, 'the watchpoint occupies a debug slot');

const wpDup = roundtrip({ id: 61, type: 'wpSet', params: { address: '0x8000' } });
assert.strictEqual(wpDup.error, 'a watchpoint already exists at 0x8000', 'a duplicate watchpoint is rejected');

const wpBadCond = roundtrip({ id: 62, type: 'wpSet', params: { address: '0x9000', conditions: 'x' } });
assert.strictEqual(wpBadCond.error, 'watchpoint conditions must be r, w, or rw', 'invalid conditions are rejected');

assert.deepStrictEqual(roundtrip({ id: 63, type: 'wpList' }),
	{ id: 63, ok: true, result: { watchpoints: [{ slot: 0, address: '0x8000', size: 8, conditions: 'w' }] } },
	'wpList reports the watchpoints that are set');

// fire captured exception handler with a watchpoint trap, emits Fr.wp and disarms.
assert.ok(typeof exceptionHandler === 'function', 'the first watchpoint installs the exception handler');
const beforeWp = sent.length;
const handled = exceptionHandler({ type: 'breakpoint', memory: { operation: 'write', address: new FakePtr(0x8000) },
	context: { pc: new FakePtr(0x4444), sp: new FakePtr(0x9000) } });
assert.strictEqual(handled, true, 'the watchpoint trap is handled');
const wpHit = sent[beforeWp].message;
assert.strictEqual(wpHit.type, 'Fr.wp', 'a watchpoint access emits a Fr.wp event');
assert.strictEqual(wpHit.id, undefined, 'the wp event has no top-level id so it is never read as a reply');
assert.strictEqual(wpHit.threadId, 4242, 'the wp event carries the faulting thread id');
assert.strictEqual(wpHit.operation, 'write', 'the wp event names the access operation');
assert.strictEqual(wpHit.address, '0x8000', 'the wp event names the accessed address');
assert.strictEqual(wpHit.pc, '0x4444', 'the wp event carries the program counter');
assert.deepStrictEqual(wpHit.context, { pc: '0x4444', sp: '0x9000' }, 'the wp event carries the register context');
assert.deepStrictEqual(roundtrip({ id: 64, type: 'wpList' }), { id: 64, ok: true, result: { watchpoints: [] } },
	'a watchpoint is one-shot, disarmed after it fires');
assert.strictEqual(hwWatch.size, 0, 'the debug slot is released after the hit');

// an unrelated exception, and a debug trap outside any watched range, are passed through.
roundtrip({ id: 65, type: 'wpSet', params: { address: '0xa000' } });
assert.strictEqual(exceptionHandler({ type: 'access-violation', context: { pc: new FakePtr(0x5555) } }), false,
	'a non-debug exception is not claimed');
assert.strictEqual(exceptionHandler({ type: 'breakpoint', memory: { operation: 'read', address: new FakePtr(0xdead) },
	context: { pc: new FakePtr(0x6666) } }), false, 'a debug trap outside any watched range is not claimed');

assert.deepStrictEqual(roundtrip({ id: 66, type: 'wpRemove', params: { address: '0xa000' } }),
	{ id: 66, ok: true, result: { address: '0xa000', removed: 1 } }, 'wpRemove disarms a watchpoint');
const wpMissing = roundtrip({ id: 67, type: 'wpRemove', params: { address: '0xa000' } });
assert.strictEqual(wpMissing.error, 'no watchpoint at 0xa000', 'removing a missing watchpoint is rejected');

roundtrip({ id: 68, type: 'wpSet', params: { address: '0xb000' } });
roundtrip({ id: 69, type: 'wpSet', params: { address: '0xc000' } });
assert.deepStrictEqual(roundtrip({ id: 70, type: 'wpRemove', params: { address: '*' } }),
	{ id: 70, ok: true, result: { removed: 2 } }, 'wpRemove * clears every watchpoint');

// host caps usable slots, so slots:1 leaves no room for a second wp.
roundtrip({ id: 71, type: 'wpSet', params: { address: '0xd000', slots: 1 } });
const wpFull = roundtrip({ id: 72, type: 'wpSet', params: { address: '0xe000', slots: 1 } });
assert.strictEqual(wpFull.error, 'no free hardware watchpoint slot', 'the host slot cap is honored');
roundtrip({ id: 73, type: 'wpRemove', params: { address: '*' } });

// java vm check
assert.deepStrictEqual(roundtrip({ id: 80, type: 'isJavaAvailable' }),
	{ id: 80, ok: true, result: { available: true } }, 'isJavaAvailable reports the bridge is reachable');

// classloader enumeration
const ldrs = roundtrip({ id: 81, type: 'loaderList' });
assert.strictEqual(ldrs.ok, true, 'loaderList returns ok');
assert.strictEqual(ldrs.result.loaders.length, 2, 'loaderList returns two loaders');
assert.strictEqual(ldrs.result.loaders[0].id, 1, 'the first loader gets id 1');
assert.strictEqual(ldrs.result.loaders[1].id, 2, 'the second loader gets id 2');
assert.notStrictEqual(ldrs.result.loaders[0].id, ldrs.result.loaders[1].id, 'loader ids are unique');
assert.strictEqual(ldrs.result.loaders[0].type, 'dalvik.system.PathClassLoader', 'the loader type is reported');

// class enumeration
assert.deepStrictEqual(roundtrip({ id: 82, type: 'classList' }),
	{ id: 82, ok: true, result: { classes: [{ name: 're.frida.minapp.MainActivity' },
		{ name: 're.frida.minapp.SampleModel' }, { name: 're.frida.minapp.DerivedModel' },
		{ name: 're.frida.minapp.NativeLib' }, { name: 're.frida.minapp.ReflectionTarget' },
		{ name: 're.frida.minapp.BaseModel' }, { name: 'java.lang.String' },
		{ name: 'java.lang.System' }, { name: 'android.app.Activity' },
		{ name: 'android.os.Bundle' }, { name: 'kotlin.Metadata' }],
		total: 11, truncated: false } },
	'classList returns all loaded classes');

// prefix filter
assert.deepStrictEqual(roundtrip({ id: 83, type: 'classList', params: { prefix: 're.frida.minapp' } }),
	{ id: 83, ok: true, result: { classes: [{ name: 're.frida.minapp.MainActivity' },
		{ name: 're.frida.minapp.SampleModel' }, { name: 're.frida.minapp.DerivedModel' },
		{ name: 're.frida.minapp.NativeLib' }, { name: 're.frida.minapp.ReflectionTarget' },
		{ name: 're.frida.minapp.BaseModel' }],
		total: 6, truncated: false } },
	'classList with prefix returns matching classes only');

// negative prefix — kotlin prefix now matches kotlin.Metadata
assert.deepStrictEqual(roundtrip({ id: 84, type: 'classList', params: { prefix: 'kotlin.' } }),
	{ id: 84, ok: true, result: { classes: [{ name: 'kotlin.Metadata' }], total: 1, truncated: false } },
	'classList with kotlin prefix returns the Metadata annotation class');

// simple name match (matches class name after last dot)
assert.deepStrictEqual(roundtrip({ id: 86, type: 'classList', params: { prefix: 'MainActivity' } }),
	{ id: 86, ok: true, result: { classes: [{ name: 're.frida.minapp.MainActivity' }],
		total: 1, truncated: false } },
	'a simple name prefix matches the class name');

// batch cap
assert.deepStrictEqual(roundtrip({ id: 85, type: 'classList', params: { max: 2 } }),
	{ id: 85, ok: true, result: { classes: [{ name: 're.frida.minapp.MainActivity' },
		{ name: 're.frida.minapp.SampleModel' }],
		total: 2, truncated: true } },
	'the max cap truncates and marks the result');

const classListAll = { classes: [{ name: 're.frida.minapp.MainActivity' },
	{ name: 're.frida.minapp.SampleModel' }, { name: 're.frida.minapp.DerivedModel' },
	{ name: 're.frida.minapp.NativeLib' }, { name: 're.frida.minapp.ReflectionTarget' },
	{ name: 're.frida.minapp.BaseModel' }, { name: 'java.lang.String' },
	{ name: 'java.lang.System' }, { name: 'android.app.Activity' },
	{ name: 'android.os.Bundle' }, { name: 'kotlin.Metadata' }],
	total: 11, truncated: false };
assert.deepStrictEqual(roundtrip({ id: 87, type: 'classList', params: {} }),
	{ id: 87, ok: true, result: classListAll },
	'classList with max omitted has no cap');
assert.deepStrictEqual(roundtrip({ id: 88, type: 'classList', params: { max: 0 } }),
	{ id: 88, ok: true, result: classListAll },
	'classList with max 0 has no cap');
assert.deepStrictEqual(roundtrip({ id: 89, type: 'classList', params: { max: 512 } }),
	{ id: 89, ok: true, result: classListAll },
	'classList with max 512 returns the full mock set');

// class describe -- basic
const desc = roundtrip({ id: 90, type: 'classDescribe', params: { className: 're.frida.minapp.SampleModel' } });
assert.strictEqual(desc.ok, true, 'classDescribe returns ok');
assert.strictEqual(desc.result.name, 're.frida.minapp.SampleModel', 'class name is correct');
assert.strictEqual(desc.result.super, 'java.lang.Object', 'superclass is Object');
assert.strictEqual(desc.result.interfaces.length, 0, 'no interfaces');
assert.strictEqual(desc.result.flags.indexOf('public') >= 0, true, 'class is public');
assert.strictEqual(desc.result.fields.length, 5, 'SampleModel has 5 fields');
assert.strictEqual(desc.result.fields[0].name, 'id', 'first field name');
assert.strictEqual(desc.result.fields[0].type, 'int', 'first field type');
assert.strictEqual(desc.result.fields[0].flags.indexOf('private') >= 0, true, 'field modifier');
assert.strictEqual(desc.result.methods.length, 4, 'SampleModel has 4 declared methods');
assert.strictEqual(desc.result.methods[0].name, 'getId', 'first method name');
assert.strictEqual(desc.result.methods[0].returnType, 'int', 'return type');
assert.strictEqual(desc.result.methods[0].isNative, false, 'not native');
assert.strictEqual(desc.result.constructors.length, 3, 'SampleModel has 3 constructors');
assert.strictEqual(desc.result.constructors[0].parameterTypes.length, 0, 'default ctor');

// class describe -- inheritance
const descDerived = roundtrip({ id: 91, type: 'classDescribe', params: { className: 're.frida.minapp.DerivedModel' } });
assert.strictEqual(descDerived.ok, true, 'DerivedModel describe ok');
assert.strictEqual(descDerived.result.super, 're.frida.minapp.BaseModel', 'superclass is BaseModel');
assert.strictEqual(descDerived.result.interfaces.length, 1, 'one interface');
assert.strictEqual(descDerived.result.interfaces[0], 're.frida.minapp.ModelInterface', 'interface name');
assert.strictEqual(descDerived.result.methods.length, 5, 'DerivedModel has 5 declared methods');
assert.strictEqual(descDerived.result.constructors.length, 2, 'DerivedModel has 2 constructors');

// class describe -- native methods
const descNative = roundtrip({ id: 92, type: 'classDescribe', params: { className: 're.frida.minapp.NativeLib' } });
assert.strictEqual(descNative.ok, true, 'NativeLib describe ok');
assert.strictEqual(descNative.result.methods[0].isNative, true, 'method is native');
assert.strictEqual(descNative.result.methods[1].isNative, true, 'method is native');

// class describe -- all modifier flags
const descRefl = roundtrip({ id: 93, type: 'classDescribe', params: { className: 're.frida.minapp.ReflectionTarget' } });
assert.strictEqual(descRefl.ok, true, 'ReflectionTarget describe ok');
assert.strictEqual(descRefl.result.fields.length, 4, '4 fields');
assert.strictEqual(descRefl.result.fields[0].flags.indexOf('public') >= 0, true, 'public field');
assert.strictEqual(descRefl.result.fields[1].flags.indexOf('private') >= 0, true, 'private field');
assert.strictEqual(descRefl.result.fields[2].flags.indexOf('protected') >= 0, true, 'protected field');
assert.strictEqual(descRefl.result.fields[3].modifiers, 0, 'package-private has no modifiers');

// class describe -- class not found
const descNotFound = roundtrip({ id: 94, type: 'classDescribe', params: { className: 'com.nonexistent.Foo' } });
assert.strictEqual(descNotFound.ok, false, 'missing class returns error');

// class describe -- missing className
const descNoName = roundtrip({ id: 95, type: 'classDescribe', params: {} });
assert.strictEqual(descNoName.ok, false, 'missing className returns error');

// class load monitor -- enable
const monOn = roundtrip({ id: 100, type: 'classLoadMonitor', params: { enable: true } });
assert.strictEqual(monOn.ok, true, 'classLoadMonitor enable returns ok');
assert.strictEqual(monOn.result.enabled, true, 'classLoadMonitor reports enabled');

// class load monitor -- already enabled, no re-snapshot
const monRe = roundtrip({ id: 101, type: 'classLoadMonitor', params: { enable: true } });
assert.strictEqual(monRe.ok, true, 'classLoadMonitor re-enable returns ok');

// newly loaded classes -- before any load, returns empty
const nlcEmpty = roundtrip({ id: 102, type: 'newlyLoadedClasses', params: {} });
assert.strictEqual(nlcEmpty.ok, true, 'newlyLoadedClasses returns ok');
assert.deepStrictEqual(nlcEmpty.result.classes, [], 'new classes list is initially empty');
assert.strictEqual(nlcEmpty.result.count, 0, 'count is 0 when empty');

// simulate class load via the mock loadClass hook on the ClassLoader class
const testLoader = makeClassLoaderObj();

testLoader.loadClass.overload().implementation = function (name) {
	if (name !== 'com.dynamic.TestClass') {
		return this.loadClass(name);
	}
	return null;
};

testLoader.loadClass('com.dynamic.TestClass');
const nlcAfter = roundtrip({ id: 103, type: 'newlyLoadedClasses', params: {} });
assert.strictEqual(nlcAfter.ok, true, 'newlyLoadedClasses returns ok after load');

// class load monitor -- disable
const monOff = roundtrip({ id: 104, type: 'classLoadMonitor', params: { enable: false } });
assert.strictEqual(monOff.ok, true, 'classLoadMonitor disable returns ok');
assert.strictEqual(monOff.result.enabled, false, 'classLoadMonitor reports disabled');

// newly loaded classes -- after disable, returns empty
const nlcAfterOff = roundtrip({ id: 105, type: 'newlyLoadedClasses', params: {} });
assert.strictEqual(nlcAfterOff.ok, true, 'newlyLoadedClasses returns ok after monitor off');
assert.strictEqual(nlcAfterOff.result.count, 0, 'count is 0 after monitor stopped');

// class load monitor -- missing enable boolean
const monBad = roundtrip({ id: 106, type: 'classLoadMonitor', params: {} });
assert.strictEqual(monBad.ok, false, 'classLoadMonitor without enable boolean returns error');

// RegisterNatives -- enable
const rnOn = roundtrip({ id: 110, type: 'rnSet', params: { enable: true } });
assert.strictEqual(rnOn.ok, true, 'rnSet enable returns ok');
assert.strictEqual(rnOn.result.enabled, true, 'rnSet reports enabled');
const rnHookAddrs = Array.from(interceptors.keys());
assert.strictEqual(rnHookAddrs.length, 1, 'rnSet hooks a single RegisterNatives address');
const tableBase = 0xcafe0000;
const rn215 = '0x' + (tableBase + 215 * 8 + 0x100).toString(16);
const rn218 = '0x' + (tableBase + 218 * 8 + 0x100).toString(16);
assert.deepStrictEqual(rnHookAddrs, [rn215], 'rnSet hooks JNI table index 215, not MonitorExit at 218');
assert.ok(rnHookAddrs.indexOf(rn218) < 0, 'rnSet does not hook MonitorExit');

// RegisterNatives -- re-enable
const rnRe = roundtrip({ id: 111, type: 'rnSet', params: { enable: true } });
assert.strictEqual(rnRe.ok, true, 'rnSet re-enable returns ok');

// RegisterNatives -- list (empty until invoked)
const rnList1 = roundtrip({ id: 112, type: 'rnList', params: {} });
assert.strictEqual(rnList1.ok, true, 'rnList returns ok');
assert.deepStrictEqual(rnList1.result.invocations, [], 'rn list is initially empty');

// RegisterNatives -- disable
const rnOff = roundtrip({ id: 113, type: 'rnSet', params: { enable: false } });
assert.strictEqual(rnOff.ok, true, 'rnSet disable returns ok');
assert.strictEqual(rnOff.result.enabled, false, 'rnSet reports disabled');

// RegisterNatives -- missing enable bool
const rnBad = roundtrip({ id: 114, type: 'rnSet', params: {} });
assert.strictEqual(rnBad.ok, false, 'rnSet without enable boolean returns error');

// rnSet onEnter hook, fire captured interceptor, verify rnList and async event.
const rnOn2 = roundtrip({ id: 115, type: 'rnSet', params: { enable: true } });
assert.strictEqual(rnOn2.ok, true, 'rnSet re-enable for onEnter test');
const rnIntKey = Array.from(interceptors.keys()).pop();
const rnMethodsPtr = new FakePtr(0xf000);
const envCallsBeforeHit = javaGetEnvCalls;
const sentBeforeHit = sent.length;
// simulate a RN call: 2 methods, valid ptrs
fireRn(rnIntKey, [
	/* JNIEnv* */ new FakePtr(0xaaa0),
	/* jclass */  new FakePtr(0xbbb0),
	/* methods */ rnMethodsPtr,
	/* nMethods*/ new FakePtr(2)
]);
assert.strictEqual(sent.length, sentBeforeHit, 'interceptor callbacks do not send');
assert.strictEqual(javaGetEnvCalls, envCallsBeforeHit, 'interceptor callbacks do not call Java.vm.getEnv');

const beforeRnHit = sent.length;
const rnList2 = roundtrip({ id: 116, type: 'rnList', params: {} });
assert.strictEqual(rnList2.ok, true, 'rnList after invocation returns ok');
assert.strictEqual(rnList2.result.invocations.length, 1, 'rnList has one entry after invocation');
assert.strictEqual(rnList2.result.count, 1, 'rnList count matches');
assert.strictEqual(rnList2.result.invocations[0].className, 'com.example.TestClass', 'entry class name is correct');
assert.strictEqual(rnList2.result.invocations[0].methods[0].name, 'nativeMethod', 'entry method name is correct');
const rnHitEvt = sent.slice(beforeRnHit).find(function (s) {
	return s.message && s.message.type === 'Fr.rn';
});
assert.ok(rnHitEvt, 'rnList flush emits Fr.rn');
assert.strictEqual(rnHitEvt.message.className, 'com.example.TestClass', 'rn event carries the class name');
assert.strictEqual(rnHitEvt.message.methods.length, 2, 'rn event carries the methods array');

// depth guard — a nested invocation on the same thread is counted once
const nestedOuter = {};
interceptors.get(rnIntKey).onEnter.call(nestedOuter, [new FakePtr(0xaaa0), new FakePtr(0xbbb0), rnMethodsPtr, new FakePtr(2)]);
interceptors.get(rnIntKey).onEnter.call({}, [new FakePtr(0xaaa0), new FakePtr(0xbbb0), rnMethodsPtr, new FakePtr(2)]);
interceptors.get(rnIntKey).onLeave.call(nestedOuter);
const rnListNested = roundtrip({ id: 1160, type: 'rnList', params: {} });
assert.strictEqual(rnListNested.result.count, 1, 'nested RegisterNatives is recorded once');

// rnList drains the buffer each call
const rnListDrain = roundtrip({ id: 117, type: 'rnList', params: {} });
assert.deepStrictEqual(rnListDrain.result.invocations, [], 'rnList drains after read');

// rnSet warnings — oversized nMethods
roundtrip({ id: 118, type: 'rnSet', params: { enable: true } });
const rnIntKey2 = Array.from(interceptors.keys()).pop();
const sentBeforeWarn1 = sent.length;
fireRn(rnIntKey2, [0, 0, rnMethodsPtr, new FakePtr(99999)]); // exceeds RN_MAX_METHODS
assert.strictEqual(sent.length, sentBeforeWarn1, 'oversized nMethods does not send from the interceptor');
const beforeRnWarn1 = sent.length;
roundtrip({ id: 119, type: 'rnList', params: {} });
const oversized = sent.slice(beforeRnWarn1).find(function (s) {
	return s.message && s.message.type === 'Fr.rn.warn';
});
assert.ok(oversized, 'oversized nMethods emits a warning on flush');
assert.ok(/exceeds cap/.test(oversized.message.message), 'warning names the cap');

// rnSet warnings — null methodsPtr (test before buffer fills)
roundtrip({ id: 120, type: 'rnSet', params: { enable: true } });
const rnIntKey3 = Array.from(interceptors.keys()).pop();
const sentBeforeNull = sent.length;
fireRn(rnIntKey3, [0, 0, new FakePtr(0), new FakePtr(1)]);
assert.strictEqual(sent.length, sentBeforeNull, 'null methodsPtr does not send from the interceptor');
const beforeNullPtr = sent.length;
roundtrip({ id: 1201, type: 'rnList', params: {} });
const nullPtrWarn = sent.slice(beforeNullPtr).find(function (s) {
	return s.message && s.message.type === 'Fr.rn.warn';
});
assert.ok(nullPtrWarn, 'null methodsPtr emits a warning on flush');
assert.strictEqual(nullPtrWarn.message.type, 'Fr.rn.warn', 'null methodsPtr warning type is correct');

// rnSet warnings — buffer full
roundtrip({ id: 121, type: 'rnSet', params: { enable: true } });
const rnIntKey4 = Array.from(interceptors.keys()).pop();
// fill the buffer to RN_BUFFER_MAX (512) entries
for (let i = 0; i < 512; i++) {
	fireRn(rnIntKey4, [0, 0, new FakePtr(0xf000 + i), new FakePtr(1)]);
}
// next invocation should warn
const sentBeforeBufFull = sent.length;
fireRn(rnIntKey4, [0, 0, new FakePtr(0xffff), new FakePtr(1)]);
assert.strictEqual(sent.length, sentBeforeBufFull, 'buffer-full interceptor does not send');
const beforeRnBufFull = sent.length;
roundtrip({ id: 1211, type: 'rnList', params: {} });
const bufFullWarn = sent.slice(beforeRnBufFull).find(function (s) {
	return s.message && s.message.type === 'Fr.rn.warn';
});
assert.ok(bufFullWarn, 'buffer full emits a warning');
assert.ok(/rnBuffer full/.test(bufFullWarn.message.message), 'warning names the buffer limit');

// rnSet disable with entries, clears buffer
const rnLocked = roundtrip({ id: 122, type: 'rnSet', params: { enable: false } });
assert.strictEqual(rnLocked.ok, true, 'rnSet disable after invocation returns ok');
assert.strictEqual(rnLocked.result.enabled, false, 'rnSet reports disabled after clearing');
assert.strictEqual(rnLocked.result.cleared, 0, 'rnSet reports the number of entries cleared');
const rnListDrained = roundtrip({ id: 123, type: 'rnList', params: {} });
assert.deepStrictEqual(rnListDrained.result.invocations, [], 'rnList empty after disable+clear');

// queued entries, cleared on disable without a prior list
roundtrip({ id: 124, type: 'rnSet', params: { enable: true } });
const rnIntKey5 = Array.from(interceptors.keys()).pop();
for (let i = 0; i < 3; i++) {
	fireRn(rnIntKey5, [0, 0, new FakePtr(0xf000 + i), new FakePtr(1)]);
}
const rnClearQueued = roundtrip({ id: 125, type: 'rnSet', params: { enable: false } });
assert.strictEqual(rnClearQueued.result.cleared, 3, 'disable clears queued startup captures');

// flag modules
const fm = roundtrip({ id: 130, type: 'flagModules', params: {} });
assert.strictEqual(fm.ok, true, 'flagModules returns ok');
assert.ok(Array.isArray(fm.result.modules), 'flagModules has modules array');
assert.strictEqual(fm.result.modules.length, fm.result.count, 'count matches modules array length');
assert.strictEqual(fm.result.modules[0].name, 'app', 'first module name');
assert.strictEqual(typeof fm.result.modules[0].base, 'string', 'module base is a hex string');
assert.strictEqual(typeof fm.result.modules[0].size, 'number', 'module size is a number');

// newlyLoadedClasses — add dynamic class and verify diff
roundtrip({ id: 131, type: 'classLoadMonitor', params: { enable: true } });
dynamicJavaClasses.push('com.dynamic.NewClass');
const nlc = roundtrip({ id: 132, type: 'newlyLoadedClasses', params: {} });
assert.strictEqual(nlc.ok, true, 'newlyLoadedClasses returns ok');
assert.strictEqual(nlc.result.count, 1, 'one new class detected');
assert.strictEqual(nlc.result.classes[0], 'com.dynamic.NewClass', 'the new class name is correct');
dynamicJavaClasses.length = 0;
const nlcAgain = roundtrip({ id: 133, type: 'newlyLoadedClasses', params: {} });
assert.strictEqual(nlcAgain.result.count, 0, 'second call with no new classes returns empty');

// classDescribe with Kotlin metadata
const descKt = roundtrip({ id: 134, type: 'classDescribe', params: { className: 're.frida.minapp.SampleModel' } });
assert.strictEqual(descKt.ok, true, 'classDescribe with kotlin metadata returns ok');
assert.ok(descKt.result.kotlin !== undefined, 'kotlin key is present');
assert.strictEqual(descKt.result.kotlin.k, 1, 'kotlin kind');
assert.strictEqual(descKt.result.kotlin.mv.length, 2, 'kotlin metadata version array length');
assert.strictEqual(descKt.result.kotlin.mv[0], 1, 'mv major');
assert.strictEqual(descKt.result.kotlin.mv[1], 4, 'mv minor');
assert.strictEqual(descKt.result.kotlin.xi, 0, 'kotlin xi flag');
assert.deepStrictEqual(descKt.result.kotlin.bv, [1, 0], 'kotlin bytecode version');
assert.strictEqual(descKt.result.kotlin.data1Len, 4, 'kotlin data1 length');
assert.strictEqual(descKt.result.kotlin.data2Len, 2, 'kotlin data2 length');

// classDescribe without Kotlin metadata — a class not in kotlinAnnotatedClasses
const descNoKt = roundtrip({ id: 135, type: 'classDescribe', params: { className: 're.frida.minapp.MainActivity' } });
assert.strictEqual(descNoKt.ok, true, 'classDescribe without kotlin returns ok');
assert.strictEqual(descNoKt.result.kotlin, undefined, 'no kotlin key for non-kotlin class');

// classLoadMonitor — Java not available
const javaAvailOrig = sandbox.Java.available;
sandbox.Java.available = false;
const monNoJava = roundtrip({ id: 136, type: 'classLoadMonitor', params: { enable: true } });
assert.strictEqual(monNoJava.ok, true, 'classLoadMonitor without Java returns gracefully');
assert.strictEqual(monNoJava.result.javaUnavailable, true, 'javaUnavailable flag is set');

// rnSet — Java not available
const rnNoJava = roundtrip({ id: 137, type: 'rnSet', params: { enable: true } });
assert.strictEqual(rnNoJava.ok, true, 'rnSet without Java returns gracefully');
assert.strictEqual(rnNoJava.result.javaUnavailable, true, 'javaUnavailable flag is set');

// rnSet — libart scan without Java
const findModOrig = sandbox.Process.findModuleByName;
const libartRn = new FakePtr(0x7a110000);
sandbox.Process.findModuleByName = function (name) {
	if (name !== 'libart.so') {
		return null;
	}
	return {
		name: 'libart.so',
		enumerateSymbols: function () {
			return [
				{ name: 'art::CheckJNI::RegisterNatives', address: new FakePtr(0x7a11dead) },
				{ name: 'art::JNI::RegisterNatives', address: libartRn }
			];
		}
	};
};
const rnLibart = roundtrip({ id: 138, type: 'rnSet', params: { enable: true } });
assert.strictEqual(rnLibart.ok, true, 'rnSet with libart symbols returns ok');
assert.strictEqual(rnLibart.result.enabled, true, 'libart scan arms RegisterNatives without Java');
assert.ok(interceptors.has(libartRn.toString()), 'libart RegisterNatives address is hooked');
assert.ok(!interceptors.has('0x7a11dead'), 'CheckJNI RegisterNatives is not hooked');
roundtrip({ id: 139, type: 'rnSet', params: { enable: false } });
sandbox.Process.findModuleByName = findModOrig;
sandbox.Java.available = javaAvailOrig;

console.log('ok - agent script protocol');
