'use strict';

const RZ_FRIDA_AGENT_VERSION = 1;

let rangeCache = null;
let moduleCache = null;

const breakpoints = new Map();
let nextBreakpointId = 1;
const stopped = new Map(); // tid -> {bp, address, context} per thread parked at a bp, in stop order.
const watchpoints = new Map(); // slot -> {slot, address, size, conditions} per hardware watchpoint.
const HW_WATCHPOINT_SLOTS = 4; // default, host can override it per req
let exceptionHandlerReady = false;
const loaderIds = new Map(); // classloader wrapper -> stable integer id
const idToLoader = new Map(); // stable integer id -> classloader wrapper
let nextLoaderId = 1;
let loadClassMonitorEnabled = false;
const seenLoadedClasses = new Set();
let rnHookEnabled = false;
let rnInterceptor = null;
const rnBuffer = [];
const RN_BUFFER_MAX = 512;

function isJavaAvailable() {
  return { available: typeof Java !== 'undefined' && Java.available };
}

function loaderList() {
  if (typeof Java === 'undefined' || !Java.available) {
    throw new Error('Java VM is not available');
  }
  const loaders = [];
  Java.performNow(function () {
    const list = Java.enumerateClassLoadersSync();
    for (let i = 0; i < list.length; i++) {
      const l = list[i];
      if (!loaderIds.has(l)) {
        var newId = nextLoaderId++;
        loaderIds.set(l, newId);
        idToLoader.set(newId, l);
      }
      loaders.push({ id: loaderIds.get(l), type: l.getClass().getName(), toString: l.toString() });
    }
  });
  return { loaders: loaders };
}

function classList(params) {
  if (typeof Java === 'undefined' || !Java.available) {
    throw new Error('Java VM is not available');
  }
  const prefix = typeof params.prefix === 'string' ? params.prefix : '';
  const max = (typeof params.max === 'number' && params.max > 0) ? params.max : 512;
  const classes = [];
  Java.performNow(function () {
    const all = Java.enumerateLoadedClassesSync();
    for (let i = 0; i < all.length && classes.length < max; i++) {
      var s = all[i];
      if (prefix !== '' && s.indexOf(prefix) !== 0) {
        var dot = s.lastIndexOf('.');
        if (dot < 0 || s.substring(dot + 1) !== prefix) {
          continue;
        }
      }
      classes.push({ name: s });
    }
  });
  return { classes: classes, total: classes.length, truncated: classes.length >= max };
}

function mapModifiers(modifiers) {
  var flags = [];
  if (modifiers & Java.ACC_PUBLIC) flags.push('public');
  if (modifiers & Java.ACC_PRIVATE) flags.push('private');
  if (modifiers & Java.ACC_PROTECTED) flags.push('protected');
  if (modifiers & Java.ACC_STATIC) flags.push('static');
  if (modifiers & Java.ACC_FINAL) flags.push('final');
  if (modifiers & Java.ACC_NATIVE) flags.push('native');
  if (modifiers & Java.ACC_ABSTRACT) flags.push('abstract');
  if (modifiers & Java.ACC_SYNCHRONIZED) flags.push('synchronized');
  if (modifiers & Java.ACC_STRICT) flags.push('strictfp');
  if (modifiers & Java.ACC_SYNTHETIC) flags.push('synthetic');
  return flags;
}

function paramNames(paramTypes) {
  return paramTypes.map(function (t) { return String(t.getName()); });
}

function classDescribe(params) {
  if (typeof Java === 'undefined' || !Java.available) {
    throw new Error('Java VM is not available');
  }
  var className = params.className;
  if (typeof className !== 'string' || className === '') {
    throw new Error('className must be a non-empty string');
  }
  var loader = null;
  if (typeof params.loaderId === 'number' && params.loaderId > 0) {
    loader = idToLoader.get(params.loaderId);
    if (typeof loader === 'undefined') {
      throw new Error('no classloader with id ' + params.loaderId);
    }
  }
  var result = {};
  Java.performNow(function () {
    var factory = Java.ClassFactory.get(loader);
    var wrapper = factory.use(className);

    if (wrapper === null || typeof wrapper === 'undefined') {
      throw new Error('class ' + className + ' not found');
    }

    var klass = wrapper.class;
    result.name = String(klass.getName());
    result.modifiers = klass.getModifiers();
    result.flags = mapModifiers(result.modifiers);

    var sup = klass.getSuperclass();
    result.super = (sup !== null) ? String(sup.getName()) : null;
    result.interfaces = klass.getInterfaces().map(function (i) { return String(i.getName()); });

    var checkKotlin = function () { return null; };
    try {
      var metaKlass = Java.use('kotlin.Metadata');
      if (metaKlass && metaKlass.class) {
        checkKotlin = function () { return klass.getAnnotation(metaKlass.class); };
      }
    } catch (_) { }

    var meta = checkKotlin();
    if (meta !== null) {
      result.kotlin = { k: meta.k(), mv: [meta.mv()[0], meta.mv()[1]] };
    }

    result.fields = klass.getDeclaredFields().map(function (fd) {
      return {
        name: String(fd.getName()),
        type: String(fd.getType().getName()),
        modifiers: fd.getModifiers(),
        flags: mapModifiers(fd.getModifiers())
      };
    });

    result.methods = klass.getDeclaredMethods().map(function (md) {
      var mod = md.getModifiers();
      return {
        name: String(md.getName()),
        returnType: String(md.getReturnType().getName()),
        parameterTypes: paramNames(md.getParameterTypes()),
        modifiers: mod,
        flags: mapModifiers(mod),
        isNative: (mod & Java.ACC_NATIVE) !== 0
      };
    });

    result.constructors = klass.getDeclaredConstructors().map(function (ct) {
      var cmod = ct.getModifiers();
      return {
        parameterTypes: paramNames(ct.getParameterTypes()),
        modifiers: cmod,
        flags: mapModifiers(cmod)
      };
    });
  });
  result.loader = (typeof params.loaderId === 'number' && params.loaderId > 0) ? params.loaderId : 0;
  return result;
}

function agentInfo() {
  return {
    version: RZ_FRIDA_AGENT_VERSION,
    platform: Process.platform,
    arch: Process.arch,
    pointerSize: Process.pointerSize
  };
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] < 0x10 ? '0' : '') + bytes[i].toString(16);
  }
  return out;
}

function fromHex(text) {
  if (/^0x/i.test(text)) {
    text = text.slice(2);
  }
  if (text.length % 2 !== 0) {
    throw new Error('hex input must have an even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(text)) {
    throw new Error('hex input has a non-hex character');
  }
  const out = [];
  for (let i = 0; i < text.length; i += 2) {
    out.push(parseInt(text.slice(i, i + 2), 16));
  }
  return out;
}

function requireAddress(params) {
  if (params.address === undefined || params.address === null || params.address === '') {
    throw new Error('a memory request requires an address');
  }
  return ptr(params.address);
}

function memRead(params) {
  const addr = requireAddress(params);
  const size = params.size;
  if (typeof size !== 'number' || !Number.isInteger(size) || size <= 0) {
    throw new Error('memRead requires a positive integer size');
  }
  requireMapped(addr);
  const buffer = addr.readByteArray(size);
  if (buffer === null) {
    throw new Error('cannot read ' + size + ' bytes at ' + addr);
  }
  const hex = toHex(buffer);
  return { address: addr.toString(), size: hex.length / 2, bytes: hex };
}

function memWrite(params) {
  const addr = requireAddress(params);
  if (typeof params.bytes !== 'string' || params.bytes.length === 0) {
    throw new Error('memWrite requires a hex byte string');
  }
  const bytes = fromHex(params.bytes);
  requireMapped(addr);
  addr.writeByteArray(bytes);
  return { address: addr.toString(), size: bytes.length };
}

function enumerateRanges() {
  return Process.enumerateRanges('---').map(function (range) {
    const out = { base: range.base.toString(), size: range.size, protection: range.protection };
    if (range.file) {
      out.file = { path: range.file.path, offset: range.file.offset, size: range.file.size };
    }
    return out;
  });
}

function rangeContaining(addr) {
  for (let i = 0; i < rangeCache.length; i++) {
    const range = rangeCache[i];
    const base = ptr(range.base);
    if (addr.compare(base) >= 0 && addr.compare(base.add(range.size)) < 0) {
      return range;
    }
  }
  return null;
}

// reject an addr no mapped range backs, refreshing once in case target
// mapped it after cache was filled.
function requireMapped(addr) {
  if (rangeCache === null) {
    rangeCache = enumerateRanges();
  }
  if (rangeContaining(addr) === null) {
    rangeCache = enumerateRanges();
    if (rangeContaining(addr) === null) {
      throw new Error('address ' + addr + ' is not mapped in the target');
    }
  }
}

function ranges(params) {
  const refresh = !!(params && params.refresh);
  const cached = !refresh && rangeCache !== null;
  if (!cached) {
    rangeCache = enumerateRanges();
  }
  return { ranges: rangeCache, cached: cached };
}

// json copy of a frida detail object, every NativePointer becomes a hex str.
function serialize(value) {
  return JSON.parse(JSON.stringify(value));
}

function enumerateThreads() {
  return Process.enumerateThreads().map(function (thread) {
    const out = { id: thread.id, state: thread.state, context: serialize(thread.context) };
    if (thread.entrypoint) {
      out.entrypoint = serialize(thread.entrypoint);
    }
    return out;
  });
}

function threads() {
  return { threads: enumerateThreads() };
}

function enumerateModules() {
  return Process.enumerateModules().map(function (module) {
    return { name: module.name, base: module.base.toString(), size: module.size, path: module.path };
  });
}

function modules(params) {
  const refresh = !!(params && params.refresh);
  const cached = !refresh && moduleCache !== null;
  if (!cached) {
    moduleCache = enumerateModules();
  }
  return { modules: moduleCache, cached: cached };
}

function moduleByName(name) {
  const list = Process.enumerateModules();
  for (let i = 0; i < list.length; i++) {
    if (list[i].name === name) {
      return list[i];
    }
  }
  throw new Error('no module named ' + name);
}

function moduleListing(type, params) {
  if (typeof params.module !== 'string' || params.module.length === 0) {
    throw new Error(type + ' requires a module name');
  }
  const module = moduleByName(params.module);
  const items = (type === 'imports') ? module.enumerateImports()
    : (type === 'symbols') ? module.enumerateSymbols()
      : module.enumerateExports();
  const result = { module: params.module };
  result[type] = serialize(items || []);
  return result;
}

function bpSet(params) {
  const addr = requireAddress(params);
  const key = addr.toString();
  if (breakpoints.has(key)) {
    throw new Error('a breakpoint already exists at ' + key);
  }
  const id = nextBreakpointId++;
  const listener = Interceptor.attach(addr, {
    onEnter() {
      try {
        const tid = Process.getCurrentThreadId();
        // serialized context can exceed the arm64 send limit, so keeping it empty.
        send({ type: 'frida.bp', bp: id, address: key, threadId: tid, context: {} });
        stopped.set(tid, { bp: id, address: key, context: this.context });
        let resumed = false;
        do {
          const op = recv('frida.cont.' + tid, function (message) {
            resumed = true;
            if (typeof message.id === 'number') {
              send({ id: message.id, ok: true, result: { resumed: true, threadId: tid } });
            }
          });
          op.wait();
        } while (!resumed);
        stopped.delete(tid);
      } catch (e) {
        send({ type: 'frida.bp.err', error: e && e.message ? e.message : String(e) });
      }
    }
  });
  breakpoints.set(key, { id: id, address: key, listener: listener });
  return { address: key, bp: id };
}

function bpList() {
  const list = [];
  breakpoints.forEach(function (bp) {
    list.push({ bp: bp.id, address: bp.address });
  });
  return { breakpoints: list };
}

function bpRemove(params) {
  if (params && params.address === '*') {
    const removed = breakpoints.size;
    breakpoints.forEach(function (bp) {
      bp.listener.detach();
    });
    breakpoints.clear();
    return { removed: removed };
  }
  const addr = requireAddress(params);
  const key = addr.toString();
  const bp = breakpoints.get(key);
  if (!bp) {
    throw new Error('no breakpoint at ' + key);
  }
  bp.listener.detach();
  breakpoints.delete(key);
  return { address: key, removed: 1 };
}

function parkedThreads() {
  const ids = Array.from(stopped.keys());
  return { parked: ids, recent: ids.length ? ids[ids.length - 1] : null };
}

// resolve the bp stop a reg req targets, or fail.
function stoppedThread(params) {
  if (params.threadId === undefined || params.threadId === null) {
    throw new Error('a register request requires a thread id');
  }
  const entry = stopped.get(params.threadId);
  if (!entry) {
    throw new Error('thread ' + params.threadId + ' is not stopped at a breakpoint');
  }
  return entry;
}

function regRead(params) {
  const entry = stoppedThread(params);
  return { threadId: params.threadId, bp: entry.bp, address: entry.address };
}

function regWrite(params) {
  const entry = stoppedThread(params);
  if (typeof params.register !== 'string' || params.register.length === 0) {
    throw new Error('a register write requires a register name');
  }
  if (params.value === undefined || params.value === null || params.value === '') {
    throw new Error('a register write requires a value');
  }
  // own property check only, so inherited names arent written.
  const snapshot = serialize(entry.context);
  if (!Object.prototype.hasOwnProperty.call(snapshot, params.register)) {
    throw new Error('no register named ' + params.register);
  }
  entry.context[params.register] = ptr(params.value);
  return { threadId: params.threadId, register: params.register, value: entry.context[params.register].toString() };
}

function watchpointConditions(value) {
  if (value === undefined || value === null || value === '') {
    return 'rw';
  }
  if (value !== 'r' && value !== 'w' && value !== 'rw') {
    throw new Error('watchpoint conditions must be r, w, or rw');
  }
  return value;
}

// arm/clear a debug slot on every current thread, tolerating refusing ones.
function eachThreadWatchpoint(slot, addr, size, conditions) {
  const threads = Process.enumerateThreads();
  let applied = 0;
  for (let i = 0; i < threads.length; i++) {
    try {
      if (addr === null) {
        threads[i].unsetHardwareWatchpoint(slot);
      } else {
        threads[i].setHardwareWatchpoint(slot, addr, size, conditions);
      }
      applied++;
    } catch (e) {
      // skip it, wont take slot.
    }
  }
  return applied;
}

function clearWatchpoint(wp) {
  eachThreadWatchpoint(wp.slot, null, 0, null);
  watchpoints.delete(wp.slot);
}

// install process wide handler lazily on the first watchpoint.
function ensureExceptionHandler() {
  if (exceptionHandlerReady) {
    return;
  }
  Process.setExceptionHandler(function (details) {
    if (watchpoints.size === 0) {
      return false;
    }
    if (details.type !== 'breakpoint' && details.type !== 'single-step') {
      return false;
    }
    // frida may report accessed addr in memory.address or at top level.
    var mem = details.memory || null;
    var accessAddr = (mem && mem.address) ? mem.address : (details.address || null);
    var fired = null;
    if (accessAddr) {
      watchpoints.forEach(function (wp) {
        const base = ptr(wp.address);
        if (!fired && accessAddr.compare(base) >= 0 && accessAddr.compare(base.add(wp.size)) < 0) {
          fired = wp;
        }
      });
      if (!fired) {
        // a trap on addr we arent watching is not ours.
        return false;
      }
    }
    const watched = [];
    watchpoints.forEach(function (wp) {
      watched.push({ slot: wp.slot, address: wp.address, size: wp.size, conditions: wp.conditions });
    });
    // disarm before resuming so instruction doesnt retrap.
    if (fired) {
      clearWatchpoint(fired);
    } else {
      watchpoints.forEach(function (wp) { eachThreadWatchpoint(wp.slot, null, 0, null); });
      watchpoints.clear();
    }
    let wpCtx = {};
	try {
		wpCtx = serialize(details.context);
	} catch (_) {
		/* keep empty */
	}
    send({
      type: 'frida.wp',
      threadId: Process.getCurrentThreadId(),
      pc: details.context && details.context.pc ? details.context.pc.toString() : null,
      operation: details.memory ? details.memory.operation : null,
      address: accessAddr ? accessAddr.toString() : null,
      watched: watched,
      context: wpCtx
    });
    return true;
  });
  exceptionHandlerReady = true;
}

function wpSet(params) {
  const addr = requireAddress(params);
  const key = addr.toString();
  let found = false;
  watchpoints.forEach(function (wp) { if (wp.address === key) { found = true; } });
  if (found) {
    throw new Error('a watchpoint already exists at ' + key);
  }
  let size = params.size;
  if (size === undefined || size === null) {
    size = Process.pointerSize;
  }
  if (typeof size !== 'number' || !Number.isInteger(size) || size <= 0) {
    throw new Error('a watchpoint requires a positive integer size');
  }
  const conditions = watchpointConditions(params.conditions);
  const maxSlots = (typeof params.slots === 'number' && params.slots > 0) ? params.slots : HW_WATCHPOINT_SLOTS;
  let slot = -1;
  for (let i = 0; i < maxSlots; i++) {
    if (!watchpoints.has(i)) {
      slot = i;
      break;
    }
  }
  if (slot === -1) {
    throw new Error('no free hardware watchpoint slot');
  }
  ensureExceptionHandler();
  if (eachThreadWatchpoint(slot, addr, size, conditions) === 0) {
    throw new Error('no thread accepted the hardware watchpoint');
  }
  watchpoints.set(slot, { slot: slot, address: key, size: size, conditions: conditions });
  return { slot: slot, address: key, size: size, conditions: conditions };
}

function wpList() {
  const list = [];
  watchpoints.forEach(function (wp) {
    list.push({ slot: wp.slot, address: wp.address, size: wp.size, conditions: wp.conditions });
  });
  return { watchpoints: list };
}

function wpRemove(params) {
  if (params && params.address === '*') {
    const removed = watchpoints.size;
    watchpoints.forEach(function (wp) { eachThreadWatchpoint(wp.slot, null, 0, null); });
    watchpoints.clear();
    return { removed: removed };
  }
  const addr = requireAddress(params);
  const key = addr.toString();
  let found = null;
  watchpoints.forEach(function (wp) { if (wp.address === key) { found = wp; } });
  if (!found) {
    throw new Error('no watchpoint at ' + key);
  }
  clearWatchpoint(found);
  return { address: key, removed: 1 };
}

function classLoadMonitor(params) {
    if (typeof Java === 'undefined' || !Java.available) {
        throw new Error('Java VM is not available');
    }
    if (typeof params.enable !== 'boolean') {
        throw new Error('classLoadMonitor requires an enable boolean');
    }
    if (params.enable) {
        if (loadClassMonitorEnabled) {
            return { enabled: true };
        }
        Java.performNow(function () {
            var current = Java.enumerateLoadedClassesSync();
            for (var i = 0; i < current.length; i++) {
                seenLoadedClasses.add(current[i]);
            }
        });
        loadClassMonitorEnabled = true;
        return { enabled: true };
    }
    loadClassMonitorEnabled = false;
    seenLoadedClasses.clear();
    return { enabled: false };
}

function newlyLoadedClassesGet() {
    if (!loadClassMonitorEnabled) {
        return { classes: [], count: 0, monitor: false };
    }
    var result = [];
    Java.performNow(function () {
        var current = Java.enumerateLoadedClassesSync();
        for (var i = 0; i < current.length; i++) {
            if (!seenLoadedClasses.has(current[i])) {
                seenLoadedClasses.add(current[i]);
                result.push(current[i]);
            }
        }
    });
    return { classes: result, count: result.length };
}

function rnSet(params) {
    if (typeof Java === 'undefined' || !Java.available) {
        throw new Error('Java VM is not available');
    }
    if (typeof params.enable !== 'boolean') {
        throw new Error('rnSet requires an enable boolean');
    }
    if (params.enable) {
        if (rnHookEnabled) {
            return { enabled: true, invocations: rnBuffer.length };
        }
        // libart symbols
        let rnAddr = null;
        try {
            const art = Process.findModuleByName('libart.so');
            if (art) {
                const symbols = art.enumerateSymbols();
                for (let i = 0; i < symbols.length; i++) {
                    const name = symbols[i].name;
                    if (name.indexOf('art') >= 0 &&
                        name.indexOf('JNI') >= 0 &&
                        name.indexOf('RegisterNatives') >= 0 &&
                        name.indexOf('CheckJNI') < 0) {
                        rnAddr = symbols[i].address;
                        break;
                    }
                }
            }
        } catch (e) {
            /* not available */
        }
        // fallback
        if (!rnAddr) {
            const env = Java.vm.getEnv();
            const tablePtr = env.handle.readPointer();
            if (!tablePtr.isNull()) {
                const ps = Process.pointerSize;
                rnAddr = tablePtr.add(218 * ps).readPointer(); // RN is fcn 215 & 3 reserved slots
                if (rnAddr.isNull()) {
                    rnAddr = tablePtr.add(215 * ps).readPointer();
                }
            }
        }
        if (!rnAddr || rnAddr.isNull()) {
            throw new Error('RegisterNatives entry not found; is this an Android target with libart.so?');
        }
        rnInterceptor = Interceptor.attach(rnAddr, {
            onEnter: function (args) {
                try {
                    const nMethods = args[3].toInt32();
                    if (nMethods <= 0 || nMethods > 16384) {
                        return;
                    }
                    if (rnBuffer.length >= RN_BUFFER_MAX) {
                        return;
                    }
                    const methodsPtr = args[2];
                    if (methodsPtr.isNull()) {
                        return;
                    }
                    const clsName = env.getClassName(args[1]);
                    const methods = [];
                    for (let i = 0; i < nMethods; i++) {
                        const off = i * 3 * ps;
                        const namePtr = methodsPtr.add(off).readPointer();
                        if (namePtr.isNull()) {
                            continue;
                        }
                        const sigPtr = methodsPtr.add(off + ps).readPointer();
                        const fnPtr = methodsPtr.add(off + 2 * ps).readPointer();
                        if (fnPtr.isNull()) {
                            continue;
                        }
                        methods.push({
                            name: namePtr.readUtf8String(),
                            signature: sigPtr.isNull() ? '' : sigPtr.readUtf8String(),
                            address: fnPtr.toString()
                        });
                    }
                    if (methods.length) {
                        const entry = { className: clsName, methods: methods };
                        rnBuffer.push(entry);
                        send({ type: 'frida.rn', className: clsName, methods: methods });
                    }
                } catch (e) {
                    /* ignore malformed invocations */
                }
            }
        });
        rnHookEnabled = true;
        return { enabled: true, invocations: rnBuffer.length };
    }
    rnHookEnabled = false;
    if (rnInterceptor) {
        rnInterceptor.detach();
        rnInterceptor = null;
    }
    const remaining = rnBuffer.length;
    rnBuffer.length = 0;
    return { enabled: false, cleared: remaining };
}

function rnList() {
    const entries = rnBuffer.slice();
    rnBuffer.length = 0;
    return { invocations: entries, count: entries.length };
}

function flagModules() {
    const modules = Process.enumerateModules();
    const result = [];
    for (let i = 0; i < modules.length; i++) {
        const m = modules[i];
        result.push({ name: m.name, base: m.base.toString(), size: m.size });
    }
    return { modules: result, count: result.length };
}

function invalidateCaches() {
  rangeCache = null;
  moduleCache = null;
}

function handleRequest(request) {
  const type = request.type;
  const params = request.params || {};
  switch (type) {
    case 'ping':
      return agentInfo();
    case 'eval': {
      const source = params.source;
      if (typeof source !== 'string') {
        throw new Error('eval requires a string source');
      }
      // keeps snippet global
      const value = (0, eval)(source);
      invalidateCaches();
      return { value: value === undefined ? null : value, type: typeof value };
    }
    case 'memRead':
      return memRead(params);
    case 'memWrite':
      return memWrite(params);
    case 'ranges':
      return ranges(params);
    case 'threads':
      return threads();
    case 'modules':
      return modules(params);
    case 'exports':
      return moduleListing('exports', params);
    case 'imports':
      return moduleListing('imports', params);
    case 'symbols':
      return moduleListing('symbols', params);
    case 'bpSet':
      return bpSet(params);
    case 'bpList':
      return bpList();
    case 'bpRemove':
      return bpRemove(params);
    case 'bpParked':
      return parkedThreads();
    case 'regRead':
      return regRead(params);
    case 'regWrite':
      return regWrite(params);
    case 'wpSet':
      return wpSet(params);
    case 'wpList':
      return wpList();
    case 'wpRemove':
      return wpRemove(params);
    case 'isJavaAvailable':
      return isJavaAvailable();
    case 'loaderList':
      return loaderList();
    case 'classList':
      return classList(params);
    case 'classDescribe':
      return classDescribe(params);
    case 'classLoadMonitor':
      return classLoadMonitor(params);
    case 'newlyLoadedClasses':
      return newlyLoadedClassesGet();
    case 'rnSet':
      return rnSet(params);
    case 'rnList':
      return rnList();
    case 'flagModules':
      return flagModules();
    default:
      throw new Error('unknown request type: ' + String(type));
  }
}

function onRequest(request) {
  recv(onRequest);
  const id = request ? request.id : undefined;
  if (typeof id !== 'number') {
    return;
  }
  try {
    send({ id: id, ok: true, result: handleRequest(request) });
  } catch (e) {
    send({ id: id, ok: false, error: (e && e.message) ? e.message : String(e) });
  }
}

recv(onRequest);

rpc.exports = {
  ping() {
    return agentInfo();
  }
};

send({ type: 'agent.ready', version: RZ_FRIDA_AGENT_VERSION });
