let wasm;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_2.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    }
}

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_2.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}
/**
 * @param {PublicKey} delegating_pk
 * @param {Uint8Array} plaintext
 * @returns {[Capsule, Uint8Array]}
 */
export function encrypt(delegating_pk, plaintext) {
    _assertClass(delegating_pk, PublicKey);
    const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.encrypt(delegating_pk.__wbg_ptr, ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {SecretKey} delegating_sk
 * @param {Capsule} capsule
 * @param {Uint8Array} ciphertext
 * @returns {Uint8Array}
 */
export function decryptOriginal(delegating_sk, capsule, ciphertext) {
    _assertClass(delegating_sk, SecretKey);
    _assertClass(capsule, Capsule);
    const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decryptOriginal(delegating_sk.__wbg_ptr, capsule.__wbg_ptr, ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * @param {SecretKey} receiving_sk
 * @param {PublicKey} delegating_pk
 * @param {Capsule} capsule
 * @param {VerifiedCapsuleFrag[]} vcfrags
 * @param {Uint8Array} ciphertext
 * @returns {Uint8Array}
 */
export function decryptReencrypted(receiving_sk, delegating_pk, capsule, vcfrags, ciphertext) {
    _assertClass(receiving_sk, SecretKey);
    _assertClass(delegating_pk, PublicKey);
    _assertClass(capsule, Capsule);
    const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decryptReencrypted(receiving_sk.__wbg_ptr, delegating_pk.__wbg_ptr, capsule.__wbg_ptr, vcfrags, ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * @param {SecretKey} delegating_sk
 * @param {PublicKey} receiving_pk
 * @param {Signer} signer
 * @param {number} threshold
 * @param {number} shares
 * @param {boolean} sign_delegating_key
 * @param {boolean} sign_receiving_key
 * @returns {VerifiedKeyFrag[]}
 */
export function generateKFrags(delegating_sk, receiving_pk, signer, threshold, shares, sign_delegating_key, sign_receiving_key) {
    _assertClass(delegating_sk, SecretKey);
    _assertClass(receiving_pk, PublicKey);
    _assertClass(signer, Signer);
    const ret = wasm.generateKFrags(delegating_sk.__wbg_ptr, receiving_pk.__wbg_ptr, signer.__wbg_ptr, threshold, shares, sign_delegating_key, sign_receiving_key);
    return ret;
}

/**
 * @param {Capsule} capsule
 * @param {VerifiedKeyFrag} kfrag
 * @returns {VerifiedCapsuleFrag}
 */
export function reencrypt(capsule, kfrag) {
    _assertClass(capsule, Capsule);
    _assertClass(kfrag, VerifiedKeyFrag);
    const ret = wasm.reencrypt(capsule.__wbg_ptr, kfrag.__wbg_ptr);
    return VerifiedCapsuleFrag.__wrap(ret);
}

const CapsuleFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_capsule_free(ptr >>> 0, 1));

export class Capsule {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Capsule.prototype);
        obj.__wbg_ptr = ptr;
        CapsuleFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CapsuleFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_capsule_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    __getClassname() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.capsule___getClassname(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.capsule_toBytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    toBytesSimple() {
        const ret = wasm.capsule_toBytesSimple(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {Capsule}
     */
    static fromBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.capsule_fromBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Capsule.__wrap(ret[0]);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.capsule_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {Capsule} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, Capsule);
        const ret = wasm.capsule_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) Capsule.prototype[Symbol.dispose] = Capsule.prototype.free;

const CapsuleFragFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_capsulefrag_free(ptr >>> 0, 1));

export class CapsuleFrag {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(CapsuleFrag.prototype);
        obj.__wbg_ptr = ptr;
        CapsuleFragFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CapsuleFragFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_capsulefrag_free(ptr, 0);
    }
    /**
     * @param {Capsule} capsule
     * @param {PublicKey} verifying_pk
     * @param {PublicKey} delegating_pk
     * @param {PublicKey} receiving_pk
     * @returns {VerifiedCapsuleFrag}
     */
    verify(capsule, verifying_pk, delegating_pk, receiving_pk) {
        const ptr = this.__destroy_into_raw();
        _assertClass(capsule, Capsule);
        _assertClass(verifying_pk, PublicKey);
        _assertClass(delegating_pk, PublicKey);
        _assertClass(receiving_pk, PublicKey);
        const ret = wasm.capsulefrag_verify(ptr, capsule.__wbg_ptr, verifying_pk.__wbg_ptr, delegating_pk.__wbg_ptr, receiving_pk.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return VerifiedCapsuleFrag.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.capsulefrag_toBytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    toBytesSimple() {
        const ret = wasm.capsulefrag_toBytesSimple(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {CapsuleFrag}
     */
    static fromBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.capsulefrag_fromBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return CapsuleFrag.__wrap(ret[0]);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.capsulefrag_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {VerifiedCapsuleFrag}
     */
    skipVerification() {
        const ret = wasm.capsulefrag_skipVerification(this.__wbg_ptr);
        return VerifiedCapsuleFrag.__wrap(ret);
    }
    /**
     * @param {CapsuleFrag} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, CapsuleFrag);
        const ret = wasm.capsulefrag_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) CapsuleFrag.prototype[Symbol.dispose] = CapsuleFrag.prototype.free;

const CurvePointFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_curvepoint_free(ptr >>> 0, 1));

export class CurvePoint {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(CurvePoint.prototype);
        obj.__wbg_ptr = ptr;
        CurvePointFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CurvePointFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_curvepoint_free(ptr, 0);
    }
    /**
     * @returns {[Uint8Array, Uint8Array] | undefined}
     */
    coordinates() {
        const ret = wasm.curvepoint_coordinates(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) CurvePoint.prototype[Symbol.dispose] = CurvePoint.prototype.free;

const KeyFragFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keyfrag_free(ptr >>> 0, 1));

export class KeyFrag {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(KeyFrag.prototype);
        obj.__wbg_ptr = ptr;
        KeyFragFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        KeyFragFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keyfrag_free(ptr, 0);
    }
    /**
     * @param {PublicKey} verifying_pk
     * @param {PublicKey | null} delegating_pk
     * @param {PublicKey | null} receiving_pk
     * @returns {VerifiedKeyFrag}
     */
    verify(verifying_pk, delegating_pk, receiving_pk) {
        const ptr = this.__destroy_into_raw();
        _assertClass(verifying_pk, PublicKey);
        const ret = wasm.keyfrag_verify(ptr, verifying_pk.__wbg_ptr, delegating_pk, receiving_pk);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return VerifiedKeyFrag.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.keyfrag_toBytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {KeyFrag}
     */
    static fromBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.keyfrag_fromBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return KeyFrag.__wrap(ret[0]);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.keyfrag_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {VerifiedKeyFrag}
     */
    skipVerification() {
        const ret = wasm.keyfrag_skipVerification(this.__wbg_ptr);
        return VerifiedKeyFrag.__wrap(ret);
    }
    /**
     * @param {KeyFrag} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, KeyFrag);
        const ret = wasm.keyfrag_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) KeyFrag.prototype[Symbol.dispose] = KeyFrag.prototype.free;

const ParametersFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_parameters_free(ptr >>> 0, 1));

export class Parameters {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ParametersFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_parameters_free(ptr, 0);
    }
    constructor() {
        const ret = wasm.parameters_new();
        this.__wbg_ptr = ret >>> 0;
        ParametersFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @returns {CurvePoint}
     */
    get u() {
        const ret = wasm.parameters_u(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
}
if (Symbol.dispose) Parameters.prototype[Symbol.dispose] = Parameters.prototype.free;

const PublicKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_publickey_free(ptr >>> 0, 1));

export class PublicKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(PublicKey.prototype);
        obj.__wbg_ptr = ptr;
        PublicKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PublicKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_publickey_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    __getClassname() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.publickey___getClassname(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    toCompressedBytes() {
        const ret = wasm.publickey_toCompressedBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {PublicKey}
     */
    static fromCompressedBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.publickey_fromCompressedBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PublicKey.__wrap(ret[0]);
    }
    /**
     * @param {Uint8Array} prehash
     * @param {RecoverableSignature} signature
     * @returns {PublicKey}
     */
    static recoverFromPrehash(prehash, signature) {
        const ptr0 = passArray8ToWasm0(prehash, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        _assertClass(signature, RecoverableSignature);
        const ret = wasm.publickey_recoverFromPrehash(ptr0, len0, signature.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return PublicKey.__wrap(ret[0]);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.publickey_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {PublicKey} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, PublicKey);
        const ret = wasm.publickey_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) PublicKey.prototype[Symbol.dispose] = PublicKey.prototype.free;

const RecoverableSignatureFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_recoverablesignature_free(ptr >>> 0, 1));

export class RecoverableSignature {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(RecoverableSignature.prototype);
        obj.__wbg_ptr = ptr;
        RecoverableSignatureFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RecoverableSignatureFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_recoverablesignature_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    toBEBytes() {
        const ret = wasm.recoverablesignature_toBEBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {RecoverableSignature}
     */
    static fromBEBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.recoverablesignature_fromBEBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return RecoverableSignature.__wrap(ret[0]);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.recoverablesignature_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {RecoverableSignature} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, RecoverableSignature);
        const ret = wasm.recoverablesignature_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) RecoverableSignature.prototype[Symbol.dispose] = RecoverableSignature.prototype.free;

const ReencryptionEvidenceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_reencryptionevidence_free(ptr >>> 0, 1));

export class ReencryptionEvidence {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ReencryptionEvidence.prototype);
        obj.__wbg_ptr = ptr;
        ReencryptionEvidenceFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ReencryptionEvidenceFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_reencryptionevidence_free(ptr, 0);
    }
    /**
     * @param {Capsule} capsule
     * @param {VerifiedCapsuleFrag} vcfrag
     * @param {PublicKey} verifying_pk
     * @param {PublicKey} delegating_pk
     * @param {PublicKey} receiving_pk
     */
    constructor(capsule, vcfrag, verifying_pk, delegating_pk, receiving_pk) {
        _assertClass(capsule, Capsule);
        _assertClass(vcfrag, VerifiedCapsuleFrag);
        _assertClass(verifying_pk, PublicKey);
        _assertClass(delegating_pk, PublicKey);
        _assertClass(receiving_pk, PublicKey);
        const ret = wasm.reencryptionevidence_new(capsule.__wbg_ptr, vcfrag.__wbg_ptr, verifying_pk.__wbg_ptr, delegating_pk.__wbg_ptr, receiving_pk.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        ReencryptionEvidenceFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.reencryptionevidence_toBytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {ReencryptionEvidence}
     */
    static fromBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.reencryptionevidence_fromBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ReencryptionEvidence.__wrap(ret[0]);
    }
    /**
     * @returns {CurvePoint}
     */
    get e() {
        const ret = wasm.parameters_u(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get ez() {
        const ret = wasm.reencryptionevidence_ez(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get e1() {
        const ret = wasm.reencryptionevidence_e1(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get e1h() {
        const ret = wasm.reencryptionevidence_e1h(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get e2() {
        const ret = wasm.reencryptionevidence_e2(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get v() {
        const ret = wasm.reencryptionevidence_v(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get vz() {
        const ret = wasm.reencryptionevidence_vz(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get v1() {
        const ret = wasm.reencryptionevidence_v1(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get v1h() {
        const ret = wasm.reencryptionevidence_v1h(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get v2() {
        const ret = wasm.reencryptionevidence_v2(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get uz() {
        const ret = wasm.reencryptionevidence_uz(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get u1() {
        const ret = wasm.reencryptionevidence_u1(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get u1h() {
        const ret = wasm.reencryptionevidence_u1h(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    get u2() {
        const ret = wasm.reencryptionevidence_u2(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    get kfragValidityMessageHash() {
        const ret = wasm.reencryptionevidence_kfragValidityMessageHash(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {boolean}
     */
    get kfragSignatureV() {
        const ret = wasm.reencryptionevidence_kfragSignatureV(this.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) ReencryptionEvidence.prototype[Symbol.dispose] = ReencryptionEvidence.prototype.free;

const SecretKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secretkey_free(ptr >>> 0, 1));

export class SecretKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SecretKey.prototype);
        obj.__wbg_ptr = ptr;
        SecretKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SecretKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secretkey_free(ptr, 0);
    }
    /**
     * Generates a secret key using the default RNG and returns it.
     * @returns {SecretKey}
     */
    static random() {
        const ret = wasm.secretkey_random();
        return SecretKey.__wrap(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    toBEBytes() {
        const ret = wasm.secretkey_toBEBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {SecretKey}
     */
    static fromBEBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.secretkey_fromBEBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SecretKey.__wrap(ret[0]);
    }
    /**
     * Generates a secret key using the default RNG and returns it.
     * @returns {PublicKey}
     */
    publicKey() {
        const ret = wasm.secretkey_publicKey(this.__wbg_ptr);
        return PublicKey.__wrap(ret);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.secretkey_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {SecretKey} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, SecretKey);
        const ret = wasm.secretkey_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) SecretKey.prototype[Symbol.dispose] = SecretKey.prototype.free;

const SecretKeyFactoryFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secretkeyfactory_free(ptr >>> 0, 1));

export class SecretKeyFactory {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SecretKeyFactory.prototype);
        obj.__wbg_ptr = ptr;
        SecretKeyFactoryFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SecretKeyFactoryFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secretkeyfactory_free(ptr, 0);
    }
    /**
     * Generates a secret key factory using the default RNG and returns it.
     * @returns {SecretKeyFactory}
     */
    static random() {
        const ret = wasm.secretkeyfactory_random();
        return SecretKeyFactory.__wrap(ret);
    }
    /**
     * @returns {number}
     */
    static seedSize() {
        const ret = wasm.secretkeyfactory_seedSize();
        return ret >>> 0;
    }
    /**
     * @param {Uint8Array} seed
     * @returns {SecretKeyFactory}
     */
    static fromSecureRandomness(seed) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.secretkeyfactory_fromSecureRandomness(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SecretKeyFactory.__wrap(ret[0]);
    }
    /**
     * @param {Uint8Array} label
     * @returns {Uint8Array}
     */
    makeSecret(label) {
        const ptr0 = passArray8ToWasm0(label, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.secretkeyfactory_makeSecret(this.__wbg_ptr, ptr0, len0);
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * @param {Uint8Array} label
     * @returns {SecretKey}
     */
    makeKey(label) {
        const ptr0 = passArray8ToWasm0(label, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.secretkeyfactory_makeKey(this.__wbg_ptr, ptr0, len0);
        return SecretKey.__wrap(ret);
    }
    /**
     * @param {Uint8Array} label
     * @returns {SecretKeyFactory}
     */
    makeFactory(label) {
        const ptr0 = passArray8ToWasm0(label, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.secretkeyfactory_makeFactory(this.__wbg_ptr, ptr0, len0);
        return SecretKeyFactory.__wrap(ret);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.secretkeyfactory_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) SecretKeyFactory.prototype[Symbol.dispose] = SecretKeyFactory.prototype.free;

const SignatureFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_signature_free(ptr >>> 0, 1));

export class Signature {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Signature.prototype);
        obj.__wbg_ptr = ptr;
        SignatureFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SignatureFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signature_free(ptr, 0);
    }
    /**
     * @param {PublicKey} verifying_pk
     * @param {Uint8Array} message
     * @returns {boolean}
     */
    verify(verifying_pk, message) {
        _assertClass(verifying_pk, PublicKey);
        const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signature_verify(this.__wbg_ptr, verifying_pk.__wbg_ptr, ptr0, len0);
        return ret !== 0;
    }
    /**
     * @returns {Uint8Array}
     */
    toDerBytes() {
        const ret = wasm.signature_toDerBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {Signature}
     */
    static fromDerBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signature_fromDerBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Signature.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    toBEBytes() {
        const ret = wasm.signature_toBEBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} data
     * @returns {Signature}
     */
    static fromBEBytes(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signature_fromBEBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Signature.__wrap(ret[0]);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.signature_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {Signature} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, Signature);
        const ret = wasm.signature_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) Signature.prototype[Symbol.dispose] = Signature.prototype.free;

const SignerFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_signer_free(ptr >>> 0, 1));

export class Signer {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SignerFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signer_free(ptr, 0);
    }
    /**
     * @param {SecretKey} secret_key
     */
    constructor(secret_key) {
        _assertClass(secret_key, SecretKey);
        const ret = wasm.signer_new(secret_key.__wbg_ptr);
        this.__wbg_ptr = ret >>> 0;
        SignerFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array} message
     * @returns {Signature}
     */
    sign(message) {
        const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signer_sign(this.__wbg_ptr, ptr0, len0);
        return Signature.__wrap(ret);
    }
    /**
     * @returns {PublicKey}
     */
    verifyingKey() {
        const ret = wasm.signer_verifyingKey(this.__wbg_ptr);
        return PublicKey.__wrap(ret);
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.signer_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) Signer.prototype[Symbol.dispose] = Signer.prototype.free;

const VerifiedCapsuleFragFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_verifiedcapsulefrag_free(ptr >>> 0, 1));

export class VerifiedCapsuleFrag {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(VerifiedCapsuleFrag.prototype);
        obj.__wbg_ptr = ptr;
        VerifiedCapsuleFragFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        VerifiedCapsuleFragFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_verifiedcapsulefrag_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    __getClassname() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedcapsulefrag___getClassname(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {CapsuleFrag}
     */
    unverify() {
        const ret = wasm.capsulefrag_skipVerification(this.__wbg_ptr);
        return CapsuleFrag.__wrap(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.verifiedcapsulefrag_toBytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    toBytesSimple() {
        const ret = wasm.verifiedcapsulefrag_toBytesSimple(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedcapsulefrag_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {VerifiedCapsuleFrag} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, VerifiedCapsuleFrag);
        const ret = wasm.verifiedcapsulefrag_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) VerifiedCapsuleFrag.prototype[Symbol.dispose] = VerifiedCapsuleFrag.prototype.free;

const VerifiedKeyFragFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_verifiedkeyfrag_free(ptr >>> 0, 1));

export class VerifiedKeyFrag {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(VerifiedKeyFrag.prototype);
        obj.__wbg_ptr = ptr;
        VerifiedKeyFragFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        VerifiedKeyFragFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_verifiedkeyfrag_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    __getClassname() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedkeyfrag___getClassname(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.verifiedkeyfrag_toBytes(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.verifiedkeyfrag_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {VerifiedKeyFrag} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, VerifiedKeyFrag);
        const ret = wasm.verifiedkeyfrag_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) VerifiedKeyFrag.prototype[Symbol.dispose] = VerifiedKeyFrag.prototype.free;

const EXPECTED_RESPONSE_TYPES = new Set(['basic', 'cors', 'default']);

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                const validResponse = module.ok && EXPECTED_RESPONSE_TYPES.has(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_apply_55d63d092a912d6f = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = Reflect.apply(arg0, arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_13410aac570ffff7 = function() { return handleError(function (arg0, arg1) {
        const ret = arg0.call(arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_a5400b25a865cfd8 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = arg0.call(arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_capsule_new = function(arg0) {
        const ret = Capsule.__wrap(arg0);
        return ret;
    };
    imports.wbg.__wbg_crypto_574e78ad8b13b65f = function(arg0) {
        const ret = arg0.crypto;
        return ret;
    };
    imports.wbg.__wbg_getRandomValues_b8f5dbd5f3995a9e = function() { return handleError(function (arg0, arg1) {
        arg0.getRandomValues(arg1);
    }, arguments) };
    imports.wbg.__wbg_get_0da715ceaecea5c8 = function(arg0, arg1) {
        const ret = arg0[arg1 >>> 0];
        return ret;
    };
    imports.wbg.__wbg_get_458e874b43b18b25 = function() { return handleError(function (arg0, arg1) {
        const ret = Reflect.get(arg0, arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_isArray_030cce220591fb41 = function(arg0) {
        const ret = Array.isArray(arg0);
        return ret;
    };
    imports.wbg.__wbg_length_186546c51cd61acd = function(arg0) {
        const ret = arg0.length;
        return ret;
    };
    imports.wbg.__wbg_length_6bb7e81f9d7713e4 = function(arg0) {
        const ret = arg0.length;
        return ret;
    };
    imports.wbg.__wbg_msCrypto_a61aeb35a24c1329 = function(arg0) {
        const ret = arg0.msCrypto;
        return ret;
    };
    imports.wbg.__wbg_new_1f3a344cf3123716 = function() {
        const ret = new Array();
        return ret;
    };
    imports.wbg.__wbg_new_da9dc54c5db29dfa = function(arg0, arg1) {
        const ret = new Error(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_newfromslice_074c56947bd43469 = function(arg0, arg1) {
        const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_newnoargs_254190557c45b4ec = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_newwithlength_a167dcc7aaa3ba77 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_node_905d3e251edff8a2 = function(arg0) {
        const ret = arg0.node;
        return ret;
    };
    imports.wbg.__wbg_process_dc0fbacc7c1c06f7 = function(arg0) {
        const ret = arg0.process;
        return ret;
    };
    imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349 = function(arg0, arg1, arg2) {
        Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
    };
    imports.wbg.__wbg_push_330b2eb93e4e1212 = function(arg0, arg1) {
        const ret = arg0.push(arg1);
        return ret;
    };
    imports.wbg.__wbg_randomFillSync_ac0988aba3254290 = function() { return handleError(function (arg0, arg1) {
        arg0.randomFillSync(arg1);
    }, arguments) };
    imports.wbg.__wbg_require_60cc747a6bc5215a = function() { return handleError(function () {
        const ret = module.require;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_static_accessor_GLOBAL_8921f820c2ce3f12 = function() {
        const ret = typeof global === 'undefined' ? null : global;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_THIS_f0a4409105898184 = function() {
        const ret = typeof globalThis === 'undefined' ? null : globalThis;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_SELF_995b214ae681ff99 = function() {
        const ret = typeof self === 'undefined' ? null : self;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_WINDOW_cde3890479c675ea = function() {
        const ret = typeof window === 'undefined' ? null : window;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_subarray_70fd07feefe14294 = function(arg0, arg1, arg2) {
        const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_verifiedkeyfrag_new = function(arg0) {
        const ret = VerifiedKeyFrag.__wrap(arg0);
        return ret;
    };
    imports.wbg.__wbg_versions_c01dfd4722a88165 = function(arg0) {
        const ret = arg0.versions;
        return ret;
    };
    imports.wbg.__wbg_wbindgendebugstring_99ef257a3ddda34d = function(arg0, arg1) {
        const ret = debugString(arg1);
        const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbg_wbindgenisfunction_8cee7dce3725ae74 = function(arg0) {
        const ret = typeof(arg0) === 'function';
        return ret;
    };
    imports.wbg.__wbg_wbindgenisnull_f3037694abe4d97a = function(arg0) {
        const ret = arg0 === null;
        return ret;
    };
    imports.wbg.__wbg_wbindgenisobject_307a53c6bd97fbf8 = function(arg0) {
        const val = arg0;
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbg_wbindgenisstring_d4fa939789f003b0 = function(arg0) {
        const ret = typeof(arg0) === 'string';
        return ret;
    };
    imports.wbg.__wbg_wbindgenisundefined_c4b71d073b92f3c5 = function(arg0) {
        const ret = arg0 === undefined;
        return ret;
    };
    imports.wbg.__wbg_wbindgennumberget_f74b4c7525ac05cb = function(arg0, arg1) {
        const obj = arg1;
        const ret = typeof(obj) === 'number' ? obj : undefined;
        getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
    };
    imports.wbg.__wbg_wbindgenstringget_0f16a6ddddef376f = function(arg0, arg1) {
        const obj = arg1;
        const ret = typeof(obj) === 'string' ? obj : undefined;
        var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbg_wbindgenthrow_451ec1a8469d7eb6 = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbindgen_cast_2241b6af4c4b2941 = function(arg0, arg1) {
        // Cast intrinsic for `Ref(String) -> Externref`.
        const ret = getStringFromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_cast_cb9088102bce6b30 = function(arg0, arg1) {
        // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
        const ret = getArrayU8FromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_export_2;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
        ;
    };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('umbral_pre_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
