// ==UserScript==
// @exclude       *
// @author        kkhaike&zxf10608
// ==UserLibrary==
// @name          115decode
// @version       2.0
// @license       MIT
// @description   115下载请求编码解码器
// ==/UserScript==

// ==/UserLibrary==

(function(global) {
    'use strict';

    const KTS = [240, 229, 105, 174, 191, 220, 191, 138, 26, 69, 232, 190, 125, 166, 115, 184, 222, 143, 231, 196, 69, 218, 134, 196, 155, 100, 139, 20, 106, 180, 241, 170, 56, 1, 53, 158, 38, 105, 44, 134, 0, 107, 79, 165, 54, 52, 98, 166, 42, 150, 104, 24, 242, 74, 253, 189, 107, 151, 143, 77, 143, 137, 19, 183, 108, 142, 147, 237, 14, 13, 72, 62, 215, 47, 136, 216, 254, 254, 126, 134, 80, 149, 79, 209, 235, 131, 38, 52, 219, 102, 123, 156, 126, 157, 122, 129, 50, 234, 182, 51, 222, 58, 169, 89, 52, 102, 59, 170, 186, 129, 96, 72, 185, 213, 129, 156, 248, 108, 132, 119, 255, 84, 120, 38, 95, 190, 232, 30, 54, 159, 52, 128, 92, 69, 44, 155, 118, 213, 27, 143, 204, 195, 184, 245];
    const KEY_S = [0x29, 0x23, 0x21, 0x5E];
    const KEY_L = [120, 6, 173, 76, 51, 134, 93, 24, 76, 1, 63, 70];

    let cryptoObj = null;
    const randomByteBuffer = new Uint8Array(1);

    function initCrypto() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
            cryptoObj = globalThis.crypto;
        }
    }

    function getRandomNonZeroByte() {
        if (cryptoObj) {
            while (true) {
                cryptoObj.getRandomValues(randomByteBuffer);
                if (randomByteBuffer[0] !== 0) return randomByteBuffer[0];
            }
        }
        while (true) {
            const value = Math.floor(Math.random() * 0x100);
            if (value !== 0) return value;
        }
    }

    function stringToBytes(s) {
        if (typeof s !== 'string') {
            throw new TypeError('stringToBytes: s must be a string');
        }
        const ret = [];
        for (let i = 0; i < s.length; i++) {
            ret.push(s.charCodeAt(i));
        }
        return ret;
    }

    function bytesToString(b) {
        if (!Array.isArray(b)) {
            throw new TypeError('bytesToString: b must be an array');
        }
        let ret = '';
        for (let i = 0; i < b.length; i++) {
            ret += String.fromCharCode(b[i]);
        }
        return ret;
    }

    class RSA {
        constructor() {
            this.n = bigInt('8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683', 16);
            this.e = bigInt('10001', 16);
        }

        a2hex(byteArray) {
            return byteArray.map(b => ('0' + b.toString(16)).slice(-2)).join('');
        }

        hex2a(hex) {
            const codes = [];
            for (let i = 0; i < hex.length; i += 2) {
                codes.push(parseInt(hex.substr(i, 2), 16));
            }
            return String.fromCharCode(...codes);
        }

        pkcs1pad2(s, n) {
            if (n < s.length + 11) return null;
            const ba = [];
            let i = s.length - 1;
            while (i >= 0 && n > 0) {
                ba[--n] = s.charCodeAt(i--);
            }
            ba[--n] = 0;
            while (n > 2) {
                ba[--n] = getRandomNonZeroByte();
            }
            ba[--n] = 2;
            ba[--n] = 0;
            return bigInt(this.a2hex(ba), 16);
        }

        pkcs1unpad2(a) {
            let b = a.toString(16);
            if (b.length % 2 !== 0) {
                b = '0' + b;
            }
            const c = this.hex2a(b);
            let i = 1;
            while (c.charCodeAt(i) !== 0) {
                i++;
            }
            return c.slice(i + 1);
        }

        encrypt(text) {
            const m = this.pkcs1pad2(text, 0x80);
            const c = m.modPow(this.e, this.n);
            let h = c.toString(16);
            while (h.length < 0x80 * 2) {
                h = '0' + h;
            }
            return h;
        }

        decrypt(text) {
            const a = bigInt(this.a2hex(stringToBytes(text)), 16);
            const c = a.modPow(this.e, this.n);
            return this.pkcs1unpad2(c);
        }
    }

    const rsa = new RSA();

    function m115_getkey(length, key) {
        if (typeof length !== 'number' || !Number.isInteger(length)) {
            throw new TypeError('m115_getkey: length must be an integer');
        }
        if (key != null) {
            const results = [];
            for (let i = 0; i < length; i++) {
                results.push(((key[i] + KTS[length * i]) & 0xff) ^ KTS[length * (length - 1 - i)]);
            }
            return results;
        }
        return length === 12 ? KEY_L.slice(0) : KEY_S.slice(0);
    }

    function xor115_enc(src, srclen, key, keylen) {
        const mod4 = srclen % 4;
        const ret = [];
        if (mod4 !== 0) {
            for (let i = 0; i < mod4; i++) {
                ret.push(src[i] ^ key[i % keylen]);
            }
        }
        for (let i = mod4; i < srclen; i++) {
            ret.push(src[i] ^ key[(i - mod4) % keylen]);
        }
        return ret;
    }

    function m115_sym_encode(src, srclen, key1, key2) {
        const k1 = m115_getkey(4, key1);
        const k2 = m115_getkey(12, key2);
        let ret = xor115_enc(src, srclen, k1, 4);
        ret.reverse();
        return xor115_enc(ret, srclen, k2, 12);
    }

    function m115_sym_decode(src, srclen, key1, key2) {
        const k1 = m115_getkey(4, key1);
        const k2 = m115_getkey(12, key2);
        let ret = xor115_enc(src, srclen, k2, 12);
        ret.reverse();
        return xor115_enc(ret, srclen, k1, 4);
    }

    function m115_asym_encode(src, srclen) {
        const m = 128 - 11;
        let ret = '';
        const chunks = Math.ceil(srclen / m);
        for (let i = 0; i < chunks; i++) {
            const start = i * m;
            const end = Math.min((i + 1) * m, srclen);
            ret += rsa.encrypt(bytesToString(src.slice(start, end)));
        }
        return window.btoa(rsa.hex2a(ret));
    }

    function m115_asym_decode(src, srclen) {
        const m = 128;
        let ret = '';
        const chunks = Math.ceil(srclen / m);
        for (let i = 0; i < chunks; i++) {
            const start = i * m;
            const end = Math.min((i + 1) * m, srclen);
            ret += rsa.decrypt(bytesToString(src.slice(start, end)));
        }
        return stringToBytes(ret);
    }

    function m115_encode(src, tm) {
        if (typeof src !== 'string') {
            throw new TypeError('m115_encode: src must be a string');
        }
        if (typeof tm !== 'number' || !Number.isInteger(tm)) {
            tm = Math.floor(Date.now() / 1000);
        }

        const key = stringToBytes(md5(`!@###@#${tm}DFDR@#@#`));
        let tmp = stringToBytes(src);
        tmp = m115_sym_encode(tmp, tmp.length, key, null);
        tmp = key.slice(0, 16).concat(tmp);

        return {
            data: m115_asym_encode(tmp, tmp.length),
            key: key
        };
    }

    function m115_decode(src, key) {
        if (typeof src !== 'string') {
            throw new TypeError('m115_decode: src must be a string');
        }
        if (!Array.isArray(key)) {
            throw new TypeError('m115_decode: key must be an array');
        }

        let tmp = stringToBytes(window.atob(src));
        tmp = m115_asym_decode(tmp, tmp.length);
        return bytesToString(m115_sym_decode(tmp.slice(16), tmp.length - 16, key, tmp.slice(0, 16)));
    }

    initCrypto();

    global.m115_encode = m115_encode;
    global.m115_decode = m115_decode;

    global.lib115 = {
        encode: m115_encode,
        decode: m115_decode
    };

})(typeof window !== 'undefined' ? window : this);