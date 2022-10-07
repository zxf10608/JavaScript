// ==UserScript==
// @exclude       *
// @author        zxf10608
// ==UserLibrary==
// @name          115decode
// @version       1.4
// @license       MIT
// @description   115下载请求编码解码器
// ==/UserScript==

// ==/UserLibrary==


	//公匙
	var pub_key = '-----BEGIN PUBLIC KEY-----\
	MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGhpgMD1okxLnUMCDNLCJwP/P0\
	UHVlKQWLHPiPCbhgITZHcZim4mgxSWWb0SLDNZL9ta1HlErR6k02xrFyqtYzjDu2\
	rGInUC0BCZOsln0a7wDwyOA43i5NO8LsNory6fEKbx7aT3Ji8TZCDAfDMbhxvxOf\
	dPMBDjxP5X3zr7cWgwIDAQAB\
	-----END PUBLIC KEY-----';
   //私匙
    var private_key = '-----BEGIN RSA PRIVATE KEY-----\
	MIICXAIBAAKBgQCMgUJLwWb0kYdW6feyLvqgNHmwgeYYlocst8UckQ1+waTOKHFC\
	TVyRSb1eCKJZWaGa08mB5lEu/asruNo/HjFcKUvRF6n7nYzo5jO0li4IfGKdxso6\
	FJIUtAke8rA2PLOubH7nAjd/BV7TzZP2w0IlanZVS76n8gNDe75l8tonQQIDAQAB\
	AoGANwTasA2Awl5GT/t4WhbZX2iNClgjgRdYwWMI1aHbVfqADZZ6m0rt55qng63/\
	3NsjVByAuNQ2kB8XKxzMoZCyJNvnd78YuW3Zowqs6HgDUHk6T5CmRad0fvaVYi6t\
	viOkxtiPIuh4QrQ7NUhsLRtbH6d9s1KLCRDKhO23pGr9vtECQQDpjKYssF+kq9iy\
	A9WvXRjbY9+ca27YfarD9WVzWS2rFg8MsCbvCo9ebXcmju44QhCghQFIVXuebQ7Q\
	pydvqF0lAkEAmgLnib1XonYOxjVJM2jqy5zEGe6vzg8aSwKCYec14iiJKmEYcP4z\
	DSRms43hnQsp8M2ynjnsYCjyiegg+AZ87QJANuwwmAnSNDOFfjeQpPDLy6wtBeft\
	5VOIORUYiovKRZWmbGFwhn6BQL+VaafrNaezqUweBRi1PYiAF2l3yLZbUQJAf/nN\
	4Hz/pzYmzLlWnGugP5WCtnHKkJWoKZBqO2RfOBCq+hY4sxvn3BHVbXqGcXLnZPvo\
	YuaK7tTXxZSoYLEzeQJBAL8Mt3AkF1Gci5HOug6jT4s4Z+qDDrUXo9BlTwSWP90v\
	wlHF+mkTJpKd5Wacef0vV+xumqNorvLpIXWKwxNaoHM=\
	-----END RSA PRIVATE KEY-----';
	

	
	
    var rsa = forge.pki.rsa;
    var new_rsa = new MyRsa();
    const priv = forge.pki.privateKeyFromPem(private_key);
    const pub = forge.pki.publicKeyFromPem(pub_key);
    const g_key_l = [120, 6, 173, 76, 51, 134, 93, 24, 76, 1, 63, 70];
    const g_key_s = [0x29, 0x23, 0x21, 0x5e];
    const g_kts = [240, 229, 105, 174, 191, 220, 191, 138, 26, 69, 232, 190, 125, 166, 115, 184, 222, 143, 231, 196, 69, 218, 134, 196, 155, 100, 139, 20, 106, 180, 241, 170, 56, 1, 53, 158, 38, 105, 44, 134, 0, 107, 79, 165, 54, 52, 98, 166, 42, 150, 104, 24, 242, 74, 253, 189, 107, 151, 143, 77, 143, 137, 19, 183, 108, 142, 147, 237, 14, 13, 72, 62, 215, 47, 136, 216, 254, 254, 126, 134, 80, 149, 79, 209, 235, 131, 38, 52, 219, 102, 123, 156, 126, 157, 122, 129, 50, 234, 182, 51, 222, 58, 169, 89, 52, 102, 59, 170, 186, 129, 96, 72, 185, 213, 129, 156, 248, 108, 132, 119, 255, 84, 120, 38, 95, 190, 232, 30, 54, 159, 52, 128, 92, 69, 44, 155, 118, 213, 27, 143, 204, 195, 184, 245];

    var m115_l_rnd_key = [];
    var m115_s_rnd_key = [];
    var key_s = [];
    var key_l = [];

    function intToByte(i) {
        var b = i & 0xFF;
        var c = 0;
        if (b >= 256) {
            c = b % 256;
            c = -1 * (256 - c);
        } else {
            c = b;
        }
        return c;
    };

    function stringToArray(s) {
        var map = Array.prototype.map;
        var array = map.call(s, function(x) {
            return x.charCodeAt(0);
        });
        return array;
    };

    function arrayTostring(array) {
        var result = '';
        for (var i = 0; i < array.length; ++i) {
            result += (String.fromCharCode(array[i]));
        }
        return result;
    };

    function m115_xorinit(randkey, sk_len) {
        var length = sk_len * (sk_len - 1);
        var index = 0;
        var xorkey = '';
        if (randkey) {
            for (let i = 0; i < sk_len; i++) {
                let x = intToByte((randkey[i]) + (g_kts[index]));
                xorkey += String.fromCharCode(g_kts[length] ^ x);
                length -= sk_len;
                index += sk_len;
            }
            if (sk_len == 4) {
                key_s = stringToArray(xorkey);
            } else if (sk_len == 12) {
                key_l = stringToArray(xorkey);
            }
        }
    };

    function xor115_enc(src, key) {
        var lkey = key.length;
        var secret = [];
        var num = 0;

        var pad = (src.length) % 4;
        if (pad > 0) {
            for (var i = 0; i < pad; i++) {
                secret.push((src[i]) ^ key[i]);
            }
            src = src.slice(pad);
        }

        for (var i = 0; i < src.length; i++) {
            if (num >= lkey) {
                num = num % lkey;
            }
            secret.push((src[i] ^ key[num]));
            num += 1;
        }
        return secret;
    };


    function genRandom(len) {
        var keys = [];
        var chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz23456789';

        var maxPos = chars.length;
        for (var i = 0; i < len; i++) {
            keys.push(chars.charAt(Math.floor(Math.random() * maxPos))
                .charCodeAt(0));
        }
        return keys;
    };

    m115_l_rnd_key = genRandom(16);
    m115_xorinit(m115_l_rnd_key, 4);

    function m115_encode(plaintext) {
        key_l = g_key_l;
        var tmp = xor115_enc(stringToArray(plaintext), key_s)
            .reverse();
        var xortext = xor115_enc(tmp, key_l);
        var text = arrayTostring(m115_l_rnd_key) + arrayTostring(xortext);
        var ciphertext = pub.encrypt(text);
        ciphertext = encodeURIComponent(forge.util.encode64(ciphertext));
        var new_ciphertext = new_rsa.encrypt(text);
        new_ciphertext = encodeURIComponent(forge.util.encode64(new_ciphertext));
        return ciphertext;
    };

    function m115_decode(ciphertext) {
        //debugger;
        //console.log('m115_decode:' + ciphertext);
        let bciphertext = forge.util.decode64(ciphertext);
        let block = bciphertext.length / (128);
        let plaintext = '';

        let index = 0;
        for (let i = 1; i <= block; ++i) {
            plaintext += new_rsa.decrypt(bciphertext.slice(index, i * 128));
            index += 128;
        }

        m115_s_rnd_key = stringToArray(plaintext.slice(0, 16));
        plaintext = plaintext.slice(16);
        m115_xorinit(m115_l_rnd_key, 4);
        m115_xorinit(m115_s_rnd_key, 12);
        let tmp = xor115_enc(stringToArray(plaintext), key_l)
            .reverse();
        plaintext = xor115_enc(tmp, key_s);
        //console.log('key_s:' + key_s);
        return arrayTostring(plaintext);
    };