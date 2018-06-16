/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

if (typeof Components !== "undefined") {
  Components.utils.import("resource://gre/modules/ctypes.jsm");
  Components.utils.import("resource://gre/modules/Services.jsm");
}

const LOCATION = "resource:///modules/DNS.jsm";

// These constants are luckily shared, but with different names
const NS_T_TXT = 16; // DNS_TYPE_TXT
const NS_T_SRV = 33; // DNS_TYPE_SRV

function load_libresolv() {
  this._open();
}

load_libresolv.prototype = {
  library: null,

  _open: function() {
    function findLibrary() {
      let lastException = null;
      let libnames = [ctypes.libraryName("resolv.9"),
              ctypes.libraryName("resolv")];
      for (let libname of libnames) {
        try {
          return ctypes.open(libname);
        } catch (ex) {
          lastException = ex;
        }
      }
      throw("Could not find libresolv in any of " + libnames + " Exception: " +
            lastException + "\n");
    }

    function declare(symbolNames, ...args) {
      let lastException = null;
      if (!Array.isArray(symbolNames)) {
        symbolNames = [symbolNames];
      }

      for (let name of symbolNames) {
        try {
          return library.declare(name, ...args);
        } catch (ex) {
          lastException = ex;
        }
      }

      throw("Failed to declare " + symbolNames + " Exception: " + lastException +
            "\n");
    }

    let library = this.library = findLibrary();
    this.res_search =
      declare(["res_9_search", "res_search", "__res_search"],
              ctypes.default_abi, ctypes.int, ctypes.char.ptr, ctypes.int,
              ctypes.int, ctypes.unsigned_char.ptr, ctypes.int);
    this.res_query =
      declare(["res_9_query", "res_query", "__res_query"],
              ctypes.default_abi, ctypes.int, ctypes.char.ptr, ctypes.int,
              ctypes.int, ctypes.unsigned_char.ptr, ctypes.int);
    this.dn_expand =
      declare(["res_9_dn_expand", "dn_expand", "__dn_expand"],
              ctypes.default_abi, ctypes.int, ctypes.unsigned_char.ptr,
              ctypes.unsigned_char.ptr, ctypes.unsigned_char.ptr,
              ctypes.char.ptr, ctypes.int);
    this.dn_skipname =
      declare(["res_9_dn_skipname", "dn_skipname", "__dn_skipname"],
              ctypes.default_abi, ctypes.int, ctypes.unsigned_char.ptr,
              ctypes.unsigned_char.ptr);
    this.ns_get16 =
      declare(["res_9_ns_get16", "ns_get16"], ctypes.default_abi,
              ctypes.unsigned_int, ctypes.unsigned_char.ptr);
    this.ns_get32 =
      declare(["res_9_ns_get32", "ns_get32"], ctypes.default_abi,
              ctypes.unsigned_long, ctypes.unsigned_char.ptr);

    this.QUERYBUF_SIZE = 1024;
    this.NS_MAXCDNAME = 255;
    this.NS_HFIXEDSZ = 12;
    this.NS_QFIXEDSZ = 4;
    this.NS_RRFIXEDSZ = 10;

    this.NS_C_IN = 1;
  },

  close: function() {
    this.library.close();
    this.library = null;
  },

  _mapAnswer: function(typeId, answer, idx, length) {
    if (typeId == NS_T_SRV) {
      let prio = this.ns_get16(answer.addressOfElement(idx));
      let weight = this.ns_get16(answer.addressOfElement(idx + 2));
      let port = this.ns_get16(answer.addressOfElement(idx + 4));

      let hostbuf = ctypes.char.array(this.NS_MAXCDNAME)();
      let hostlen = this.dn_expand(answer.addressOfElement(0),
                     answer.addressOfElement(length),
                     answer.addressOfElement(idx + 6),
                     hostbuf, this.NS_MAXCDNAME);
      let host = hostlen > -1 ? hostbuf.readString() : null;
      return new SRVRecord(prio, weight, host, port);
    } else if (typeId == NS_T_TXT) {
      // TODO should only read dataLength characters
      let data = ctypes.unsigned_char.ptr(answer.addressOfElement(idx + 1));
      return new TXTRecord(data.readString());
    }
    return {};
  },

  lookup: function(name, typeId) {
    let qname = ctypes.char.array()(name);
    let answer = ctypes.unsigned_char.array(this.QUERYBUF_SIZE)();
    let length =
      this.res_search(qname, this.NS_C_IN, typeId, answer, this.QUERYBUF_SIZE);

    // There is an error.
    if (length < 0)
      return -1;

    let results = [];
    let idx = this.NS_HFIXEDSZ;

    let qdcount = this.ns_get16(answer.addressOfElement(4));
    let ancount = this.ns_get16(answer.addressOfElement(6));

    for (let qdidx = 0; qdidx < qdcount && idx < length; qdidx++) {
      idx += this.dn_skipname(answer.addressOfElement(idx),
                  answer.addressOfElement(length)) + this.NS_QFIXEDSZ;
    }

    for (let anidx = 0; anidx < ancount && idx < length; anidx++) {
      idx += this.dn_skipname(answer.addressOfElement(idx),
                  answer.addressOfElement(length));
      let rridx = idx;
      let type = this.ns_get16(answer.addressOfElement(rridx));
      let dataLength = this.ns_get16(answer.addressOfElement(rridx + 8));

      idx += this.NS_RRFIXEDSZ;

      if (type === typeId) {
        let resource = this._mapAnswer(typeId, answer, idx, length);
        resource.type = type;
        resource.nsclass = this.ns_get16(answer.addressOfElement(rridx + 2));
        resource.ttl = this.ns_get32(answer.addressOfElement(rridx + 4))|0;
        results.push(resource);
      }
      idx += dataLength;
    }
    return results;
  }
};

function load_dnsapi() {
  this._open();
}

load_dnsapi.prototype = {
  library: null,

  _open: function() {
    function declare(symbolName, ...args) {
      try {
        return library.declare(symbolName, ...args);
      } catch (ex) {
        throw("Failed to declare " + symbolName + " Exception: " + ex + "\n");
      }
    }

    let library = this.library = ctypes.open(ctypes.libraryName("DnsAPI"));

    this.DNS_SRV_DATA = ctypes.StructType("DNS_SRV_DATA", [
      { pNameTarget: ctypes.jschar.ptr },
      { wPriority: ctypes.unsigned_short },
      { wWeight: ctypes.unsigned_short },
      { wPort: ctypes.unsigned_short },
      { Pad: ctypes.unsigned_short }
    ]);

    this.DNS_TXT_DATA = ctypes.StructType("DNS_TXT_DATA", [
      { dwStringCount: ctypes.unsigned_long },
      { pStringArray: ctypes.jschar.ptr.array(1) }
    ]);

    this.DNS_RECORD = ctypes.StructType("_DnsRecord");
    this.DNS_RECORD.define([
      { pNext: this.DNS_RECORD.ptr },
      { pName: ctypes.jschar.ptr },
      { wType: ctypes.unsigned_short },
      { wDataLength: ctypes.unsigned_short },
      { Flags: ctypes.unsigned_long },
      { dwTtl: ctypes.unsigned_long },
      { dwReserved: ctypes.unsigned_long },
      { Data: this.DNS_SRV_DATA } // its a union, can be cast to many things
    ]);

    this.PDNS_RECORD = ctypes.PointerType(this.DNS_RECORD);
    this.DnsQuery_W =
      declare("DnsQuery_W", ctypes.winapi_abi, ctypes.long, ctypes.jschar.ptr,
              ctypes.unsigned_short, ctypes.unsigned_long, ctypes.voidptr_t,
              this.PDNS_RECORD.ptr, ctypes.voidptr_t.ptr);
    this.DnsRecordListFree =
      declare("DnsRecordListFree", ctypes.winapi_abi, ctypes.void_t,
              this.PDNS_RECORD, ctypes.int);

    this.ERROR_SUCCESS = ctypes.Int64(0);
    this.DNS_QUERY_STANDARD = 0;
    this.DnsFreeRecordList = 1;
  },

  close: function() {
    this.library.close();
    this.library = null;
  },

  _mapAnswer: function(typeId, data) {
    if (typeId == NS_T_SRV) {
      let srvdata = ctypes.cast(data, this.DNS_SRV_DATA);
      return new SRVRecord(srvdata.wPriority, srvdata.wWeight,
                 srvdata.pNameTarget.readString(),
                 srvdata.wPort);
    } else if (typeId == NS_T_TXT) {
      let txtdata = ctypes.cast(data, this.DNS_TXT_DATA);
      let data = null;
      if (txtdata.dwStringCount > 0) {
        data = txtdata.pStringArray[0].readString();
      }
      return new TXTRecord(data);
    }

    return {};
  },

  lookup: function(name, typeId) {
    let queryResultsSet = this.PDNS_RECORD();
    let qname = ctypes.jschar.array()(name);
    let dnsStatus = this.DnsQuery_W(qname, typeId, this.DNS_QUERY_STANDARD,
                    null, queryResultsSet.address(), null);

    // There is an error.
    if (ctypes.Int64.compare(dnsStatus, this.ERROR_SUCCESS) != 0)
      return -1;

    let results = [];
    for (let presult = queryResultsSet; presult && !presult.isNull();
         presult = presult.contents.pNext) {
      let result = presult.contents;
      if (result.wType == typeId) {
        let resource = this._mapAnswer(typeId, result.Data)
        resource.type = result.wType;
        resource.nsclass = 0;
        resource.ttl = result.dwTtl|0;
        results.push(resource);
      }
    }

    this.DnsRecordListFree(queryResultsSet, this.DnsFreeRecordList);
    return results;
  }
};

function SRVRecord(prio, weight, host, port) {
  this.prio = prio;
  this.weight = weight;
  this.host = host;
  this.port = port;
}

function TXTRecord(data) {
  this.data = data;
}

function asyncify(method) {
  return function(...args) {
    return new Promise((resolve, reject) => {
      let worker = new ChromeWorker(LOCATION);
      worker.onmessage = function(event) {
        if (event.data.hasOwnProperty("type") && event.data.type == "error")
          reject(event.data.message);
        else
          resolve(event.data);
      };
      worker.onerror = function(event) {
        reject(event.message);
      };

      worker.postMessage({
        OS: Services.appinfo.OS,
        method: method,
        args: args,
      });
    });
  };
}

if (typeof Components === "undefined") {
  // We are in a worker, wait for our message then execute the wanted method
  onmessage = function(event) {
    try {
      let data = event.data;
      let DNS = (data.OS == "WINNT" ? new load_dnsapi() : new load_libresolv());
      let result = DNS[data.method].apply(DNS, data.args);
      postMessage(result);
      close();
    } catch(e) {
      dump(e);
      postMessage({type: "error", message: e});
      close();
    };
  };
}
else {
  // We are loaded as a JSM, provide the async front that will start the
  // worker.
  var dns_async_front = {
    /**
     * Constants for use with the lookup function.
     */
    TXT: NS_T_TXT,
    SRV: NS_T_SRV,

    /**
     * Do an asynchronous DNS lookup. The returned promise resolves with
     * one of the Answer objects as defined above, or rejects with the
     * error from the worker.
     *
     * Example: DNS.lookup("_caldavs._tcp.example.com", DNS.SRV)
     *
     * @param name          The name to look up.
     * @param typeId        The RR type to look up as a constant.
     * @return              A promise resolved when completed.
     */
    lookup: /* function(name, typeId) */ asyncify("lookup"),

    /** Convenience functions */
    srv: function(name) { return this.lookup(name, NS_T_SRV); },
    txt: function(name) { return this.lookup(name, NS_T_TXT); },
  }
  this.DNS = dns_async_front;
  this.EXPORTED_SYMBOLS = ["DNS"];
}
