/* eslint-disable node/no-callback-literal, camelcase */
const events = require('node:events');
const net = require('node:net');
const util = require('node:util');
const crypto = require('node:crypto');
const tls = require('node:tls');

const POP3Grammar = {
  // in POP3 the available commands vary by state
  states: {
    AUTHORIZATION: {
      USER: 'username',
      PASS: 'password',
      APOP: 'username digest',
      CAPA: null,
      QUIT: null,
      STLS: null,
      AUTH: 'mechanism [initial-response]'
    },
    TRANSACTION: {
      CAPA: null,
      STAT: null,
      LIST: '[which]',
      RETR: 'which',
      DELE: 'which',
      NOOP: null,
      RSET: null,
      TOP: 'which [howmuch]',
      UIDL: '[which]',
      QUIT: null
      // TODO: LAST?
    },
    UPDATE: {
      // this state only exists while "quitting", so has no commands
    }
  },
  // capabilities are any optional or extended commands (except APOP,
  // which is announced by the format of the hello message, and PASS
  // which is implied by the USER capability)
  // see https://tools.ietf.org/rfc/rfc2449.txt
  // key is the command, value is what's sent as a capability
  capabilities: {
    TOP: 'TOP',
    UIDL: 'UIDL',
    USER: 'USER',
    STLS: 'STLS',
    AUTH: 'SASL PLAIN'
  },
  EOL: '\r\n'
};

function POP3Server (hostname, options) {
  net.Server.call(this);

  this.hostname = hostname;
  this.log = options?.log ?? console.log;
  this.debug = options?.debug ?? false;
  this.apop = options?.apop ?? true;
  this.tlsOptions = {
    isServer: true,
    honorCipherOrder: options?.honorCipherOrder ?? true,
    requestOCSP: options?.requestOCSP ?? false,
    key: options.key,
    cert: options.cert
  };
  // to enable TLS at least a cert and a key must be provided in options
  Object.defineProperty(this, 'starttlsEnabled', { get: () => !!this.tlsOptions.key && !!this.tlsOptions.cert });
  if (this.starttlsEnabled) {
    this.tlsOptions.sessionIdContext = crypto.createHash('sha1').update(process.argv.join(' ')).digest('hex').slice(0, 32);
    Object.defineProperty(this, 'secureContext', {
      get: function () {
        return this._secureContext || (this._secureContext = tls.createSecureContext(this.tlsOptions));
      }
    });
  }

  this.on('connection', function (socket) {
    const connection = new POP3Connection(this, socket, this.apop && this.shake());
    const callback = function (ok) {
      if (!ok) {
        return connection.end();
      }
      return connection.respondHello();
    };
    if (!this.emit('connected', connection, callback)) {
      return callback(true);
    }
  }.bind(this));

  this.once('listening', function () {
    this.log('POP3 server listening at ' + this.address().port);
  }.bind(this));
}

util.inherits(POP3Server, net.Server);

POP3Server.prototype.shake = function () {
  // generate some salt for the APOP command
  // see README for explanation of this logic
  let salt = this.apop;
  if (typeof (salt) === 'function') {
    salt = salt();
  }
  if (salt === true) {
    salt = crypto.randomBytes(6).toString('hex');
  }
  if (!salt) {
    return undefined;
  }
  // make sure salt is a string at this point
  salt = '' + salt;
  if (salt.startsWith('<')) {
    return salt;
  }
  return '<' + salt + '@' + this.hostname + '>';
};

// TODO: add err argument to callbacks, return a 'command not implemented' instead of empty stuff

POP3Server.prototype.capabilities = function (state, callback) {
  // per the RFC:
  // Capabilities available in the AUTHORIZATION state MUST be announced
  // in both states.
  const extensions = Object.keys(POP3Grammar.capabilities).filter(function (c) {
    return c in POP3Grammar.states[state] || (state !== 'AUTHORIZATION' && c in POP3Grammar.states.AUTHORIZATION);
  });
  const capabilities = extensions.map(e => POP3Grammar.capabilities[e]);
  // do not include STLS capability if starttls not enabled
  if (!this.starttlsEnabled) {
    const stls = capabilities.indexOf('STLS');
    if (stls >= 0) {
      capabilities.splice(stls, 1);
    }
  }
  if (!this.emit('capabilities', capabilities, callback)) {
    return callback(capabilities);
  }
};

POP3Server.prototype.authenticate = function (user, password, method, hashfunc, callback) {
  if (!this.emit('authenticate', user, password, method, hashfunc, callback)) {
    this.emit('error', method + ' command received but no authenticate listeners found');
    return callback(false);
  }
};

POP3Server.prototype.list = function (user, which, callback) {
  // which is an optional argument in the protocol
  if (typeof callback === 'undefined' && typeof which === 'function') {
    callback = which;
    which = null;
  }
  if (!this.emit('list', user, which, callback)) {
    return callback([]);
  }
};

POP3Server.prototype.uidl = function (user, which, callback) {
  // which is an optional argument in the protocol
  if (typeof callback === 'undefined' && typeof which === 'function') {
    callback = which;
    which = null;
  }
  if (!this.emit('uidl', user, which, callback)) {
    return callback([]);
  }
};

POP3Server.prototype.retrieve = function (user, which, callback) {
  if (!this.emit('retrieve', user, which, callback)) {
    return callback('command not implemented');
  }
};

POP3Server.prototype.quit = function (user, dele, callback) {
  // In strict POP3 protocol no permanent changes (like deleting messages) are supposed to be made
  // until a valid QUIT command is sent.  This event is the server's chance to do that.
  if (!this.emit('quit', user, dele, callback)) {
    return callback(true);
  }
};

function createServer (hostname, options, connectedListener) {
  // if options not given connectedListener may be in the wrong spot
  if (typeof connectedListener === 'undefined' && typeof options === 'function') {
    connectedListener = options;
    options = undefined;
  }

  const server = new POP3Server(hostname, options);

  if (connectedListener) {
    server.on('connected', connectedListener);
  }

  return server;
}

function parse_command (buffer) {
  let s = buffer.toString('ASCII');
  const end = s.indexOf(POP3Grammar.EOL);
  if (end < 0) {
    return null;
  } // don't have a full command yet, keep buffering
  s = s.substring(0, end); // trim off the EOL (and anything following it)
  return s.split(' ').filter(t => t && t.length);
}

function POP3Connection (server, socket, salt) {
  events.EventEmitter.call(this);

  this.server = server;
  // bind writeLine so it is easier to use in iterators
  this.writeLine = this.writeLine.bind(this);
  this.salt = salt;
  // bind apop_hash, so we can pass it out the app
  this.apop_hash = this.apop_hash.bind(this);

  // start every connection in authorization state
  this.state = 'AUTHORIZATION';
  this.user = null; // populated by USER, APOP, or AUTH
  this.sizes = null; // populated by STAT or LIST
  this.dele = {}; // populated by DELE, cleared by RSET

  // add listeners for all the supported commands
  Object.keys(this.commands).forEach(function (cmd) {
    this.on(cmd, this.commands[cmd].bind(this));
  }.bind(this));

  this.setSocket(socket);
}

util.inherits(POP3Connection, events.EventEmitter);

POP3Connection.prototype.setSocket = function (socket) {
  // if we already had a socket (as in TLS upgrade), remove existing listeners
  if (this.socket) {
    this.socket.removeAllListeners('data');
    this.socket.removeAllListeners('error');
  }

  this.socket = socket;

  // for now just log errors
  this.socket.on('error', function (error) {
    this.server.log('ERROR', error);
  }.bind(this));

  // add a data listener that parses input and dispatches command events
  this.socket.on('data', function (data) {
    if (this.server.debug) {
      let line = data.toString('ASCII').trim(); // or maybe UTF-8?
      // redact plaintext passwords
      if (line.toUpperCase().startsWith('PASS')) {
        line = line.substring(0, 4) + ' [redacted]';
      }
      this.server.log('C:', line);
    }
    const tokens = parse_command(data);
    // TODO: if tokens is null that means we haven't gotten an EOL yet and should keep buffering
    const cmd = tokens.shift().toUpperCase();
    if (!this.listenerCount(cmd)) {
      return this.respondErr('unknown/unsupported command ' + cmd);
    }
    if (!(cmd in POP3Grammar.states[this.state])) {
      return this.respondErr('command ' + cmd + 'is not available in ' + this.state + ' state');
    }
    let params = POP3Grammar.states[this.state][cmd];
    if (!params) {
      if (tokens.length) {
        return this.respondErr(cmd + ' does not take a parameter');
      }
    } else {
      // TODO: rather than parsing the params string just store the needed structure in the grammar
      params = params.split(' ');
      const optional_count = params.reduce((n, a) => n + a.startsWith('['), 0);
      const min_param_count = params.length - optional_count;
      const max_param_count = params.length;
      if (tokens.length < min_param_count) {
        return this.respondErr(cmd + ' expects ' +
          (optional_count ? 'at least ' : '') +
          min_param_count +
          'parameter' + (min_param_count ? 's' : ''));
      } else if (tokens.length > max_param_count) {
        return this.respondErr(cmd + ' expects ' +
          (optional_count ? 'at most ' : '') +
          max_param_count +
          'parameter' + (max_param_count ? 's' : ''));
      }
    }
    // TODO: do this emit asynchronously?
    return this.emit(cmd, tokens);
  }.bind(this));
};

POP3Connection.prototype.apop_hash = function (password) {
  return crypto.createHash('md5').update(this.salt + password).digest('hex');
};

// to allow a consistent interface with APOP (which hashes passwords) and USER/PASS (which doesn't)
// this function is used as the "hash_password" argument in the USER/PASS case
POP3Connection.prototype.noop_hash = function (password) {
  return password;
};

POP3Connection.prototype.starttls = function (callback) {
  if (this.socket instanceof tls.TLSSocket) {
    return callback('TLS already started');
  }

  this.server.log('starting TLS');

  const socketOptions = Object.assign({}, this.server.tlsOptions);
  socketOptions.SNICallback = function (servername, snicb) {
    this.server.log('SNICallback', servername);
    return snicb(null, this.server.secureContext);
  }.bind(this);

  let errorOnStart = false;
  const onError = function (err) {
    this.server.log('TLS error:', err);
    errorOnStart = true;
    // TODO: raise an error on the server?
  }.bind(this);

  this.socket.once('error', onError);

  // upgrade connection
  const tlsSocket = new tls.TLSSocket(this.socket, socketOptions);

  const unexpected_events = ['error', 'close', '_tlsError', 'clientError', 'tlsClientError'];

  unexpected_events.forEach((e) => tlsSocket.once(e, onError));

  tlsSocket.on('secure', function () {
    this.socket.removeListener('error', onError);
    unexpected_events.forEach((e) => tlsSocket.removeListener(e, onError));
    if (errorOnStart) {
      // attempt to end it, ignoring any exceptions
      try { tlsSocket.end(); } catch (E) { }
      return; // leave the existing socket in place
    }
    this.server.log('TLS secure');
    this.setSocket(tlsSocket);
  }.bind(this));

  return callback(null);
};

POP3Connection.prototype.commands = {
  CAPA: function () {
    this.server.capabilities(this.state, function (capabilities) {
      this.respondOk('Capability list follows');
      capabilities.forEach(this.writeLine);
      this.writeMultilineEnd();
    }.bind(this));
  },
  USER: function (args) {
    // NOTE: we don't actually validate users until PASS (or on APOP)
    this.user = args[0];
    this.respondOk();
  },
  PASS: function (args) {
    if (!this.user) {
      return this.respondErr('PASS must be preceded with USER');
    }
    const password = args.shift();
    // TODO: assert password
    this.server.authenticate(this.user, password, 'PASS', this.noop_hash, function (ok, message) {
      if (ok) {
        this.state = 'TRANSACTION';
        return this.respondOk();
      }
      this.user = null;
      return this.respondErr(message || 'invalid user name or password');
    }.bind(this));
  },
  APOP: function (args) {
    if (!this.salt) {
      return this.respondErr('APOP command not enabled');
    }
    this.user = args.shift();
    const password = args.shift();
    this.server.authenticate(this.user, password, 'APOP', this.apop_hash, function (ok, message) {
      if (ok) {
        this.state = 'TRANSACTION';
        return this.respondOk();
      }
      this.user = null;
      return this.respondErr(message || 'invalid user name or password');
    }.bind(this));
  },
  QUIT: function () {
    if (this.state === 'AUTHORIZATION') {
      // never authorized, so never did any transactions, so can just close
      return this.bye();
    }
    this.state = 'UPDATE';
    const dele = Object.keys(this.dele).map(n => parseInt(n)).sort();
    this.server.quit(this.user, dele, function (ok) {
      // TODO: what to do if not ok?
      return this.bye();
    }.bind(this));
  },
  NOOP: function () {
    return this.respondOk();
  },
  UIDL: function (args) {
    return this.server.uidl(this.user, args[0], function (which, uids) {
      if (which) {
        if (!uids) {
          this.respondErr('no such message');
        } else if (!Array.isArray(uids)) {
          this.respondOk(which + ' ' + uids);
        } else if (!uids.length) {
          this.respondErr('no such message');
        } else {
          this.respondOk(which + ' ' + uids[0]);
        }
      } else {
        // TODO: create a "send_enumeration" utility for these
        this.respondOk();
        this.writeLines(uids.map((uid, i) => [i + 1, uid].join(' ')));
      }
    }.bind(this, args[0]));
  },
  STAT: function () {
    // TODO: if (!this.user) { error }
    const callback = function (sizes) {
      // cache them for another STAT or LIST call
      if (this.sizes === null) {
        this.sizes = sizes;
      }
      // sum the sizes, excluding deleted messages
      const total = sizes.reduce((sum, size, i) => sum + (+!this.dele[i + 1] * size), 0);
      this.respondOk([sizes.length, total].join(' '));
    }.bind(this);
    if (this.sizes !== null) {
      return callback(this.sizes);
    }
    return this.server.list(this.user, callback);
  },
  LIST: function (args) {
    const which = args.shift();
    if (which && this.dele[which]) {
      return this.respondErr('no such message');
    }
    const callback = function (sizes) {
      // if possible cache sizes for another STAT or LIST call
      if (!which && this.sizes == null) {
        this.sizes = sizes;
      }
      // if which was specified we send just a one line response
      if (which) {
        if (sizes && sizes.length === 1) {
          return this.respondOk('' + which + ' ' + sizes[0]);
        } else {
          return this.respondErr('no such message');
        }
      }
      // else it's a multiline (TODO: unless empty?)
      const lines = sizes.filter((size, i) => !this.dele[i + 1])
        .map((size, i) => [i + 1, size].join(' '));
      this.respondOk('scan listing follows');
      this.writeLines(lines);
    }.bind(this);
    if (this.sizes !== null) {
      if (which) {
        const s = this.sizes[which - 1];
        return callback(s ? [s] : []);
      }
      return callback(this.sizes);
    }
    return this.server.list(this.user, which, callback);
  },
  RETR: function (args) {
    const which = parseInt(args.shift());
    if (this.dele[which]) {
      return this.respondErr('no such message');
    }
    return this.server.retrieve(this.user, which, function (message) {
      // a blank line should separate the headers from the body
      const lines = message?.headers?.concat?.('').concat(message.body);
      if (!lines) {
        return this.respondErr('no such message');
      }
      this.respondOk();
      this.writeLines(lines);
    }.bind(this));
  },
  TOP: function (args) {
    const which = parseInt(args.shift());
    if (this.dele[which]) {
      return this.respondErr('no such message');
    }
    // Per the RFC (https://tools.ietf.org/html/rfc1081) the second argument to TOP is optional.
    // The default values does not seem to be explicitly stated but the example suggests 10.
    const n = parseInt(args.shift() || '10');
    return this.server.retrieve(this.user, which, function (message) {
      let lines = message.headers.concat('');
      if (!lines) {
        return this.respondErr('no such message');
      }
      // NOTE: the delimiter for counting lines in the context of the message body isn't
      // defined by the POP3 RFC, and it is not uncommon for bodies to use mixed delimiters
      // (or even HTML <br/> tags) to delimit them.  Here we just split on \n or \r\n.
      if (n > 0) {
        lines = lines.concat(message.body.split(/\r?\n/).slice(0, n));
      }
      this.respondOk();
      this.writeLines(lines);
    }.bind(this));
  },
  DELE: function (args) {
    const which = parseInt(args.shift());
    if (this.dele[which]) {
      return this.respondErr('message ' + which + ' already deleted');
    }
    // TODO: out of range case:
    // return this.respondErr('no such message')
    this.dele[which] = true;
    this.respondOk('message ' + which + ' deleted');
  },
  RSET: function (args) {
    this.dele = {};
    this.respondOk();
  },
  STLS: function () {
    this.server.log('calling starttls');
    this.starttls(function (err) {
      this.server.log('starttls callback invoked', err);
      if (err) {
        return this.respondErr(err);
      }
      this.respondOk('Begin TLS negotiation');
    }.bind(this));
  }
};

POP3Connection.prototype.writeLine = function (line) {
  if (this.server.debug) {
    this.server.log('S:', line);
  }
  this.socket.write(line);
  return this.socket.write(POP3Grammar.EOL);
};

POP3Connection.prototype.writeMultilineEnd = function () {
  return this.writeLine('.');
};

POP3Connection.prototype.writeLines = function (lines) {
  lines.forEach(this.writeLine);
  return this.writeMultilineEnd();
};

POP3Connection.prototype.respondOk = function (extra) {
  if (typeof extra !== 'undefined') {
    return this.writeLine(['+OK', extra].join(' '));
  }
  return this.writeLine('+OK');
};

POP3Connection.prototype.respondErr = function (err) {
  return this.writeLine(['-ERR', err].join(' '));
};

POP3Connection.prototype.helloMessage = function () {
  return 'POP3 server ready' + (this.salt ? ' ' + this.salt : '');
};

POP3Connection.prototype.respondHello = function () {
  return this.respondOk(this.helloMessage());
};

POP3Connection.prototype.bye = function () {
  this.respondOk('bye');
  return this.end();
};

POP3Connection.prototype.end = function () {
  if (this.socket) {
    this.socket.end();
    this.socket.destroy();
    delete this.socket;
  }
  return this.removeAllListeners();
  // TODO: verify connection gets gc'd
};

module.exports.POP3Grammar = POP3Grammar;
module.exports.POP3Server = POP3Server;
module.exports.createServer = createServer;
