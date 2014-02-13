var https = require('https');
var http = require('http');
var crypto = require('crypto');
var redis = require('redis');
var cfg = require('envigor')();

var db = redis.createClient(cfg.redis.port, cfg.redis.hostname,
  {no_ready_check: true});
if (cfg.redis.password) db.auth(cfg.redis.password);

var serverOpts = {
  // handshakeTimeout by default is 120 seconds which sounds WAY too high
  //handshakeTimeout: 20000,
  // mitigate BEAST attacks by preferring non-vulerable ciphers
  honorCipherOrder: true
};

var proxy = require('http-proxy').createProxyServer({
  xfwd: true, secure: false
});

// WAIT THIS HAS TO RETURN SYNCHRONOUSLY OH NUTS
function getSecureContext(domain, cb) {
  var keys = ['key:' + domain,'cert:'+ domain];
  var components = domain.split('.');

  // We go to length - 1 because nobody's going to own the TLD
  // There may be other public suffixes we'll disallow, but this one
  // we can 100% not do
  for (var i=1; i < components.length - 1; i++) {
    var wildDomain = components.slice(i).join('.');
    keys[i*2] = 'key:*.'+wildDomain;
    keys[i*2 + 1] = 'cert:*.'+wildDomain;
  }
  db.mget(keys,function(err, creds) {
    if (err) return cb(err);
    for (var i = 0; i < keys.length; i+=2) {
      if (creds[i]) {
        return cb(null,crypto.createCredentials({
          key: creds[i],
          cert: creds[i+1]
        }));
      }
    }
    return cb(null, null);
  });
}

function getTarget(domain, cb) {
  var keys = ['target:' + domain];
  var components = domain.split('.');

  // We go to length - 1 because nobody's going to own the TLD
  // There may be other public suffixes we'll disallow, but this one
  // we can 100% not do
  for (var i=1; i < components.length - 1; i++) {
    keys[i] = 'target:*.'+components.slice(i).join('.');
  }
  db.mget(keys,function(err, targets) {
    if (err) return cb(err);
    for (var i = 0; i < keys.length; i++) {
      if (targets[i]) return cb(null,targets[i]);
    }
    return cb(null, null);
  });
}

function respondError(err, req, res){
  res.statusCode = 500;
  // TODO: handle error object
  res.end();
}

function respondNotFound(req, res){
  res.statusCode = 404;
  res.end();
}

function forwardRequest(req, res) {
  getTarget(req.headers.host, function(err, target) {
    if (err) return respondError(err, req, res);
    if (target) return proxy.web(req, res, {target:target});
    else return respondNotFound(req, res);
  });
}

function redirectToHttps(req, res) {
  var host = req.headers.host;
  if (host) {
    res.statusCode = 301;
    res.setHeader('Location', 'https://' + host + req.url);
    res.end();
  } else {
    // They're not following the HTTP/1.1 spec - should this just be a 400?
    respondNotFound(req, res);
  }
}

https.createServer(serverOpts,forwardRequest);
http.createServer(serverOpts,redirectToHttps).listen(80);
