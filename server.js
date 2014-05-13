#!/usr/bin/env node

var https = require('https');
var http = require('http');
var crypto = require('crypto');
var msgpack = require('msgpack');

var domains = Object.create(null);

function getDomain(domain) {
  // return any credentials for this domain itself
  if (domains[domain]) return domains[domain];

  var components = domain.split('.');

  // We go to length - 1 because nobody's going to own the TLD
  // There may be other public suffixes we'll disallow, but this one
  // we can 100% not do
  for (var i = 1; i < components.length - 1; i++) {
    var wildDomain = '*.' + components.slice(i).join('.');
    // return any wildcard credentials for a higher-level domain
    if (domains[wildDomain]) return domains[wildDomain];
  }

  return null;
}

function getCredentials(domain) {
  var record = getDomain(domain);
  return record && record.credentials;
}

function getTarget(domain) {
  var record = getDomain(domain);
  return record && record.target;
}

function getRedirect(domain) {
  var record = getDomain(domain);
  return record && record.redirect;
}

function updateDomains(message) {
  // there should really only be one domain per message but
  var msgDomains = Object.keys(message);
  // For the domain(s) in the message
  for (var i = 0; i < msgDomains.length; i++) {
    var domain = msgDomains[i];
    // If there's content in the message for this domain
    if (message[domain]) {
      // Create any new domain
      if (!domains[domain]) domains[domain] = {};
      // Update any target
      if (message[domain].target) {
        domains[domain].target = message[domain].target;
        delete domains[domain].redirect;
      }
      // If not target but redirect, set redirect instead
      else if (message[domain].redirect) {
        domains[domain].redirect = message[domain].redirect;
        delete domains[domain].target;
      }
      // Create credentials for any key + cert pairs
      if (message[domain].key && message[domain].cert)
        domains[domain].credentials = crypto.createCredentials({
          key: message[domain].key,
          cert: message[domain].cert
        });
    // Delete any keys that are nulled in the message
    } else {
      delete domains[msgDomains[i]];
    }
  }
}

process.stdin.resume();

var msgstream = new msgpack.Stream(process.stdin);

msgstream.addListener('msg', updateDomains);

var serverOpts = {
  // handshakeTimeout by default is 120 seconds which sounds WAY too high
  //handshakeTimeout: 20000,
  // mitigate BEAST attacks by preferring non-vulerable ciphers
  honorCipherOrder: true,
  SNICallback: getCredentials
};

var proxy = require('http-proxy').createProxyServer({
  xfwd: true, secure: false
});

function respondError(err, req, res) {
  res.statusCode = 500;
  // TODO: handle error object
  res.end();
}

function respondNotFound(req, res) {
  res.statusCode = 404;
  res.end();
}

function respondRedirect(req, res, url) {
  res.statusCode = 301;
  res.setHeader('Location', url);
  res.end();
}

function forwardRequest(req, res) {
  var record = req.headers.host && getDomain(req.headers.host);
  if (record && record.target)
    return proxy.web(req, res, {target:record.target});
  else if (record && record.redirect)
    return respondRedirect(req, res, record.redirect);
  else return respondNotFound(req, res);
}

function redirectToHttps(req, res) {
  var host = req.headers.host;
  // If they're asking for a name we're proxying
  if (host && getDomain(host)) {
    return respondRedirect('https://' + host + req.url);
  } else {
    return respondNotFound(req, res);
  }
}

https.createServer(serverOpts, forwardRequest).listen(443);
http.createServer(serverOpts, redirectToHttps).listen(80);
