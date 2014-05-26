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

  // If we tried the domain and any possible wildcards and got no success,
  // we didn't find a record
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

function processSelfUpdate(update) {
  // If the update content is not null
  if (update) {

    // (Re)start the HTTPS server when we get a key and cert
    if (update.key && update.cert) {
      serverOpts.key = update.key;
      serverOpts.cert = update.cert;
      startHttpsServer();
    }

    // Self updates only test for HTTPS server credentials
    // and ignore target / redirect records

  // If the update content is null
  } else {
    // Stop the HTTPS server and clear the credentials
    stopHttpsServer();
    delete serverOpts.key;
    delete serverOpts.cert;
  }
}

function processDomainUpdate(domain, update) {
  // If the update content is not null
  if (update) {
    // Create any new domain
    if (!domains[domain]) domains[domain] = {};

    // Update any target
    if (update.target) {
      domains[domain].target = message[domain].target;
      delete domains[domain].redirect;
    }
    // If not target but redirect, set redirect instead
    else if (update.redirect) {
      domains[domain].redirect = message[domain].redirect;
      delete domains[domain].target;
    }

    // Create credentials for any key + cert pairs
    if (update.key && update.cert)
      domains[domain].credentials = crypto.createCredentials({
        key: update.key, cert: update.cert
      });

  // If the update content is null
  } else {
    // Delete the domain record
    delete domains[domain];
  }
}

function updateDomains(message) {
  // there should really only be one domain per message but
  var msgDomains = Object.keys(message);
  // For the domain(s) in the message
  for (var i = 0; i < msgDomains.length; i++) {
    var domain = msgDomains[i];

    // If this is a self-content message
    if (domain == '@') {
      // process it as such
      processSelfUpdate(message[domain]);
    // Otherwise
    } else {
      // Process content for the domain
      processDomainUpdate(message[domain]);
    }
  }
}

process.stdin.resume();

var msgstream = new msgpack.Stream(process.stdin);

msgstream.addListener('msg', updateDomains);

var serverOpts = {
  // handshakeTimeout by default is 120 seconds which sounds WAY too high
  //handshakeTimeout: 20000,
  // mitigate BEAST attacks by preferring non-vulnerable ciphers
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

http.createServer(redirectToHttps).listen(80);

var httpsServer = null;

function stopHttpsServer(cb) {
  httpsServer.close(function(){httpsServer = null; cb && cb()});
}

function startHttpsServer(cb) {
  if (httpsServer) stopHttpsServer(startHttpsServer.bind(null,cb));
  httpsServer = https.createServer(serverOpts, forwardRequest).listen(443,cb);
}
