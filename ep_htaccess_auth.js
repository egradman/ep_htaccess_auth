// htaccess based authentication for etherpad

var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
var crypto = require('crypto');
var pass = require("pass");
var fs = require("fs");
var async = require("async");

var htaccess_file = "";

if (settings.ep_htaccess_auth) {
    if (settings.ep_htaccess_auth.htaccess_file) htaccess_file = settings.ep_htaccess_auth.htaccess_file;
}

exports.authenticate = function(hook_name, context, cb) {
  console.debug('ep_htaccess_auth.authenticate');

  if (context.req.headers.authorization && context.req.headers.authorization.search('Basic ') === 0) {
    var userpass = new Buffer(context.req.headers.authorization.split(' ')[1], 'base64').toString().split(":")
    var username = userpass[0];
    var password = userpass[1];

    data = fs.readFileSync(htaccess_file, {encoding: "utf8"});
    lines = data.split("\n");
    var validated = async.some(lines, function(line, callback) {
      s = line.split(":");
      if (s.length < 2) return callback(false);
      h_username = s[0];
      h_hash = s[1];
      if (h_username != username) return callback(false);
      pass.validate(password, h_hash, function(err, success) {
        callback(success);
      })
    }, function(result){
      if (result) {
        context.req.session.user = username;
        cb([true]);
      } else {
        cb([false]);
      }
    });
  } else {
    cb([false]);
  }
};
