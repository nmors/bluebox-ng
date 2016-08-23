// Copyright Antonio Carrasco <ancahy2600 gmail com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

'use strict';


// Private stuff

const sip = require('sip');
const lodash = require('lodash');
const fs = require('fs');
const crypto = require('crypto');
const logger = require('../utils/logger');

const pathSocket = process.env.HOME + '/.bluebox-ng';
const HELP = {
  description: 'Crack password of SIP captured sessions',
  options: {
    sipSessions: {
      type: 'fileSessions',
      description: 'File with SIP sessions created by sipDump',
      defaultValue: `${pathSocket}/sessionsSip.json`,
    },
    passwords: {
      type: 'userPass',
      description: 'Password (or file with them) to test',
      defaultValue: 'file:../artifacts/dics/passSIP.txt',
    },
  },
};


function crackPasswordDigest(objSIP,sipMethod,sipPass){

  let textToMD5A;
  let textToMD5B;
  let textToMD5Resp;
  let hashStringA;
  let hashStringB;
  let hashStringResp;

  textToMD5A=[objSIP.username,objSIP.realm,sipPass].join(':').replace(/\"/g,"");
  //console.log(textToMD5A);
  textToMD5B=[sipMethod,objSIP.uri].join(':').replace(/\"/g,"");
  //console.log(textToMD5B);
  hashStringA=crypto.createHash('md5').update(textToMD5A).digest('hex');
  hashStringB=crypto.createHash('md5').update(textToMD5B).digest('hex');
  textToMD5Resp=[hashStringA,objSIP.nonce.replace(/\"/g,""),hashStringB].join(':');
  //console.log(textToMD5Resp);
  hashStringResp=crypto.createHash('md5').update(textToMD5Resp).digest('hex');

  return hashStringResp;
}


// Public stuff

module.exports.help = HELP;
module.exports.run = (options, callback) => {
  //console.log(options);
  let objSessionSIP;
  let contPassFind = 0;
  fs.readFile(options.sipSessions, 'utf8', (err, data) => {
    if (err) throw err;
    objSessionSIP = JSON.parse(data);
    lodash.each(objSessionSIP, (v, k) => {
      logger.bold('Cracking password:');
      logger.json(v);
      logger.info('');
      options.passwords.some(function(p) {
        //console.log(p);
        let respTmpCrack;
        respTmpCrack = crackPasswordDigest(v.data,v.method, p);
        //console.log('Intento: ' + p + " -> " + respTmpCrack);
        if (respTmpCrack === v.data.response) {
          logger.highlight(`Password match: ${p} \n`);
          contPassFind ++;
          return true;
        }
      });
    });
    callback(false,{Passwords: contPassFind});
  });
  //callback(false, listDictSessionResponse, 'sessionCrack');

};
