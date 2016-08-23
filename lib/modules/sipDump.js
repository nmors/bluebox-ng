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

const fs = require('fs');
const sip = require('sip');
const pcap = require('pcap');
const lodash = require('lodash');
const logger = require('../utils/logger');
const net = require('net');
const readline = require('readline');

const pathSocket =  process.env.HOME + '/.bluebox-ng';
const HELP = {
  description: 'Capture SIP Authentications',
  options: {
    interface: {
      type: 'interface',
      description: 'Interface to listen on',
      defaultValue: 'eth0',
    },
    filter: {
      type: 'filter',
      description: 'BPF packet filter',
      defaultValue: 'udp and port 5060',
    },
    file: {
      type: 'file',
      description: 'File name to save SIP sessions',
      defaultValue: `${pathSocket}/sessionsSip.json`,
    },
    socket: {
      type: 'socket',
      description: 'File socket for IPC',
      defaultValue: 'blueboxSipDump.sock',
    },
  },
};


// Public stuff


module.exports.help = HELP;
module.exports.run = (options, callback) => {
  //Avoid reinit the module
  try {
      fs.accessSync(`${pathSocket}/${options.socket}`, fs.F_OK);
      console.log('Ya hay sercivio');
      callback('Ya hay servicio',[]);
  } catch (e) {
      console.log('No se ha arrancado servicio');
  }

  let pcapSession;
  const listSIPSessions = [];
  const listDictSessionResponse = [];
  const server = net.createServer((c) => {
    c.on('data', (data) => {
      logger.highlight(`\nCommand: ${data} `);
      if (data == 'start') {
        pcapSession = pcap.createSession(options.interface, options.filter);
        logger.highlight('Initializing sniffer...');
        pcapSession.on('packet', (rawPacket) => {
          const packet = pcap.decode.packet(rawPacket);
          const bufSIP = Buffer.from(packet.payload.payload.payload.data, 'uft8');
          const sipPacket = sip.parse(bufSIP.toString());
          const date = new Date();

          if (sipPacket !== undefined) {
            if (sipPacket.hasOwnProperty('method')) {
              const sipMethod = sipPacket.method.toUpperCase();

              logger.info(`\nTime: ${date.getTime() / 1000}`);
              logger.highlight(`${sipMethod}::SRC:${packet.payload.payload.saddr.addr.join('.')}:\
${packet.payload.payload.payload.sport} --> DST:\
${packet.payload.payload.daddr.addr.join('.')}:${packet.payload.payload.payload.dport}`);
              if (sipMethod === 'INVITE' || sipMethod === 'REGISTER') {
                if (sipPacket.headers.authorization) {
                  listSIPSessions.push({method: sipMethod, data: sipPacket.headers.authorization[0]});
                  logger.infoHigh(`\tUser:${sipPacket.headers.authorization[0].username} ->  \
MD5 Response:${sipPacket.headers.authorization[0].response}\n`);
                }
              }
            }
          }
        });
        callback(false, ['OK']);
      } else if (data == 'stop') {
        logger.highlight('Stop sniffer...');
        pcapSession.close();
        lodash.each(listSIPSessions, (v, k) => {
          let tmpResponse = {
            session: k +1,
            method: v.method,
            data: v.data,
          };
          listDictSessionResponse.push(tmpResponse);
        });
        //logger.infoHigh('\n\n');
        let noCuotes = JSON.stringify(listDictSessionResponse);
        fs.writeFile(options.file, noCuotes.replace(/\\"/g, ''), (err) => {
          if (err) {
            //throw err;
            callback(true, [err]);
          } else{
            logger.info(`Hash saved on ${options.file}`);
            callback(false, ['OK']);
          }
        });
      } else {
        logger.error('Command not found');
      }
    });

  });

  //server.on('error', (err) => {
  //  callback(true, err);
  //  throw err;
  //});
  server.listen(`${pathSocket}/${options.socket}`, (err) => {
    logger.info('sipDump: Listening for commands...');
    callback(false, {resource: options.socket});
    //console.log('Listening for commands:');
  });

  server.on('error', (e) => {
    if (e.code == 'EADDRINUSE') {
      callback('sipDump is in use', []);
    } else {
      callback(e,[]);
    }
  });






  /*
  const pcapSession = pcap.createSession(options.interface, options.filter);
  const listSIPSessions = [];
  const listDictSessionResponse = [];
  pcapSession.on('packet', (rawPacket) => {
    const packet = pcap.decode.packet(rawPacket);
    const bufSIP = Buffer.from(packet.payload.payload.payload.data, 'uft8');
    const sipPacket = sip.parse(bufSIP.toString());
    const date = new Date();

    if (sipPacket !== undefined) {
      if (sipPacket.hasOwnProperty('method')) {
        const sipMethod = sipPacket.method.toUpperCase();

        logger.info(`\nTime: ${date.getTime() / 1000}`);
        logger.highlight(`${sipMethod}::SRC:${packet.payload.payload.saddr.addr.join('.')}:\
${packet.payload.payload.payload.sport} --> DST:\
${packet.payload.payload.daddr.addr.join('.')}:${packet.payload.payload.payload.dport}`);
        if (sipMethod === 'INVITE' || sipMethod === 'REGISTER') {
          if (sipPacket.headers.authorization) {
            listSIPSessions.push({method: sipMethod, data: sipPacket.headers.authorization[0]});
            logger.infoHigh(`\tUser:${sipPacket.headers.authorization[0].username} ->  \
MD5 Response:${sipPacket.headers.authorization[0].response}\n`);
          }
        }
      }
    }
  });
  */
  /*
  localRl.on('line', (line) =>  {
    pcapSession.close();
    //localRl.close();
    lodash.each(listSIPSessions, (v, k) => {
      //  logger.infoHigh(`${k + 1}) ${v.username} | ${v.uri} | ${v.response}`);
      let tmpResponse = {
        session: k +1,
        method: v.method,
        data: v.data,
      };
      listDictSessionResponse.push(tmpResponse);
    });
    //logger.infoHigh('\n\n');
    let noCuotes = JSON.stringify(listDictSessionResponse);
    fs.writeFile(options.file, noCuotes.replace(/\\"/g, ''), (err) => {
    if (err) throw err;
      console.log('It\'s saved!');
      callback(false, listDictSessionResponse);
    });
    //callback(false, listDictSessionResponse);
  });
   */
  /*
  //process.stdin.setRawMode(true);
  process.stdin.on('keypress', (str, key) => {
    //if (key.name === 'l') {
    //console.log(key);
    if (key && key.meta && key.name == 'l') {
      pcapSession.close();
      //logger.info('\nSessions:');
      //logger.infoHigh('\n\n');
      lodash.each(listSIPSessions, (v, k) => {
        //  logger.infoHigh(`${k + 1}) ${v.username} | ${v.uri} | ${v.response}`);
        let tmpResponse = {
          session: k +1,
          method: v.method,
          data: v.data,
        };
        listDictSessionResponse.push(tmpResponse);
      });
      //logger.infoHigh('\n\n');
      let noCuotes = JSON.stringify(listDictSessionResponse);
      fs.writeFile(options.file, noCuotes.replace(/\\"/g, ''), (err) => {
      if (err) throw err;
        console.log('It\'s saved!');
        callback(false, listDictSessionResponse);
      });
      //callback(false, listDictSessionResponse);
    }
    //if (key.ctrl && key.name === 'c') {
    //    process.emit('SIGINT')
    //}
    //process.stdout.write('.')
  });
  */
};
