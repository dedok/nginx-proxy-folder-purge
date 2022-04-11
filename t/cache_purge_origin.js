#!/usr/bin/env node

/*
 * Copyright (C)
 */


/*
 * Description:
 * An origin server emulation. The goal of the script is working within tests.
 */
var http = require('http');
var os = require('os');

http.createServer(function (req, res) {

    setTimeout(function () {

        res.statusCode = 200;
        res.setHeader('Content-Type', 'plain/text');
        res.setHeader('Transfer-Encoding', 'chunked');

        if (req.headers['x-origin-option-vary']) {
            res.setHeader('Vary', req.headers['x-origin-option-vary']);
        }

        /** Basic URL
         */
        var l = 4;

        for (var i = 0; i < l; ++i) {
            res.write("Uptime: " + os.uptime() + "\n");
        }

        res.end();

    }, 0)
}).on('connection', function (socket) {
    socket.setTimeout(10000*2);
}).listen(9999);
