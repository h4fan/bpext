#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request

from flask_jsonrpc import JSONRPC, JSONRPCView 

from rpcconfig import RpcHost, RpcPort, RpcPath, RpcAuthName, RpcToken

class UnauthorizedError(Exception):
    pass


class AuthorizationView(JSONRPCView):
    def check_auth(self) -> bool:
        print(request.headers)
        username = request.headers.get(RpcAuthName)
        return username == RpcToken

    def dispatch_request(self):
        if not self.check_auth():
            raise UnauthorizedError()
        return super().dispatch_request()


# Flask application
app = Flask(__name__)

# Flask-JSONRPC
jsonrpc = JSONRPC(app, RpcPath, jsonrpc_site_api=AuthorizationView)


@jsonrpc.method('App.index')
def index() -> str:
    return 'Welcome to Flask JSON-RPC'


import mmh3, json
import requests
import codecs
from rpcconfig import Faviconhashdict
from dbop import loghttp, markrecord, logvul, loghttp2db, dboplog2favdb, dbgetunmarkresultbydns

@jsonrpc.method('faviconhash')
def faviconhash(faviconurl: str) -> str:
    response = requests.get(faviconurl, headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"},  verify = False)
    favicon = codecs.encode(response.content,"base64")
    favhash = mmh3.hash(favicon)
    if favhash in Faviconhashdict.keys():
        dboplog2favdb(faviconurl, favhash, Faviconhashdict[favhash])
        return json.dumps({"status":"ok", "data": Faviconhashdict[favhash]})
    else:
        dboplog2favdb(faviconurl, favhash, "")
        return json.dumps({"status":"error", "data": ""})

@jsonrpc.method('insertscanreq')
def insertscanreq(dns: str, requrl: str, reqcontent: str, scantype: str) -> str:
    loghttp(dns, requrl, reqcontent, scantype)
    return json.dumps({"status":"ok", "data": "insert ok"})


@jsonrpc.method('markscanresult')
def markscanresult(dns: str) -> str:
    markrecord(dns)
    return json.dumps({"status":"ok", "data": dns})

@jsonrpc.method('getunmarkresultbydns')
def getunmarkresultbydns(dns: str) -> str:
    result = dbgetunmarkresultbydns(dns)
    return json.dumps({"status":"ok", "data": result})


@jsonrpc.method('logvul')
def logvul2(requrl: str, reqcontent: str, scantype: str) -> str:
    logvul(requrl, reqcontent, scantype)
    return json.dumps({"status":"ok", "data": scantype})

@jsonrpc.method('loghttp2db')
def rpcloghttp2db(requrl: str, reqmethod: str, reqfulldata: str, respheaders: str) -> str:
    loghttp2db(requrl, reqmethod, reqfulldata, respheaders)
    return json.dumps({"status":"ok", "data": "insert ok"})


if __name__ == '__main__':
    app.run(host=RpcHost, port = RpcPort )