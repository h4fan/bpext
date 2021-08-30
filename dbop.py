#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3,datetime

from rpcconfig import DbLogName, Log2dbDbName

db_str = DbLogName


def gettime():
    timenow = (datetime.datetime.utcnow() + datetime.timedelta(hours=8))
    timetext = timenow.strftime('%Y/%m/%d %H:%M:%S') + " UTC+8"
    return timetext

def markrecord(dns):
    conn = sqlite3.connect(db_str)
    c = conn.cursor()

    c.execute("update scanresult set status=1 where dns = ?",(dns,))
    # may lost some data

    conn.commit()
    conn.close()
    return 

def dbgetunmarkresultbydns(dns):
    conn = sqlite3.connect(db_str)
    c = conn.cursor()

    c.execute("select * from scanresult where dns = ? and status = 0",(dns,))

    values = c.fetchall()
    result_json = []
    for row in values:
        result_json.append({"dns":row[0],"requrl":row[1],"reqcontent":row[2],"scantype":row[4]})

    conn.commit()
    conn.close()
    return result_json



def loghttp(dns, requrl, reqcontent, scantype):

    conn = sqlite3.connect(db_str)

    c = conn.cursor()
    status = 0
    scandate = gettime()

    c.execute("insert into scanresult values(?,?,?,?,?,?)",(dns,requrl,reqcontent,status,scantype,scandate))

    conn.commit()
    conn.close()


def logvul(requrl, reqcontent, scantype):

    conn = sqlite3.connect(db_str)

    c = conn.cursor()
    status = 3
    scandate = gettime()
    dns = ""

    c.execute("insert into vulresult values(?,?,?,?,?,?)",(dns,requrl,reqcontent,status,scantype,scandate))

    conn.commit()
    conn.close()

def loghttp2db(requrl, reqmethod, reqfulldata, respheaders):

    conn = sqlite3.connect(Log2dbDbName)

    c = conn.cursor()
    logtimestamp = gettime()
    tags = ""

    c.execute("insert into reqmessage values(?,?,?,?,?,?)", (requrl,reqmethod,reqfulldata,respheaders,logtimestamp,tags))

    conn.commit()
    conn.close()


def dboplog2favdb(url, favhash, tags):
    conn = sqlite3.connect(db_str)

    c = conn.cursor()
    scandate = gettime()

    c.execute("insert into favdb values(?,?,?,?)",(url,favhash,tags,scandate))

    conn.commit()
    conn.close()