#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3

from rpcconfig import Log2dbDbName
db_str = Log2dbDbName


conn = sqlite3.connect(db_str)

c = conn.cursor()

# Create table
c.execute('''CREATE TABLE reqmessage
             (requrl text,reqmethod text,reqfulldata text,respheaders text, logtimestamp text, tags text)''')


# Insert a row of data
#c.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")

# Save (commit) the changes
conn.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
conn.close()
