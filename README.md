# bpext
burpsuite python extention (burpsuite python 插件)


## cspreport2me
将csp report 全部报告给我。  
用法：cspreport2me中的REPORT_API替换为你的csp report api.

## assetextract
修改版 BurpJSLinkFinder，利用referer将相对url进行拼接，得到绝对url，方便扫描。当然这种拼法会有不少误报。  
用法：将logpath修改为存放log的目录。


由于jython目前只有2.7版本，一些python的库无法使用，所以通过jsonrpc的方式，进行调用。
运行rpcstart.sh启动rpc server。可以加入到burpsuite启动脚本中。

## favscan.py
扫描favicon.ico并进行匹配识别

