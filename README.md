# libpcap_packet_analysis
基于libpcap对捕获的数据包载入并分析处理，最后做进一步可视化分析

读取基本数据存库，将每条记录的捕获记录序号、源IP地址、目标IP地址、源端口、目标端口、协议类型、净荷长度写入数据库表中；读取http-request表的载荷，将其拆分为get、host、url、Cookie等字段；最后，采用MVC web系统展示数据并做进一步的表格数据查询，与前端数据接口进行通信，实现登录认证、统计功能、复现功能、解析功能。

第三部分以及数据库，需要的可以联系，由于文件内容较大，依赖的数据包比较多，不方便上传
