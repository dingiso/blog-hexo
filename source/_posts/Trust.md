---
title: Shattered Chain of Trust
date: 2021-07-10 23:12:39
tags:
---

# Shattered Chain of Trust: Understanding Security Risks in Cross-Cloud IoT Access Delegation

#### 关键词：Cross-cloud & Delegation  & Real-Worlds

<!--more-->

## 简介

作为主要的IoT服务平台，IoT云使得IoT用户能够远程控制设备（这种远程控制甚至可以跨越不同的IoT云平台）。支撑这种跨云平台的设备访问及其权限控制的是各个IoT云平台的授权机制。然而，由于缺少跨IoT云平台授权的行业标准，现有的授权机制往往由各厂商自己开发设计。而统一接口、安全协商机制等的缺失，使得现有的IoT授权机制存在严重安全隐患。本研究工作针对上述问题，对主流IoT云平台的授权机制的安全问题进行了系统性的研究，提出了基于形式化安全验证的授权机制漏洞检测方法，开发了半自动检测与验证工具（VerioT），首次对包括Google Home、Philips Hue、MiHome、Samsung SmartThings等在内的10个主流IoT平台的跨云授权机制进行了详细的安全评估，发现了设备敏感信息泄露、授权数据泄露、OAuth令牌泄露、授权API滥用等多个漏洞。利用这些漏洞可以实现对智能门锁、智能开关、智能灯泡等各种智能家居设备的恶意控制，使得高达数百万用户的智能家居系统和服务受到严重的安全威胁。通过PoC攻击验证和对攻击过程的系统性分析研究，进一步提出了设计安全的跨云IoT授权机制所要遵循的原则。

### Inroduction

IoT 代理机制存在漏洞， 利用自己开发的半自动验证工具进行了实地的验证

这种漏洞可能存在于攻击者假冒设备，有权限的公司员工

行业还未有标准性的解决方法，但本文提出了一些准则

（进程间调用文件的权限链-IoT设备形式更多，使用的权限协议更加复杂）

设计一种能包含所有权限的机制，还是分成类来表示权限等级或（不同用处）

不同的厂商使用不同的权限协议，而那些标准代理协议（比如WAVE）再实际环境需要很长实践部署和起作用，所以首先要做的，还是对现有代理协议的深入分析

这些攻击可能产生的后果是十分严重的，从失去对设备的控制到被攻击者获取到敏感的设备ID以通过伪装解锁受害者的门锁

举了几个例子：

* 绕过 Tuya Cloud ， 通过使用已在Tuya上失效的OAuth Token，在其他平台访问设备

方法：

* 设计了一个半自动验证工具 VerioT，进行对IoT代理系统的模型检查
  * 手工对于手册和app的分析太繁琐了，所以将其抽象化为**基本的委托类型**和**对应的数据流**，这些对于不同的平台都是大致一样的
  * 利用现有的委托系统进行定制和升级，并利用 Spin 对其进行检查，任何反例都可能代表可能的攻击途径，以判断系统中的弱点 （all except one ？）

成功发现了常用IoT 中的6个高危漏洞

### 贡献

* 对于IoT设备权限委托的首个**系统性分析**
* IoT委托系统的形式化验证 - 文中的委托系统的**基础模型，委托操作模板，安全特性，改良技术**都能很好的帮助委托系统逐步发展

### Cloud-based IoT access

![Complex Delegation in IoT](https://securitygossip.com/images/2020-09-27/fig1.PNG)

#### 设备注册和用户操作：

* 设备通过内置的出厂信息注册到设备供应商或者提供服务的第三方云上
* 云验证用户身份，并将其发出的指令转发给设备， 或者可以设置触发条件（回家灯亮） 使设备自动运行

#### 权限委托

* 为了使用户可以方便管理不同厂商的设备，所以出现了将权限委托给 Google Home 的操作
* 这种委托表现为 用户（或app？）可以利用  token 访问并控制连接在厂商云的设备
* 拿 OAuth token 举例
  * 登入 Google Home 的app
  * 输入厂商云账户的密钥（凭证信息）
  * 如果通过认证，厂商云会生成access token给 Google Home 作为一种接口访问设备

#### 代理委托链

1. 设备权限给了厂商云
2. 厂商云把权限交给了受委托的云（Google Home）
3. 受委托的云又把权限交给了其他受委托的云
4. 5.云把权限交给了用户


6. 用户把权限又给了其他的云

> **个人拙见**： 个人觉得 3以后的操作都是有风险的，应该转化为 以厂商云为中心，任何权限操作都应该直接与厂商云交涉（问题可能存在于下面2.3.2.2），同时获得的权限是与设备（实例）绑定的，Google Home 得到的权限只有他才能使用

#### 跨云委托机制

* OAuth ：比如Google，获取到设备ID，名字等来对设备进行操作
* Custom：定制的，可能自组织的 - 比如SmartThings 通过秘密的URL来控制设备，厂商需要上传一个SmartApp（？）

**个人拙见:** 代理链的安全性 和 安全协议的杂糅和复杂性是一个很严重的问题

### 2.3  安全需求

1.  安全且具有一致性的委托协议
    1. 问题 ：不同厂商的安全约束不同
    2. 要求： 能适应不同安全约束且具有一致性的协议
2.  不可绕过且可传递的委托控制
    1. 全面性： 安全由多方共同保证
    2. 链：比如 a->b->c->d 如果取消了b的权限，那么cd也要撤销

### 2.4 威胁模型

用户模型：

* 系统管理员，IoT云 - 可信任的
* 被授权的用户 - 有危害的
  * 能够获取凭证和其他有用信息，例如发出请求、从日志文档中提取信息、捕获流量等
  * 无法窃听其他各方之间的通信

权限可以委托给其他用户

## 2 跨云IoT委托的安全性

对 10 个主流的IoT云进行分析，总结了五大漏洞，并将其分为两大类

### 2.1 云之间缺少协调

#### 漏洞一：设备ID泄露

![Figure 2](https://securitygossip.com/images/2020-09-27/fig2.PNG)

SmartThings把控制权委托给 Google Home ，通过 OAuth token和 设备ID 

##### **漏洞**

* 设备ID 是 长效性的，固定的 - 是触发设备和控制它的认证token
* Google 可能将ID给只是具有 **临时访问权限** 的用户

##### **攻击**

​	Airbnb的房主将 Google Home 上设备的权限给游客，那么游客就会永远掌握了SmartThings 的设备ID，游客可以利用ID制造设备时间伪造等攻击。


> **个人拙见** ：这类似于 重放攻击 ？要具有随机性，时效性？
>
> 我觉得这也对应了作者前面说的不同的安全协议对于不同信息的重要程度的认知不同，同时我也觉得发放给不信任的用户的信息应该有时效性且跟个人信息绑定

#### 漏洞二：泄露被委托云的秘密

![Figure 3](https://securitygossip.com/images/2020-09-27/fig3.PNG)

在SmartThings上，delegator需要上传一个SmartApp的软件模块到SmartThings平台上，来帮助执行委派协议，管理设备的访问权限。例如，IFTTT云会通过分享一个秘密的URL来实现对设备访问权限的委派，当SmartThings上报一个事件时，会触发IFTTT云上的一个小程序，通过预先指定的规则来控制IFTTT云上的设备

##### **漏洞**

* 通过IFTTT SmartApp提供的API，SmartThings用户可以获取秘密URL。该URL是固定的

##### 攻击

​	在SmartThings上，一旦Airbnb的管理者将设备的权限赋给一位游客，那么IFTTT的秘密URL就会永久暴露，这个游客就可以在之后直接与IFTTT设备进行通信

### 2.2 安全政策执行不力

#### 漏洞三：暴露委托云中的隐藏设备

![Figure 4](https://securitygossip.com/images/2020-09-27/fig4.PNG)

LIFX是一个IoT设备供应商，如果委派SmartThings来管理设备，则SmartThings需要运行LIFX SmartApp。在SmartThings上，可以将用户能够访问的设备定义为一个组，称作location，其中也包含与设备关联的SmartApp，location是SmartThings设备委派的最小单元；如果管理员想要授权某个location的设备，他需要将该location的控制权赋予delegatee user。LIFX SmartApp可以授权用户仅能访问设备的子集。

##### 漏洞

* LIFX SmartApp在SmartThings云上没有得到正确的保护，SmartThings上的授权用户可以从要给location的私有存储中读取信息。如图4所示。

#### 漏洞四：OAuth 陷阱

![Figure 5](https://securitygossip.com/images/2020-09-27/fig5.PNG)

Tuya云采用标准的OAuth协议来委派Google Home对设备进行管理控制：Google Home上的用户输入Tuya凭据，如果检测通过，则Tuya会将其OAuth token转发给Google Home。

##### 漏洞

* Tuya云使用的OAuth方案不满足IoT委派机制的可传递性要求。
* Tuya云分发的设备访问OAuth token不代表用户，而代表Google

##### 攻击

如果用户在Tuya云上的访问权限被撤销，他仍可以使用其OAuth token通过Google Home来访问设备

#### 漏洞五：滥用跨云委托的API

{% asset_img Figure6.jpg Figure6 %}

Philips Hue允许被授权用户通过手机应用访问Philips Hue网桥

- 首先按下设备上按钮，开启绑定过程
- Philips应用通过本地网络从设备自动获取一个秘密token，称作whitelistID
- 用户登陆其Philips应用来从Philips云端获取OAuth token

有了这两个token，用户就可以通过Philips云来访问Hue网桥。云平台检查OAuth token，然后转发这些命令到设备，由设备检查whitelistID。如果撤销用户的访问权限，管理员只需要在云控制台上删除用户的whitelistID，即删掉设备上的whitelistID，这样用户的命令会被设备拒绝。

Philips云使用一个API接口将设备访问权限授予另一个IoT云，用户在委托云中输入其Philips凭据，然后调用该API，这会返回OAuth token以及由设备生成的新的whitelistID。这样，委托云就可以向Philips Hue云发出命令来操控设备。

##### 缺陷：

- 在撤销权限时，管理员会删除whitelstID，但委派用户的帐户仍保留在由Philips云维护的设备访问列表中。

##### 攻击：

在权限被撤销后，用户可以重新调用API接口，获得到新的whitelistID和OAuth token，仍然可以访问 Philips Hue网桥。

 ## 3. 系统建模和形式验证

![Figure 7](https://securitygossip.com/images/2020-09-27/fig7.PNG)

半自动验证工具- VerioT 检查现实世界中IoT云委托机制的漏洞

#### 主要架构

* 模型生成器：model generator
  * 为每个 dele-setting 生成工程模型
  * 以 配置文件作为输入
  * 包括参与者（ delegator and delegatee clouds, user, device） 和对应的委托操作
* 模型检查器：model checker
  * 验证预定义的安全属性
* 反例分析器：counterexample analyzer
  * 生成一种反例，可能的攻击方式，具有跨系统委托的访问路径，使未经授权的用户访问设备

#### 3.2 结果

评估了主流的10个IoT跨云委托机制，发现了6类新的授权缺陷，手工确认了这些缺陷并使用真实设备实现了这五类缺陷的端到端攻击。



## Reference

[SecurityGossip](https://securitygossip.com/blog/2020/09/27/shattered-chain-of-trust-understanding-security-risks-in-cross-cloud-iot-access-delegation/)

[VerioT](http://https//sites.%20google.com/view/shattered-chain-of-trust-under/%20home?authuser=1)

[Video](https://youtu.be/R0FrXgxhyC0)

