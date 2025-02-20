---
title: Gem5 演讲稿
date: 2021-01-13 08:05:34
tags: [sim,gem5,risc-v]
description: 演讲稿
---

本文是 gem5 视频搭配的演讲稿的部分内容
[视频地址](https://www.bilibili.com/video/BV155411J7gY?from=search&seid=12575992805936022279)

[slides地址](https://github.com/isrc-cas/PLCT-Open-Reports/blob/master/20210120-Gem5-LuRuibo.pdf)

<!--more-->

# Gem5 演讲稿

### Atomic

1. **计时**-计时访问是最详细的访问。它们反映了我们为实现实际时间所做的最大努力，并包括排队延迟和资源争用的建模。一旦在将来的某个时间点成功发送了计时请求，则发送请求的设备将无法获得响应，或者如果无法完成请求，则将获得NACK（以下更多内容）。定时和原子访问不能在内存系统中共存。
2. **原子**访问-原子访问比详细访问要快。它们用于快速转发和预热缓存，并返回大约时间来完成请求，而不会引起任何资源争用或排队延迟。发送原子访问后，将在函数返回时提供响应。原子和定时访问不能在内存系统中共存。
3. **功能性**-与原子性访问一样，功能性访问是瞬间发生的，但是与原子性访问不同，它们可以与原子性或定时访问共存于存储系统中。功能性访问用于诸如加载二进制文件，检查/更改模拟系统中的变量以及允许将远程调试器附加到模拟器之类的事情。重要说明是设备接收到功能访问时，如果它包含一个数据包队列，则必须在所有数据包中搜索该功能访问正在执行的请求或响应，并且必须对其进行适当更新。该`Packet::intersect()`和`fixPacket()`方法可以帮助这一点。

### O3 Cpu

Fetch：在每个周期获取指令，并根据所选策略选择要从哪个线程获取信息。在此阶段，首先创建DynInst。还处理分支预测。

Decode:  处理PC相关的无条件分支的处理

Rename：利用PR File,两种情况会终止： 没有足够寄存器来重命名，后续资源已经用完(序列化指令 )

IEW ： 将指令分派给指令队列，告诉指令队列发出指令，执行并写回指令

Commit: 处理指令可能引起的任何故障。还可以在分支预测错误的情况下处理重定向前端。

E in E : 最后执行存在潜在的错误，这些错误不会在程序结果中显示。其次，通过在流水线的开始执行，指令全部按顺序执行，那么乱序的load interaction负载交互会丢失。我们的模型能够避免这些因流水线设计产生的不足并提供准确的时序模型。

Template Policy: 利用模板来实现多态性，主要是利用 Impl 定义类，优点是不需要传统虚拟函数/基类。主要缺点是必须在编译时完全定义CPU，并且模板化的类需要手动实例化。

ISA 独立性： 将代码分为 与 ISA 无关和ISA有关的代码，提高复用性

分支预测：分支是错误时，通知 commit stage 压缩ROB内不用的代码

### CLassic Memory System

**MOESI:**  数据一致性协议 Owned 状态省一次读

express snoops: 原子的，能瞬间返回，在时序模式也可以使用，防止泛洪

cache： 内存映射数据包和侦听数据包。内存映射的请求在内存层次结构中向下，而响应在内存层次结构中向上（相同的路由返回）。侦听请求在缓存层次结构中沿水平方向移动，侦听响应在层次结构中沿水平方向向下（相同的路由返回）。普通监听在水平方向上运行，而快速监听则在缓存层次结构中。

### Ruby

SLICC :  代表用于*实现缓存一致性的规范语言*。本质上，缓存一致性协议的行为类似于状态机。SLICC用于指定状态机的行为。并可施加某种约束。例如，SLICC可以限制单个循环中可能发生的转换数量。除了协议规范外，SLICC还将内存模型中的某些组件组合在一起。如下图所示，状态机从互连网络的输入端口获取输入，并在网络的输出端口将输出排队，从而将缓存/内存控制器与互连网络本身连接在一起。

sequencer： Sequencer类负责向处理器子系统（包括缓存和片外内存）提供来自处理器的加载/存储/原子内存请求。当每个内存请求由内存子系统完成时，也会通过定序器将响应发送回处理器。系统中模拟的每个硬件线程（或内核）都有一个定序器

Replacement Policies： LRU 和 Pseudo-LRU

TOPAZ -该模拟器已准备好在gem5中运行，并在原始的ruby网络模拟器上添加了大量功能。



