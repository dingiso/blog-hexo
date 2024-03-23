---
title: μEmu
date: 2021-09-14 09:27:23
tags: Security
---

论文分析及总结
<!--more-->

## Automatic Firmware Emulation through Invalidity-guided Knowledge Inference

### Introduction

不像现存的工作为每个外设建立一个通用的模型，该文章着眼于正确模拟外设的每一个独立的存取点

`( individual peripheral access points )`

```mermaid
graph LR
A(图片) --> B(符号化寄存器) -- 推理规则 --> C(知识库)

```

MCU的代码可以分为三个部分：

* 处理核心人物逻辑的 task code  ( in firmware )
* 处理外部事件的 kernel 和 driver code

> task code , kernel & driver 三者的相对位置和调用关系

代码的常常出问题在 task & driver code （可能因为kernel 是另一个研究领域的，或者有些根本没有kernel)

#### Challenge

动态分析MCU固件的 task code 很难，因为他需要依赖

* 引导时的运行时环境
* task 直接调用的驱动功能

所以需要模拟器模拟 MCU SoCs 的 task code ，这需要很多人力。

> 引导(bootstrap) ：启动时进行开机自检（POST）、初始化[周边设备](https://zh.wikipedia.org/wiki/周邊裝置)、然后加载[操作系统](https://zh.wikipedia.org/wiki/操作系统)。一些嵌入式系统直接运行存储在[ROM](https://zh.wikipedia.org/wiki/ROM)中的可执行程序
>
> 运行时环境（Runtime Environment）：软件库，环境变量，系统资源等

#### Conducted Research

* 将不支持的外设转发给真实的硬件
  * 大规模不行
* 模拟抽象层，固件依赖抽象层运行 - 
  * 需要生态支持，不支持定制SOC
  * 不好解耦固件和驱动的安全测试
  * 没有对外设逻辑的测试
* 全系统模拟 无需硬件 所以可以在硬件不可知时实现高保真度的模拟
  * 不能模拟复杂的例子 
  * P2IM 需要盲猜读状态寄存器的反应，所以搜索范围太大了-不实际
  * Laelaps :  只能找到短期未来的好的选择，长期来说未必好。
  * 两者都可能会崩溃或死机

失败的原因在于任一时刻外设的动作由多个寄存器状态共同决定的 

问题的重点在于缺乏**固件语义** 。P2IM 将每一个外设和外设存取单独考虑，而没有将多个寄存器依赖考虑。因为仅使用观察的方法会丢失掉很多**上下文信息**。

#### Our idea

模拟整体的硬件行为，包括外设。在每个存取点**考虑依赖**的进行回复，实现这个目标需要回答两个问题

* 如何判断外设输入是否是适当的
* 如何获得适当的外设输入

本文有以下观点：

1. 固件收到的反应不正确时，执行阶段应该反射出错误，并进入一种失效状态
2. 失效的执行状态直接反应为一条失效的路径

为了防止执行到失效的路径,符号化外设的响应

> When the SR register was accessed, the response to it is dependent upon the value of the CR register at that moment
>
> 我理解的是，当存取SR寄存器时，已知SR的值，所以操作取决于CR的值。- 这句话是为了表述我们对一个寄存器操作时，可能触发此代码段/interrupt，所以要根据CR判断是否触发

### Vocabulary

|                |            |
| -------------- | ---------- |
| leverage       | 影响       |
| peripheral     | 外设       |
| heuristic      | 启发法     |
| empirically    | 经验地     |
| knowledge base | 知识库     |
| integrate      | 融入       |
| mitigation     | 缓解，减轻 |
| propose        | 提议，建议 |
| agnostic       | 不可知     |
| fidelity       | 精确       |
| code snippet   | 代码段     |
