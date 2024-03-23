---
title: 深入理解计算机系统-RISC-V 
date: 2020-07-23 16:03:05
tags: [OS,RISC-V]
---

本文是在阅读《深入理解计算机系统-RISC-V 》后写的，主要针对risc-v架构的内容的阐述

<!--more-->

# 计算机组成与设计RISC-V 

## Chapter1 Computer Abstractions and Technology

### 1.1 Intorduction

计算机应用主要分**三**个领域 ： PC ， 服务器 ，嵌入式

在现在时代 PC 已经逐渐被 PMD（Personal Mobile Device） 所取代

本书涉猎的内容

> 高级语言如何转为机器语言，硬件如何执行程序；
>
> 软硬件接口是什么，软件如何让硬件执行特定功能；
>
> 什么决定了程序的性能，怎么提高性能，降低能耗；
>
> 并行计算的原因及其后续演进；
>
> 现代计算机架构中的八个伟大思想；

### 1.2 八个伟大的计算机思想

* 摩尔定律的发明
* 抽象化方法
* 加速常用事务
* 并行计算
* 流水线机制
* 预测机制
* 内存的金字塔结构
* 利用冗余提高可靠性

两种 底层软件： 操作系统 和 编译器

### 1.6 计算机的表现

定义时间

运行时间分为 ： 经过时间 ， 相应时间 ， 运行时间

CPU 执行时间分为 ： 单纯执行程序的时间 ， 为了执行程序 而 调用 操作系统的时间

- 时钟周期数=指令个数$$\times$$指令平均时钟个数
- clock cycles per instrunction,简称 `CPI`  为所有指令执行的时钟个数的平均

CPU 执行时间 = 指令数 * CPI * 时钟时间

评判标准

要依据不同情况而判断，如一些服务器对IO很依赖，需要软硬件综合性能，

而一些应用则可能只关注 吞吐量 或者反应时间，或者两者的组合。

所以为提高表现，你必须要知道哪些方面影响着他，从而方便找到瓶颈

提高标准

减少应用程序的时钟个数或者提高时钟频率

### 1.7 功耗墙

首先介绍了8代Intel CPU的频率和功耗走势图；需要注意的是在Pentium4（2001）时，频率达到3.6GHz,功耗达到103M，起后频率与功耗都有降低；

其次介绍单个晶体管的动态功耗(焦耳和瓦特角度）：
 Energy![\propto](https://math.jianshu.com/math?formula=%5Cpropto)1/2![\times](https://math.jianshu.com/math?formula=%5Ctimes)Capacitive load![\times](https://math.jianshu.com/math?formula=%5Ctimes) Voltages2
 Power![\propto](https://math.jianshu.com/math?formula=%5Cpropto)1/2![\times](https://math.jianshu.com/math?formula=%5Ctimes)Capacitive load![\times](https://math.jianshu.com/math?formula=%5Ctimes) Voltages2 ![\times](https://math.jianshu.com/math?formula=%5Ctimes)Frequency switched

Frequency switched和时钟频率相关；
 with regard to the Figure, how could clock rates grow by a factor of 1000 while power increased by only a factor of 30?(频率有1000倍增长而功耗只有30倍增长)
 Energy and thus power can be reduced by lowering the voltage，每代CPU都采用这种技术，即每代电压减少15%（0.0225）

In 20 years, voltages have gone from 5V to 1V, which is why the increase in power is only 30 times.(0.0225x1000=22.5![\approx](https://math.jianshu.com/math?formula=%5Capprox)30)

现代的问题是，继续降低电压会使晶体管too leaky（服务器芯片40%功耗来源于leakage）

to try to adress the power problem, designers have already attached large devices to increase cooling. and they turn off parts of the chip that are not used in a given clock cycle.
 尽管需要高昂的降温设备（300W功耗），这种方案还是应用于PC和server，而PMD则不需要；

Power  is  a challenge for integrated circuits for 2 reasons:

1. power must be brought in and distributed around the chip;现代芯片可能需要数百个ground和power的引脚
2. power is dissipated as heat and must be removed.(功耗消耗为热量需要更贵的散热设备)

> 为了解决能耗问题，引入多处理器概念，要求我们要重新编写程序以适应。

## Chapter2 计算机 “语言” 介绍

### 2.2 硬件编程语言

`add a,b,c`  将变量`b`，`c`相加后放入`a`中

每个 RISC-V 指令 只执行一个操作，最多允许三个变量

```
//例1 a = b+c+d+e
add a,b,c
add a,a,d
add a,a,e
```

> 设计理念1 ：简单有利于规整化

### 2.3 操作数

RISCV中，算术运算指令的操作数只能来自于寄存器，每个寄存器大小为64bits，只有32个

> 设计理念2：简洁就是速度

理解：当寄存器变多，硬件寻址时间会随之变长，从而降低性能；

寄存器表示方法 = X + 数字

寄存器的容量是有限的，当需要大的数据结构时，就需要存储在内存中，内存相比于寄存器要大的多，但是访问速度也有数量级的差距。

但算术指令只能操作寄存器，所以我们要先将内存中的数据读入寄存器，进行操作后，再存回内存中，其中 内存-》寄存器 称为 load，寄存器-》内存 称为 store

```assembly
#例子2 ： g=h+A[8] A为大64位数据 编译器分配 g-X20 h-X21 A的基址存在X22

ld x9, 8(x22) // 临时寄存器 x9 得到 A[8]
add x20,x21,x9 // g = h + A[8]
```

`8(x22)` 为一种内存表示法，8是偏移量，x22 存储了A数组的基址

现在大部分结构仍然采用 字节 寻址的方式，RISC-V也不例外；所以寄存器和内存都表示为0x8，0x10，0x18 等

在 64bit 中 byte 的排序问题，一般有两种方式： 大端-从大到小，小端-从小到大

RISC-V 采用小端寻址的方式

```assembly
#例子3 A[12]=h+A[8]
ld  x9,64(x22)
add x9,x21,x9
sd  x9,96(x22)
```

这种平凡的访问内存的行为称为 寄存器溢出

#### 常量 和 立即数

RISC-V 将近一半的指令需要操作 立即数 或 常量

```assembly
# 例4 ： x22+4
ld  x9,AddConstant 4(x3) // x9 = constant 4
add x22,x22,x9
```

程序编译后会将常量4 写入内存中

```assembly
# 例5：立即数指令
addi x22,x22,4 //x22=x22+4
```

注意: 对于常用的常量0 ， RISC-V 将 `0` 固定放入 `x0` 中

### 2.5 指令表示

![指令表示](https://upload-images.jianshu.io/upload_images/18610675-d358b3032c45c963.PNG?imageMogr2/auto-orient/strip|imageView2/2/w/750/format/webp)

### 2.6 逻辑指令

`左移` `右移` `AND` `OR` `XOR` `NOT` 等

### 2.7 分支指令

两个主要指令：

```assembly
// 如果相等则继续
beq rs1,rs2,L1
// 如果不等则继续
bne rs1,rs2,L1
```

#### 例6

如何将以下c语言编译为RISC-V格式

```c
// c 语言
if(i==j) f=g+h; 
else f = g-h;
```

| f    | g    | h    | i    | j    |
| ---- | ---- | ---- | ---- | ---- |
| x19  | x20  | x21  | x22  | x23  |

```assembly
// RISC - V 
bne x22,x23,Else
add x19,x20,x21
Else: sub x19,x20,x21
Exit:
```

#### 例7 - loops

```c
while(save[i]==k) i+=1;
```

| i    | k    | 数组基址 |
| ---- | ---- | -------- |
| x22  | x24  | x25      |

```assembly
Loop: slli x10,x22,3 # x10 = i*8 左移三位
add x10,x10,x25 # x10 = save[i]的地址
ld  x9,0(x10) # x9 = save[i]的值
bne x9,x24 Exit #如果 save[i]！=k 退出
addi x22,x22,1 # i=i+1
beq x0,x0,Loop #回到开始
Exit:
```

**名词解释：**  基本块（ basic block）

基本块就是一系列除了结尾就没有分支，除了开始姐们为分支标签的语句，通俗来说，只要基本块中第一条指令被执行了，那么基本块内所有执行都会按照**顺序**仅**执行一次** 。编译的第一步就是将程序分成基本块

#### 其他分支语句

`blt`   和  `bge`   将寄存器的值当做    补码    进行比较

`bltu` 和 `bgeu` 将寄存器的值当作无符号数进行比较

```assembly
# if x20>=x11 or if x20 negative
bgeu x20,x11,IndexOutOfBounds
```

### 2.8 计算机硬件对过程的支持

**过程**或者**函数**是用来结构化程序的工具，使用过程能够让程序变得易读且增强代码的重用性，程序员只需要关注任务的一部分。参数可以用来传递和返回值，可以用作过程和其他程序的接口。我们可以认为过程就像一个执行秘密任务的间谍，获取所需资源、执行任务、掩盖行踪，最后带着结果回到原处。任务完成后就不再干涉其他任务。同样我们可以将过程的执行分为六步 :

1.  将参数放在过程能访问的地方
2.  将控制交给过程
3.  获取需要的存储资源给过程
4.  完成预定的任务
5.  将结果放到调用程序能访问的地方
6.  将控制交回源点

由于寄存器是在计算机中最快的存储器，程序应尽可能使用寄存器。RISC-V提供了一些寄存器来给调用过程时使用 :

- `x10`-`x17` : 存储需要传递的参数 和 返回值
- `x1` : 存储过程调用源点的地址

除了分配了这些寄存器，RISC-V提供了一条跳转链接指令jal。

```assembly
jal ProcedureAddress
```

jal ： 跳转 并 连接 程序结构，主要完成

* 跳转到`ProcedureAddress`继续执行
* 将`ProcedureAddress` 保存到 `x1` 寄存器

被执行的过程取到x1地址，并继续执行

```assembly
jalr x0,0(x1)
```

或 直接进行无条件跳转

```assembly
jal x0,Label
```

---

如果一个过程需要用到多个寄存器，使用完成后还需要恢复，存储多个值是，就需要使用**堆栈**

例如

```c
long long int leaf_example(long long int g,long long int h,
                           long long int i,long long int j)
{
    long long int f;
    f=(g+h)-(i+j);
    return f;
}
```

翻译为汇编语言

```assembly
leaf_example:
addi sp,sp,-24
sd x5,16(sp)
sd x6,8(sp)
sd x20,0(sp)

add x5,x10,x11
add x6,x12,x13
sub x20,x5,x6
addi x10,x20,0

ld x20,0(sp)
ld x6,8(sp)
ld x5,16(sp)
addi sp,sp,24
jaalr x0,0(x1)
```

其中  **g/h/i/j对应x10/x11/x12/x13，f对应x20**

#### 寄存器分类

RISC-V 将 19 个临时寄存器分为两类

* x5-x7 and x28-x31 ： 在过程调用时不会被调用方保存的
* x8-x9 and x18-x27 ： 在过程调用时一定会被保存的

所以  line3/4/13/14 store和load 的操作可以省去

#### 嵌套程序

如果程序 调用其他的函数，我们很好理解，但是 如果调用自己，形成递归过程，我们就要特殊注意了

**例子 ： 递归**

```c
long long int fact(long long int n){
  if(n<1) 
      return(1)
  else 
      return (n*fact(n-1))
}
//parameter n存在x10中
```

```assembly
FACT:
  addi sp,sp,-16   //adjust stack for 2 items
      sd   x1,8(sp)    //save the return address
      sd   x10,0(sp)   //save the argument n

      addi x5,x10,-1   //x5=n-1
      bge  x5,x0,L1    //if(n-1)>=0,go to L1

      addi x10,x0,1    //return 1
      addi sp,sp,16    //pop 2 items off stack
      jalr x0,0(x1)    //return to caller

L1: 
  addi x10,x10,-1  //n>=1: argument gets(n-1)
      jal  x1,FACT     //call fact with(n-1)

      addi x6,x10,0    //return from jal:move result of fact(n-1) to x6
      ld   x10,0(sp)   //restore argument n
      ld   x1,8(sp)    //restore the return address
      addi sp,sp,16    //adjust stack point to pop 2 items

      mul  x10,x10,x6  //return n*fact(n-1)
      jalr x0,0(x1)    //return to the caller 
 
```

​     注意jal、jalr，ld 等指令指挥这指令跳来跳去，并且将stack的参数一步步的推出；

C语言变量可以按照2类分：

- 类型
  - 数字
  - 字符
- 生命周期
  - automatic
  - static

automatic对于一个过程而言是本地的，程序调用完成后自动消失；

static则贯穿始终；一般用static标识声明；

#### 总结一下

| Preserved                      | Not Preserved                    |
| ------------------------------ | -------------------------------- |
| saved registers：x8-x9,x18-x19 | Temprary registers:x5-x7,x28-x31 |
| Stack pointer register:x2(sp)  | Argument/result register:x10-x17 |
| Frame pointer:x8(fp)           |                                  |
| Return address:x1(ra)          |                                  |
| Stack above the stack pointer  | Stack below the stack pointer    |

**在栈上为新数据申请空间**

 **Stack**被称为栈，存储程序调用的automatic型的本地变量；

>  The segment of the stack containing a procdure's saved registers and local variables is called a **procedure frame** or **activation record**.

一些RISC-V编译器使用`FP（frame pointer）`指向栈的收低值。使用FP的好处是可以很方面的定位local parameter的位置，方便调试与定位；

Stack一般是从高地址往低地址递减的；

**在堆上为新数据申请空间**

 **Heap**被称为堆，存储程序调用的static型变量；

*  Heap是从低地址向高地址增加的；
* 堆的第一个地址是保留的reserved，接着是**text segement**（the home of the RISC-V machine code），再往上就是static data segment

>  C语言中用malloc用free来分配和释放heap空间；
>  C语言这种手动分配和释放空间的机制带来了很多bug，相比JAVA则不会；

最后用一个表格来说明RISC-V寄存器的约定：

| Name    | Register number | Usage                         | Presrved on call |
| ------- | --------------- | ----------------------------- | ---------------- |
| x0      | 0               | The constant value 0          | n.a              |
| x1(ra)  | 1               | Return address(link register) | yes              |
| x2(sp)  | 2               | Stack pointer                 | yes              |
| x3(gp)  | 3               | Global pointer                | yes              |
| x4(tp)  | 4               | Thread pointer                | yes              |
| x5-x7   | 5-7             | Temporaries                   | no               |
| x8-x9   | 8-9             | Saved                         | yes              |
| x10-x17 | 10-17           | Arguments/results             | no               |
| x18-x27 | 18-27           | Saved                         | yes              |
| x28-x31 | 28-31           | Temporaries                   | no               |

### 2.9 人机交互

计算机如何显示呢，通常使用8bit的ASCII码；

为了方便字符操作，RISC-V提供了两个汇编指令

```assembly
lbu x12,0(x10) # 读
sb x12,0(x11)  # 写
```

`lbu: `无符号加载数据,将字节加载到目的寄存器的最右端；

 `sb:`  保存字节,将最右侧的字节存入内存；

**string有3种表示方式：**

1. string第一个地址保留，给出string长度；- JAVA
2. 用一个伴随变量来表示string长度；
3. 最后用一个特殊字符表示string结束； - C

RISC-V需要使用load/store 半个机器字指令来load和store一个字符；

```assembly
lhu x19,0(x10) //Read halfword from source
sh  x10,0(x11)  //Write halfword to destination
```

### 2.10 RISC-V 对于大立即数和 地址 的处理方法

### 2.11 并行 和 指令 ： 同步

数据竞争 ： 两个程序 访问同一个数据，一个未写完，一个已经开始读

> 同步机制通常是由用户级软件例程构建的，这些例程依赖于硬件提供的同步指令
>
> 软件之间通过硬件提供的同步指令来构造同步机制，
>
> 我们专注于 同步中 的 lock unlock ，这对于单处理器很容易执行

我们在多处理器中实现同步所需要的关键能力是一组具有自动读取和修改内存位置能力的硬件原语;

以atomic exchange/atomic swap为例，它主要完成两个存储之间的数值交换；

 Lock = **0**表示unlock，Lock = **1**则表示lock；

 从而引出lr.d(读取双保留字)和sc.d(存储有条件的双字)

```assembly
        addi x12,x0,1       //copy locked value
again:  lr.d x10,(x20)      //load-reserved to read lock
        bne  x10,x0,again   //check if it is 0 yet
        sc.d x11,x12,(x20)  //attempt to store new value
        bne  x11,x0,again   //branch if store fails

        sd x0,0(x20)        //free lock by writing 0
```

### 2.12 编译 和  连接 程序

本节主要讲从磁盘一段C语言文件到计算机可以执行的程序之间的4个步骤：

![img](https://upload-images.jianshu.io/upload_images/18610675-031b6a1271e0666f.png?imageMogr2/auto-orient/strip|imageView2/2/w/928/format/webp)

**Compiler**

Compiler将高级语言编译为通用的汇编（通用的汇编是因为没有目的器件）

**Assembler**

Assembler就是器件对应的编译器，将通用汇编编译成对应器件支持的汇编；

**Linker**

链接器，将源文件和 库文件，进行链接

**如何做到修改了一行代码而不用重新开始编译；**

**Dynamically Linked Libraries**

 传统的link libraries的方法是static方法，有一些缺点：

- The library routines become part of the executable code.木已成舟，再难修改；
- 所有的routines都要被load，管你要不要；

这些缺点导致了DLL(Dynamically linked libraries)的出现；

DLL,where the library routines are not linked an loaded until the program is run



 **Starting a JAVA Program**

 初步认识一些JVM和JIT吧

![img](https:////upload-images.jianshu.io/upload_images/18610675-cbac66de1d7fe674.png?imageMogr2/auto-orient/strip|imageView2/2/w/535/format/webp)

各个平台有不同的JVM，如windows JVM，UNIX JVM等，分别负责将JVM虚拟机最终解

Windows和Unix instruction；

