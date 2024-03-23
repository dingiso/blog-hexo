---
title: 在QEMU中定制RISCV指令并测试 
date: 2021-02-13 12:05:34
tags: [QEMU,RISC-V,sim] 
description: 包含在QEMU中如何定制指令和如何
---
本文主要是介绍

1. 通过QEMU中提供的Decode Tree 的方法定义指令编码
2. 定义指令的转义和指令的基础逻辑
3. 利用二进制的方式定义测试程序并测试
4. 使用 P扩展(Packed SIMD) 作为示例

<!--more-->

### QEMU 下载

为了更改QEMU的源码，我们需要正确下载源代码并自行进行编译，QEMU提供了两种方式方便我们下载。

通过 `git` 的方式下载 QEMU 的**最新**源码 - 该方式可能需要一个稳定的 "科学的" 网络

```bash
git clone https://gitlab.com/qemu-project/qemu.git
cd qemu
git submodule init
git submodule update --recursive
```

同样的，我们可以直接选择下载官网打包好的最新稳定版的QEMU源码，这能让你更稳定，快速的得到代码，但可能不是 git 同步的最新版本 - [QEMU-5.2.0](https://download.qemu.org/qemu-5.2.0.tar.xz)

```bash
wget https://download.qemu.org/qemu-5.2.0.tar.xz
tar xvJf qemu-5.2.0.tar.xz
cd qemu-5.2.0
```

通过以上方式下载过后，我们可以开始进行指令的添加了

### 指令编码 - Decode Tree

为了方便开发者和编译检查，QEMU 中的指令的二进制指令编码都是以`Decode Tree` 方式进行定义的，QEMU的内部程序在编译时会将其自动解析为 c 语言。

特别地，像 RISC-V 这种拥有固定指令格式的 ISA 特别契合 Decode Tree。因为各个指令段都在固定的位置。各个段的重复性要高很多，足以节省很多代码空间

下面我们已一种最常用的三参数指令的P扩展`add16`作为例子：

```bash
#！target/riscv/insn*.decode
#        31:25   24:20 19:15 14:12 11:7  6:0
add16    0100000 ..... ..... 000   ..... 1110111 @r
#        funct7  Rs2   Rs1  funct3  Rd   opcode
```

```c
# 其中用到的各个定义如下
# Formats 32:
@r       ....... ..... ..... ...   ..... ....... &r  %rs2 %rs1 %rd

# Fields:
%rs2       20:5
%rs1       15:5
%rd        7:5
```

一个指令的定义有以下几个过程

1. 找到官方文件对于指令编码的定义，将指令名称`add16`和二进制编码`0100000 ..... ..... 000   ..... 1110111`填入
2. 通过指令对于参数的定义，选取合适的`Format`，例如 `@r` ，就顺序包含了两个输入寄存器`rs1 & rs2` 和输出寄存器`rd`
3. 如果没有，就需要自己定义

有关decoder tree 的具体内容，接下来的博客可能会进行阐述，

但是有的 blogs 已经有了详细的阐述，qemu 官方也有，下面给出链接，大家可以参阅

QEMU官方： [Decode Tree的定义](https://qemu.readthedocs.io/en/latest/devel/decodetree.html)

其他博客的定义：[Part-1](https://0xc0de.tw/QEMU-Decodetree-%E8%AA%9E%E6%B3%95%E4%BB%8B%E7%B4%B9-Part-1/)，[Part-2](https://0xc0de.tw/QEMU-Decodetree-%E8%AA%9E%E6%B3%95%E4%BB%8B%E7%B4%B9-Part-2/)

### 指令转译 - trans 

QEMU在执行时，会将 `target instructions`(e.g. RISC-V instructions) 转译成 `TCG ops`，而`TCG ops`则会再转译为`host instructions`(e.g. x86 instruction)。而`trans_add16()` 实际执行了 `add16` 指令对应的 `TCG ops`

```bash
#！ QEMU dynamic instructions translation
+---------------------+      +---------+      +-------------------+
| Target Instructions | ---> | TCG ops | ---> | Host instructions |
+---------------------+      +---------+      +-------------------+
     (e.g. RISC-V)                                  (e.g. x86)
```

关于 `TCG` 的说明，可以参考 `QEMU` 的 `documentations` [Translator Internals](https://github.com/qemu/qemu/blob/master/docs/devel/tcg.rst)，[TCG Readme](https://github.com/qemu/qemu/blob/master/tcg/README)

为了方便定义和区分，新建一个文件`./target/riscv/insn_trans/trans_rvp.inc.c`来定义`P Extension`指令的`trans_xx()`函数

```c
#！ ./target/riscv/insn_trans/trans_rvb.c.inc
/*
 * RISC-V translation routines for the RVP Standard Extension.
 */

static bool trans_add16(DisasContext *ctx, arg_pcnt *a) {
    if (a->rd != 0) {
        TCGv t0 = tcg_temp_new();
        TCGv t1 = tcg_temp_new();
        TCGv rt = tcg_temp_new();
        
        gen_get_gpr(t0, a->rs1);   
        gen_get_gpr(t1, a->rs2);
        
        gen_helper_add16(rt, t0, t1);
        
        gen_set_gpr(a->rd, rt);
        
        tcg_temp_free(rt);
        tcg_temp_free(t0);
        tcg_temp_free(t1);
    }
    return true;
}
```

由于对`x0`(`zero register`)的写入都会被忽略，因此首先判断`rd`是否为**0**，若为**0**则不做任何事情

接着声明两个TCG variable：`t0和t1`，利用`gen_get_gpr()`将`rs1,rs2`寄存器的值存入变量

声明一个新变量 `rt`  利用 `gen_set_gpr()` 将 结果存入 `rd` 寄存器中

利用新声明的变量调用`gen_helper_add16()`函数转向`helper function`，该函数计算完成后，会将结果保存在`rd`(i.e. `cpu_gpr[a->rd]`)寄存器中。

P.S. 其实这里可以简单的直接将`cpu_gpr[a->rs1]`传入，省略TCG variable: `t0,t1` 的声明：

**注意 ： 该方法不推荐使用，我们在测试过程发现这样可能导致错误的产生**

```c
#! ./target/riscv/insn_trans/trans_rvp.c.inc
/*
 * RISC-V translation routines for the RVB Standard Extension.
 */

static bool trans_add16(DisasContext *ctx, arg_pcnt *a) {
    if (a->rd != 0) {
        gen_helper_add16(cpu_gpr[a->rd], cpu_gpr[a->rs1], cpu_gpr[a->rs2]);
    }
    return true;
}
```

### 指令的逻辑  - helper function 

```c
#define DEF_HELPER_2(name, ret, t1, t2) \
  DEF_HELPER_FLAGS_2(name, 0, ret, t1, t2)
//DEF_HELPER_FLAGS_2(name,flag,ret,t1,t2)
```

为了方便QEMU对于helper function的调用和定义，我们需要定义一个函数`DEF_HELPER_x = DEF_HELPER_FLAGS_x`  对QEMU声明函数的名称和参数, **x**代表该**指令需要的参数**-(自变量），不带 `_FLAGS` 的函数会利用命令自动将 **FLAGS**参数置为0。

* **name** ：指令的名称，连接成 `HELPER(name) / helper_name` 的形式作为 **helper function**
*  **flag**    :  函数权限位，TCG调用的权限，全局不读/写，返回值无用，无返回值。`tcg.h`
*   **ret**     :  `helper function`返回值
*  **t1- tn** ：`helper function`的参数

ret 和 t1-tn 的类型可以是，

| 类型 | 意义                                           |
| ---- | ---------------------------------------------- |
| tl   | target_ulong - QEMU中保存寄存器值得基本单位    |
| env  | environment - CPUXXSTATE 保存CPU状态寄存器的值 |
| i64  | integer-64 - 64位整型可用于浮点数指令          |

`add16`的 helper function 定义如下:

```c
#! ./target/riscv/helper.h
/* Packed-SIMD Extension */
DEF_HELPER_2(add16, tl, tl, tl)
DEF_HELPER_FLAGS_3(add16, 0, tl, tl, tl)
```

两种定义意义相同

```c
#! ./target/riscv/bitmanip_helper.c
/*
 * RISC-V P Extension Helpers for QEMU.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"

#define u16p uint16_t *

#if defined(TARGET_RISCV32)
const uint32_t LC_16BIT = 2;
#else
const uint32_t LC_16BIT = 4;
#endif

// target_ulong HELPER(add16)(target_ulong rs1, target_ulong rs2) 
target_ulong helper_add16 (target_ulong rs1, target_ulong rs2) {
    target_ulong rd = 0;
    u16p rs1_p = (u16p)&rs1;
    u16p rs2_p = (u16p)&rs2;
    u16p rd_p  = (u16p)&rd;

    for (unsigned i = 0; i < LC_16BIT; i++)
        rd_p[i] = rs1_p[i] + rs2_p[i];

    return rd;
}
```

该函数就是`add16`的实际逻辑函数，`helper function` 接受两个 `target_ulong` 类型的 `rs1&rs2`, 并将结果返回，存储在 `rd` 寄存器

`add16` 指令的内容，是将寄存器分为多个**16**位数并分别计算，因此我们将`rs1/2` 变为**16**位的数组(指针)并分别进行加法运算，得到结果然后返回。

#### 补充

为了使指令成功执行，我们还需要填写以下代码

```c
#! ./target/riscv/meson.build
riscv_ss.add(files(
  'psimd_helper.c',
))

```

```c
#! ./target/riscv/translate.c
/* Include insn module translation function */
#include "insn_trans/trans_rvp.c.inc"

```

### 指令的测试

在我们了解了指令的添加流程后，我们要对添加后的指令进行测试以确保指令的正确性。

为了成功编译，你需要事先安装`riscv64-unknown-elf-gcc`来编译测试程序，你可以通过  [riscv-gnu-toolchain](https://github.com/riscv/riscv-gnu-toolchain) 进行编译安装

下面我将介绍一下QEMU的编译过程，鉴于我们只需要QEMU的用户态测试程序，我们执行以下命令在你保存qemu的文件夹下：

```bash
mkdir build
cd build
../configure --target-list=riscv64-linux-user
make
```

`build` 文件夹用于保存你的编译结果，你也可以自由选择想要保存的文件夹。

接着我们创建一个 `p_test` 文件夹保存测试程序并进行测试, 因为原有的工具链并不含有新添加的指令，没办法编译成合适的二进制编码，所以我们使用内联汇编为其提供二进制编码，省去更改工具链的麻烦。



```c
#! ./build/p_test/add16.c

#include<stdio.h>

__attribute__((noinline))
int mac_asm(int a,int b,int c) {
        asm __volatile__ (".word 0x40c58577\n");
        asm __volatile__ ("mv  %0,a0\n"
                : "=r"(a)
                :
                :);
        printf("a=%d\n",a);
        return a;
}

int main(){
        int a=5,b=0xFFFEFFFF,c=0xFFFEFFFF;
        printf("add16:=0x%x\n  add:=0x%x\n",mac_asm(a,b,c),b+c);
        return 0;
}

```

`RISC-V` 会将函数的参数放入 `a0-a7` 寄存器中，并将 `a0` 寄存器中的值返回

<img src="https://raw.githubusercontent.com/dingiso/dingiso.github.io/main/img/reg_table.png" />

`a0-a7`  对应 `x10-x17` 和二进制编码 `10-17` ， 因此最后的指令编码如下

```ruby
# Encoding used for "add16 a0, a1, a2"
0x40c58577 [base 16]
==
# Group by related bit chunks:
0100000 01100 01011 000 01010 1110111 [base 2]
^       ^     ^     ^   ^     ^
|       |     |     |   |     |
|       |     |     |   |     opcode (6..2=0x1D 1..0=3)
|       |     |     |   dest (10 : a0)
|       |     |     funct3 (14..12=0)
|       |     src1 (11 : a1)
|       src2 (12 : a2)
funct7 (31..25=0x40)
```

为了防止在编译过程中，编译器会对寄存器进行优化，将返回值存入其他寄存器，我们使用 `mv` 指令强制将变量 `a` 的值赋给 `a0` 寄存器,这样就能成功将值返回。

```bash
riscv64-unknown-elf-gcc  -o x x.c
../qemu-riscv64 xx
```

我们利用以上指令执行，返回正确的结果

```bash
add16:=0xfffcfffe
  add:=0xfffdfffe
```

`add16` 由于每16位进行计算，所以无后**16**位的进位，中间位是`c`，而`add`由于有进位，所以是`d`

---

在QEMU中定制指令的流程大致如同本文的介绍，但是由于 `add16` 仅涉及数值的计算，而没有像

`csr` 相关指令涉及 `CPURISCVState` 的更新，以及像`jal`指令涉及`DisasContext`的判断，因此相对简单，对于其他指令，需要在好好的研究以下

>Refrences:
>
>[QEMU-使用 Decodetree新增 RISC-V 指令](https://0xc0de.tw/QEMU-%E4%BD%BF%E7%94%A8-Decodetree-%E6%96%B0%E5%A2%9E-RISC-V-%E6%8C%87%E4%BB%A4/)
>
>[RISC-V: custom instruction and its simulation](https://quasilyte.dev/blog/post/riscv32-custom-instruction-and-its-simulation/#adding-mac-instruction-to-the-rv32im)
>
>[riscv-p-spec](https://github.com/riscv/riscv-p-spec/blob/master/P-ext-proposal.adoc)

感谢在学习过程中，老师们的指导，非常感谢！！

