### HexRays SDK
HexRays SDK 在反汇编器里的二进制代码有2种表达形式：

+ microcode: 机器码先被转换成微码(类似LLVM IR等中间语言)，反汇编器会对它进行反复优化和转换（译者注：这个过程和LLVM IR的opt类似，机器码一开始转成的微码是未被优化的，更接近于机器码的，然后通过多次的优化PASS过程，逐步转成优化过的微码，优化过后的微码则更接近于人写出来的源码）
+ ctree: ctree是建立在充分优化过的微码的基础上的，它将二进制代码用类似抽象语法树(AST)的形式来表达，其中是由一些类似C语言的语句(statements)和表达式(expressions)组成的。它可以直接用来打印并生成C代码的。
### Microcode
microcode主要是通过下面的几个类来表示：

+ mba_t, 保存了关于反汇编代码的基础信息，以及所有基础块(Basic Block)的集合。
+ mblock_t, 一个基础块(Basic Block)，包括了该基础块内所有指令(instructions)的列表。
+ minsn_t, 一个指令(instruction)，包含了3个操作数(operands)：left, right, destination。
+ mop_t, 一个操作数，根据它的类型可能包含不同的信息，例如可能是一个数字，寄存器，栈变量等。
+ mlist_t, 内存或寄存器地址的列表。它可以包含巨大的内存区间或很多个寄存器，这个类在反汇编器中被广泛的使用。它可以表示一个指令访问的一个地址的列表或者甚至表示一整个基础块。它也被很多函数作为其参数使用。例如，一个函数用来搜索一个指令引用到一个mlist_t的列表。
更多内容可参考 IDA插件开发2 - Microcode in pictures 。
### CTree
CTree主要是通过下面的几个类来表示的：

+ cfunc_t 保存关于反汇编代码的基本信息，包含一个 mba_t 的指针，删除 cfunc_t 时也会删除 mba_t(尽管，反汇编器返回的是 cfuncptr_tr ，它是一个带引用计数的指针，会在没有外部引用时删除其下面所有包含的函数，cfunc_t 有一个函数体(body）， 用 cinsn_t 对象来表示的反汇编的函数体。
+ cinsn_t 是一个C语句，它可以是一个复杂的语句，或其他任何合法的C语句（例如if,for,while,return,expression-statement等），根据它的不同类型它可以包含一些不同的指针指向额外的信息。例如if语句有一个指针指向 cif_t ，它内部保存着 if 条件，then 分支和一个可选的else分支。请注意尽管我们称 cinsn_t 为语句（statements），而不是指令(instructions)，因为对于我们而言，指令是microcode的一部分，而不是ctree的概念。
+ cexpr_t 是一个C表达式，它通常是C语句的一部分，当需要的时候，cexpr_t 有一个type字段，它记录着表达式的类型。
+ citem_t 是 cinsn_t 和 cexpr_t 的父类，它包含一些通用的信息，例如地址，标签和操作符(opcode)。
+ cnumber_t 是一个常量64-bit数字。除了它的值之外，还包含了如何表达它的信息：十进制，十六进制，或一个常量符号（例如枚举符号），请注意在microcode中我们会使用另一个类( mnumber_t )来表达数字（m开头的都是microcode的，c开头的类都是ctree的）。 更多内容可参考 IDA插件开发3 - Hex-Rays Decompiler primer
### common
除此之外，还有一些类同时被microcode和ctree模块使用：

+ lvar_t ，是一个局部变量，可以表示一个栈或者寄存器变量。一个变量拥有一个名字，类型，位置等信息。在 mba->vars 中保存着一个变量的列表。
+ lvar_locator_t 保存着一个变量的位置 ( vdloc_t ) 和定义它的地址。
+ vdloc_t 描述一个变量的位置，例如一个寄存器的编号，一个栈的偏移，或在一个复杂的情形下可能是一个混合了寄存器和栈的位置。它和在IDA内使用的 argloc_t 很相似，argloc_t 和 vdloc_t 的不同在于：
+ vdloc_t 绝对不会使用 ARGLOG_REG2
+ vdloc_t 使用 micro 寄存器number，而不是 processor 寄存器number。
+ vdloc_t 中的栈偏移绝对不会是负数，而argloc_t则可能是负数。
上面这些就是在头文件中所有重要的类了，另外还有很多辅助的类，请查阅头文件来查看它们的定义。(译者注：请注意这里提到的这个hexrays.hpp头文件，它有一万多行代码！)


### ida py类信息
https://hex-rays.com/products/decompiler/manual/sdk/annotated.shtml


###  Hex-Rays Decompiler - User Manual
https://hex-rays.com/products/decompiler/manual/