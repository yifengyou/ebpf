# clang与llvm

LLVM（Low Level Virtual Machine），即底层虚拟机。它是一个由C++编写而成的编译器基础框架，利用虚拟技术创造出编译时期、链接时期、运行时期以及“闲置时期”的最优化框架。从宏观上来讲，LLVM不仅仅是一个编译器或者虚拟机，它是一个众多编译器工具及低级工具技术的统称，它包含了一个前端、优化器、后端以及众多的函数库和模板。从微观上来讲，可以把它看做后端编译器，用来生成目标代码，前端编译器为Clang。Xcode5版本之前，编译器默认使用的是GCC，从Xcode5之后编译器默认使用LLVM。原因后面马上讲到。

CLang是一个由C++编写的编译器前端，能够编译C/C++/Objective等高级语言，属于LLVM的一部分，发布于BSD（自由软件中使用最广发的许可证之一）许可证下，其目的就是为了超越GCC。经过测试证明，Clang编译Objective-C代码的速度为GCC的3倍左右，同时它还能针对用户发生的编译错误准确地给出建议。


## 与gcc区别

* Clang比GCC编译用的时间更短，包括预处理、语法分析、解析、语义分析、抽象语法树生成的时间。
* Clang比GCC的内存占用更小。
* Clang生成的中间产物比GCC更小。
* Clang的错误提示比GCC更加友好。
* Clang有静态分析，GCC没有。
* Clang使用BSD许可证，GCC使用GPL许可证。
* Clang从一开始就被设计为一个API，允许它被源代码分析工具和IDE集成。GCC被构建成一个单一的静态编译器，这使得它非常难以被作为API并集成到其他工具中。
* GCC比Clang支持更多的语言，例如Java。
* GCC比Clang支持更多的平台。
* GCC比Clang更流行。
* 在iOS开发中，经常使用Clang将Objective-C代码转化成C++代码，从而分析代码的底层实现


## 参考

* <https://blog.csdn.net/ShockYu/article/details/102793708>
