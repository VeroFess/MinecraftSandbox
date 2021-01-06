# MinecraftSandbox
一个用于增强在使用第三方Mod时的Minecraft游戏的安全性的程序。

A program used to enhance the security of Minecraft games when using third-party Mods.



(c) 2020 Binklac Workstation. All rights reserved.


## Windows 环境
---

**注意， 在Windows下，该程序需要管理员权限！**

```
Useage For Windows: SandboxLauncherWindows.exe
        [/D path] [/J java-program] [/P parameters-for-java]
        [/F filename-or-path1,access;filename-or-path2,access;...]
        [/Remap filename-or-path1,destination;filename-or-path2,destination;...]
```


- ```/D path ```

        指定一个工作目录。

- ```/J java-program```

        java.exe或者javaw.exe的位置，注意，应当尽可能的使用绝对路径。

- ```/P parameters-for-java```      

        java.exe或者javaw.exe的参数，沙盒将会原封不动的将它们传递给Java

- ```/F filename-or-path1,access;filename-or-path2,access;...```

        设置文件或目录的权限，使Minecraft可以读取或写入它们。
        可选的权限有R, RW, N。
        R: 允许读取该文件但不可写入该文件
        W: 允许读取和写入该文件， 在Windows上，这个标志将会扩展到"完全控制"
        N: 对该文件没有任何权限，任何针对文件的操作将会得到一个权限异常

        当输入的目标为一个目录的时候，对该目录的权限将会应用到其子目录及内部文件上
        在分配权限时，应当遵守最小权限原则，只应该对必要的文件和目录设置对应的权限
        最简单的方法是给予Java和Minecraft目录读取权限，并且给予存档目录和配置文件目录写入权限

- ```/Remap filename-or-path1,destination;filename-or-path2,destination;...```

        强制重定向Minecraft对某个文件或者目录的读写操作，用于强制性版本隔离。
        注意: 当前版本未实现该功能，需要使用请切换至Dev-1.7分支
