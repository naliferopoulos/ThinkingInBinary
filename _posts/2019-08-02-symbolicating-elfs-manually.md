---
title: "Symbolicating stripped ELF files manually"
categories:
  - Blog
tags:
  - Post Formats
  - readability
  - standard
---

Let's face the truth, debugging and pwning stripped ELFs is a tedious process. The lack of symbols means that we need to type a lot of addresses manually, which is error prone and a hassle. Wouldn't it be nice if we could add some custom symbols on the binary? Researching the process didn't yield the resources I expected, so here I am writing a guide.

### Generating a test file

Our first step would be to generate a test file.

```
//example.c

int main() {
  return 0;
}
```

And compile it. (Without PIE)

```
$ gcc -o example example.c -no-pie
```

Now if we examine the ELF's sections, we should see **.symtab**, the symbol table section.

```
$ readelf -S example

**snip**
[26] .symtab           SYMTAB           0000000000000000  00003048
       00000000000005d0  0000000000000018          27    44     8
**snip**
```

There it is! Now let's strip the binary!

```
$ strip -p -s example
```

Now if we load it into GDB, no symbols should be there for us.

```
$ gdb ./example

pwndbg> p main
No symbol table is loaded.  Use the "file" command.
```
Also note that I am using pwndbg extensions for GDB, and that is why the prompt looks funny, but all features shown here exist in the vanilla GDB.

### Identifying the address of main

One of the most common symbols on an ELF file, is the main() function. We need to examine the stripped ELF to identify it's main function. However, this process is not as straight-forward as expected, since the first code run is that of **_entry**, which calls __libc_start_main, passing in as an argument the actual entry point of the main() function. Bingo!

First, we examine the ELF header to identify the entry point.

```
$ readelf -h example

ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401020
  Start of program headers:          64 (bytes into file)
  Start of section headers:          12592 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           64 (bytes)
  Number of section headers:         25
  Section header string table index: 24
```

Aha! Our entry is at **0x401020**. Let's examine that code.

```  
$ objdump -D example -j .text

0000000000401020 <.text>:                                                                      
  401020:       31 ed                   xor    %ebp,%ebp
  401022:       49 89 d1                mov    %rdx,%r9                                        
  401025:       5e                      pop    %rsi                     
  401026:       48 89 e2                mov    %rsp,%rdx                                       
  401029:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
  40102d:       50                      push   %rax                               
  40102e:       54                      push   %rsp     
  40102f:       49 c7 c0 70 11 40 00    mov    $0x401170,%r8
  401036:       48 c7 c1 10 11 40 00    mov    $0x401110,%rcx
  40103d:       48 c7 c7 02 11 40 00    mov    $0x401102,%rdi
  401044:       ff 15 a6 2f 00 00       callq  *0x2fa6(%rip)        # 0x403ff0    
  40104a:       f4                      hlt

```

We observe that a call to what we assume to be __libc_start_main happens, with the argument **0x401102** passed through RDI. If our assumptions are correct, there should be our main(). 

```
  401102:       55                      push   %rbp                                                                                                                                            
  401103:       48 89 e5                mov    %rsp,%rbp         
  401106:       b8 00 00 00 00          mov    $0x0,%eax            
  40110b:       5d                      pop    %rbp              
  40110c:       c3                      retq           
```

Indeed, that is our empty stack frame creation code, and absolutely useless main. Now let us symbolicate the binary with our new-found knowledge.

### Symbolicating the binary

Now we need to somehow create a symbol table for our binary with a new entry for main. It's type should be that of a function, and the entry point of the symbol should be relative to the **.text** section. Luckily, objcopy can help us, but first we need to calculate how far away is our main from the start of the .text section.

We simply subtract 0x401020 (the start of .text) from 0x401102 (the start of main).

```
$ python -c "print hex(0x401102-0x401020)"

0xe2
```

Next, we will use objdump to add a *global* symbol named *main*, of type *function* to our binary.

```
$ objcopy ./example --add-symbol main=.text:0xe2,function,global ./example-with-symbols
```

We can now load our new binary into GDB and attempt to print the address of main, or disassemble it, or even break at it.

```
$ gdb ./example-with-symbols

pwndbg> p main
$1 = {<text variable, no debug info>} 0x401102 <main>

pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000401102 <+0>:     push   rbp
   0x0000000000401103 <+1>:     mov    rbp,rsp
   0x0000000000401106 <+4>:     mov    eax,0x0
   0x000000000040110b <+9>:     pop    rbp
   0x000000000040110c <+10>:    ret  
   
pwndbg> break main
Breakpoint 1 at 0x401106

pwndbg> r
Breakpoint main    
```

You can repeat the process to symbolicate any handful function. Enjoy your symbolicated binary and pop some shells! :)