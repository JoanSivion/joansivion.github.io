---
layout: post
title: "Qiling Labs"
date: 2021-07-21 13:32:20 +0300
img: ./qilinglabs/qiling_small.png # Add image post (optional)
description: Write up for Qiling Labs (@ShielderSec)
---

- [Introduction](#introduction)
- [Setup](#setup)
- [Challenges](#challenges)
  - [Challenge 1 : Memory mapping](#challenge-1--memory-mapping)
  - [Challenge 2 : Syscall return hijack](#challenge-2--syscall-return-hijack)
  - [Challenge 3 : FS & Syscall hijack](#challenge-3--fs--syscall-hijack)
  - [Challenge 4 : Hook address 1](#challenge-4--hook-address-1)
  - [Challenge 5 : External function hooking 1](#challenge-5--external-function-hooking-1)
  - [Challenge 6 : Hook address 2](#challenge-6--hook-address-2)
  - [Challenge 7 : External function hooking 2](#challenge-7--external-function-hooking-2)
  - [Challenge 8 : Find a structure in memory](#challenge-8--find-a-structure-in-memory)
  - [Challenge 9 : External function hooking 2](#challenge-9--external-function-hooking-2)
  - [Challenge 10 : Hijack FS](#challenge-10--hijack-fs)
  - [Challenge 11 : Hooking instructions](#challenge-11--hooking-instructions)
  - [Yay!](#yay)
- [Conclusion](#conclusion)

## Introduction
A few days ago, [Th3Zer0][TheZero] from the IT security company [Shielder][shielder] published the **Qiling Labs** challenge :

{:refdef: style="text-align: center;"}
![image](../assets/img/qilinglabs/shielder_tweets.png)
{: refdef}

[Qiling][qiling] is a binary emulation framework built on top of the [Unicorn engine][unicorn] which understands OS concepts (executable format such as ELF, dynamic linkers, syscalls, IO handlers...). Very convenient to quickly emulate an executable binary without emulating its entire OS. If you want more details about the differences between Qiling and other emulators, you can read [the associated section on Github][diff_emu]

Inspired by [FridaLab][frida-labs], Qiling Labs is as a serie of 11 small challenges that aims at **showcasing some useful features of Qiling**. The idea is to encourage newcomers to learn about the framework while having fun.

As for me, I discovered and used Qiling for the first time a few weeks ago for a small research project and really enjoyed working with the framework.

This article presents **my solutions for the QilingLab challenges**. Of course, if you are interested in learning about Qiling, I encourage you to first try the challenges yourself ([here][challenge]) before reading further.

## Setup
The challenges are contained in a single Linux ELF binary which is available for x86_64 or aarch64. Since I am working on a x86_64 machine, I chose to **play with the aarch64 binary** (```qilinglab-aarch64```) to better demonstrate the usefulness of the emulation framework.

First of all, let's try to launch (aka emulate) the binary with Qiling. To do that, we only need to provide the```path```of the binary and a```rootfs```(the root of the filesystem from the point of view of the emulated binary) :

{% highlight python %}
from qiling import *

if __name__ == '__main__':

    path = ["qilinglab-aarch64"]
    rootfs = "/"

    ql = Qiling(path, rootfs)
    ql.run()
{% endhighlight %}

Here I specified the root of my machine's filesystem as rootfs, let's run the script and see the results:

{% highlight console %}
└─$ python3 solve.py                                                          
...
FileNotFoundError: [Errno 2] No such file or directory: '//lib/ld-linux-aarch64.so.1'
{% endhighlight %}

As you can see, we get an error because shared libraries required to load the ELF binary are missing. It isn't really surprising because I provided the rootfs of my x86_64 machine which does not contain any aarch64 libraries. 

To make things work, we need to give Qiling **a rootfs which contains the right libraries for loading the ELF**. Even though we can easily find that on the internet, Qiling already provides a minimalist aarch64 Linux rootfs that we can download and use ([https://github.com/qilingframework/rootfs/tree/master/arm64_linux][link1]) :

{% highlight console %}
└─$ ls my_rootfs/lib 
ld-2.24.so  ld-linux-aarch64.so.1  libc.so.6
{% endhighlight %}

*NB : if other shared libraries were required to emulate the binary, we would have needed to download them and add them to our rootfs*

Now by specifying our new custom rootfs in the script, we can successfully emulate the binary:

{% highlight python %}
from qiling import *

if __name__ == '__main__':

    path = ["qilinglab-aarch64"]
    rootfs = "my_rootfs"

    ql = Qiling(path, rootfs)
    ql.run()
{% endhighlight %}

{% highlight console %}
└─$ python3 solve.py 
Welcome to QilingLab.
Here is the list of challenges:
Challenge 1: Store 1337 at pointer 0x1337.
Challenge 2: Make the 'uname' syscall return the correct values.
Challenge 3: Make '/dev/urandom' and 'getrandom' "collide".
Challenge 4: Enter inside the "forbidden" loop.
Challenge 5: Guess every call to rand().
Challenge 6: Avoid the infinite loop.
Challenge 7: Don't waste time waiting for 'sleep'.
Challenge 8: Unpack the struct and write at the target address.
Challenge 9: Fix some string operation to make the iMpOsSiBlE come true.
Challenge 10: Fake the 'cmdline' line file to return the right content.
Challenge 11: Bypass CPUID/MIDR_EL1 checks.

Checking which challenge are solved...
Note: Some challenges will results in segfaults and infinite loops if they aren't solved.

...

unicorn.unicorn.UcError: Invalid memory read (UC_ERR_READ_UNMAPPED)
{% endhighlight %}

Yay! **The binary is executed** and prints the list of the challenges before crashing because of an invalid memory read. This is the expected behavior and the first issue we will have to solve during Challenge 1.


## Challenges

For each of the challenge, in addition to the given instruction, a tiny bit of reverse engineering (I'll use [Ghidra][ghidra]) is required to understand what we have to do in order to pass each check. 

{:refdef: style="text-align: center;"}
![image](../assets/img/qilinglabs/ghidra_0.png)
{: refdef}

Since it's not a reverse engineering challenge, the binary is neither stripped, nor obfuscated. Therefore, we can focus on the Qiling part.

### Challenge 1 : Memory mapping
{% highlight python %}
'''
Challenge 1: Store 1337 at pointer 0x1337.
'''
{% endhighlight %}

{% highlight c %}
void challenge1(char *check) {
  if (_DAT_00001337 == 1337) {
    *check = 1;
  }
}
{% endhighlight %}

The program tries to read memory at the address 0x1337 which is not mapped, hence the ```UC_ERR_READ_UNMAPPED``` we get when we run the binary. 

To pass this check, we just need to **map this area of virtual memory and write the expected value**:

{% highlight python %}
def challenge1(ql):
    
    # ql.mem.map(addr, size) must be page aligned
    ql.mem.map(0x1000, 0x1000, info = "[challenge1]")
    ql.mem.write(0x1337, ql.pack16(1337))
{% endhighlight %}

{% highlight console %}
Challenge 1: SOLVED
{% endhighlight %}

*Note: we can display the complete memory map with ql.mem.show_mapinfo() to see the area we just mapped (it is necessary to increase the level of verbosity to see the output)*

{% highlight python %}
In [2]: ql.verbose = 4

In [3]: ql.mem.show_mapinfo()
[=]     Start      End        Perm    Label          Image
[=]     00001000 - 00002000   rwx     [challenge1]   
[=]     555555554000 - 555555556000   r-x     /home/joansivion/security/projects/qiling_lab/qilinglab-aarch64   /home/joansivion/security/projects/qiling_lab/qilinglab-aarch64
[=]     555555566000 - 555555568000   rw-     /home/joansivion/security/projects/qiling_lab/qilinglab-aarch64   /home/joansivion/security/projects/qiling_lab/qilinglab-aarch64
[=]     555555568000 - 55555556a000   rwx     [hook_mem]     
[=]     7ffff7dd5000 - 7ffff7e04000   rwx     /home/joansivion/security/projects/qiling_lab/my_rootfs/lib/ld-linux-aarch64.so.1   
[=]     7ffffffde000 - 80000000e000   rwx     [stack]
{% endhighlight %}

### Challenge 2 : Syscall return hijack
{% highlight python %}
'''
Challenge 2: Make the 'uname' syscall return the correct values.
'''
{% endhighlight %}

{% highlight c %}
void  challenge2(char *check) {
    unsigned int i, j, k, l;
    struct utsname name; 
    char qiling_OS[10]; 
    char chall_start[24];

    if ( uname(&name) ) {
        perror("uname");
    }
    else {
        strcpy(qiling_OS, "QilingOS");
        strcpy(chall_start, "ChallengeStart");
        i = 0;
        j = 0;
        while ( k < strlen(qiling_OS) ) {
            if ( name.sysname[k] == qiling_OS[k] )
                ++i;
            ++k;
        }
        while ( l < strlen(chall_start) ) {
            if ( name.version[l] == chall_start[l] )
                ++j;
            ++l;
        }
        if ( i == strlen(qiling_OS) && j == strlen(chall_start) && i > 5 )
            *check = 1;
    }
}
{% endhighlight %}

The```uname```syscall returns information about the underlying OS. In our case, it returns a pointer to the following structure:
{% highlight c %}
struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];   
    char version[65];
    char machine[65];
    char domainname[65];
};
{% endhighlight %}

In order to pass the check of the challenge, the```sysname```must be *QilingOS* and the```version```must be *ChallengeStart*. To satisfy those conditions, we can use Qiling API to **hook the syscall just before it returns** using```set_syscall```and```QL_INTERCEPT.EXIT```:

{% highlight python %}
from qiling.const import * # for QL_INTERCEPT.EXIT

def my_uname_on_exit_hook(ql, *args):

    # Resulting structure is stored on the stack at offset 0x40
    '''
    ...
    00100d28 e0 03 01 91     add        x0,sp,#0x40
    00100d2c a1 ff ff 97     bl         uname               int uname(utsname * __name)
    ...
    '''
    out_struct_addr = ql.reg.sp + 0x40

    # Overwrite sysname
    sysname_addr = out_struct_addr 
    ql.mem.write(sysname_addr,  b"QilingOS\x00")

    # Overwrite version
    version_addr = out_struct_addr + 65*3
    ql.mem.write(version_addr,  b"ChallengeStart\x00")

def challenge2(ql):
    
    # QL_INTERCEPT.EXIT to trigger the hook after the syscall execution
    ql.set_syscall("uname", my_uname_on_exit_hook, QL_INTERCEPT.EXIT)
{% endhighlight %}

{% highlight console %}
Challenge 2: SOLVED
{% endhighlight %}

### Challenge 3 : FS & Syscall hijack
{% highlight python %}
'''
Challenge 3: Make '/dev/urandom' and 'getrandom' "collide".
'''
{% endhighlight %}

{% highlight c %}
void challenge3(char *check) {
    int n; 
    int i; 
    int fd; 
    char x; 
    char buf1[32]; 
    char buf2[32]; 

    fd = open("/dev/urandom", 0);
    read(fd, buf1, 32);
    read(fd, x, 1);
    close(fd);
    getrandom(buf2, 32, 1);
    n = 0;
    for ( i = 0; i <= 31; ++i ) {
        if ( buf1[i] == buf2[i] && buf1[i] != x )
            ++n;
    }
    if ( n == 32 )
        *check = 1;
}
{% endhighlight %}

The above code fetches 32 random bytes from two different sources : the file```/dev/urandom```and the syscall```getrandom```. To pass the check, the following conditions must be met:

1. **The 32 bytes obtained from the two sources have to be identical**
2. The code also **reads one byte** from```/dev/urandom```: **this byte must be different** from all the other bytes

Two Qiling mechanisms will be used to solve this challenge:

* The```set_syscall```function to hijack the```getrandom```syscall and make him return 00 bytes. This time, instead of hijacking the exit of the syscall, we will completly overwrite it with our function.
* The```add_fs_mapper```function coupled with a```QlFsMappedObject```to define a custom behavior when operations are performed on```/dev/urandom```. In particular, we will make it return 00 bytes to match```getrandom```when several bytes are requested (**condition 1**) and a different byte when only one byte is requested (**condition 2**)

{% highlight python %}
class Fake_urandom(QlFsMappedObject):

    # Fake read fs operation
    def read(self, size):
        if size == 1:
            return b"\x41"
            
        return b"\x00"*size

    # Fake close fs operation
    def close(self):
        return 0

def getrandom_hook(ql, buf, buflen, flags, *args, **kw):
    ql.mem.write(buf, b"\x00"*buflen)
    ql.os.set_syscall_return(0)

def challenge3(ql):
    ql.set_syscall("getrandom", getrandom_hook)
    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
{% endhighlight %}

{% highlight console %}
Challenge 3: SOLVED
{% endhighlight %}

### Challenge 4 : Hook address 1
{% highlight python %}
'''
Challenge 4: Enter inside the "forbidden" loop.
'''
{% endhighlight %}

{% highlight c %}
void challenge4(char *check) {
    int i;
    i = 0;
    while (i < 0) {
        *check = 1;
        i = i + 1;
    }
}
{% endhighlight %}

The challenge 4 contains a loop with an **impossible entering condition**.To pass this check, we can use the```hook_address```function to enter the loop:

{% highlight python %}
def forbidden_loop_hook(ql):
    '''
    00100fe0 3f 00 00 6b     cmp        w1,w0           <--- HOOK HERE 
    00100fe4 eb fe ff 54     b.lt       LAB_00100fc0
    '''
    ql.reg.x0 = 1

def challenge4(ql):
    # Get the module base address
    base_addr = ql.mem.get_lib_base(ql.path)
    # Address we need to patch
    test_forbidden_loop_enter = base_addr + 0xfe0
    # Place hook
    ql.hook_address(forbidden_loop_hook, test_forbidden_loop_enter)

{% endhighlight %}

{% highlight console %}
Challenge 4: SOLVED
{% endhighlight %}


### Challenge 5 : External function hooking 1
{% highlight python %}
'''
Challenge 5: Guess every call to rand().
'''
{% endhighlight %}

{% highlight c %}
void challenge5(char *check) {
    
    unsigned int seed;
    int i, j;
    int buf[12];

    seed = time(0LL);
    srand(seed);
    for ( i = 0; i <= 4; ++i ) {
        buf[i] = 0;
        buf[i + 6] = rand();
    }
    for ( j = 0; j <= 4; ++j ) {
        if ( buf[j] != buf[j + 6] ) {
            *check = 0;
            return;
        }
    }
    *check = 1;
}
{% endhighlight %}

To pass the check of this challenge, all the random numbers obtained with```rand()```must be equal. Since rand is an external function, we can use```set_api```to hijack it and **make it return the same value every time**:

{% highlight python %}
def rand_hook(ql, *args, **kw):
    ql.reg.x0 = 0

def challenge5(ql):
    ql.set_api("rand", rand_hook)
{% endhighlight %}


{% highlight console %}
Challenge 5: SOLVED
{% endhighlight %}

### Challenge 6 : Hook address 2
{% highlight python %}
'''
Challenge 6: Avoid the infinite loop.
'''
{% endhighlight %}

{% highlight c %}
void challenge6(char *check) {
    do {
    } while( true );

    *check = 1;
}
{% endhighlight %}

For this one, the program is **stuck in an infinite loop**. We can reuse the same strategy we used for challenge 4 with```hook_address```:

{% highlight python %}
def infinite_loop_bypass_hook(ql):
    '''
    00101114 00 1c 00 12     and        w0,w0,#0xff
    00101118 1f 00 00 71     cmp        w0,#0x0
    0010111c 61 ff ff 54     b.ne       LAB_00101108
    '''
    ql.reg.x0 = 0

def challenge6(ql):
    # Get the module base address
    base_addr = ql.mem.get_lib_base(ql.path)
    # Address we need to patch
    cmp_infinite_loop_addr = base_addr + 0x1114
    # Place hook
    ql.hook_address(infinite_loop_bypass_hook, cmp_infinite_loop_addr)
{% endhighlight %}

{% highlight console %}
Challenge 6: SOLVED
{% endhighlight %}

### Challenge 7 : External function hooking 2
{% highlight python %}
'''
Challenge 7: Don't waste time waiting for 'sleep'.
'''
{% endhighlight %}

{% highlight c %}
void challenge7(char *check) {
    *check = 1;
    sleep(0xffffffff);
}
{% endhighlight %}

Here the code is stuck because of the call to```sleep```. There are **several ways to bypass this call** :

* Hook the sleep function with```set_api```and replace it with an empty function:
{% highlight python %}
def sleep_hook(ql):
    return

def challenge7(ql):
    ql.set_api("sleep", sleep_hook)
{% endhighlight %}

* Hook the beginning of the sleep function with```set_api```and change its argument:

{% highlight python %}
def sleep_hook(ql):
    # Change sleep n_sec argument to 0 
    ql.reg.x0 = 0

def challenge7(ql):
    ql.set_api("sleep", sleep_hook, QL_INTERCEPT.ENTER)
{% endhighlight %}

* Hook the underlying```nanosleep```syscall and replace it with an empty function (or change its argument):
{% highlight python %}
def nanosleep_hook(ql, *args, **kw):
    return

def challenge7(ql):
    ql.set_syscall("nanosleep", nanosleep_hook)
{% endhighlight %}

{% highlight console %}
Challenge 7: SOLVED
{% endhighlight %}

### Challenge 8 : Find a structure in memory
{% highlight python %}
'''
Challenge 8: Unpack the struct and write at the target address.
'''
{% endhighlight %}

{% highlight c %}
void challenge8(char *check) {
    random_struct *s;

    s = (random_struct *)malloc(24);
    s->some_string = (char *)malloc(0x1E);
    s->magic = 0x3DFCD6EA00000539;
    strcpy(s->field_0, "Random data");
    s->check_addr = check;
}

struct random_struct {
  char *some_string;
  __int64 magic;
  char *check_addr;
};

{% endhighlight %}

Here, the spirit of the challenge is get the address of```check```from the```s``` structure on the heap, and write the value 1.

One way to do that is to place a hook at the end of the```challenge8```function and get the address of the structure on the stack:

{% highlight python %}
import struct

def challenge8_hook(ql):
    '''
    001011d0 e0 17 40 f9     ldr        x0,[sp, #0x28]  <---- heap structure on stack
    001011d4 e1 0f 40 f9     ldr        x1,[sp, #0x18]
    001011d8 01 08 00 f9     str        x1,[x0, #0x10]
    001011dc 1f 20 03 d5     nop        <----------------------- HOOK HERE
    001011e0 fd 7b c3 a8     ldp        x29=>local_30,x30,[sp], #0x30
    001011e4 c0 03 5f d6     ret

    '''
    # Get heap structure address
    heap_struct_addr = ql.unpack64(ql.mem.read(ql.reg.sp + 0x28, 8))

    # Dump and unpack structure
    heap_struct = ql.mem.read(heap_struct_addr, 24)
    some_string_addr, magic, check_addr = struct.unpack('QQQ', heap_struct)

    # Write 1 to check
    ql.mem.write(check_addr, b"\x01")


def challenge8(ql):
    # Get the module base address
    base_addr = ql.mem.get_lib_base(ql.path)
    # Address after check's address has been written to heap structure
    end_of_challenge8 = base_addr + 0x11dc
    # Place hook
    ql.hook_address(challenge8_hook, end_of_challenge8)
{% endhighlight %}

To demonstrate the use of more Qiling functionnalities, let's also **solve the challenge with another strategy**. Instead of directly reading the address of the heap structure from the stack, we will find the structure in memory using```ql.mem.search```:

{% highlight python %}
def challenge8_hook(ql):

    # Find all occurrences of the magic in memory
    MAGIC = 0x3DFCD6EA00000539
    magic_addrs = ql.mem.search(ql.pack64(MAGIC)) 

    # There may be several occurences of the magic in memory
    # Let's verify we have the right one using the string
    # "Random data" which should be stored in our structure
    for magic_addr in magic_addrs:

        # Dump and unpack the candidate structure
        candidate_heap_struct_addr = magic_addr - 8
        candidate_heap_struct = ql.mem.read(candidate_heap_struct_addr, 24)
        string_addr, _ , check_addr = struct.unpack('QQQ', candidate_heap_struct)
        
        # Dereference the address and read the string
        if ql.mem.string(string_addr) == "Random data":

            # We found the structure : write 1 to check
            ql.mem.write(check_addr, b"\x01")
            break
        
def challenge8(ql):
    # Get the module base address
    base_addr = ql.mem.get_lib_base(ql.path)
    # Address after check's address has been written to heap structure
    end_of_challenge8 = base_addr + 0x11dc
    # Place hook
    ql.hook_address(challenge8_hook, end_of_challenge8)
{% endhighlight %}

{% highlight console %}
Challenge 8: SOLVED
{% endhighlight %}

### Challenge 9 : External function hooking 2
{% highlight python %}
'''
Challenge 9: Fix some string operation to make the iMpOsSiBlE come true.
'''
{% endhighlight %}

{% highlight c %}
void challenge9(bool *check) {
    char *i; 
    char dest[32];
    char src[32]; 

    strcpy(src, "aBcdeFghiJKlMnopqRstuVWxYz");
    strcpy(dest, src);
    for ( i = dest; *i; ++i )
        *i = tolower(*i);
    *check = strcmp(src, dest) == 0;
}
{% endhighlight %}

To pass the check in this challenge, we need to hijack the```tolower```operation to prevent the modification of the string```aBcdeFghiJKlMnopqRstuVWxYz```before the final comparaison. This can easily be done with the```set_api```function we saw earlier:

{% highlight python %}
def tolower_hook(ql):
    return

def challenge9(ql):
    ql.set_api("tolower", tolower_hook)
{% endhighlight %}

{% highlight console %}
Challenge 9: SOLVED
{% endhighlight %}

### Challenge 10 : Hijack FS
{% highlight python %}
'''
Challenge 10: Fake the 'cmdline' line file to return the right content.
'''
{% endhighlight %}

{% highlight c %}
void  challenge10(char *check) {
    int i; 
    int fd; 
    ssize_t n_bytes; 
    char buf[64];

    fd = open("/proc/self/cmdline", 0);
    if ( fd != -1 ) {
        n_bytes = read(fd, buf, 0x3FuLL);
        if ( n_bytes > 0 ) {
            close(fd);
            for ( i = 0; n_bytes > i; ++i ) {
                if ( !buf[i] )
                    buf[i] = 32;
            }
            buf[n_bytes] = 0;
            if ( !strcmp(buf, "qilinglab") )
                *check = 1;
        }
    }
}
{% endhighlight %}

The goal of this challenge is to modify the content read from```/proc/self/cmdline```. To do that, we can use a```QlFsMappedObject```like we did for```/dev/urandom```in challenge 3:

{% highlight python %}
class Fake_cmdline(QlFsMappedObject):
    def read(self, size):
        return b"qilinglab"

    def close(self):
        return 0

def challenge10(ql):
    ql.add_fs_mapper("/proc/self/cmdline", Fake_cmdline())
{% endhighlight %}

By the way, for simple case like this one, it is **also possible to directly replace the target file with another one of our host filesystem**. For instance here, after creating a file```fake_cmdline```, we can use the following code to pass the check:

{% highlight console %}
└─$ echo -n "qilinglab" > fake_cmdline                                                  
{% endhighlight %}

{% highlight python %}
def challenge10(ql):
    ql.add_fs_mapper("/proc/self/cmdline", "./fake_cmdline")
{% endhighlight %}

Finally, another valid way to solve this challenge without writing any code is to create the```/proc/self/cmdline```in our fake rootfs with the *qilinglab* string inside.

{% highlight console %}
└─$ mkdir -p ./my_rootfs/proc/self                                                     
                                                                                           
└─$ echo -n "qilinglab" > my_rootfs/proc/self/cmdline    
{% endhighlight %}

{% highlight console %}
Challenge 10: SOLVED
{% endhighlight %}

### Challenge 11 : Hooking instructions
{% highlight python %}
'''
Challenge 11: Bypass CPUID/MIDR_EL1 checks.
'''
{% endhighlight %}

{% highlight c %}

void challenge11(char *check) {
    ulong uVar1;
  
    uVar1 = cRead_8(midr_el1);
    if ((uVar1 >> 0x10) == 0x1337) {
        *check = 1;
    }
}
{% endhighlight %}

```MIDR_EL1```register contains information about the current CPU ([arm documentation][arm-doc]). It is a system register which is accessed in the challenge using the following assembly instruction:

{% highlight asm %}
00 00 38 d5     mrs        x0,midr_el1
{% endhighlight %}

To pass the check, we need to replace the returned value with the custom value```0x13370000```.

To do that, we will use the```hook_code```function which allows us to **hook every instruction used by the CPU**. When the target instruction is reached, the hook will hijack its execution.

{% highlight python %}
def midr_el1_hook(ql, address, size):  
    '''
    001013ec 00 00 38 d5     mrs        x0,midr_el1
    '''
    if ql.mem.read(address, size) == b"\x00\x00\x38\xD5":
        # Write the expected value to x0
        ql.reg.x0 = 0x1337 << 16
        # Go to next instruction
        ql.reg.arch_pc += 4

def challenge11(ql):
    ql.hook_code(midr_el1_hook)
{% endhighlight %}

**Bonus** : if we want to be more precise, we can only hook instructions executed by the main binary. This way, our hook will not be triggered in shared libraries where the target instruction is also used:

{% highlight python %}
def challenge11(ql):
    mem_map = ql.mem.map_info
    for entry in mem_map:
        start, end, flags, label = entry
        
        # [=]     555555554000 - 555555556000   r-x (5)    [redacted]/qilinglab-aarch64 
        if ql.path in label and flags == 5:
            start_hook = start
            end_hook = end
            break
    
    # Use begin and end parameters to specify the range of the hook
    ql.hook_code(midr_el1_hook, begin=start_hook, end=end_hook)
{% endhighlight %}

*NB: Since hooking every instruction is quite expensive in terms of performance, we could optimize the code above by activating the hook at the of challenge 10 (just before its needed in challenge 11) and deactivate the hook after its execution using ql.hook_del*

{% highlight console %}
Challenge 11: SOLVED
{% endhighlight %}

### Yay!


{% highlight console %}
Welcome to QilingLab.
Here is the list of challenges:
Challenge 1: Store 1337 at pointer 0x1337.
Challenge 2: Make the 'uname' syscall return the correct values.
Challenge 3: Make '/dev/urandom' and 'getrandom' "collide".
Challenge 4: Enter inside the "forbidden" loop.
Challenge 5: Guess every call to rand().
Challenge 6: Avoid the infinite loop.
Challenge 7: Don't waste time waiting for 'sleep'.
Challenge 8: Unpack the struct and write at the target address.
Challenge 9: Fix some string operation to make the iMpOsSiBlE come true.
Challenge 10: Fake the 'cmdline' line file to return the right content.
Challenge 11: Bypass CPUID/MIDR_EL1 checks.

Checking which challenge are solved...
Note: Some challenges will results in segfaults and infinite loops if they aren't solved.

Challenge 1: SOLVED
Challenge 2: SOLVED
Challenge 3: SOLVED
Challenge 4: SOLVED
Challenge 5: SOLVED
Challenge 6: SOLVED
Challenge 7: SOLVED
Challenge 8: SOLVED
Challenge 9: SOLVED
Challenge 10: SOLVED
Challenge 11: SOLVED
You solved 11/11 of the challenges

{% endhighlight %}

## Conclusion

Thanks to [Th3Zer0][TheZero] and [Shielder][shielder] for this nice little challenge. I think this format is a **great way to get started with new analysis tools** before using them on bigger project.

If you want to see more Qiling API example, you can check [Qiling's documentation][qiling-doc] which contains several sample of its main functionalities.

[TheZero]:https://twitter.com/Th3Zer0
[shielder]:https://twitter.com/ShielderSec
[qiling]:https://github.com/qilingframework/qiling
[unicorn]:https://github.com/unicorn-engine/unicorn
[diff_emu]:https://github.com/qilingframework/qiling#qiling-vs-other-emulators
[frida-labs]:https://rossmarks.uk/blog/fridalab/
[challenge]:https://www.shielder.it/blog/2021/07/qilinglab-release/
[link1]:https://github.com/qilingframework/rootfs/tree/master/arm64_linux
[ghidra]:https://ghidra-sre.org/
[arm-doc]:https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/MIDR-EL1--Main-ID-Register
[qiling-doc]:https://docs.qiling.io/en/latest/