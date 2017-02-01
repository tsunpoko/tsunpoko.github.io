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

```asm
 80485ed:	e8 40 00 00 00       	call   8048632 <getaline>
 80485f2:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 80485f5:	89 44 24 0c          	mov    DWORD PTR [esp+0xc],eax
 80485f9:	8d 45 b4             	lea    eax,[ebp-0x4c]
 80485fc:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048600:	c7 44 24 04 bb 87 04 	mov    DWORD PTR [esp+0x4],0x80487bb
 8048607:	08 
 8048608:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 804860f:	e8 bc fd ff ff       	call   80483d0 <dprintf@plt>
```

```
gdb-peda$ x/40xw 0xffffd3cc
0xffffd3cc:	0x41414141	0x00000000	0x00000000	0xffffd498
0xffffd3dc:	0xf7e41b74	0xf7fb93cc	0xffffd3fc	0x00000000
0xffffd3ec:	0xf7fb9000	0x00000000	0xf7fb9000	0x00000000
0xffffd3fc:	0x0622705a	0xffffd498	0xf7ff04c0	0xf7fb9000
0xffffd40c:	0xdf866000	0x00000000	0xf7e42016	0xffffd498
0xffffd41c:	0x0804859a	0x08048745	0xffffd44c	0xffffd44
```

```
dprintf("Hi, %s\n%s\n>>", 0xffffd3cc, 0x08048745);
						 [user input]
```
