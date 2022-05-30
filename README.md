# icedid_stage1_unpack
Automatically Unpack Icedid Stage 1 using symbolic execution

Full post: [https://matth.dmz42.org/posts/2022/automatically-unpacking-icedid-stage1-with-angr/](https://matth.dmz42.org/posts/2022/automatically-unpacking-icedid-stage1-with-angr/)

```
% ./icedid_stage1_unpack.py 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin
got data blob: 0x4c04b bytes
found potential rc4 code: 0x1800026b3
 * found caller (0x180001b77 -> 0x180001bc0)
emulating from 0x180001b77 to 0x180001bc0 (max iter = 3000)
found 1 potential keys: [b'\xc6B\xc7\x11']
trying key b'\xc6B\xc7\x11' / xor=True
decrypted data: 0x4c042 bytes
found 5 elements
- dumped 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.0
- dumped 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.1
- dumped 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.2
    looks like a PE... {'campaign_id': 109932505, 'c2': b'ilekvoyn.com'}
- dumped 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.3
- dumped 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.4
```



```
% ./icedid_stage1_unpack.py samples/17aeebe6c1098a312074b0fdeae6f97339f2d64d66a2b07496bfc1373694a4e3.bin
got data blob: 0x3820 bytes
found potential rc4 code: 0x180003fc1
 * found caller (0x1800011c3 -> 0x180001507)
emulating from 0x1800011c3 to 0x180001507 (max iter = 3000)
found 1 potential keys: [b'k\xfe\xfa\x8b']
trying key b'k\xfe\xfa\x8b' / xor=True
trying key b'k\xfe\xfa\x8b' / xor=False
decrypted data: 0x5714 bytes
found 4 elements
- dumped samples/17aeebe6c1098a312074b0fdeae6f97339f2d64d66a2b07496bfc1373694a4e3.bin.extracted.0
- dumped samples/17aeebe6c1098a312074b0fdeae6f97339f2d64d66a2b07496bfc1373694a4e3.bin.extracted.1
- dumped samples/17aeebe6c1098a312074b0fdeae6f97339f2d64d66a2b07496bfc1373694a4e3.bin.extracted.2
    looks like a PE... {'campaign_id': 429479428, 'c2': b'arelyevennot.top'}
- dumped samples/17aeebe6c1098a312074b0fdeae6f97339f2d64d66a2b07496bfc1373694a4e3.bin.extracted.3
```


```
% ./icedid_stage1_unpack.py samples/12a692718d21b8dc3a8d5a2715688f533f1a978ee825163d41de11847039393d.bin
got data blob: 0x16064 bytes
skip 0x6442458550: too many predecessors (4)
found potential rc4 code: 0x180003bbf
 * found caller (0x1800016bf -> 0x180001980)
emulating from 0x1800016bf to 0x180001980 (max iter = 3000)
hooking addr=0x18000184b size=7
hooking addr=0x180001c19 size=7
hooking addr=0x180001c09 size=7
hooking addr=0x180001bdc size=7
found 1 potential keys: [b',u\xe2I']
trying key b',u\xe2I' / xor=True
decrypted data: 0x179f7 bytes
found 5 elements
- dumped samples/12a692718d21b8dc3a8d5a2715688f533f1a978ee825163d41de11847039393d.bin.extracted.0
- dumped samples/12a692718d21b8dc3a8d5a2715688f533f1a978ee825163d41de11847039393d.bin.extracted.1
- dumped samples/12a692718d21b8dc3a8d5a2715688f533f1a978ee825163d41de11847039393d.bin.extracted.2
    looks like a PE... {'campaign_id': 3068011852, 'c2': b'yolneanz.com'}
- dumped samples/12a692718d21b8dc3a8d5a2715688f533f1a978ee825163d41de11847039393d.bin.extracted.3
- dumped samples/12a692718d21b8dc3a8d5a2715688f533f1a978ee825163d41de11847039393d.bin.extracted.4
```


The extracted data blobs are:
- 2 shellcodes
- 1 DLL
- 1 or 2 images:

```
% file 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.*
0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.0: data
0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.1: data
0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.2: PE32+ executable (DLL) (GUI) x86-64, for MS Windows
0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.3: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 800x600, components 3
0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7.bin.extracted.4: JPEG image data, Exif Standard: [TIFF image data, big-endian, direntries=7, software=Adobe Photoshop 21.2 (Windows), datetime=2021-03-25T08:49:36+07:00], baseline, precision 8, 800x800, components 3
```
