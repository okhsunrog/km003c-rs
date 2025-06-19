# Probably extracting AES keys?
```
❯ objdump -h Mtools.exe

Mtools.exe:     file format pei-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         0016d009  0000000140001000  0000000140001000  00000400  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rdata        000fe234  000000014016f000  000000014016f000  0016d600  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .data         00009200  000000014026e000  000000014026e000  0026ba00  2**4
                  CONTENTS, ALLOC, LOAD, DATA
  3 .pdata        0000d764  0000000140278000  0000000140278000  00274c00  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .rsrc         00002c38  0000000140286000  0000000140286000  00282400  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  5 .reloc        000039a0  0000000140289000  0000000140289000  00285200  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
km003c-rs on  main [✘!?] is 📦 v0.1.0 via 🦀 v1.87.0 
❯ xxd -s 0x183176 -l 16 -p Mtools.exe
46613062347441323566345230333861
km003c-rs on  main [✘!?] is 📦 v0.1.0 via 🦀 v1.87.0 
❯ xxd -s 0x1830dc -l 16 -p Mtools.exe
4c6832796642376e365837643961355a
km003c-rs on  main [✘!?] is 📦 v0.1.0 via 🦀 v1.87.0 
❯ xxd -s 0x183106 -l 16 -p Mtools.exe
73646b57373852336b35646a30664876
km003c-rs on  main [✘!?] is 📦 v0.1.0 via 🦀 v1.87.0 
❯ xxd -s 0x183135 -l 16 -p Mtools.exe
55793334565731336a486a3335393865
```

looks like the protocol uses AES-128.

the keys are in **get_crypto_key** function

functions to take a look at:
-
- FUN_1401611a0, FUN_140161180
-
  ```
  Address	Old Name	Signal Index	Parameters	New Name	Likely Purpose
  FUN_140161250	emit_device_ready_signal	0	None	signal_deviceReady	Fired after the USB device is opened and claimed.
  FUN_140161180	(new)	1	None	signal_disconnected	Fired when the device is disconnected.
  FUN_1401611d0	(new)	2	int errorCode	signal_errorOccurred	Fired when a USB transaction fails.
  FUN_140161210	emit_transaction_finished_signal	3	None	signal_transactionFinished	Fired after any command sequence completes.
  FUN_1401611a0	(new)	4	QByteArray data	signal_dataReady	Fired when new data arrives from the device.
  FUN_1401614d0	(new)	5	longlong bytes, longlong total	signal_uploadProgress	Fired during a file upload.
  FUN_140161410	(new)	6	longlong bytes, longlong total	signal_downloadProgress	Fired during a file download.
  FUN_1401614a0	(new)	7	bool success	signal_setupFinished	Fired after the setup/handshake is done.
  FUN_140161290	emit_progress_update_signal	8	int current, int total	signal_chunkProgress	Fired during chunked transfers.
  FUN_140161120	(new)	11 (0xb)	QByteArray data	signal_pdDataReady	Fired with new Power Delivery sniffer data.
  FUN_140161470	(new)	12 (0xc)	bool started	signal_streamStateChanged	Fired when a stream starts or stops.
  FUN_140161150	(new)	13 (0xd)	QByteArray data	signal_ufcsDataReady	Fired with new UFCS sniffer data.
  ```


- small subset of functionality is availabe via virtual serial port, tested, works. needs to enter full command at once, typing manually per symbol doesn't work for some reason
	- ah, look like in desktop software the virtual serial port is used only for protocol trigger?
	- yes, they have like a separate app that connects to that vcomm, and the interface is cursed

