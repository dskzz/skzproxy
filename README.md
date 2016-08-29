A proxy, packet sender and fuzzer originally based on the Black Hat Python proxy taken on a life of its own.

> ./skzproxy.py [local ip] [local port] [target ip] [target port] [receive first]

> ./skzproxy_bitsender.py [target ip] [target port] [packet file #]

> ./skzproxy_bitsender.py

##### NOTES #####
	*** NOTE!!! and TODO - This uses hardcoded paths; this needs to be changed. ***
	NOTE - All commands word in upper and lowercase.
	NOTE - when you edit a packet, split it by spaces. XX means keep same value. for example:orig: 00 01 02 03 edit: xx 04 xx 05 new: 00 04 00 05
	NOTE - The system esp the bitsender is optimized for protocols with 1-16 bytes at the top.

##### SKZPROXY.PY #####
So this is a program based on the proxy from the excellent Black Hat Python book.  
Unfortunately, the book, while it left in functions for the user to modify packets, 
it never went back and filled in those functions.  So being desirous to do so, I 
thought hey why not and dug in.  I got really into it and three days/nights later had
produced this beast.

It has two key files: skzproxy.py and skzproxy_bitsender.py (should really be bysender but hey...) 

skzproxy runs exactly as you think it should, in the following format:

	skzproxy.py [localip, 0.0.0.0] [localport] [fwd-to-ip-addr] [fwd-to-port] [optional rcv first]

Once it's running you can view the packets over the wire, modify packets on the fly, 
save packets, dump as decimal or hex, etc.

First you get the packet and you get the prompt:
	Enter to continue, X to play w/ packet, f# or f to fast forward, q to quit, N for name >

Simple interface; if you just want to watch the packet flow type ff and hit enter.  
TODO - Implement the ff by #, rewind by # also help on this prompt.

The X instruction brings up the interesting "Play with Packet" interface:

	[?] 0-8; Range: R/S/L/E/def; Prt H/N/W; SO/[C]lear/[F]ire; Q/help/ret >help
	(E)dit - Edit this range of bytes
	(R)ange - Select a range of bytes to work with. *** First byte is 0
	(S)ave - Save the changes to a file
	(SO) - Save original to a file.
	(SR) - Save range to a file.
	(L)oad - Load the packet back.
	(C)lear - Clear the changes
	(F)ire - Sends the bytes back into the proxy and sends
	(H)ex, (B)inary, (D)ec - Print the byte selection as Hex, Binary or Decimal Number
	(W)hole - Print entire packet
	(N)ame - Change the name of the packet exchange, like login, request, etc
	(NP)Name Project - Change the project name
	(I)nfo - Packet information
	(Q)uit - Quit this program
	(def) - Makes this range Default range
	(help) - type help for this cruft
	[ret] - Press return to continue

The rest is pretty self explanitory and apart from wanting to add in a "repeat sending custom packets" feature
is pretty much good to go. 

TODO - add a "repeat sending custom packets" feature.

What's interesting is how it saves the packets which is how it interacts with the bitsender...

All packets that are saved - S - are saved in the ./save_packets/ folder in the format:

	projectname-transaction_[R|L]####.pbin

For example:

	chal1-login_R0002_mod.pbin

You can change the project name and the transaction name w/ N and NP.  
TODO - Save all command.

As of now you need to go through each packet and save it with X, S, F repeatedly.

##### SKZPROXY_BITSENDER.py #####
This is actually the more heavily used part of the system.  While the proxy is limited to interacting 
with the current packet stream, bitsender allows a user to send customized bytes to the target.  

You can run the bitsender without any parameters - # bitsender.py  and set the target via the T command. 
OR you can specify a target ip on the command line as such:

	python skzproxy_bitsender.py 10.1.1.1 8080

You can load a packet to work with from the ./save_packets/ folder; you are presented with a list of all files.
Enter the L command:

	> l
	1 - chal1-login_L0001_mod.pbin
	2 - chal1-login_L0002_mod.pbin
	3 - chal1-login_L0003_mod.pbin
	4 - chal1-login_L0004_mod.pbin
	5 - chal1-login_L0005_mod.pbin
	6 - chal1-login_L0006_mod.pbin
	7 - chal1-login_L0007_mod.pbin
	8 - chal1-login_L0011_mod.pbin
	9 - chal1-login_R0001_mod.pbin
	10 - chal1-login_R0002_mod.pbin
	11 - chal1-login_R0003_mod.pbin
	12 - chal1-login_R0004_mod.pbin
	13 - chal1-login_R0005_mod.pbin
	14 - chal1-login_R0006_mod.pbin
	15 - chal1-login_R0007_mod.pbin
	16 - chal1-login_R0119_mod.pbin
	17 - chal1-sale_L0021_mod.pbin

TODO - allow alternate ordering methods.

You then pick your file and it will load the binary from the packet binary and dump the hex. 

	Pick your file >2
	Picked # 2 - chal1-login_L0002_mod.pbin
	Loaded file /root/Desktop/pentest/tools/skzproxy/save_packets/chal1-login_L0002_mod.pbin
	0000 00 08 00 02 57 BF 8C 94                          ....W...

Alternatively, you can specify the packet to load on the command line; load file 2 w/ 
	python skzproxy_bitsender.py 10.1.1.1 8080 2

You can also create a new packet from scratch with the N command.  

Bottom line, you need to get a packet loaded and then you will be ready to mess with it:
Then type help to get the help commands:

	*** Skzproxy Bytesender ***
	T	Target IP and port; this can also override the command line.
	L	Print the file list and load a file (by number)
	E	Edit the packet
	R	Reset the packet, discard changes made
	N	New packet from scratch. 
	V	View the packetS	SEND THE PACKET
	I	Information print
	Q	Quit
	C	Reconnect to Target
	A	Save response
	AS	Save packet sent


##### THE FUZZ #####
Bitsender has a built in fuzzer.  It's basic, with no real intelligence (yet) and only a bare bones
output system (but it does include a nifty progress bar!).  
TODO - Finish the fuzz output system.

The fuzzer allows you to modify certain bytes and run a range for each from 00 - FF.  The fuzzer will 
recursively go through every possible combination supplied by the user.

Here is the Fuzzer command listing

	FUZZING MENU
	F	Setup the bytes to fuzz
	Z	Fire the fuzzer
	D	Delete fuzzed bytes; also good to see what's set to fuzz
	FO	See the fuzz setup
	ZO	Set the fuzz options
	FD	Setup a fuzz delay
	FV	Set the delay on the fuzzer

For example, here we set up the fuzzing
	Num -  0  1  2  3  4  5  6  7
	Hex - 00 08 00 02 57 BF 8C 94

	Pick bytes to fuzz, sep by space or , 0 - 8; Note only 1-16 displayed. 
	> 3,5,7
	Byte 3 Range to fuzz (##-## up to FF) or enter to do 0-FF
	> a-f
	OK range:a:f

	Byte 5 Range to fuzz (##-## up to FF) or enter to do 0-FF
	> 1-9
	OK range:1:9

	Byte 7 Range to fuzz (##-## up to FF) or enter to do 0-FF
	> 1-f
	OK range:1:f
	
	> fo
	*** Fuzzing options ***
	Fuzz options reconnect: Yes (1)
	Fuzz options backwards first: Yes (1)
	Fuzz options sec delay between attempts: 0
	Total fuzz attempts: 560.
	Fuzzing 3 bytes.
	1 - Byte 3: a:f
	2 - Byte 5: 1:9
	3 - Byte 7: 1:f

TODO - fix output display to make sure the range shows 5 chars

That's it, just hit the Z command and it will fire!


