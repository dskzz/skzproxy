import os
import sys, io
import re
import socket
import threading

# 
# Globals
# 
packet_info_name = 'chal1'
packet_info_action_name = 'login'
packet_info_source = 'sender'
packet_info_number = '1'

packet_count = 0

binstr = None
binstr_originial = None
binstr_new = None 
only_byte = None
low_byte= None
high_byte= None
max_bytes = None
mode = None

master_only_byte = None
master_low_byte = "0"
master_high_byte = "8"

max_bytes = None

fast_forward = None

save_dir = '/root/Desktop/pentest/tools/skzproxy/save_packets'

def out( string_to_print , text_for_prompt="+" ):
	print "[%s] %s\n" %( text_for_prompt, string_to_print)

def server_loop( local_host, local_port, remote_host, remote_port, receive_first ):
	
	server = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
	
	try:
		server.bind( (local_host, local_port) )
	except:
		out( "Failed to listen on %s:%d" %(local_host,local_port), "!!")
		os._exit(0)
	
	out( "[*] Listening on %s:%d" % (local_host,local_port), "*")
	
	server.listen( 5 )
	
	while True:
		client_socket, addr = server.accept( )
		
		#print the local connection information
		out(" Received incoming connect from %s:%d" %( addr[0],addr[1] ), ">" )
		
		#start a thread to talk to the remote host
		proxy_thread = threading.Thread( target=proxy_handler, 
		args=(client_socket,remote_host,remote_port,receive_first))
		
		proxy_thread.start()


def proxy_handler( client_socket, remote_host, remote_port, receive_first ):
	global packet_count
	# connect to the remote host
	remote_socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
	remote_socket.connect( (remote_host,remote_port) )
	
	# receive data from the remote end if necessary
	if receive_first:
		remote_buffer = receive_from( remote_socket )
		hexdump( remote_buffer )
		
		# send to our response handler
		remote_buffer = response_handler( remote_buffer )
		
		# if we have data to send to our local client, send it
		if len( remote_buffer):
			out( "Sending %d bytes to localhost." %( len(remote_buffer)), "<")
			client_socket.send( remote_buffer )
			
	# not lets loop and read from loca, send to remote, send to local 
	# rinse wash repeat
	while True:
		packet_count+=1
		#read from local host
		local_buffer = receive_from( client_socket )
		
		if len( local_buffer ):
			set_packet_owner_name( "L" )
			out( "#L%d -- Received %d bytes from localhost" % (packet_count, len(local_buffer)), ">")
			hexdump( local_buffer ) 
			
			# Send it to our request handler
			local_buffer = request_handler( local_buffer )
			
			# Send off the data to the remote host
			remote_socket.send( local_buffer ) 
			out(" Sent to remote", '>' )
			
		# receive back the response
		remote_buffer = receive_from( remote_socket ) 
		
		if len( remote_buffer ) :
			set_packet_owner_name( "R" )
			out( "#R%d -- Received %d bytes from remote" %(packet_count, len(remote_buffer)),  "<")
			hexdump( remote_buffer ) 
			
			#send to our response handler
			remote_buffer = response_handler( remote_buffer ) 
			
			# send response to the local socket
			client_socket.send( remote_buffer ) 
			
			out( "Sent to localhost", "<" )
			
			
		#no more data? kill
		if not len(local_buffer) or not len(remote_buffer):
			client_socket.close( )
			remote_socket.close( )
			out("Nore more data. Closing", "*")
			break
			
		
def hexdump( src, length=16):
	result = []
	digits = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b''.   join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])

		result.append( b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text) )
	print b'\n'.join(result)

def receive_from( connection ):
	buffer = ""
	
	# We set a 2 second timeout; depending on your target, this may need to be adjusted
	connection.settimeout( 2 )
	
	try:
		#keep reading into buffer until no more data or timeout
		while True:
			data = connection.recv(4096)
			
			if not data:
				break
				
			buffer += data
	except:
		pass
	
	return buffer

# mod any responses destined for REMOTE HOST	
def request_handler( buffer ):
	return pwp_prompt( buffer )
	
# mod any responses destined for LOCAL HOST
def response_handler( buffer ):
	# PERFORM PACKET MODS
	return pwp_prompt( buffer )
		
def pwp_prompt( buffer ):
	global fast_forward, packet_count
	string = "Press enter to continute, X to play w/ packet, # to fast forward, q to quit"
	control = raw_input( string )
	
	if control == 'X' or control == 'x':
		return __play_with_a_packet( packet_count, buffer )
	elif control == 'q' or control == 'Q':
		os._exit(0)
	elif isinstance( control, int):
		fast_forward = control
		print "Fast forward to " + fast_forward
		return buffer
	else:
		return buffer
	

def main( ):
	if len(sys.argv[1:]) != 5:
		out("Usage ./skzproxy.py [localhost] [localport] [remotehost] [remoteport] [recieve_first]", "#")
		out("Example ./proxy.py 127.0.0.1 9999 10.12.132.1 9000 True", "#")
		sys.exit( 0 )
		
	#setup local host listening parameters
	local_host = sys.argv[1]
	local_port = int( sys.argv[2] )
	
	remote_host = sys.argv[3]
	remote_port = int( sys.argv[4] )
	
	receive_first = sys.argv[5]
	
	if "True" in receive_first:
		receive_first = True
	else:
		receive_first = False
		
	#now spin up listening socket
	server_loop( local_host, local_port, remote_host, remote_port, receive_first )
	
#
# PLAY WITH A PACKET...THE PACKET PLAYER PROGRAM
#	
def __play_with_a_packet ( packet_num, packet_bytes ):
	global packet_info_source, packet_info_number, max_bytes
	global binstr_new, binstr_original
	
	packet_info_number = packet_num

	binstr_new = bytearray( packet_bytes )
	binstr_original = bytearray( packet_bytes )
	max_bytes = len( binstr_new )
	
	print "Playing with packet. Legnth: " + str(max_bytes)
#	binstr_for_restore = bytearray( binary_file.read() )
#	binstr_to_send_back_home = bytearray( binary_file.read() )
#	binary_file.close()
	run_packet( )

	return binstr_new

def help():
	help = "(E)dit - Edit this range of bytes\n"
	help += "(R)ange - Select a range of bytes to work with. *** First byte is 0\n"
	help += "(S)ave - Save the changes to a file\n"
	help += "(SO) - Save original to a file.\n"
	help += "(SR) - Save range to a file.\n"
	help += "(L)oad - Load the packet back.\n"
	help += "(C)lear - Clear the changes\n"
	help += "(F)ire - Sends the bytes back into the proxy and sends\n" 
	help += "(H)ex, (B)inary, (D)ec - Print the byte selection as Hex, Binary or Decimal Number\n"
	help += "(W)hole - Print entire packet\n"
	help += "(N)ame - Change the name of the packet exchange, like login, request, etc\n"
	help += "(NP)Name Project - Change the project name\n"
	help += "(I)nfo - Packet information\n"
	help += "(Q)uit - Quit this program\n"
	help += "(def) - Makes this range Default range\n"
	help += "(help) - type help for this cruft\n"
	help += "[ret] - Press return to continue\n\n"
	return help

def set_packet_info( source='test', number='1'):
	global packet_info_source, packet_info_number
	packet_info_source = source
	packet_info_number = number
	

def run_packet( ):
	global mode, high_byte, only_byte, binstr_new
	while True:
		if high_byte is None and only_byte is None:
			assign_range_from_master( )
		
		if not mode:
			pick_new_mode()
		else:
			print "\n%s:%s >" %(mode, get_range_string() )	
		
		if 	mode == 'R' or mode == 'r':
			pick_a_byte( )
			printer('hex' )
			new_line( )
			
		elif 	mode == 'Q' or mode == 'q':
			os._exit(0 )
			
		elif mode == 'L' or mode == 'l':
			print "Loading file"
			load_from_file( ) 
			printer( )
			new_line( )
		
		elif mode == 'S' or mode == 's':
			print "Dump binary range"
			save_to_file( ) 
			new_line( )
		
		elif mode == 'SO' or mode == 'so':
			print "Save ALL as binary"
			save_to_file( 'all' ) 
			new_line( )
		
		elif mode == 'SR' or mode == 'sr':
			print "Save RANGE"
			save_to_file( 'range' ) 
			new_line( )
		
		elif mode == 'W' or mode=='w':
			printer_all( )
			new_line( )
			
		elif mode == 'HELP' or mode=='help':
			print help( ) 
			new_line( )
			
		elif mode == 'def' or mode == 'DEF':
			save_master_range( )
			new_line
			
		elif mode == 'H' or mode == 'h' or mode == 'P' or mode == 'p':
			printer( 'hex' )
			new_line( )
			
		elif mode == 'b' or mode == 'B':
			printer( 'bin' )
			new_line( )
			
		elif mode == 'D' or mode == 'd':
			printer( 'dec' )
			new_line( )
		
		elif mode == 'N' or mode == 'n':
			pick_new_action_name( )
			new_line( ) 
		
		elif mode == 'NP' or mode == 'np':
			pick_new_project_name( )
			new_line( ) 
		
		elif mode == 'I' or mode == 'i':
			print_info( )
			new_line( )
		
		elif mode == 'c' or mode == 'C':
			restore_old_bytes( )
			new_line( )
			
		elif mode == 'E' or mode == 'e':
			edit_mode( )
		
		elif mode == 'f' or mode == 'F':
			new_line( )
			return binstr_new
						
		else:
			new_line( )

		
			
def edit_mode():
	#printer( 'hex' )		#first print the string
	prompt = 	"Enter new string.  Type x or X for each byte to remain same or new val. "
	prompt +=	"If you shorten str, will fill with existing vals. Blank ret when done\n"
	prompt +=	 " " +printer( 'edit' ) + "\n>"
	
	mod = raw_input( prompt)
	if mod == "":
		new_line( )
		return
	process_edit( mod )


def process_edit( line ):
	global binstr_new
	global only_byte, low_byte, high_byte, max_bytes
	
	line = re.sub( '\s{1,}' , ' ', line.rstrip() )
	entries = line.split()
	count = len( entries)
	count_binstr = len( binstr_new)
	
	#chop off anything longer than the source string.
	if count > count_binstr:
		count = count_binstr 
	
	hexaPattern = "\s--[0-9a-fA-F]+[--]?\s"
	#editing single byte	
	if high_byte == None and only_byte:
		print "x"
		if entries[0] == 'x' or entries[0] == 'X' or entries[0] == 'xx' or entries[0] == 'XX':
			return
		else:
			binstr_new[only_byte] = entries[0]
	#editing range of bytes
	elif high_byte:
		bottom_of_orig = low_byte
		for index in range( 0, count ):
			target = int(bottom_of_orig) + int(index)
			if entries[index] == 'x' or entries[index] == 'X' or entries[index] == 'xx' or entries[index] == 'XX':
				continue
			
			if re.search(hexaPattern, entries[index]):
				return -1
			else:
				new_val = int( entries[index], 16 )
				print "Change " + str(binstr_new[target]) + " to " + hex(new_val)
				binstr_new[target] = new_val
				
				#binstr_new[target] = entries[index]
	else:
		print "full"
	
	print "Edited."
	printer( 'hex' )
	

def print_info():
	global packet_info_source, packet_info_number, packet_info_action_name
	global only_byte, low_byte, high_byte, max_bytes
	global save_dir, binstr_original, max_bytes, fast_forward
	strg = 		"[+] Packet info name: " + packet_info_name +"\n"
	strg += 	"[+] Packet info Action Name:" + str( packet_info_action_name )+"\n"
	strg += 	"[+] Packet info source :" + str( packet_info_source )+"\n"
	strg += 	"[+] Packet info number:" + str( packet_info_number )+"\n"
	strg += 	"[+] Only byte: " + str(only_byte) +"\n"
	strg += 	"[+] Low byte:" + str(low_byte) +"\n"
	strg += 	"[+] High byte:" + str(high_byte) +"\n"
	strg += 	"[+] Path:" + save_dir +"\n"
	strg += 	"[+] Length:" + str( max_bytes ) + "\n"
	strg += 	"[+] Fast forward:" + str( fast_forward ) + "\n"
	strg += 	"\n"
	print strg

def pick_new_project_name( ):
	global packet_info_name
	string = "Pick new project name for (like program name etc) >"
	packet_info_name = raw_input( string )

def pick_new_action_name( ):
	global packet_info_action_name
	string = "Pick new action name for packet group (like login, options, etc) >"
	packet_info_action_name = raw_input( string )

def set_packet_owner_name( target ):
	global packet_info_source
	packet_info_source = target

	
def pick_new_mode():
	global mode

	range_str = get_range_string()
	
	string = "[?] %s; Range: R/S/L/E/def; Prt H/N/W; SO/[C]lear/[F]ire; Q/help/ret >" %range_str
	mode= raw_input( string )
	
def load_from_file( ):
	global only_byte, low_byte, high_byte, max_bytes
	global packet_info_source, packet_info_number, packet_info_name, packet_info_name,packet_info_action_name
	global binstr_new, binstr_original
	file_name = save_dir + '/' + packet_info_name + '-' + packet_info_action_name + '_' + packet_info_source + str(leading_zero(packet_info_number))

	file_name = file_name +'_mod'
	print "Loading file: "+file_name
	try:
		bin_file = open( file_name + '.pbin' , 'rb+')	
		binstr_new = bytearray( bin_file.read() )
		bin_file.close( )
		
		if ( os.path.isfile( file_name+".conf" )):
			fz = open( file_name + ".conf", "r" )
			directive = fz.read( )
			fz.close()
			x = directive.split("-")
			low_byte,high_byte = x[0],x[1]
		
		print "Loaded: " +file_name
	except:
		print "Failed loading file " +file_name
	
	count = len( binstr_new )
	print "Loaded " + str(count) + " bytes."
	
def save_to_file( save='mod' ):
	global only_byte, low_byte, high_byte, max_bytes
	global packet_info_source, packet_info_number, packet_info_name, packet_info_name,packet_info_action_name
	global binstr_new, binstr_original
	
	file_name = save_dir + '/' + packet_info_name + '-' + packet_info_action_name + '_' + packet_info_source + str( leading_zero(packet_info_number) )
	file_list = list()
	
	if save == 'mod':
		file_name = file_name +'_mod' + '.pbin'
		print "Saving file as MOD: "+file_name
		try:
			fz = open( file_name, "wb+" )
			fz.write(   bytes( binstr_new ) )
			fz.close()
			
			fz = open( file_name + ".conf", "w+" )
			fz.write(   low_byte + "-" + high_byte )
			fz.close()
			
			print "Saved original as: " +file_name
		except:
			print "Could not save file " +file_name
#			print "ERROR error({0}) : {1}" +format(errno, stderror)
	elif save == 'range' and high_byte is not None:
		#just save the range
		file_name = file_name +  '_RANGE'  +   '-'   + low_byte + '-' + high_byte+'.pbin'
		print "Saving file as RANGE: "+file_name
		try:
			fz = open( file_name, 'wb+') 
			fz.write(   bytes( binstr_original ) )
			fz.close()
			print "Saved range as: " +file_name
		except:
			print "Could not save rage as: " +file_name
			
	else:
		file_name = file_name + '_full'+'.pbin'
		print "Saving file as FULL: "+file_name
		try:
			fz = open( file_name, 'wb+') 
			fz.write(   bytes( binstr_original ) )
			fz.close()
			print "Saved original as: " +file_name
		except:
			print "Could not save file " +file_name

	
def leading_zero( number ):
	
	number = str(number)
	if len( number ) == 1:
		return '000' + number
	elif len( number ) == 2:
		return '00' + number
	elif len( number ) == 3:
		return '0' + number
	else:
		return number			
	
def new_line():
	global mode
	mode = None
	print "\n"

def restore_old_bytes():
	global binstr_new,binstr_original
	binstr_new = binstr_original
	
def save_master_range():
	global master_only_byte, master_low_byte, master_high_byte
	global only_byte, low_byte, high_byte
	
	if only_byte:
		print "Saved %s as range" %only_byte
		master_only_byte = only_byte
		
	if high_byte:
		print "Saved %s-%s as range" %(low_byte, high_byte)
		master_high_byte = high_byte
		master_low_byte = low_byte

	
def assign_range_from_master():
	global master_only_byte, master_low_byte, master_high_byte
	global only_byte, low_byte, high_byte
	
	if master_only_byte:
		print "Assigned %s" %master_only_byte
		only_byte = master_only_byte
		
	if master_high_byte:
		print "Assigned %s-%s" %(low_byte,high_byte)
		high_byte = master_high_byte
		low_byte = master_low_byte

	
			
def pick_a_byte():
	global only_byte,high_byte,low_byte
	target_byte_string = raw_input( "Pick the bytes to work on: # or #-#> ")
	matchObj = re.match( r'(\d*?)-(\d*)', target_byte_string, re.M|re.I )
	if matchObj:
		low_byte = matchObj.group(1)
		high_byte =  matchObj.group(2)
	else:
		matchObj = re.match( r'(\d*)', target_byte_string, re.M )
		if matchObj:
			only_byte = matchObj.group()
			
def get_range_string():
	global only_byte,high_byte,low_byte

	if only_byte and high_byte == None:
		range_str = only_byte
	elif high_byte and only_byte == None:
		range_str = low_byte + "-" + high_byte
	else:
		range_str = "ALL"
		
	return range_str
		
def printer_all( format = 'hex' ):
	global binstr_new
	print "Printing entire packet."
	hexdump_pwp ( binstr_new )
		
def printer( format='hex' ):
	global only_byte,high_byte,low_byte, binstr_new
	print "Printing range %s in string" %( get_range_string() )
	couple_bytes = None
	
	if high_byte:
		#seek position and read N bytes
		print "Seeking %d through %d" %(int(low_byte), int(high_byte))
		#binstr_new.seek( int(low_byte) ) # go to beginning
		#couple_bytes = binstr_new.read( int(high_byte) - int(low_byte) )
		couple_bytes = binstr_new[int(low_byte):int(high_byte)] 
	
	if only_byte:
		print "Seeking %d" %(int(only_byte))
		 # go to beginning
		couple_bytes = binstr_new[ int(only_byte) ]
		hexdump (couple_bytes)

	if only_byte == None and high_byte == None:
		hexdump( binstr_new.read( ) )
	
	if format == 'hex':
		print "Dumping hex\n"
		hexdump_pwp (couple_bytes)
	elif format == 'dec':
		print "Dumping decimal\n"
		decdump_pwp (couple_bytes)
	elif format == 'bin':
		print "Dumping Binary\n"
		bindump (couple_bytes)
	elif format == 'edit':
		print couple_bytes
		return print_hex_for_edit( couple_bytes )

def print_hex_for_edit( src, length=16):
	result = []
	digits = 4 if isinstance(src, unicode) else 2
	print src +"\n--\n"
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, x) for x in s])	
	return hexa
		
def bindump( src, length=16):
	print "Not implemented"		

def decdump_pwp( src, length=16 ):
	result = []
	digits = 4 if isinstance(src, unicode) else 2
	
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b' '.   join( [str(ord(x)) for x in s])

		result.append( b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text) )
	print b'\n'.join(result)


	
def hexdump_pwp( src, length=16):
	result = []
	src = str(src)
	digits = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b''.   join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])

		result.append( b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text) )
	print b'\n'.join(result)


	
	
	
main( )

		