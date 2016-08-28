import os
import sys, io
import re
import socket
import threading
import difflib
# 
# Globals
# 
packet_info_name = 'skzproxy-challenge2'
packet_info_source = 'L'
packet_info_number = '1'

packet_count = 0

bin_stream = None
bin_stream_original = None
new_bin_stream = None
baseline_resp = None
prior_response = None
recursion_counter = 0

master_only_byte = None
master_low_byte = "0"
master_high_byte = "8"

max_bytes = None

fast_forward = None

save_dir = '/root/Desktop/pentest/tools/skzproxy/save_packets'
sock = None
fuzz_byte_list = list()
fuzz_range_list= list()
fuzz_options_reconnect = None
fuzz_options_reverse = None
fuzz_options_delay = 0
fuzz_options_verbose = 0
# who is target?
	# open dir      
# port?
# which file?
# load file?
# send
target_ip = None
target_port = None

picked_file = None

def main( ):
	global target_ip, target_port, bin_stream, sock
	
	if len(sys.argv[1:]):
		target_ip = sys.argv[1]
		if sys.argv[2]:
			target_port = int( sys.argv[2] )
			inet_setup_networking( )
		else:
			print "You need to specify a port!"
		try:
			if  sys.argv[3]:
				file_listing( sys.argv[3] )
				file_show_the_file( )
		except:
			None
	
	while True:
		string = 	"(T)gt; (L)d, (E)dt, (R)str, (N)ew, (V)iew, (S)nd, (I)nf, (Q)t, re(C)nct\n"
		string += 	"FUZZ> F-setup, Z-fire, D-del; FO-see opts, ZO-set opts, FD-set delay, FV - verbose \n"
		string += 	"> "
		cmd = raw_input( string )
		if cmd == 'L' or cmd == 'l':
			file_listing( )
			
		if cmd == 'N' or cmd == 'n':
			edit_custom_packet( )
		
		if cmd == 'F' or cmd == 'f':
			if bin_stream is None:
				print "Need a packet if you want to fuzz"
				continue
			else:
				fuzz_setup_fuzzing( )
		
		if cmd == 'Z' or cmd == 'z':
			if bin_stream is None:
				print "Need a packet if you want to fuzz"
				continue
			if len(fuzz_byte_list[:1]) <1:
				print "Need to set up fuzzer before you fuzz. Press F to set up."
				continue
			fuzz_DOIT( )
		
		if cmd == 'FO' or cmd == 'fo':
			fuzz_print_fuzzing_options( )
		
		if cmd == 'ZO' or cmd == 'zo':
			fuzz_setup_fuzzing_options( )
		
		if cmd == 'FD' or cmd == 'fd':
			fuzz_setup_fuzzing_options_delay( )
		
		if cmd == 'FV' or cmd == 'fv':
			print "ADD VERBOSITY FOR FUZZER"
		
		if cmd == 'D' or cmd == 'd':
			fuzz_delete_fuzz_var( )
		
		if cmd == 'C' or cmd == 'c':
			if target_ip is None:
				print "Need IP address."
				continue
			else:
				sock.close( )
				inet_setup_networking( )
		elif cmd =='V' or cmd == 'v':
			if bin_stream:
				file_show_the_file( )
		elif cmd == 'E' or cmd == 'e':
			if bin_stream is None:
				print "Need to load some packets\n"
			else:
				edit_packet( )
		elif cmd == 'R' or cmd == 'r':
			if bin_stream is None or bin_stream_original is None:
				print "Need to load some packets\n"
			else:
				edit_restore_packet( )
		elif cmd =='Q' or cmd == 'q':
			sys.exit( )
		elif cmd == 'T' or cmd == 't':
			inet_set_target( )
		elif cmd == 'I' or cmd == 'i':
			print_info( )
		elif cmd == 'S' or cmd == 's':
			final = None
			if bin_stream is None:
				print "Need to specify packets to send."
				continue
			if target_ip is not None:
				print "Sending packet."
				final = inet_send_the_packet( )
			else:
				print "Need an IP address"
			if final is not None:
				hexdump_stream( final )
		else:
			None
		print "\n"
		
def inet_setup_networking( ):
	#setup local host listening parameters
	global target_ip, target_port, sock
	
	if target_ip is not None and target_port is not None:
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.timeout(4)
			sock.connect(( target_ip, target_port ))
		except:
			print "Failed to open socket"
	else:
		print "Can't connect. - " +target_ip +":"+str(target_port)
	
	print "Connection OK..."
	
def inet_send_the_packet( ):
	global sock, bin_stream, target_ip, target_port
	data = None
	
	try:
		sock.connect(( target_ip, target_port ))
	except:
		None
	
	print "\n"
	print "Attempting to send "+ str( len( bin_stream) ) + " bytes to "+target_ip + ":"+str(target_port)
	hexdump(bin_stream)
	
	if sock is None:
		inet_setup_networking( )
				
	try:
		print "Sending"
		sock.send(  bin_stream )
	except:
		print "Failed to send"
		
	try:
		data = sock.recv(4096)
		print "Received " + str(len(data)) + " bytes"
	except:
		print "Failed to receive response"
	
	print "Completed..."
	return data
	
def print_info( ):
	global target_ip, target_port, picked_file, bin_stream, bin_stream_original
	
	print "Target_ip: " +target_ip if target_ip else None
	print "Target_port: " + str(target_port) if target_port else None
	print "Picked File: " + picked_file if picked_file else None
	print "Packets Len: " + str(len( bin_stream )) if bin_stream else None
	print "Original Len: " + str(len( bin_stream_original )) if bin_stream_original else None
	fuzz_print_fuzzing_options( )
	
def inet_set_target():
	global target_ip, target_port
	string = "Please enter an ip:port >"
	loc = raw_input( string )
	ip_parts = loc.split(":")
	target_ip = ip_parts[0]
	target_port = ip_parts[1]

def file_listing( cmd_line = None ):
	global picked_file
	file_list = list()
	index = 1
	
	for file in ( sorted(os.listdir( save_dir))):
		if file.endswith(".pbin"):
			if cmd_line is None:
				print str( index ) +' - '+file
			file_list.append( file )
			index += 1
	
	if cmd_line is not None:
		picked_file = file_list[ int(cmd_line) -1]	
		print "Picked # " + picked_file +" from command line"
		load_the_file( picked_file )
		return 
	
	string = "Pick your file >"
	picked_index = raw_input( string )
	
	if picked_index:
		picked_file = file_list[int(picked_index) -1]	
		print "Picked # " +str(picked_index) + " - " + picked_file
		load_the_file( picked_file )
		
def load_the_file( file_name ):
	global bin_stream, save_dir, bin_stream_original 
	file_name_local = save_dir + '/' + file_name
	try:
		bin_file = open( file_name_local, 'rb+')	
		bin_stream = bytearray( bin_file.read() )
		bin_file.seek(0)
		bin_stream_original = bytearray( bin_file.read() )
#		new_bin_stream = bytearray( bin_file.read() )
		bin_file.close( )
	except:
		print "Failed to load file " + file_name_local
	
	print "Loaded file "+file_name_local
	file_show_the_file( )
	
			
def file_show_the_file( ):
	global bin_stream
	hexdump( bin_stream )

	
def hexdump( src, length=16):
	global bin_stream
	result = [ ]
	digits = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.  join( ["%0*X" % ( digits, x ) for x in s] )
		text = b''.join([chr(x) if 0x20 <= x < 0x7F else b'.' for x in s])
		result.append( b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text) )
		
	print b'\n'.join(result)	

def hexdump_stream( src, length=16):
	result = []
	digits = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b''.   join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])

		result.append( b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text) )
	print b'\n'.join(result)

def hexdump_to_string( src, range=0, length=16 ):
	result = [ ]
	digits = 4 if isinstance(src, unicode) else 2
	
	len_to_print = len(src)
	if ( range > 0 ):
		print range
		len_to_print = range
	for i in xrange(0, len_to_print, length):
		s = src[i:i+length]
		hexa = b' '.  join( ["%0*X" % ( digits, x ) for x in s] )
		
		result.append( b"%-*s" % (length*(digits + 1), hexa) )
	return b'\n'.join(result)

def edit_restore_packet( ):
	global bin_stream, bin_stream_original
	bin_stream[:] = bin_stream_original
	hexdump(bin_stream)
	hexdump(bin_stream_original)

	
def edit_custom_packet( ):
	global bin_stream
	prompt = "Enter your packet in hex format, seperated by spaces.\n>"
	packet = raw_input( prompt )
	
	packet = re.sub( '\s{1,}' , ' ', packet.rstrip() )
	entries = packet.split()
	count = len( entries )
	new_buffer = list()
	new_line = None
	
	for byte in entries:
		byte = is_this_valid_hex( byte ) 
		new_buffer.append( int( byte, 16) ) 
	
	bin_stream = bytearray( new_buffer )
	
	
def edit_packet( ):
	global bin_stream
	prompt = 	"Enter new string.  Type x or X for each byte to remain same or new val. "
	prompt +=	"If you shorten str, will fill with existing vals. Blank ret when done\n"
	prompt +=	 " " + hexdump_to_string( bin_stream, 16 ) + "\n>"
	
	mod = raw_input( prompt)
	if mod == "":
		return
	edit_process_edit( mod )
		

def edit_process_edit( line ):
	global bin_stream
		
	line = re.sub( '\s{1,}' , ' ', line.rstrip() )

	entries = line.split()
	count = len( entries )
	count_binstr = len( bin_stream )
	
	#chop off anything longer than the source string.
	if count > count_binstr:
		count = count_binstr 
	
	hexaPattern = "\s--[0-9a-fA-F]+[--]?\s"
	#editing single byte	
	for index in range( 0, count ):
		target = int(index)
			
		if entries[index] == 'x' or entries[index] == 'X' or entries[index] == 'xx' or entries[index] == 'XX':
				continue
		
		entries[index] = is_this_valid_hex( entries[index] )
		
		new_val = int( entries[index], 16 )
		print "Change " + str( bin_stream[target] ) + " to " + hex(new_val)
		bin_stream[target] = new_val
				
				#binstr_new[target] = entries[index]
	print "Edited."
	file_show_the_file(  )


def is_this_valid_hex( val ):
	val = str( val )
	Valid='1''2''3''4''5''6''7''8''9''10''A''B''C''D''E''F"a"b"c"d"e"f'
	
	if len(val) <1:
		print "*** Bad value for "+val +" returning 00 "
		return '00'
	
	if ( len(val) >2):
		print "*** Bad value for "+val +" returning 00 "
		return '00'
	
	for char in str(val):
		if char not in Valid:
			print "Invalid characters found in "+val+ " returning 00."
			return '00'
	return val

#only dump first 16.
# todo - make it show multiple sets of 16
def hexdump_for_fuzzing( ):
	global bin_stream
	bytes = len( bin_stream )
	length = 16
	i = 0
	subset = bin_stream[i:i+length]
	byteno_stack = list( )
	hexval_stack = list( )
	counter = 0
	for x in subset:
		byteno_stack.append( "%2s" % (str(counter) ) )
		hexval_stack.append( "%0*X" % (2, x ))
		counter += 1

	num_str = ' ' . join( byteno_stack )
	hex_str  = ' ' . join( hexval_stack )
	print "Num - " + num_str
	print "Hex - " + hex_str
	

def fuzz_print_fuzzing_options():
	global fuzz_byte_list, fuzz_range_list, fuzz_options_reconnect, fuzz_options_reverse, fuzzing_options_delay
	fuzz_byte_count = len( fuzz_byte_list)
	
	x= 'No'
	if fuzz_options_reconnect == 1:
		x= 'Yes'
	
	y= 'No'
	if fuzz_options_reverse == 1:
		y= 'Yes'
	
	warning = ''
	if int(fuzz_calc( )) > 1000:
		warning = " *** MORE THAN 1000 ATTEMPTS, CAUTION ***\n"
	
	fostr =   "*** Fuzzing options ***\n"
	fostr += warning
	fostr += "Fuzz options reconnect: " + x + " ("+ str(fuzz_options_reconnect)+")" +"\n"
	fostr += "Fuzz options backwards first: " + y+ " ("+ str(fuzz_options_reverse)+")" +"\n"
	fostr += "Fuzz options sec delay between attempts: " + str(fuzz_options_delay) +"\n"
	fostr += "Total fuzz attempts: "+ str( fuzz_calc( ) ) + ".\n"
	fostr += "Fuzzing "+ str(fuzz_byte_count) + " bytes.\n"
	fostr += warning
	
	for i in range(0, fuzz_byte_count):
		fostr += str(i + 1) +" - Byte " + str(fuzz_byte_list[i]) + ": " + str(fuzz_range_list[i]) + "\n"
	
	print fostr
	
def fuzz_delete_fuzz_var( ):
	global fuzz_byte_list, fuzz_range_list
	fuzz_numbers = list( )
	
	for x in fuzz_byte_list:
		fuzz_numbers.append( "%5s" % (str(x) ) )
	
	num_str = ' ' . join( fuzz_numbers )
	range_str = ' ' . join( fuzz_range_list )
				
	prompt = 		num_str+"\n"
	prompt += 	range_str+"\n"
	prompt += 	"Enter a byte fuzz which you want to delete >"
	del_fuzz_byte = raw_input( prompt )
	
	if not fuzz_byte_list:
		print "Nothing set to fuzz!"
		return
	if del_fuzz_byte > max( fuzz_byte_list ):
		print "Too big."
		return
	
	print "Deleting " + str(del_fuzz_byte) +"."
	try:
		del_indx = fuzz_byte_list.index( str(del_fuzz_byte) )
		print "Deleting "+str( del_fuzz_byte ) + " at index: " + str( del_indx )
		del fuzz_byte_list[del_indx]
		del fuzz_range_list[del_indx]
	except:
		print "Failed to delete "+str( del_fuzz_byte ) +"."
		return
	
def fuzz_setup_fuzzing( ):
	global bin_stream, fuzz_byte_list, fuzz_range_list, fuzz_options_reconnect
	fuzz_max = len( bin_stream )
	
	hexdump_for_fuzzing()
	
	# Get the list and put it into fuzz_this.
	prompt = "Pick bytes to fuzz, sep by space or , 0 - "+ str(len( bin_stream )) +"; Note only 1-16 displayed. \n> "
	fuzz_this = raw_input( prompt )
		
	# Split fuzz this, fuzz_entries is now the official list.  
	# count_fuzz_entries is the number entered (in the list)
	fuzz_entries = re.split(',| ', fuzz_this)
	count_fuzz_entries = len( fuzz_entries )
	
	# loop through 0 through fuzz_entries
	index = 0
	for index in xrange( 0, count_fuzz_entries ):
		
		#if this fuzz_entry is larger than the number of elements in the packet, 
		if int( fuzz_entries[index] ) > int( fuzz_max ):
			print str( fuzz_entries[index] ) + " is too big. Set to " + str(fuzz_max)
			fuzz_entries[index] = fuzz_max
		
		# OK, so now put the entry into our master fuzz byte list.
		# TODO - check if entry in master byte list then overwrite instead of append.
		try:
			del_ind = fuzz_byte_list.index( fuzz_entries[index] )
			print del_ind
			del fuzz_byte_list[del_ind]
			del fuzz_range_list[del_ind]
		except:
			None
	
		fuzz_byte_list.append( fuzz_entries[index] )
		
		# now get the range to fuzz
		new_prompt = "Byte %s Range to fuzz (##-## up to FF) or enter to do 0-FF\n> " %str(fuzz_entries[index])
		range = fuzz_sort_the_range( raw_input( new_prompt ) )
		fuzz_range_list.append( range )
	
	if fuzz_options_reconnect is None:
		fuzz_setup_fuzzing_options( )
	# And get this options.
	
def fuzz_setup_fuzzing_options():
	global fuzz_options_reconnect, fuzz_options_reverse
	prompt = "Reconnect on no response? Y/n >"
	fuzzopt = raw_input( prompt )
	if fuzzopt == 'q' or fuzzopt == 'Q':
		sys.exit( )
	if fuzzopt == 'N':
		fuzz_options_reconnect = 0
	else:
		fuzz_options_reconnect = 1

	prompt = "Loop backwards first? Y/n >"
	fuzzopt = raw_input( prompt )
	if fuzzopt == 'q' or fuzzopt == 'Q':
		sys.exit( )
	if fuzzopt == 'N':
		fuzz_options_reverse = 0
	else:
		fuzz_options_reverse = 1

		
def fuzz_sort_the_range( fuzz_range ):
	if len(fuzz_range)<1:
		return "00:FF"
	
	range_split = re.split( '-|:|,| ', fuzz_range  )
	
	if (range_split):
		None
	else:
		print "Split failed - "+fuzz_range
		return "00:FF"
	
	low_byte = is_this_valid_hex( range_split[0] )
	high_byte = is_this_valid_hex( range_split[1] )
	
	if int(low_byte, 16) > int(high_byte, 16):
		print "Swapping low " +low_byte + " and high byte " + high_byte
		temp_byte = high_byte
		high_byte = low_byte
		low_byte = temp_byte
	
	print "OK range:" + low_byte + ":" + high_byte +"\n"
	return low_byte + ":" + high_byte
	
def fuzz_setup_fuzzing_options_delay():
	global fuzz_options_delay
	old_just_in_case = fuzz_options_delay
	prompt = "Enter your delay in seconds. Currently at " + str(fuzz_options_delay)+" > "
	new_delay = raw_input( prompt )
	try:
		fuzz_options_delay = int(new_delay, 10)
	except:
		fuzz_options_delay = old_just_in_case
	
def fuzz_calc( ):
	global fuzz_range_list
	
	calc = 1
	for r in fuzz_range_list:
		l = r.split( ':' )
		range_low = int( l[0], 16 )
		range_high = int( l[1], 16 )
	#	print "%s Ranges %d - %d" %(r, range_low, range_high)
		calc *= (range_high - range_low)
	return calc
	
def fuzz_DOIT( ):
	global bin_stream, new_bin_stream, baseline_resp
	printProgress(0, int( fuzz_calc() ), prefix = 'FUZZ:', suffix = 'Complete', barLength = 50)
	baseline_resp = inet_send_the_packet( )
	new_bin_stream =  bin_stream 
	fuzz_recurse( )
	
def fuzz_recurse( ind=0 ):
	global new_bin_stream, fuzz_byte_list, fuzz_range_list, recursion_counter
	
	if ind >= len(fuzz_byte_list):
		return
	if ind >= len(fuzz_range_list):
		return

	# setup	
	this_byte = fuzz_byte_list[ind]
	fuzz_rages = fuzz_range_list[ind]
	l = fuzz_rages.split( ':' )
	low_range = l[0]
	high_range = l[1]
	ind += 1
	# Do the loop
	for new_val in range( int(low_range,16), int(high_range,16)+1 ):
		new_bin_stream[ int( this_byte ) ] = new_val
		# FIRE!
		if ind == len(fuzz_byte_list):
			recursion_counter += 1
			printProgress(recursion_counter, int( fuzz_calc() ), prefix = 'FUZZ:', suffix = 'Complete', barLength = 50)
			fuzz_fire( new_bin_stream )
		fuzz_recurse( 	ind )
#	

def fuzz_fire( new_bin_stream ):
#	print "FUZZER firing:"
	#hexdump( new_bin_stream )
	fuzz_handle_response( 
		fuzz_inet_send_the_packet( ) )
	
def fuzz_handle_response( fuzz_resp ):
	global baseline_resp, prior_response
	if fuzz_resp == '-1' or fuzz_resp == '-2' or fuzz_resp == '-3':
		fuzz_fail( fuzz_resp )
	
	if len( fuzz_resp ) == 0:
		if( fuzz_options_reconnect ):
			sock.close( )
			inet_setup_networking( )
	else:
#		diff = difflib.SequenceMatcher( None, baseline_resp, fuzz_resp )
		if fuzz_resp <> prior_response:
			print  "\n________  _______  _______  _______  _______  _______ "
			print "FUZZ String:"
			hexdump( new_bin_stream )
			
			print "\nFUZZ RESPONSE:"
			hexdump_stream( fuzz_resp )
			if prior_response:
				print "\nPrior Response:"
				hexdump_stream( prior_response )
			print "\nBaseline Response:"
			hexdump_stream( baseline_resp )
			print "\n"
#			print diff
	prior_response = fuzz_resp

def fuzz_compress_fuzzed_bitstream_lt8b( ):
		None
			
def fuzz_logger( str ):
	print "FUZZ: "
	
def fuzz_fail( err ):
	print "*** Fuzzer got an error: " + str( err )
	

def fuzz_inet_send_the_packet( ):
	global new_bin_stream, target_ip, target_port
	data = None
	try:
		sock.connect(( target_ip, target_port ))
	except:
		None
	
	if sock is None:
		inet_setup_networking( )
				
	try:
		sock.send(  new_bin_stream )
	except:
		print "***Failed to send***"
		return "-2"
		
	try:
		data = sock.recv(4096)
	except:
		return "-3"
	
	return data

# Print iterations progress
def printProgress (iteration, total, prefix = '', suffix = '', decimals = 1, barLength = 100):
    
#    Call in a loop to create terminal progress bar
 #   @params:
  #      iteration   - Required  : current iteration (Int)
#        total       - Required  : total iterations (Int)
 #       prefix      - Optional  : prefix string (Str)
  #      suffix      - Optional  : suffix string (Str)
   #     decimals    - Optional  : positive number of decimals in percent complete (Int)
#    barLength   - Optional  : character length of bar (Int)
	
	formatStr       = "{0:." + str(decimals) + "f}"
	percents        = formatStr.format(100 * (iteration / float(total)))
	filledLength    = int(round(barLength * iteration / float(total)))
	bar             = '*' * filledLength + '-' * (barLength - filledLength)
    
	sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),
	sys.stdout.flush()
	if iteration == total:
		sys.stdout.write('\n')
		sys.stdout.flush()	


main()
