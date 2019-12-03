import sys
import generator

ipAddress = sys.argv[1]
portAddress = int(sys.argv[2])
filename = sys.argv[3]

generator.generator_payloads(ipAddress, portAddress, filename)

