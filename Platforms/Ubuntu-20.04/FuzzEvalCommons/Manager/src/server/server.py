from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor


import filecmp
import os
import argparse
import pathlib
import glob
import shutil
import subprocess
import datetime

STOP_COMMAND = "NONE"
DEBUG = False
TIMESTAMP = False


def isValid(data, modulussize):
    # print("HELLO WORLD")
    # trivial checks
    # print(len(data))
    data = bytearray.fromhex(data)
    # print(data)
    
    if(len(data) != modulussize):
        # print("Length Problem")
        return False
    if(data[0] != 0x00):
        return False
    if(data[1] != 0x01):
        return False
    
    padding_count = 0
    idx = 2
    while(idx < len(data)):
        if(data[idx] == 0xFF): # valid padding bytes
            padding_count+=1
            idx+=1
        elif(data[idx] == 0x00): # padding finished
            idx+=1
            break
        else:
            return False # anything else in padding is not allowed
    
    data_bytes_count = len(data[idx:])
    
    if(padding_count<8):
        return False
    
    return modulussize == (padding_count+data_bytes_count+3)

class LoggingProtocol(Protocol):

    def __init__(self, factory):
        self.factory = factory

    def connectionMade(self):
        self.factory.numProtocols = self.factory.numProtocols + 1
        # self.transport.write(b"Welcome! There are currently %d open connections.\n" % (self.factory.numProtocols,))

    def connectionLost(self, reason):
        self.factory.numProtocols = self.factory.numProtocols - 1

    def dataReceived(self, data):
        curstamp = None
        if(TIMESTAMP):
            curstamp = datetime.datetime.timestamp(datetime.datetime.now())
        if(DEBUG):
            print("New Data Received")
        self.transport.loseConnection()
        decoded_data = ""
        try:
            decoded_data = data.decode('utf-8')
        except Exception as e:
            with open(self.factory.server_log_file, "a") as f:
                f.write("Exception when decoding utf-8 string: {}".format(datetime.datetime.now()))
                f.write("Data: (bytes)")
                f.write(data)
                f.write("\n")
                
                
        try:
            if(decoded_data.strip() == STOP_COMMAND):
                print("STOP COMMAND RECEIVED!")
                print("REACOTR SHUTTING DOWN.....")
                reactor.stop()
            
            else:
                v = isValid(decoded_data.split(",")[0], modulussize=2048//8)
                vv = 0
                if(v == True):
                    vv = 1
                
                WRITE_DATA = decoded_data+","+str(vv)+"\n"
                if(TIMESTAMP):
                    WRITE_DATA = str(curstamp)+","+WRITE_DATA
                    
                self.factory.fp.write(WRITE_DATA)
                self.factory.fp.flush()
                os.fsync(self.factory.fp)
                
        except Exception as e:
            WRITE_DATA = decoded_data+",-1"+"\n"
            if(TIMESTAMP):
                    WRITE_DATA = str(curstamp)+","+WRITE_DATA
                    
            self.factory.fp.write(WRITE_DATA)
            with open(self.factory.server_log_file, "a") as f:
                f.write("Exception when calling isValid(): {}".format(datetime.datetime.now()))
                f.write("Data: (decoded)")
                f.write(decoded_data)
                f.write("\n")
                   
        
        # print("Number of open connections: {}".format(self.factory.numProtocols))
        

        
        # self.factory.fp.flush()


class LogFileFactory(Factory):
    protocol = LoggingProtocol
    # server_log_file = "LOG.txt"

    def __init__(self, log_file_name) -> None:
        self.numProtocols = 0
        self.log_file_name = log_file_name
        self.server_log_file = self.log_file_name+"-debug-log.log"

    def startFactory(self):
        if(DEBUG):
            print("SERVER STARTING IN DEBUG MODE....")
        else:
            print("SERVER STARTING...")
        
        self.fp = open(self.log_file_name, "a")
        with open(self.server_log_file, "a") as f:
            f.write("Server Starting at: {}\n".format(datetime.datetime.now()))
        return super().startFactory()

    def stopFactory(self):
        self.fp.close()
        print("SERVER STOPPING...")
        with open(self.server_log_file, "a") as f:
            f.write("Server Stopping at: {}\n".format(datetime.datetime.now()))
        return super().stopFactory()

    def buildProtocol(self, addr):
        return LoggingProtocol(self)

def main():
    parser = argparse.ArgumentParser(description="Run Logger Server For Fuzzing Campaigns.")
    parser.add_argument("-lp", '--logfilepath', help='Path to the logfile', required=True)
    parser.add_argument("-p", '--portnumber', help='Port number for running the server.', default=9090)
    parser.add_argument("-sc", '--stopcommand', help="Command for turning off the server", default="STOP_SERVER_NOW")
    parser.add_argument("-bl", '--backlog', help="backlog value for the server", default=100)
    parser.add_argument("-d","--debug", action="store_true")
    parser.add_argument("-ts","--timestamp", action="store_true" )
    
    args = vars(parser.parse_args())
    global STOP_COMMAND
    global DEBUG,TIMESTAMP
    STOP_COMMAND = args["stopcommand"]
    DEBUG = args['debug']
    TIMESTAMP = args['timestamp']
    # 8007 is the port you want to run under. Choose something >1024
    endpoint = TCP4ServerEndpoint(reactor, int(args['portnumber']), backlog=int(args['backlog']))
    factory = LogFileFactory(args['logfilepath'])
    endpoint.listen(factory)
    reactor.run()


if __name__ == "__main__":
    main()
