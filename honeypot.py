from twisted.internet import protocol, reactor
from twisted.protocols import basic

class HoneyPotProtocol(basic.LineReceiver):
    def connectionMade(self):
        print("Connection made")
        self.sendLine(b"Welcome to the honeypot!")
        self.sendLine(b"Username: ")

    def lineReceived(self, line):
        print(f"Received: {line}")
        username = line.strip()
        self.sendLine(f"Password for {username}:".encode())
        print(f"Sent: Password for {username}")

    def rawDataReceived(self, data):
        print(f"Raw data received: {data}")
        with open("honeypot.log", "ab") as log_file:
            log_file.write(data)

class HoneyPotFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return HoneyPotProtocol()

if __name__ == "__main__":
    reactor.listenTCP(22, HoneyPotFactory())
    print("Honeypot is successfully running on port 22")
    reactor.run()
