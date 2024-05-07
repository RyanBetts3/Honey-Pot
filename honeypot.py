import logging
import re
from twisted.internet import protocol, reactor
from twisted.protocols import basic

# Configure logging
logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Define allowed usernames and passwords
ALLOWED_CREDENTIALS = {
    "admin": "s3cr3tP@ssw0rd",
    "user1": "qwerty123",
    "user2": "password123",
}

class HoneyPotProtocol(basic.LineReceiver):
    def connectionMade(self):
        logging.info(f"Connection made from {self.transport.getPeer().host}")
        self.sendLine(b"Welcome to the honeypot!")
        self.sendLine(b"Username: ")
        self.state = "USERNAME"

    def lineReceived(self, line):
        line = line.strip()

        if self.state == "USERNAME":
            self.handle_username(line)
        elif self.state == "PASSWORD":
            self.handle_password(line)
        else:
            logging.warning(f"Received unexpected input: {line}")

    def handle_username(self, username):
        logging.info(f"Received username: {username}")
        if username in ALLOWED_CREDENTIALS:
            self.username = username
            self.sendLine(f"Password for {username}:".encode())
            self.state = "PASSWORD"
        else:
            self.sendLine(b"Invalid username. Try again.")
            self.state = "USERNAME"

    def handle_password(self, password):
        logging.info(f"Received password for {self.username}")
        if password == ALLOWED_CREDENTIALS[self.username]:
            self.sendLine(b"Login successful!")
        else:
            self.sendLine(b"Invalid password. Access denied.")
            self.transport.loseConnection()

    def rawDataReceived(self, data):
        logging.info(f"Raw data received: {data}")

class HoneyPotFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return HoneyPotProtocol()

if __name__ == "__main__":
    reactor.listenTCP(22, HoneyPotFactory())
    logging.info("Honeypot is successfully running on port 22")
    reactor.run()