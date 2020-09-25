"""
Uses twisted conch to create an SFTP client that can send files.
"""

import attr
from attr.converters import optional
from twisted.conch.client.default import SSHUserAuthClient
from twisted.conch.client.direct import SSHClientFactory
from twisted.conch.error import ConchError
from twisted.conch.scripts.cftp import ClientOptions
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.ssh.common import NS
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.filetransfer import FileTransferClient, FXF_WRITE, FXF_CREAT, FXF_TRUNC, SFTPError, \
    ClientFile  # noqa
from twisted.internet import reactor, defer, error
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue, succeed, fail, log
from twisted.internet.protocol import connectionDone
from twisted.python import failure

"""
Default Chunk Size. The max chunk size is system dependent, this provides a reasonable default
so that the client does not always have to specify a chunk size for file transfer.
"""
CHUNK_SIZE = 8192


@attr.s(frozen=True)
class FileInfo(object):
    """
    Class that tells SFTP details about the file to send.
    """
    directory = attr.ib(converter=str)  # type: str
    name = attr.ib(converter=str)  # type: str
    data = attr.ib()  # type: str
    chunk_size = attr.ib(converter=int, default=CHUNK_SIZE)  # type: int

    def to_path(self):
        """
        Turns the folder and file name into a file path.
        """
        return self.directory + "/" + self.name


@attr.s(frozen=True)
class SFTPClientOptions(object):
    """
    Client options for sending SFTP files.

    :param host: the host of the SFTP server
    :param port: the port ofo the SFTP server
    :param fingerprint: the expected fingerprint of the host
    :param user: the user to login as
    :param identity: the identity file, optional and like the "-i" command line option
    :param password: an optional password
    """
    host = attr.ib(converter=str)  # type: str
    port = attr.ib(converter=int)  # type: int
    fingerprint = attr.ib(converter=str)  # type: str
    user = attr.ib(converter=str)  # type: str
    identity = attr.ib(converter=optional(str), default=None)  # type: Optional[str]
    password = attr.ib(converter=optional(str), default=None)  # type: Optional[str]


@inlineCallbacks
def get_client(client_options):
    # type: (SFTPClientOptions)->Deferred
    """
    Primary function to send an file over SFTP. You can send a pass word, identity, or both.
    :param client_options: the client connection options
    :return: A deferred that signals "OK" if successful.
    """
    options = ClientOptions()
    options["host"] = client_options.host
    options["port"] = client_options.port
    options["password"] = client_options.password
    options["fingerprint"] = client_options.fingerprint
    options["reconnect"] = False

    if client_options.identity:
        options.identitys = [client_options.identity]

    conn = SFTPConnection()
    auth = SFTPUserAuthClient(client_options.user, options, conn)
    factory = yield connect(options, auth)
    factory.client = yield conn.getSftpClientDeferred()

    returnValue(factory)


def connect(options, userAuthObject):
    d = Deferred()
    factory = SFTPClientFactory(d, options, userAuthObject)
    reactor.connectTCP(options["host"], options["port"], factory)
    return d.addCallback(lambda ignore: factory)


class SFTPClientFactory(SSHClientFactory):

    def __init__(self, d, options, userAuthObject):
        SSHClientFactory.__init__(self, d, options, _verify_host_key, userAuthObject)

    def clientConnectionLost(self, connector, reason):
        self.client.connectionLost(reason)

    def makeDirectory(self, path, attrs):
        return self.client.makeDirectory(path, attrs)

    def openFile(self, filename, flags, attrs):
        return self.client.openFile(filename, flags, attrs)


def _verify_host_key(transport, host, pubKey, fingerprint):
    expected = transport.factory.options.get("fingerprint", None)
    if fingerprint == expected:
        return succeed(1)

    log.error(
        "SSH Host Key fingerprint of ({fp}) does not match the expected value of ({expected}).",
        fp=fingerprint, expected=expected)

    return fail(ConchError("Host fingerprint is unexpected."))


class SFTPSession(SSHChannel):
    """
    Creates an SFTP session. This is used to connect the SFTPClient.
    """
    name = "session"

    @inlineCallbacks
    def channelOpen(self, whatever):
        """
        Called when the channel is opened.  "whatever" is any data that the
        other side sent us when opening the channel.

        @type whatever: L{bytes}
        """
        yield self.conn.sendRequest(self, "subsystem", NS("sftp"), wantReply=True)

        client = SFTPClient()
        client.makeConnection(self)
        self.dataReceived = client.dataReceived
        self.conn.notifyClientIsReady(client)


class SFTPClient(FileTransferClient):

    def _sendRequest(self, msg, data):
        """
        The conch implementation appears to have a bug in it. This ensures we will fail if
        the connection has been lost rather than strand the request deferred.
        """
        if not self.connected:
            return defer.fail(error.ConnectionLost())

        return FileTransferClient._sendRequest(self, msg, data)

    def connectionLost(self, reason=connectionDone):
        """
        Called when connection to the remote subsystem was lost.
        Any pending requests are aborted.
        """
        self.connected = False

        # If there are still requests waiting for responses when the
        # connection is lost, fail them.
        if self.openRequests:
            # Even if our transport was lost "cleanly", our
            # requests were still not cancelled "cleanly".
            requestError = error.ConnectionLost()
            requestError.__cause__ = reason.value
            requestFailure = failure.Failure(requestError)
            while self.openRequests:
                _, deferred = self.openRequests.popitem()
                deferred.errback(requestFailure)


class SFTPConnection(SSHConnection):
    def __init__(self):
        """
        Adds a deferred here so client can add a callback when the SFTP client is ready.
        """
        SSHConnection.__init__(self)
        self._sftpClient = Deferred()
        self.sftpSession = SFTPSession()

    def serviceStarted(self):
        """
        Opens an SFTP session when the SSH connection has been started.
        """
        self.openChannel(self.sftpSession)

    def notifyClientIsReady(self, client):
        """
        Trigger callbacks associated with our SFTP client deferred. It's ready!
        """
        log.info("Setting SFTP Client Deferred")
        if not self._sftpClient.called:
            self._sftpClient.callback(client)

    def getSftpClientDeferred(self):
        log.info("Getting SFTP Client Deferred")
        return self._sftpClient


class SFTPUserAuthClient(SSHUserAuthClient):
    """
    Twisted Conch doesn't have a way of getting a password. By default it gets it from stdin. This allows it
    to be retrieved from options instead.
    """
    def getPassword(self, prompt = None):
        """
        Get the password from the client options, is specified.
        """
        if "password" in self.options:
            return succeed(self.options["password"])

        return SSHUserAuthClient.getPassword(self, prompt)


@inlineCallbacks
def send_file(client, file_info):
    # type: (FileTransferClient, FileInfo) -> Deferred
    """
    Creates a directory if required and then creates the file.
    :param client: the SFTP client to use
    :param file_info: contains file name, directory, and data
    """
    try:
        log.info("makeDirectory...")
        d = yield client.makeDirectory(file_info.directory, {})
        log.info("makeDirectory -> ({result})", result=str(d))

    except SFTPError as e:
        # In testing on various system, either a 4 or an 11 will indicate the directory
        # already exist. We are fine with that and want to continue if it does. If we misinterpreted
        # error code here we are probably still ok since we will just get the more systemic error
        # again on the next call to openFile.
        if e.code != 4 and e.code != 11:
            raise e

    f = yield client.openFile(file_info.to_path(), FXF_WRITE | FXF_CREAT | FXF_TRUNC, {})

    try:
        yield _write_chunks(f, file_info.data, file_info.chunk_size)

    finally:
        yield f.close()


@inlineCallbacks
def _write_chunks(f, data, chunk_size):
    # type: (ClientFile, str, int) -> Deferred
    """
    Convenience function to write data in chunks

    :param f: the file to write to
    :param data: the data to write
    :param chunk_size: the chunk size
    """
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset: offset + chunk_size]
        yield f.writeChunk(offset, chunk)


