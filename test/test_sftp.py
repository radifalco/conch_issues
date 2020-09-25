import traceback

import paramiko
import pytest
from mocksftp.keys import SAMPLE_USER_PRIVATE_KEY
from pytest_twisted.plugin import inlineCallbacks
from twisted.internet.error import ConnectionLost

import sftp
from sftp import SFTPClientOptions, FileInfo

paramiko.util.log_to_file('paramiko.log')


@inlineCallbacks
def test_sftp_error(sftp_server):
    client = yield sftp.get_client(
        SFTPClientOptions(
            host=sftp_server.host,
            port=sftp_server.port,
            fingerprint="84:f2:ef:b1:94:cb:d9:2f:cb:e6:f4:5c:07:9b:d8:3f",
            user="sample-user",
            identity=SAMPLE_USER_PRIVATE_KEY
        ))

    yield sftp.send_file(client, FileInfo(
        directory="test-directory",
        name="test-file.txt",
        data="This is data"))

    f = open(sftp_server.root + "/test-directory/test-file.txt", "r")
    assert f.read() == "This is data"

    # Mimic a server shutting us down
    sftp_server.stop()

    with pytest.raises(ConnectionLost):
        # Why does this hang? No result callback or errback
        yield sftp.send_file(client, FileInfo(
            directory="test-directory2",
            name="test-file2.txt",
            data="This is data2"))

    sftp_server.start()
