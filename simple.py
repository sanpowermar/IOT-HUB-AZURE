import socket, struct, ssl

def _enc_len(n):
    out = b""
    while True:
        d = n % 128
        n //= 128
        if n:
            d |= 0x80
        out += bytes((d,))
        if not n:
            return out

def _read(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise OSError("MQTT socket closed")
        data += part
    return data

class MQTTClient:
    def __init__(self, client_id, server, port=0, user=None, password=None,
                 keepalive=0, ssl=False, ssl_params=None):
        self.client_id = client_id.encode() if isinstance(client_id, str) else client_id
        self.server = server
        self.port = port or (8883 if ssl else 1883)
        self.user = user.encode() if isinstance(user, str) else user
        self.password = password.encode() if isinstance(password, str) else password
        self.keepalive = keepalive
        self.use_ssl = ssl
        self.ssl_params = ssl_params or {}
        self.sock = None
        self.packet_id = 0

    def connect(self, clean_session=True):
        addr = socket.getaddrinfo(self.server, self.port)[0][-1]
        sock = socket.socket()
        sock.settimeout(15)
        sock.connect(addr)
        if self.use_ssl:
            sock = ssl.wrap_socket(sock, **self.ssl_params)
        self.sock = sock
        flags = 0x02 if clean_session else 0
        if self.user is not None: flags |= 0x80
        if self.password is not None: flags |= 0x40
        var = b"\x00\x04MQTT\x04" + bytes((flags,)) + struct.pack("!H", self.keepalive)
        payload = struct.pack("!H", len(self.client_id)) + self.client_id
        if self.user is not None: payload += struct.pack("!H", len(self.user)) + self.user
        if self.password is not None: payload += struct.pack("!H", len(self.password)) + self.password
        body = var + payload
        self.sock.write(b"\x10" + _enc_len(len(body)) + body)
        header = _read(self.sock, 1)[0]
        rem = _read(self.sock, 1)[0]
        if rem != 2: raise OSError("Unexpected MQTT CONNACK length")
        ack = _read(self.sock, 2)
        if header != 0x20 or ack[1] != 0:
            raise OSError("MQTT CONNACK error code " + str(ack[1]))
        return 0

    def publish(self, topic, msg, retain=False, qos=0):
        if isinstance(topic, str): topic = topic.encode()
        if isinstance(msg, str): msg = msg.encode()
        if qos not in (0, 1): raise ValueError("QoS 0 or 1 only")
        flags = 0x01 if retain else 0
        packet_id = b""
        if qos == 1:
            self.packet_id = self.packet_id % 65535 + 1
            packet_id = struct.pack("!H", self.packet_id)
            flags |= 0x02
        body = struct.pack("!H", len(topic)) + topic + packet_id + msg
        self.sock.write(bytes((0x30 | flags,)) + _enc_len(len(body)) + body)
        if qos == 1:
            header = _read(self.sock, 1)[0]
            rem = _read(self.sock, 1)[0]
            if rem != 2: raise OSError("Unexpected PUBACK length")
            ack_id = struct.unpack("!H", _read(self.sock, 2))[0]
            if (header >> 4) != 4 or ack_id != self.packet_id:
                raise OSError("Invalid MQTT PUBACK")
        return self.packet_id if qos else 0

    def disconnect(self):
        if self.sock:
            try: self.sock.write(b"\xE0\x00")
            finally:
                self.sock.close()
                self.sock = None
