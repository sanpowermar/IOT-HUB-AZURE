# Wokwi ESP32 + DHT22 + Azure IoT Hub
# MicroPython | MQTT over TLS | DigiCert root certificate embedded below
#
# Required separate library: umqtt/simple.py
# Fill in HUB_HOST and DEVICE_KEY_B64 with your own Azure values.
# Never share your device key.

import network
import time
import json
import machine
import ssl
import ntptime
import ubinascii
import uhashlib
from machine import Pin
from umqtt.simple import MQTTClient

# ========== EDIT THESE SETTINGS ==========
HUB_HOST = "YOUR_HUB_NAME.azure-devices.net"
DEVICE_ID = "water-level-01"
DEVICE_KEY_B64 = "PASTE_DEVICE_PRIMARY_KEY_HERE"

WIFI_SSID = "Wokwi-GUEST"
WIFI_PASSWORD = ""
TRIG_PIN = 5
ECHO_PIN = 18
TANK_DEPTH_CM = 100.0
TELEMETRY_INTERVAL_SECONDS = 10
SAS_TOKEN_LIFETIME_SECONDS = 3600
# =========================================

MQTT_PORT = 8883
MQTT_USERNAME = HUB_HOST + "/" + DEVICE_ID + "/?api-version=2021-04-12"
TELEMETRY_TOPIC = "devices/" + DEVICE_ID + "/messages/events/"

# Public DigiCert Global Root G2 certificate (PEM format).
# Embedded here so Wokwi does not need a separate .crt/.pem file.
CA_CERT = r"""
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----
""".strip().encode()

trig = Pin(TRIG_PIN, Pin.OUT)
echo = Pin(ECHO_PIN, Pin.IN)
trig.value(0)


def unix_time():
    # MicroPython ESP32 commonly counts from 2000-01-01, Unix from 1970-01-01.
    return int(time.time()) + 946684800


def url_encode(value):
    if isinstance(value, str):
        value = value.encode()
    out = ""
    for b in value:
        c = chr(b)
        if ((c >= "a" and c <= "z") or
            (c >= "A" and c <= "Z") or
            (c >= "0" and c <= "9") or c in "-_.~"):
            out += c
        else:
            out += "%%%02X" % b
    return out


def hmac_sha256(key, message):
    block_size = 64
    if len(key) > block_size:
        key = uhashlib.sha256(key).digest()
    if len(key) < block_size:
        key += b"\x00" * (block_size - len(key))
    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5c) for x in key)
    inner = uhashlib.sha256(ipad + message).digest()
    return uhashlib.sha256(opad + inner).digest()


def generate_sas_token():
    resource_uri = (HUB_HOST + "/devices/" + DEVICE_ID).lower()
    expiry = unix_time() + SAS_TOKEN_LIFETIME_SECONDS
    string_to_sign = (url_encode(resource_uri) + "\n" + str(expiry)).encode()
    try:
        key = ubinascii.a2b_base64(DEVICE_KEY_B64.strip())
    except Exception:
        raise ValueError("DEVICE_KEY_B64 must be the Base64 Primary Key from Azure")
    digest = hmac_sha256(key, string_to_sign)
    signature = ubinascii.b2a_base64(digest).strip().decode()
    return ("SharedAccessSignature sr=" + url_encode(resource_uri) +
            "&sig=" + url_encode(signature) + "&se=" + str(expiry))


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print("Connecting to Wokwi-GUEST Wi-Fi...")
        wlan.connect(WIFI_SSID, WIFI_PASSWORD)
        deadline = time.time() + 30
        while not wlan.isconnected() and time.time() < deadline:
            time.sleep(1)
    if not wlan.isconnected():
        raise RuntimeError("Wi-Fi connection failed")
    print("Wi-Fi connected:", wlan.ifconfig()[0])


def sync_clock():
    print("Synchronizing clock using NTP...")
    last_error = None
    for _ in range(5):
        try:
            ntptime.settime()
            if unix_time() > 1700000000:
                print("Clock synchronized (Unix UTC):", unix_time())
                return
        except Exception as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError("NTP time sync failed: " + str(last_error))


def connect_azure():
    print("Connecting to Azure IoT Hub over MQTT/TLS...")
    client = MQTTClient(
        client_id=DEVICE_ID,
        server=HUB_HOST,
        port=MQTT_PORT,
        user=MQTT_USERNAME,
        password=generate_sas_token(),
        keepalive=60,
        ssl=True,
        ssl_params={
            "server_hostname": HUB_HOST,
            "cert_reqs": ssl.CERT_REQUIRED,
            "cadata": CA_CERT,
        },
    )
    client.connect()
    print("Connected to Azure IoT Hub securely.")
    return client


def main():
    if "YOUR_HUB_NAME" in HUB_HOST or "PASTE_DEVICE_PRIMARY_KEY_HERE" in DEVICE_KEY_B64:
        raise ValueError("Edit HUB_HOST and DEVICE_KEY_B64 near the top of main.py.")
    connect_wifi()
    sync_clock()
    mqtt = connect_azure()
    message_id = 0

    while True:
        try:
            trig.value(0)
            time.sleep_us(2)
            trig.value(1)
            time.sleep_us(10)
            trig.value(0)

            duration_us = machine.time_pulse_us(echo, 1, 30000)
            if duration_us < 0:
                raise OSError("Ultrasonic echo timeout; check TRIG/ECHO wiring")

            distance_cm = round((duration_us * 0.0343) / 2.0, 2)
            water_level_cm = max(0.0, min(TANK_DEPTH_CM, TANK_DEPTH_CM - distance_cm))
            water_level_percent = round((water_level_cm / TANK_DEPTH_CM) * 100.0, 1)
            if water_level_percent <= 20:
                level_status = "LOW"
            elif water_level_percent >= 90:
                level_status = "FULL"
            else:
                level_status = "NORMAL"

            message_id += 1
            payload = {
                "deviceId": DEVICE_ID,
                "messageId": message_id,
                "distanceCm": distance_cm,
                "waterLevelCm": round(water_level_cm, 2),
                "waterLevelPercent": water_level_percent,
                "levelStatus": level_status,
                "timestampUtcEpoch": unix_time()
            }
            message = json.dumps(payload)
            mqtt.publish(TELEMETRY_TOPIC, message, qos=1)
            print("Telemetry published:", message)
            time.sleep(TELEMETRY_INTERVAL_SECONDS)
        except Exception as exc:
            print("Telemetry error:", repr(exc))
            try:
                mqtt.disconnect()
            except Exception:
                pass
            time.sleep(5)
            connect_wifi()
            sync_clock()
            mqtt = connect_azure()


try:
    main()
except Exception as exc:
    print("PROJECT STOPPED:", repr(exc))
    print("Check hub hostname, device key, NTP, MQTT library, and TLS support.")
