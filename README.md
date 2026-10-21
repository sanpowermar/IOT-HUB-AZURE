# Wokwi + Azure IoT Hub: Smart Water Tank Level Monitor

- ESP32 + HC-SR04 ultrasonic sensor
- MicroPython
- Azure IoT Hub via MQTT/TLS on port 8883
- DigiCert Global Root G2 certificate is embedded in `main.py`; no separate .crt file is required.

## Wiring
HC-SR04 VCC -> ESP32 VIN; GND -> GND; TRIG -> GPIO 5; ECHO -> GPIO 18.
For physical hardware, HC-SR04 ECHO is commonly 5V; use a voltage divider/level shifter before ESP32 GPIO.

## Wokwi setup
1. Open https://wokwi.com/projects/new/micropython-esp32
2. Replace `diagram.json` and `main.py` with included files.
3. Add `umqtt` folder containing `simple.py` and `__init__.py`.
4. In `main.py`, set `HUB_HOST` to your real Azure hostname and `DEVICE_KEY_B64` to the Primary Key for the new device.

## Azure setup
Reuse your existing IoT Hub, but create a NEW device identity: `water-level-01`.
Portal: IoT Hub > Devices > Add Device > Device ID `water-level-01` > Save; copy that device's Primary Key.
Do not use the full connection string and do not share the key.

## Monitor events in Azure Cloud Shell (PowerShell)
```powershell
az iot hub monitor-events --hub-name YOUR_HUB_NAME --device-id water-level-01
```
Keep Wokwi running. JSON fields: `distanceCm`, `waterLevelCm`, `waterLevelPercent`, `levelStatus`.

The code assumes tank depth is 100 cm. Example: distance 35 cm means estimated water level 65 cm (65%). Click HC-SR04 in Wokwi to change its distance.

If MQTT/TLS fails, verify hub hostname, device ID/key, NTP time and firmware TLS support. Do not disable certificate verification.
