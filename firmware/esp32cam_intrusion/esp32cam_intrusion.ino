/*
 * ESP32-CAM Intrusion Detection - camera node
 *
 * Captures JPEG frames at a fixed interval and uploads them over HTTPS/TLS
 * to the Flask backend (POST /api/upload). The backend runs YOLO11 person
 * detection and restricted-zone checks; this node only captures and sends.
 *
 * Board: "AI Thinker ESP32-CAM"  (Arduino IDE, esp32 core by Espressif >= 2.0)
 * Copy secrets.example.h -> secrets.h and fill in your values before building.
 */

#include "esp_camera.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"
#include "secrets.h"

// ---------- AI Thinker ESP32-CAM pin map ----------
#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27
#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22
#define FLASH_LED_PIN      4
#define STATUS_LED_PIN    33   // on-board red LED, active LOW

static const uint32_t CAPTURE_INTERVAL_MS = 1000;  // one frame per second
static const uint32_t HTTP_TIMEOUT_MS     = 10000;

WiFiClientSecure tlsClient;
uint32_t lastCapture = 0;
uint32_t consecutiveFailures = 0;

bool initCamera() {
  camera_config_t config;
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer   = LEDC_TIMER_0;
  config.pin_d0 = Y2_GPIO_NUM;  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;  config.pin_d7 = Y9_GPIO_NUM;
  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sccb_sda = SIOD_GPIO_NUM;
  config.pin_sccb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;
  config.grab_mode = CAMERA_GRAB_LATEST;   // always send the freshest frame

  if (psramFound()) {
    config.frame_size = FRAMESIZE_VGA;     // 640x480 is a good fit for YOLO11
    config.jpeg_quality = 12;
    config.fb_count = 2;
    config.fb_location = CAMERA_FB_IN_PSRAM;
  } else {
    config.frame_size = FRAMESIZE_QVGA;
    config.jpeg_quality = 15;
    config.fb_count = 1;
    config.fb_location = CAMERA_FB_IN_DRAM;
  }

  esp_err_t err = esp_camera_init(&config);
  if (err != ESP_OK) {
    Serial.printf("[CAM] init failed: 0x%x\n", err);
    return false;
  }
  Serial.println("[CAM] ready");
  return true;
}

// TLS certificate checks need a real clock; the ESP32 boots at 1970.
void syncClock() {
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  Serial.print("[NTP] syncing time");
  time_t now = time(nullptr);
  uint32_t start = millis();
  while (now < 1700000000 && millis() - start < 10000) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println(now >= 1700000000 ? " ok" : " failed (TLS may fail)");
}

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  Serial.printf("[WiFi] connecting to %s", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 20000) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[WiFi] connected, IP %s\n", WiFi.localIP().toString().c_str());
    syncClock();
  } else {
    Serial.println("\n[WiFi] failed, will retry");
  }
}

bool uploadFrame(camera_fb_t *fb) {
  HTTPClient http;
  String url = String("https://") + SERVER_HOST + ":" + SERVER_PORT + "/api/upload";
  if (!http.begin(tlsClient, url)) {
    Serial.println("[HTTP] begin failed");
    return false;
  }
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.addHeader("Content-Type", "image/jpeg");
  http.addHeader("X-Camera-Id", CAMERA_ID);
  http.addHeader("X-API-Key", DEVICE_API_KEY);

  int code = http.POST(fb->buf, fb->len);
  if (code > 0) {
    String body = http.getString();
    Serial.printf("[HTTP] %d %s\n", code, body.c_str());
  } else {
    Serial.printf("[HTTP] error: %s\n", http.errorToString(code).c_str());
  }
  http.end();
  return code == 200;
}

void setup() {
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);  // avoid resets on weak USB power
  Serial.begin(115200);
  pinMode(FLASH_LED_PIN, OUTPUT);
  digitalWrite(FLASH_LED_PIN, LOW);
  pinMode(STATUS_LED_PIN, OUTPUT);
  digitalWrite(STATUS_LED_PIN, HIGH);

  if (!initCamera()) {
    delay(3000);
    ESP.restart();
  }

  // Pin the backend's self-signed certificate so only our server is trusted.
  tlsClient.setCACert(SERVER_CA_CERT);
  connectWiFi();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
    delay(1000);
    return;
  }
  if (millis() - lastCapture < CAPTURE_INTERVAL_MS) {
    delay(10);
    return;
  }
  lastCapture = millis();

  camera_fb_t *fb = esp_camera_fb_get();
  if (!fb) {
    Serial.println("[CAM] capture failed");
    return;
  }
  digitalWrite(STATUS_LED_PIN, LOW);
  bool ok = uploadFrame(fb);
  digitalWrite(STATUS_LED_PIN, HIGH);
  esp_camera_fb_return(fb);

  consecutiveFailures = ok ? 0 : consecutiveFailures + 1;
  if (consecutiveFailures >= 30) {
    Serial.println("[SYS] too many failures, restarting");
    ESP.restart();
  }
}
