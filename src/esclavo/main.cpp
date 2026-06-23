#include <Arduino.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <mbedtls/md.h>

#define SCK_PIN   18
#define MISO_PIN  19
#define MOSI_PIN  23
#define SS_PIN    5
#define RST_PIN   4

#define PMK_KEY "CONTROL_PERSONAL"
#define LMK_KEY "ACCESO_SEGURO_16"

const byte FILAS = 4;
const byte COLUMNAS = 4;
char mapaTeclas[FILAS][COLUMNAS] = {
    {'1','2','3','A'},
    {'4','5','6','B'},
    {'7','8','9','C'},
    {'*','0','#','D'}
};
byte pinesFilas[FILAS]    = {13, 12, 14, 27};
byte pinesColumnas[COLUMNAS] = {26, 25, 33, 32};

LiquidCrystal_I2C lcd(0x27, 16, 2);
MFRC522 rfid(SS_PIN, RST_PIN);
Keypad teclado = Keypad(makeKeymap(mapaTeclas), pinesFilas, pinesColumnas, FILAS, COLUMNAS);
Preferences prefUsers;
Preferences prefFIFO;

uint8_t macMaestro[] = {0xD4, 0xE9, 0xF4, 0x8D, 0x0D, 0x48};

struct __attribute__((packed)) PaqueteESPNOW {
    uint8_t tipo;
    char origen;
    char tipoAcceso;
    char direccion;
    uint8_t hashPIN[32];
    char uidTarjeta[15];
    uint32_t timestamp;
    uint8_t numLog;
};

struct __attribute__((packed)) LogEntry {
    uint32_t timestamp;
    char origen;
    char tipoAcceso;
    char direccion;
    char identificador[32];
    bool concedido;
};
static_assert(sizeof(LogEntry) == 40, "LogEntry size must be 40");

enum EstadoConexion {
    CONECTADO,
    DESCONECTADO,
    ESCANEANDO,
    SINCRONIZANDO
};

EstadoConexion estado = DESCONECTADO;
volatile bool pongRecibido = false;
volatile bool ackRecibido = false;
volatile uint8_t ackNumLog = 0;

enum SyncStep {
    SYNC_IDLE,
    SYNC_LOG_SEND,
    SYNC_LOG_WAIT
};

SyncStep syncStep = SYNC_IDLE;
uint32_t syncHead = 0;
uint32_t syncTail = 0;
unsigned long syncTimer = 0;

String pinBuffer = "";
QueueHandle_t colaESPNOW;
bool esperandoVeredicto = false;
unsigned long tiempoEsperaVeredicto = 0;
volatile bool fallbackPendiente = false;

uint8_t hashPendiente[32];
char tipoPendiente;
char uidPendiente[32];

int scanChannel = 0;
int syncChannel = 1;
unsigned long lastRxTime = 0;
unsigned long scanTimer = 0;
const int canales[11] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

void calcularSHA256(const String& input, uint8_t* output) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char*)input.c_str(), input.length());
    mbedtls_md_finish(&ctx, output);
    mbedtls_md_free(&ctx);
}

void initUserDB() {
    if (prefUsers.getUInt("count", 0) == 0) {
        uint8_t hash[32];
        calcularSHA256("1234", hash);
        prefUsers.putBytes("pin_0", hash, 32);
        prefUsers.putString("uid_0", "");
        prefUsers.putUInt("count", 1);
    }
}

bool validarLocalmente(char tipo, const uint8_t* hashPIN, const char* uid) {
    uint32_t count = prefUsers.getUInt("count", 0);
    for (uint32_t i = 0; i < count; i++) {
        if (tipo == 'P' && hashPIN) {
            char key[12];
            snprintf(key, sizeof(key), "pin_%u", i);
            if (!prefUsers.isKey(key)) continue;
            uint8_t almacenado[32];
            size_t len = prefUsers.getBytes(key, almacenado, 32);
            if (len == 32 && memcmp(almacenado, hashPIN, 32) == 0) return true;
        }
        if (tipo == 'T' && uid) {
            char key[12];
            snprintf(key, sizeof(key), "uid_%u", i);
            if (!prefUsers.isKey(key)) continue;
            String almacenado = prefUsers.getString(key, "");
            if (almacenado.length() > 0 && almacenado == uid) return true;
        }
    }
    return false;
}

char determinarDireccionLocal(const char* identificador) {
    uint32_t tail = prefFIFO.getUInt("tail", 0);
    uint32_t head = prefFIFO.getUInt("head", 0);
    uint32_t same = 0;
    for (uint32_t i = head; i < tail; i++) {
        char key[14];
        snprintf(key, sizeof(key), "log_%u", i);
        if (!prefFIFO.isKey(key)) continue;
        LogEntry e;
        memset(&e, 0, sizeof(e));
        size_t len = prefFIFO.getBytes(key, (uint8_t*)&e, sizeof(LogEntry));
        if (len != sizeof(LogEntry)) continue;
        if (e.concedido && strncmp(e.identificador, identificador, sizeof(e.identificador)) == 0) {
            same++;
        }
    }
    return (same % 2 == 0) ? 'E' : 'S';
}

void addLogToFifo(const LogEntry& entry) {
    uint32_t tail = prefFIFO.getUInt("tail", 0);
    char key[14];
    snprintf(key, sizeof(key), "log_%u", tail);
    prefFIFO.putBytes(key, (uint8_t*)&entry, sizeof(LogEntry));
    prefFIFO.putUInt("tail", tail + 1);
}

bool readLogFromFifo(uint32_t index, LogEntry* entry) {
    char key[14];
    snprintf(key, sizeof(key), "log_%u", index);
    size_t len = prefFIFO.getBytes(key, (uint8_t*)entry, sizeof(LogEntry));
    return len == sizeof(LogEntry);
}

void removeLogFromFifo(uint32_t index) {
    char key[14];
    snprintf(key, sizeof(key), "log_%u", index);
    prefFIFO.remove(key);
}

uint32_t getFifoCount() {
    uint32_t head = prefFIFO.getUInt("head", 0);
    uint32_t tail = prefFIFO.getUInt("tail", 0);
    return (tail >= head) ? (tail - head) : 0;
}

void actLCD(const String& l0, const String& l1, uint16_t ms) {
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print(l0);
    lcd.setCursor(0, 1);
    lcd.print(l1);
    if (ms) {
        delay(ms);
        lcd.clear();
    }
}

void alEnviarDatos(const uint8_t *mac_addr, esp_now_send_status_t status) {
    if (status != ESP_NOW_SEND_SUCCESS) {
        if (esperandoVeredicto) fallbackPendiente = true;
        Serial.println("[CB] Send FAIL");
    } else {
        Serial.println("[CB] Send OK");
    }
}

void alRecibirDatos(const uint8_t *mac, const uint8_t *incomingData, int len) {
    PaqueteESPNOW pkt;
    int cp = (len < (int)sizeof(PaqueteESPNOW)) ? len : (int)sizeof(PaqueteESPNOW);
    memcpy(&pkt, incomingData, cp);
    lastRxTime = millis();

    Serial.printf("[RX] De %02x:%02x:%02x:%02x:%02x:%02x | Tipo=%c | Len=%d\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pkt.tipo, cp);

    if (pkt.tipo == 'O') {
        pongRecibido = true;
    } else if (pkt.tipo == 'K') {
        ackRecibido = true;
        ackNumLog = pkt.numLog;
    }

    xQueueSendFromISR(colaESPNOW, &pkt, NULL);
}

void procesarPaquete(PaqueteESPNOW* pkt) {
    if (pkt->tipo == 'O' || pkt->tipo == 'K') return;

    if (pkt->tipo == 'V') {
        if (esperandoVeredicto) {
            esperandoVeredicto = false;
            if (pkt->tipoAcceso == 'G') actLCD("ACCESO OK", "Bienvenido!", 2000);
            else actLCD("ACCESO DENEGADO", "Clave/Tag Inval", 2000);
            actLCD("Pasa Tag/PIN:", "", 0);
        }
        return;
    }

    if (pkt->tipo == 'U') {
        uint32_t idx = pkt->numLog;
        if (pkt->tipoAcceso == 'C') {
            uint32_t oldCount = prefUsers.getUInt("count", 0);
            for (uint32_t i = idx; i < oldCount; i++) {
                char k[12];
                snprintf(k, sizeof(k), "pin_%u", i);
                prefUsers.remove(k);
                snprintf(k, sizeof(k), "uid_%u", i);
                prefUsers.remove(k);
            }
            prefUsers.putUInt("count", idx);
        } else if (pkt->tipoAcceso == 'E') {
            Serial.println("[DB] Sincronizacion completa");
        } else if (pkt->tipoAcceso == 'P' || pkt->tipoAcceso == 'B') {
            char k[12];
            snprintf(k, sizeof(k), "pin_%u", idx);
            prefUsers.putBytes(k, pkt->hashPIN, 32);
        }
        if (pkt->tipoAcceso == 'U' || pkt->tipoAcceso == 'B') {
            char k[12];
            snprintf(k, sizeof(k), "uid_%u", idx);
            prefUsers.putString(k, pkt->uidTarjeta);
        }
        return;
    }
}

void sendPing() {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'P';
    pkt.origen = '2';
    esp_now_send(macMaestro, (uint8_t*)&pkt, sizeof(pkt));
}

bool sendLogEntry(uint32_t index) {
    LogEntry entry;
    memset(&entry, 0, sizeof(entry));
    char key[14];
    snprintf(key, sizeof(key), "log_%u", index);
    size_t len = prefFIFO.getBytes(key, (uint8_t*)&entry, sizeof(LogEntry));
    if (len != sizeof(LogEntry)) {
        prefFIFO.remove(key);
        return false;
    }
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'L';
    pkt.origen = entry.origen;
    pkt.tipoAcceso = entry.tipoAcceso;
    pkt.direccion = entry.direccion;
    if (entry.tipoAcceso == 'T') {
        strncpy(pkt.uidTarjeta, entry.identificador, 14);
        pkt.uidTarjeta[14] = 0;
    }
    pkt.timestamp = entry.timestamp;
    pkt.numLog = (index & 0x7F) | (entry.concedido ? 0x80 : 0);
    esp_now_send(macMaestro, (uint8_t*)&pkt, sizeof(pkt));
    Serial.printf("[SEND] LogEntry idx=%u tipo=%c concedido=%d\n", index, entry.tipoAcceso, entry.concedido ? 1 : 0);
    return true;
}

void sendDBRequest() {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'R';
    pkt.origen = '2';
    esp_now_send(macMaestro, (uint8_t*)&pkt, sizeof(pkt));
    Serial.println("[SEND] DB Request");
}

void runSync() {
    unsigned long now = millis();
    switch (syncStep) {
        case SYNC_IDLE:
            syncHead = prefFIFO.getUInt("head", 0);
            syncTail = prefFIFO.getUInt("tail", 0);
            Serial.printf("[SYNC] Iniciando head=%u tail=%u\n", syncHead, syncTail);
            if (syncHead < syncTail) {
                char bufLCD[24];
                snprintf(bufLCD, sizeof(bufLCD), "Log %u/%u", syncHead + 1, syncTail);
                actLCD("Sincronizando...", bufLCD, 0);
                syncStep = SYNC_LOG_SEND;
            } else {
                estado = CONECTADO;
                sendDBRequest();
                actLCD("Pasa Tag/PIN:", "", 0);
                Serial.println("[STATE] CONECTADO");
            }
            syncTimer = now;
            break;

        case SYNC_LOG_SEND:
            ackRecibido = false;
            {
                char bufLCD[24];
                snprintf(bufLCD, sizeof(bufLCD), "Log %u/%u", syncHead + 1, syncTail);
                actLCD("Sincronizando...", bufLCD, 0);
            }
            if (sendLogEntry(syncHead)) {
                Serial.printf("[SYNC] Send idx=%u\n", syncHead);
                syncStep = SYNC_LOG_WAIT;
                syncTimer = now;
            } else {
                syncHead++;
                prefFIFO.putUInt("head", syncHead);
                syncStep = SYNC_IDLE;
                syncTimer = now;
            }
            break;

        case SYNC_LOG_WAIT:
            if (ackRecibido && ackNumLog == (uint8_t)(syncHead & 0x7F)) {
                ackRecibido = false;
                Serial.printf("[SYNC] ACK idx=%u\n", syncHead);
                removeLogFromFifo(syncHead);
                syncHead++;
                prefFIFO.putUInt("head", syncHead);
                syncTail = prefFIFO.getUInt("tail", 0);
                if (syncHead < syncTail) {
                    syncStep = SYNC_LOG_SEND;
                } else {
                    syncStep = SYNC_IDLE;
                    estado = CONECTADO;
                    sendDBRequest();
                    actLCD("Pasa Tag/PIN:", "", 0);
                    Serial.println("[STATE] CONECTADO");
                }
                syncTimer = now;
            } else if (now - syncTimer > 500) {
                Serial.printf("[SYNC] Timeout retry idx=%u\n", syncHead);
                syncStep = SYNC_LOG_SEND;
                syncTimer = now;
            }
            break;
    }
}

void procTeclado() {
    char tecla = teclado.getKey();
    if (!tecla) return;

    if (tecla >= '0' && tecla <= '9') {
        pinBuffer += tecla;
        lcd.setCursor(0, 1);
        lcd.print("                ");
        lcd.setCursor(0, 1);
        for (unsigned int i = 0; i < pinBuffer.length(); i++) lcd.print('*');
        return;
    }

    if (tecla == '*') {
        pinBuffer = "";
        lcd.setCursor(0, 1);
        lcd.print("                ");
        return;
    }

    if (tecla == '#' && pinBuffer.length() >= 4) {
        actLCD("Procesando PIN...", "", 0);

        uint8_t hash[32];
        calcularSHA256(pinBuffer, hash);
        pinBuffer = "";

        if (estado == CONECTADO) {
            PaqueteESPNOW pkt;
            memset(&pkt, 0, sizeof(pkt));
            pkt.tipo = 'A';
            pkt.origen = '2';
            pkt.tipoAcceso = 'P';
            memcpy(pkt.hashPIN, hash, 32);
            pkt.timestamp = millis();
            esp_now_send(macMaestro, (uint8_t*)&pkt, sizeof(pkt));

            tipoPendiente = 'P';
            memcpy(hashPendiente, hash, 32);
            uidPendiente[0] = 0;

            actLCD("Enviando...", "", 0);
            esperandoVeredicto = true;
            tiempoEsperaVeredicto = millis();
        } else {
            bool ok = validarLocalmente('P', hash, NULL);
            LogEntry entry;
            memset(&entry, 0, sizeof(entry));
            entry.timestamp = millis();
            entry.origen = '2';
            entry.tipoAcceso = 'P';
            strncpy(entry.identificador, "PIN Cifrado", sizeof(entry.identificador) - 1);
            entry.concedido = ok;
            entry.direccion = determinarDireccionLocal(entry.identificador);
            if (ok) actLCD("ACCESO OK", "Bienvenido!", 2000);
            else actLCD("ACCESO DENEGADO", "Clave/Tag Inval", 2000);
            addLogToFifo(entry);
            actLCD("Pasa Tag/PIN:", "", 0);
        }
    }
}

void procRFID() {
    if (!rfid.PICC_IsNewCardPresent()) return;
    if (!rfid.PICC_ReadCardSerial()) return;

    actLCD("Leyendo Tag...", "", 0);

    char uidStr[32];
    int pos = 0;
    for (byte i = 0; i < rfid.uid.size; i++) {
        pos += snprintf(uidStr + pos, sizeof(uidStr) - pos, "%s%02X", i > 0 ? ":" : "", rfid.uid.uidByte[i]);
    }

    if (estado == CONECTADO) {
        PaqueteESPNOW pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.tipo = 'A';
        pkt.origen = '2';
        pkt.tipoAcceso = 'T';
        strncpy(pkt.uidTarjeta, uidStr, 14);
        pkt.timestamp = millis();
        esp_now_send(macMaestro, (uint8_t*)&pkt, sizeof(pkt));

        tipoPendiente = 'T';
        memset(hashPendiente, 0, 32);
        strncpy(uidPendiente, uidStr, sizeof(uidPendiente) - 1);

        actLCD("Enviando...", "", 0);
        esperandoVeredicto = true;
        tiempoEsperaVeredicto = millis();
    } else {
        LogEntry entry;
        memset(&entry, 0, sizeof(entry));
        entry.timestamp = millis();
        entry.origen = '2';
        entry.tipoAcceso = 'T';
        strncpy(entry.identificador, uidStr, sizeof(entry.identificador) - 1);
        entry.concedido = validarLocalmente('T', NULL, uidStr);
        entry.direccion = determinarDireccionLocal(entry.identificador);
        if (entry.concedido) actLCD("ACCESO OK", "Bienvenido!", 2000);
        else actLCD("ACCESO DENEGADO", "Clave/Tag Inval", 2000);
        addLogToFifo(entry);
        actLCD("Pasa Tag/PIN:", "", 0);
    }

    rfid.PICC_HaltA();
}

void setup() {
    Serial.begin(115200);
    delay(500);

    colaESPNOW = xQueueCreate(10, sizeof(PaqueteESPNOW));

    lcd.init();
    lcd.backlight();
    actLCD("Esclavo P2", "Iniciando...", 1000);

    SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
    rfid.PCD_Init();
    rfid.PCD_SetAntennaGain(rfid.RxGain_max);

    prefUsers.begin("users", false);
    prefFIFO.begin("fifo", false);
    initUserDB();

    {
        uint32_t head = prefFIFO.getUInt("head", 0);
        uint32_t tail = prefFIFO.getUInt("tail", 0);
        bool purged = false;
        for (uint32_t i = head; i < tail; i++) {
            char key[14];
            snprintf(key, sizeof(key), "log_%u", i);
            if (prefFIFO.isKey(key)) {
                LogEntry dummy;
                if (prefFIFO.getBytes(key, (uint8_t*)&dummy, sizeof(LogEntry)) != sizeof(LogEntry)) {
                    prefFIFO.remove(key);
                    purged = true;
                }
            }
        }
        if (purged) {
            uint32_t newTail = head;
            {
                char key[14];
                snprintf(key, sizeof(key), "log_%u", newTail);
                while (prefFIFO.isKey(key)) {
                    newTail++;
                    snprintf(key, sizeof(key), "log_%u", newTail);
                }
            }
            prefFIFO.putUInt("tail", newTail);
            if (newTail <= head) {
                prefFIFO.putUInt("head", 0);
                prefFIFO.putUInt("tail", 0);
            }
            Serial.println("[FIFO] Entradas legacy limpiadas en startup");
        }
    }

    {
        uint32_t cachedChan = prefFIFO.getUInt("chan", 0);
        if (cachedChan >= 1 && cachedChan <= 11) {
            for (int i = 0; i < 11; i++) {
                if (canales[i] == (int)cachedChan) { scanChannel = i; break; }
            }
            Serial.printf("[CH] Cache canal=%u scanChannel=%d\n", cachedChan, scanChannel);
        }
    }

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    esp_wifi_set_channel(canales[scanChannel], WIFI_SECOND_CHAN_NONE);

    if (esp_now_init() != ESP_OK) {
        actLCD("ERROR", "ESP-NOW", 0);
        while (1);
    }

    esp_now_set_pmk((uint8_t*)PMK_KEY);
    esp_now_register_send_cb(alEnviarDatos);
    esp_now_register_recv_cb(alRecibirDatos);

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, macMaestro, 6);
    peer.channel = 0;
    peer.encrypt = true;
    memcpy(peer.lmk, LMK_KEY, 16);

    if (esp_now_add_peer(&peer) != ESP_OK) {
        actLCD("ERROR", "PEER", 0);
        while (1);
    }

    actLCD("Iniciando...", "Buscando Maestro", 0);
}

void loop() {
    PaqueteESPNOW pkt;
    while (xQueueReceive(colaESPNOW, &pkt, 0) == pdTRUE) {
        procesarPaquete(&pkt);
    }

    if (estado == DESCONECTADO || estado == ESCANEANDO) {
        unsigned long now = millis();
        if (pongRecibido) {
            pongRecibido = false;
            prefFIFO.putUInt("chan", syncChannel);
            esp_wifi_set_channel(syncChannel, WIFI_SECOND_CHAN_NONE);
            estado = SINCRONIZANDO;
            scanChannel = 0;
            scanTimer = now;
            return;
        }
        if (now - scanTimer >= 200) {
            estado = ESCANEANDO;
            syncChannel = canales[scanChannel];
            Serial.printf("[CH] Canal=%d scanChannel=%d\n", syncChannel, scanChannel);
            esp_wifi_set_channel(syncChannel, WIFI_SECOND_CHAN_NONE);
            pongRecibido = false;
            sendPing();
            scanTimer = now;
            scanChannel = (scanChannel + 1) % 11;
        }
        return;
    }

    if (estado == SINCRONIZANDO) {
        runSync();
        return;
    }

    if (estado == CONECTADO && millis() - lastRxTime > 15000) {
        estado = DESCONECTADO;
        Serial.printf("[STATE] Timeout 15s sin datos, reconectando\n");
    }

    if (esperandoVeredicto) {
        if (millis() - tiempoEsperaVeredicto > 2000 || fallbackPendiente) {
            esperandoVeredicto = false;
            fallbackPendiente = false;
            LogEntry entry;
            memset(&entry, 0, sizeof(entry));
            entry.timestamp = millis();
            entry.origen = '2';
            entry.tipoAcceso = tipoPendiente;
            bool ok = false;
            if (tipoPendiente == 'P') {
                ok = validarLocalmente('P', hashPendiente, NULL);
                strncpy(entry.identificador, "PIN Cifrado", sizeof(entry.identificador) - 1);
            } else {
                ok = validarLocalmente('T', NULL, uidPendiente);
                strncpy(entry.identificador, uidPendiente, sizeof(entry.identificador) - 1);
            }
            entry.concedido = ok;
            entry.direccion = determinarDireccionLocal(entry.identificador);
            if (ok) actLCD("ACCESO OK", "Bienvenido!", 2000);
            else actLCD("ACCESO DENEGADO", "Clave/Tag Inval", 2000);
            addLogToFifo(entry);
            actLCD("Pasa Tag/PIN:", "", 0);
        } else {
            return;
        }
    }

    procTeclado();
    procRFID();
}
