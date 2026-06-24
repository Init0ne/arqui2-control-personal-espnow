#include <Arduino.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Keypad.h>
#include <WiFi.h>
#include <esp_now.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <time.h>
#include <WebServer.h>

#define SCK_PIN   18
#define MISO_PIN  19
#define MOSI_PIN  23
#define SS_PIN    5
#define RST_PIN   4

#define PMK_KEY "CONTROL_PERSONAL"
#define LMK_KEY "ACCESO_SEGURO_16"

#define WIFI_SSID "RedmiNote14"
#define WIFI_PASS "6aypt4vhntyyxce"

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
Preferences prefLogs;

uint8_t macEsclavo[] = {0xEC, 0x62, 0x60, 0x09, 0xA7, 0xD4};

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

String pinBuffer = "";
QueueHandle_t colaESPNOW;
WebServer server(80);
bool tiempoSincronizado = false;

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

bool validarAcceso(char tipo, const uint8_t* hashPIN, const char* uid) {
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

char determinarDireccion(const char* identificador) {
    uint32_t count = prefLogs.getUInt("count", 0);
    time_t now = time(nullptr);
    if (now < 100000) return 'E';
    uint32_t today = (uint32_t)(now / 86400);
    uint32_t same = 0;
    for (uint32_t i = 0; i < count; i++) {
        char key[14];
        snprintf(key, sizeof(key), "log_%u", i);
        if (!prefLogs.isKey(key)) continue;
        LogEntry e;
        memset(&e, 0, sizeof(e));
        size_t len = prefLogs.getBytes(key, (uint8_t*)&e, sizeof(LogEntry));
        if (len != sizeof(LogEntry)) continue;
        if (e.concedido && e.timestamp / 86400 == today && strncmp(e.identificador, identificador, sizeof(e.identificador)) == 0) {
            same++;
        }
    }
    return (same % 2 == 0) ? 'E' : 'S';
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

void sendPong() {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'O';
    pkt.origen = '1';
    esp_now_send(NULL, (uint8_t*)&pkt, sizeof(pkt));
    Serial.println("[SEND] PONG");
}

void sendACK(uint8_t numLog) {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'K';
    pkt.origen = '1';
    pkt.numLog = numLog & 0x7F;
    esp_now_send(NULL, (uint8_t*)&pkt, sizeof(pkt));
    Serial.printf("[SEND] ACK numLog=%u\n", numLog & 0x7F);
}

void sendDBEnd() {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'U';
    pkt.tipoAcceso = 'E';
    pkt.numLog = 0xFF;
    esp_now_send(NULL, (uint8_t*)&pkt, sizeof(pkt));
}

void sendUserEntry(uint32_t idx) {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'U';
    pkt.numLog = (uint8_t)(idx & 0xFF);
    size_t len = 0;
    String uidVal;
    {
        char key[12];
        snprintf(key, sizeof(key), "pin_%u", idx);
        if (prefUsers.isKey(key)) {
            len = prefUsers.getBytes(key, pkt.hashPIN, 32);
        }
    }
    {
        char key[12];
        snprintf(key, sizeof(key), "uid_%u", idx);
        if (prefUsers.isKey(key)) {
            uidVal = prefUsers.getString(key, "");
            strncpy(pkt.uidTarjeta, uidVal.c_str(), 14);
        }
    }
    if (len == 32 && uidVal.length() > 0) pkt.tipoAcceso = 'B';
    else if (len == 32) pkt.tipoAcceso = 'P';
    else if (uidVal.length() > 0) pkt.tipoAcceso = 'U';
    else return;
    esp_now_send(NULL, (uint8_t*)&pkt, sizeof(pkt));
    Serial.printf("[SEND] DB user %u (tipo=%c)\n", idx, pkt.tipoAcceso);
}

void sendUserCount() {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'U';
    pkt.tipoAcceso = 'C';
    pkt.numLog = (uint8_t)(prefUsers.getUInt("count", 0) & 0xFF);
    esp_now_send(NULL, (uint8_t*)&pkt, sizeof(pkt));
}

void sendVerdict(bool granted) {
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.tipo = 'V';
    pkt.origen = '1';
    pkt.tipoAcceso = granted ? 'G' : 'D';
    esp_now_send(NULL, (uint8_t*)&pkt, sizeof(pkt));
    Serial.printf("[SEND] Veredicto: %s\n", granted ? "CONCEDIDO" : "DENEGADO");
}

void pushDBToSlave() {
    uint32_t count = prefUsers.getUInt("count", 0);
    for (int intento = 0; intento < 2; intento++) {
        sendUserCount();
        delay(100);
        for (uint32_t i = 0; i < count; i++) {
            sendUserEntry(i);
            delay(100);
        }
        sendDBEnd();
        delay(200);
    }
    Serial.printf("[DB PUSH] %u usuarios enviados (2 intentos)\n", count);
}

void logAcceso(const PaqueteESPNOW* pkt, bool concedido) {
    uint32_t idx = prefLogs.getUInt("count", 0);
    prefLogs.putUInt("count", idx + 1);
    time_t now = time(nullptr);
    if (now < 100000) now = 0;
    LogEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.timestamp = (uint32_t)now;
    entry.origen = pkt->origen;
    entry.tipoAcceso = pkt->tipoAcceso;
    if (pkt->tipoAcceso == 'T') {
        strncpy(entry.identificador, pkt->uidTarjeta, sizeof(entry.identificador) - 1);
    } else {
        strncpy(entry.identificador, "PIN Cifrado", sizeof(entry.identificador) - 1);
    }
    entry.concedido = concedido;
    entry.direccion = determinarDireccion(entry.identificador);
    prefLogs.putBytes(("log_" + String(idx)).c_str(), (uint8_t*)&entry, sizeof(LogEntry));
    Serial.printf("[LOG] %u|%c|%c|%s|%d\n",
        entry.timestamp, entry.origen, entry.tipoAcceso,
        entry.identificador, entry.concedido ? 1 : 0);
}

void handleAccess(PaqueteESPNOW* pkt) {
    Serial.printf("[ACCESO] Desde=%c Tipo=%c\n", pkt->origen, pkt->tipoAcceso);
    bool ok = false;
    if (pkt->tipoAcceso == 'P') {
        ok = validarAcceso('P', pkt->hashPIN, NULL);
        Serial.print("  Hash PIN: ");
        for (int i = 0; i < 32; i++) Serial.printf("%02x", pkt->hashPIN[i]);
        Serial.println();
    } else if (pkt->tipoAcceso == 'T') {
        ok = validarAcceso('T', NULL, pkt->uidTarjeta);
        Serial.printf("  UID: %s\n", pkt->uidTarjeta);
    }
    Serial.printf("  Resultado: %s\n", ok ? "CONCEDIDO" : "DENEGADO");
    sendVerdict(ok);
    logAcceso(pkt, ok);
}

void handlePing(PaqueteESPNOW* pkt) {
    sendPong();
    Serial.println("[PING] -> PONG enviado");
}

void handleLog(PaqueteESPNOW* pkt) {
    uint32_t idx = (pkt->numLog & 0x7F);
    bool concedido = (pkt->numLog & 0x80) != 0;
    uint32_t logIdx = prefLogs.getUInt("count", 0);
    prefLogs.putUInt("count", logIdx + 1);
    time_t now = time(nullptr);
    if (now < 100000) now = 0;
    LogEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.timestamp = (uint32_t)now;
    entry.origen = pkt->origen;
    entry.tipoAcceso = pkt->tipoAcceso;
    if (pkt->tipoAcceso == 'T') {
        strncpy(entry.identificador, pkt->uidTarjeta, sizeof(entry.identificador) - 1);
    } else {
        strncpy(entry.identificador, "PIN Cifrado", sizeof(entry.identificador) - 1);
    }
    entry.concedido = concedido;
    entry.direccion = determinarDireccion(entry.identificador);
    prefLogs.putBytes(("log_" + String(logIdx)).c_str(), (uint8_t*)&entry, sizeof(LogEntry));
    sendACK(idx);
    Serial.printf("[SYNC] Log recibido fifoIdx=%u concedido=%d -> ACK\n", idx, concedido);
}

void handleDBRequest(PaqueteESPNOW* pkt) {
    Serial.println("[DB] Solicitud de base de datos recibida");
    pushDBToSlave();
}

void alRecibirDatos(const uint8_t *mac, const uint8_t *incomingData, int len) {
    PaqueteESPNOW pkt;
    int cp = (len < (int)sizeof(PaqueteESPNOW)) ? len : (int)sizeof(PaqueteESPNOW);
    memcpy(&pkt, incomingData, cp);

    Serial.printf("[RX] De %02x:%02x:%02x:%02x:%02x:%02x | Tipo=%c | Len=%d\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pkt.tipo, cp);

    xQueueSendFromISR(colaESPNOW, &pkt, NULL);
}

void procesarPaquete(PaqueteESPNOW* pkt) {
    switch (pkt->tipo) {
        case 'A': handleAccess(pkt); break;
        case 'P': handlePing(pkt);   break;
        case 'L': handleLog(pkt);    break;
        case 'R': handleDBRequest(pkt); break;
        default:  Serial.printf("[?] Tipo desconocido: %c (0x%02x) origen=%c\n", pkt->tipo, pkt->tipo, pkt->origen); break;
    }
}

void procTecladoLocal() {
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
        actLCD("Procesando PIN...", "Local", 0);
        uint8_t hash[32];
        calcularSHA256(pinBuffer, hash);
        bool ok = validarAcceso('P', hash, NULL);
        if (ok) actLCD("ACCESO OK", "Bienvenido!", 2000);
        else actLCD("ACCESO DENEGADO", "Clave/Tag Inval", 2000);
        PaqueteESPNOW pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.origen = '1';
        pkt.tipoAcceso = 'P';
        logAcceso(&pkt, ok);
        pinBuffer = "";
        actLCD("Pasa Tag/PIN:", "", 0);
    }
}

void procRFIDLocal() {
    if (!rfid.PICC_IsNewCardPresent()) return;
    if (!rfid.PICC_ReadCardSerial()) return;

    actLCD("Leyendo Tag...", "Local", 0);

    char uidStr[32];
    int pos = 0;
    for (byte i = 0; i < rfid.uid.size; i++) {
        pos += snprintf(uidStr + pos, sizeof(uidStr) - pos, "%s%02X", i > 0 ? ":" : "", rfid.uid.uidByte[i]);
    }

    bool ok = validarAcceso('T', NULL, uidStr);
    if (ok) actLCD("ACCESO OK", "Bienvenido!", 2000);
    else actLCD("ACCESO DENEGADO", "Clave/Tag Inval", 2000);
    PaqueteESPNOW pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.origen = '1';
    pkt.tipoAcceso = 'T';
    strncpy(pkt.uidTarjeta, uidStr, sizeof(pkt.uidTarjeta) - 1);
    logAcceso(&pkt, ok);

    rfid.PICC_HaltA();
    actLCD("Pasa Tag/PIN:", "", 0);
}

void handleRoot() {
    String html = R"rawliteral(
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Control de Accesos</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;padding:20px;color:#333}
h2{text-align:center;margin-bottom:20px;color:#1a73e8}
.tab{overflow:hidden;background:#fff;border-radius:10px 10px 0 0;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.tab button{background:#f8f9fa;float:left;border:none;cursor:pointer;padding:14px 24px;font-size:15px;transition:.2s;color:#555;font-weight:500}
.tab button:hover{background:#e8f0fe;color:#1a73e8}
.tab button.active{background:#1a73e8;color:#fff}
.tabcontent{display:none;padding:20px;background:#fff;border-radius:0 0 10px 10px;box-shadow:0 2px 4px rgba(0,0,0,.1);margin-bottom:20px}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #e0e0e0;font-size:14px}
th{background:#1a73e8;color:#fff;font-weight:600}
tr:hover{background:#f5f5f5}
.badge{padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600}
.badge-ok{background:#e6f4ea;color:#137333}
.badge-deny{background:#fce8e6;color:#c5221f}
.bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:10px}
.btn{padding:8px 18px;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500;transition:.2s}
.btn-add{background:#1a73e8;color:#fff}
.btn-add:hover{background:#1557b0}
.btn-del{background:#d93025;color:#fff;padding:5px 12px;font-size:12px}
.btn-del:hover{background:#a50e0e}
.btn-cancel{background:#dadce0;color:#333}
.btn-cancel:hover{background:#bdc1c6}
.form-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 0}
input[type=text],input[type=password]{padding:8px 12px;border:1px solid #dadce0;border-radius:6px;font-size:14px;outline:none;width:200px}
input:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.2)}
#addForm{display:none;background:#f8f9fa;padding:15px;border-radius:8px;margin-top:10px}
.empty{text-align:center;color:#888;padding:30px;font-style:italic}
@media(max-width:600px){input[type=text],input[type=password]{width:100%}.bar{flex-direction:column;align-items:stretch}}
</style>
</head>
<body>
<h2>Control de Accesos — Maestro</h2>
<div class="tab">
<button class="tablinks active" onclick="abrirPestana(event,'Logs')">Logs</button>
<button class="tablinks" onclick="abrirPestana(event,'Usuarios')">Usuarios</button>
</div>
<div id="Logs" class="tabcontent" style="display:block">
<div class="bar"><span style="font-weight:500">Registros de acceso</span><button class="btn btn-del" onclick="limpiarLogs()">Limpiar Logs</button></div>
<table><thead><tr><th>Fecha/Hora</th><th>Puerta</th><th>Tipo</th><th>Dirección</th><th>Identificador</th><th>Resultado</th></tr></thead><tbody id="logBody"></tbody></table>
</div>
<div id="Usuarios" class="tabcontent">
<div class="bar"><span style="font-weight:500">Usuarios registrados</span><button class="btn btn-add" onclick="mostrarFormulario()">+ Agregar Usuario</button></div>
<div id="addForm">
<div class="form-row">
<input type="password" id="newPin" placeholder="PIN (4+ digitos)">
<input type="text" id="newUid" placeholder="UID Tag (ej: A1:B2:C3:D4)">
<button class="btn btn-add" onclick="guardarUsuario()">Guardar</button>
<button class="btn btn-cancel" onclick="cancelarAgregar()">Cancelar</button>
</div>
</div>
<table><thead><tr><th>#</th><th>PIN (hash)</th><th>UID Tag</th><th>Accion</th></tr></thead><tbody id="userBody"></tbody></table>
</div>
<script>
function abrirPestana(e,n){document.querySelectorAll('.tabcontent').forEach(t=>t.style.display='none');document.querySelectorAll('.tablinks').forEach(b=>b.className='tablinks');document.getElementById(n).style.display='block';e.currentTarget.className='tablinks active'}
async function cargarLogs(){try{const r=await fetch('/api/logs'),d=await r.json();const t=document.getElementById('logBody');t.innerHTML='';if(!d.length){t.innerHTML='<tr><td colspan="6" class="empty">Sin registros</td></tr>';return}d.forEach(l=>{const tr=t.insertRow();tr.insertCell().textContent=l.fecha;tr.insertCell().textContent=l.puerta;tr.insertCell().textContent=l.tipo;tr.insertCell().textContent=l.direccion;tr.insertCell().textContent=l.id;const c=tr.insertCell();const b=document.createElement('span');b.className='badge '+(l.resultado==='CONCEDIDO'?'badge-ok':'badge-deny');b.textContent=l.resultado;c.appendChild(b)})}catch(e){console.error(e)}}
async function cargarUsuarios(){try{const r=await fetch('/api/users'),d=await r.json();const t=document.getElementById('userBody');t.innerHTML='';if(!d.length){t.innerHTML='<tr><td colspan="4" class="empty">Sin usuarios</td></tr>';return}d.forEach((u,i)=>{const tr=t.insertRow();tr.insertCell().textContent=i+1;tr.insertCell().textContent=u.pin?u.pin.substring(0,16)+'...':'-';tr.insertCell().textContent=u.uid||'-';const c=tr.insertCell();const b=document.createElement('button');b.className='btn btn-del';b.textContent='Eliminar';b.onclick=()=>eliminarUsuario(i);c.appendChild(b)})}catch(e){console.error(e)}}
async function eliminarUsuario(i){if(!confirm('Eliminar usuario '+(i+1)+'?'))return;await fetch('/api/users/remove',{method:'POST',body:new URLSearchParams({index:i})});cargarUsuarios()}
function mostrarFormulario(){document.getElementById('addForm').style.display='block'}
function cancelarAgregar(){document.getElementById('addForm').style.display='none';document.getElementById('newPin').value='';document.getElementById('newUid').value=''}
async function guardarUsuario(){const p=document.getElementById('newPin').value.trim(),u=document.getElementById('newUid').value.trim();if(!p&&!u)return alert('Ingrese PIN o UID');const b=new URLSearchParams();if(p)b.append('pin',p);if(u)b.append('uid',u);await fetch('/api/users/add',{method:'POST',body:b});document.getElementById('newPin').value='';document.getElementById('newUid').value='';document.getElementById('addForm').style.display='none';cargarUsuarios()}
function limpiarLogs(){if(!confirm('Eliminar todos los logs?'))return;fetch('/api/logs/clear',{method:'POST'}).then(cargarLogs).catch(console.error)}
cargarLogs();cargarUsuarios();setInterval(cargarLogs,5000);
</script>
</body>
</html>
)rawliteral";
    server.send(200, "text/html", html);
}

String escaparJSON(const String& s) {
    String out;
    out.reserve(s.length() + 8);
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if ((uint8_t)c < 0x20) { char buf[8]; snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c); out += buf; }
        else out += c;
    }
    return out;
}

void handleAPILogs() {
    server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    server.sendHeader("Pragma", "no-cache");
    server.sendHeader("Expires", "0");
    uint32_t count = prefLogs.getUInt("count", 0);
    String json = "[";
    json.reserve(count * 130 + 4);
    bool primero = true;

    for (uint32_t i = 0; i < count; i++) {
        char key[14];
        snprintf(key, sizeof(key), "log_%u", i);
        
        if (!prefLogs.isKey(key)) continue;

        LogEntry entry;
        memset(&entry, 0, sizeof(entry));
        
        size_t len = prefLogs.getBytes(key, (uint8_t*)&entry, sizeof(LogEntry));
        if (len != sizeof(LogEntry)) continue; // Si falla el tamaño, solo lo salta, no lo borra en caliente

        char fechaBuf[32];
        if (entry.timestamp >= 100000) {
            time_t t = (time_t)entry.timestamp;
            struct tm *ti = localtime(&t);
            strftime(fechaBuf, sizeof(fechaBuf), "%Y-%m-%d %H:%M:%S", ti);
        } else {
            snprintf(fechaBuf, sizeof(fechaBuf), "Pendiente");
        }

        String idEsc = escaparJSON(String(entry.identificador));
        
        if (!primero) json += ',';
        primero = false;

        json += "{\"fecha\":\"";
        json += String(fechaBuf);
        json += "\",\"puerta\":\"";
        json += (entry.origen == '1') ? "Puerta Maestro" : "Puerta 2";
        json += "\",\"tipo\":\"";
        json += (entry.tipoAcceso == 'P') ? "PIN" : "Tarjeta";
        json += "\",\"direccion\":\"";
        json += entry.concedido ? ((entry.direccion == 'E') ? "ENTRADA" : "SALIDA") : "-";
        json += "\",\"id\":\"";
        json += idEsc;
        json += "\",\"resultado\":\"";
        json += entry.concedido ? "CONCEDIDO" : "DENEGADO";
        json += "\"}";
    }
    json += "]";
    server.send(200, "application/json", json);
}

void handleAPIClearLogs() {
    uint32_t count = prefLogs.getUInt("count", 0);
    for (uint32_t i = 0; i < count; i++) {
        char key[14];
        snprintf(key, sizeof(key), "log_%u", i);
        if (prefLogs.isKey(key)) {
            prefLogs.remove(key);
        }
    }
    prefLogs.putUInt("count", 0);
    Serial.println("[LOGS] Todos los logs eliminados");
    server.send(200, "text/plain", "OK");
}

void handleAPIUsers() {
    uint32_t count = prefUsers.getUInt("count", 0);
    String json = "[";
    json.reserve(count * 180 + 4);
    bool primero = true;
    for (uint32_t i = 0; i < count; i++) {
        char pinKey[12];
        char uidKey[12];
        snprintf(pinKey, sizeof(pinKey), "pin_%u", i);
        snprintf(uidKey, sizeof(uidKey), "uid_%u", i);
        bool hasPin = prefUsers.isKey(pinKey);
        bool hasUid = prefUsers.isKey(uidKey);
        if (!hasPin && !hasUid) continue;
        if (!primero) json += ',';
        primero = false;
        json += "{\"pin\":\"";
        if (hasPin) {
            uint8_t hash[32];
            size_t len = prefUsers.getBytes(pinKey, hash, 32);
            if (len == 32) {
                char hex[65];
                for (int j = 0; j < 32; j++) sprintf(hex + j * 2, "%02x", hash[j]);
                hex[64] = 0;
                json += hex;
            }
        }
        json += "\",\"uid\":\"";
        if (hasUid) {
            json += escaparJSON(prefUsers.getString(uidKey, ""));
        }
        json += "\"}";
    }
    json += "]";
    server.send(200, "application/json", json);
}

void handleAPIAddUser() {
    if (!server.hasArg("pin") && !server.hasArg("uid")) {
        server.send(400, "text/plain", "PIN o UID requerido");
        return;
    }
    uint32_t idx = prefUsers.getUInt("count", 0);
    if (idx >= 200) {
        server.send(400, "text/plain", "Maximo 200 usuarios");
        return;
    }
    if (server.hasArg("pin")) {
        String pin = server.arg("pin");
        if (pin.length() < 4) {
            server.send(400, "text/plain", "PIN debe tener 4+ digitos");
            return;
        }
        uint8_t hash[32];
        calcularSHA256(pin, hash);
        char key[12];
        snprintf(key, sizeof(key), "pin_%u", idx);
        prefUsers.putBytes(key, hash, 32);
    }
    if (server.hasArg("uid")) {
        char key[12];
        snprintf(key, sizeof(key), "uid_%u", idx);
        prefUsers.putString(key, server.arg("uid"));
    }
    prefUsers.putUInt("count", idx + 1);
    Serial.printf("[WEB] Usuario %u agregado\n", idx);
    pushDBToSlave();
    server.send(200, "text/plain", "OK");
}

void handleAPIRemoveUser() {
    if (!server.hasArg("index")) {
        server.send(400, "text/plain", "Index requerido");
        return;
    }
    uint32_t removeIdx = (uint32_t)server.arg("index").toInt();
    uint32_t count = prefUsers.getUInt("count", 0);
    if (removeIdx >= count) {
        server.send(400, "text/plain", "Index invalido");
        return;
    }
    for (uint32_t i = removeIdx + 1; i < count; i++) {
        char prevKey[12];
        snprintf(prevKey, sizeof(prevKey), "pin_%u", i - 1);
        char curKey[12];
        snprintf(curKey, sizeof(curKey), "pin_%u", i);
        if (prefUsers.isKey(curKey)) {
            uint8_t hash[32];
            size_t len = prefUsers.getBytes(curKey, hash, 32);
            if (len == 32) prefUsers.putBytes(prevKey, hash, 32);
            else prefUsers.remove(prevKey);
        } else {
            prefUsers.remove(prevKey);
        }
        snprintf(prevKey, sizeof(prevKey), "uid_%u", i - 1);
        snprintf(curKey, sizeof(curKey), "uid_%u", i);
        if (prefUsers.isKey(curKey)) {
            String uid = prefUsers.getString(curKey, "");
            if (uid.length() > 0) prefUsers.putString(prevKey, uid);
            else prefUsers.remove(prevKey);
        } else {
            prefUsers.remove(prevKey);
        }
    }
    {
        char key[12];
        snprintf(key, sizeof(key), "pin_%u", count - 1);
        prefUsers.remove(key);
    }
    {
        char key[12];
        snprintf(key, sizeof(key), "uid_%u", count - 1);
        prefUsers.remove(key);
    }
    prefUsers.putUInt("count", count - 1);
    Serial.printf("[WEB] Usuario %u eliminado\n", removeIdx);
    pushDBToSlave();
    server.send(200, "text/plain", "OK");
}

void handleAPIStatus() {
    time_t now = time(nullptr);
    struct tm *ti = localtime(&now);
    char fechaBuf[32];
    strftime(fechaBuf, sizeof(fechaBuf), "%Y-%m-%d %H:%M:%S", ti);
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"wifi\":%s,\"ntp\":%s,\"hora\":\"%s\",\"logs\":%u,\"users\":%u}",
        (WiFi.status() == WL_CONNECTED) ? "true" : "false",
        tiempoSincronizado ? "true" : "false",
        fechaBuf,
        prefLogs.getUInt("count", 0),
        prefUsers.getUInt("count", 0));
    server.send(200, "application/json", buf);
}

void setup() {
    Serial.begin(115200);
    delay(500);

    colaESPNOW = xQueueCreate(10, sizeof(PaqueteESPNOW));

    lcd.init();
    lcd.backlight();
    actLCD("Maestro P1", "Iniciando...", 1000);

    SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
    rfid.PCD_Init();
    rfid.PCD_SetAntennaGain(rfid.RxGain_max);

    prefUsers.begin("users", false);
    prefLogs.begin("logs", false);
    initUserDB();

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    actLCD("Conectando WiFi", "", 0);
    int intentos = 0;
    while (WiFi.status() != WL_CONNECTED && intentos < 40) {
        delay(500);
        intentos++;
        lcd.setCursor(0, 1);
        lcd.print(".");
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[WiFi] Conectado, canal %d\n", WiFi.channel());
        actLCD("WiFi OK", "Sinc. NTP...", 0);
        configTime(-3 * 3600, 0, "pool.ntp.org");
        time_t now = time(nullptr);
        int espera = 0;
        while (now < 100000 && espera < 20) {
            delay(500);
            now = time(nullptr);
            espera++;
            lcd.setCursor(0, 1);
            lcd.print(".");
        }
        tiempoSincronizado = (now >= 100000);
        if (tiempoSincronizado) {
            Serial.printf("[NTP] OK: %s", ctime(&now));
            char bufCanal[20];
            snprintf(bufCanal, sizeof(bufCanal), "Canal %d", WiFi.channel());
            actLCD("WiFi + NTP OK", bufCanal, 1500);
        } else {
            Serial.println("[NTP] Fallo sincronizacion");
            actLCD("WiFi OK, NTP no", "", 1500);
        }
    } else {
        actLCD("WiFi NO", "Modo standalone", 2000);
        Serial.println("[WiFi] Sin conexion, modo standalone");
    }

    if (esp_now_init() != ESP_OK) {
        actLCD("ERROR", "ESP-NOW", 0);
        while (1);
    }

    esp_now_set_pmk((uint8_t*)PMK_KEY);
    esp_now_register_recv_cb(alRecibirDatos);

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, macEsclavo, 6);
    peer.channel = 0;
    peer.encrypt = true;
    memcpy(peer.lmk, LMK_KEY, 16);

    if (esp_now_add_peer(&peer) != ESP_OK) {
        Serial.println("[!] No se pudo agregar peer Esclavo (no critico)");
    }

    server.on("/", handleRoot);
    server.on("/api/logs", handleAPILogs);
    server.on("/api/logs/clear", HTTP_POST, handleAPIClearLogs);
    server.on("/api/users", handleAPIUsers);
    server.on("/api/users/add", HTTP_POST, handleAPIAddUser);
    server.on("/api/users/remove", HTTP_POST, handleAPIRemoveUser);
    server.on("/api/status", handleAPIStatus);
    server.begin();
    Serial.printf("[HTTP] Servidor web iniciado en http://%s\n", WiFi.localIP().toString().c_str());

    actLCD("Maestro Listo", "Pasa Tag/PIN:", 0);
}

void loop() {
    PaqueteESPNOW pkt;
    while (xQueueReceive(colaESPNOW, &pkt, 0) == pdTRUE) {
        procesarPaquete(&pkt);
    }

    server.handleClient();
    procTecladoLocal();
    procRFIDLocal();
}
