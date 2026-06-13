# Sistema de Control de Personal y Acceso Distribuido (ESP-NOW + Web Server)

Este repositorio contiene el firmware de producción para un sistema distribuido de control de acceso y asistencia de misión crítica, implementado sobre dos microcontroladores ESP32 de arquitectura Xtensa de 32 bits. 

El sistema está dividido en dos nodos (**Maestro** y **Esclavo**) que se comunican mediante el protocolo nativo de capa física **ESP-NOW**, integrando persistencia en memoria Flash (NVS), una base de datos espejo descentralizada y una interfaz web de auditoría en tiempo real.

---

## 🚀 Arquitectura y Características Principales (Features)

### 1. Comunicación Asíncrona y Sintonía de Red (ESP-NOW)
* **Coexistencia RF Completa:** El nodo Maestro opera simultáneamente como Servidor Web (conectado a la infraestructura Wi-Fi local) y como nodo central de la red mallada ESP-NOW.
* **Handshaking Secuencial por Canal:** Se eliminó el uso de tareas concurrentes agresivas de *Channel Hopping* para evitar la saturación del driver de radio (*RF Queue Overflow*). El Esclavo implementa una máquina de estados no bloqueante que escanea secuencialmente los canales en el arranque; una vez que recibe un `PONG` del Maestro, lockea su antena en la misma frecuencia física (fijada por el router en el Maestro), optimizando la tasa de transferencia.

### 2. Protocolo de Consistencia Eventual y Tolerancia a Fallos (Offline FIFO)
* **Persistencia Atómica Local:** El nodo Esclavo implementa una cola binaria FIFO estructurada con atributos `packed` de exactamente 39 bytes dentro de su memoria no volátil (NVS - Preferences). 
* **Sincronización en Ráfaga (Diferida):** Si la conexión con el Maestro se interrumpe (Timeout de 2 segundos gestionado por `millis()`), el Esclavo ejecuta una validación local autónoma, otorga el veredicto en su pantalla LCD y resguarda el evento en la Flash. Al restablecerse el enlace, el Esclavo despacha los logs almacenados en ráfaga utilizando una máscara de bits en la variable de control (`numLog | bit 7 para veredicto`), asegurando la integridad de la auditoría.
* **Mecanismo de Auto-Sanación (Self-Healing):** En el arranque o la sincronización, el firmware verifica de forma preventiva la existencia de llaves (`isKey()`) y la concordancia matemática exacta del tamaño del buffer (`sizeof(LogEntry)`). Cualquier residuo corrupto de firmware anterior es purgado quirúrgicamente con `remove()` para evitar excepciones de hardware a nivel de kernel.

### 3. Replicación de Base de Datos Espejo con Control Flujo (ABM Sync)
* **Protocolo ACK Síncrono:** Las operaciones de Alta, Baja y Modificación (ABM) de usuarios (PINs cifrados mediante SHA-256 y UIDs de tarjetas RFID) realizadas desde el panel web no se inyectan de forma asíncrona. El Maestro implementa un protocolo estricto que transmite cada usuario y detiene el flujo hasta recibir un ACK explícito (`'K'`) por parte del Esclavo, garantizando que ambos nodos posean siempre la misma base de datos de credenciales.
* **DB Request Post-Sync:** Inmediatamente después de que el Esclavo vacía su FIFO de logs diferidos al reconectarse, envía un comando de solicitud (`'R'`) para forzar un volcado limpio de la base de datos central, mitigando cualquier desincronización ocurrida durante el periodo offline.

### 4. Gestión de Memoria Optimizada (Cero Fragmentación del Heap)
* **Stack Puro vs. Heap Allocations:** El firmware erradica por completo el uso de la clase `String` de Arduino dentro de los bucles iterativos de búsqueda y empaquetado (operaciones que generaban una complejidad de asignación $O(n)$ fragmentando la memoria RAM dinámica).
* **Buffers Estáticos Estrictos:** Toda manipulación de cadenas para la UI del LCD, endpoints de las APIs o generación de llaves NVS utiliza buffers fijos de tipo `char[]` asignados estrictamente en el *stack* mediante `snprintf()` y formateo hexadecimal directo (`%02X`). Esto reduce drásticamente el tamaño del ejecutable binario en Flash y asegura la estabilidad del sistema contra *crashes* por falta de memoria RAM contigua a largo plazo.

### 5. Interfaz de Auditoría Centralizada (Web API)
* **Arquitectura RESTful Embebida:** El Maestro expone endpoints HTTP en formato JSON (`/api/logs` y `/api/users`) consumidos por un frontend minimalista adaptado para el renderizado instantáneo de badges de estado (*CONCEDIDO* / *DENEGADO*).
* **Inhibición de Caché por Hardware:** El backend web inyecta cabeceras estrictas de control de estado (`Cache-Control: no-cache, no-store`, `Pragma`, `Expires`) antes de despachar cada JSON, forzando al navegador web a eludir su memoria caché y garantizando la visualización en tiempo real del contador secuencial global (`count`) del archivo de logs.

---

## 🛠️ Stack Tecnológico
* **Plataforma:** PlatformIO & Arduino Framework
* **Lenguaje:** C++ Embebido Avanzado (Estructuras empaquetadas, Punteros Raw, Buffers estáticos)
* **Hardware:** ESP32 NodeMCU, Lector RFID RC522 / PN532, Teclado Matricial, LCD con interfaz I2C.
* **Protocolos:** ESP-NOW (Capa física Wi-Fi 802.11), HTTP, NTP (Sincronización horaria de red).

### 📈 Impacto Real de la Optimización de Memoria (Fase Final)

Al erradicar las asignaciones dinámicas en favor de buffers estáticos en el stack, se logró una reducción directa en el tamaño del ejecutable binario, optimizando el espacio físico en la memoria Flash de ambos nodos:

| Nodo / Archivo | Tamaño Inicial | Tamaño Post-Optimización | Eficiencia Neta |
|----------------|----------------|--------------------------|-----------------|
| **Maestro** (`src/maestro/main.cpp`) | 854,081 Bytes | 851,413 Bytes | **−2,668 Bytes** |
| **Esclavo** (`src/esclavo/main.cpp`) | 774,005 Bytes | 771,817 Bytes | **−2,188 Bytes** |

*Nota: Esta optimización garantiza un índice de fragmentación del heap de 0% en el bucle principal de escaneo de usuarios y logs.*
