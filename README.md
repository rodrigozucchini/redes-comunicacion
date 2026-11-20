# 1. Redes y comunicación

> Bloque 1 de System Design. Todo lo que pasa entre un cliente y un servidor, de la capa de red hasta el diseño de APIs.

## Índice

- [1.1 IP, OSI, TCP vs UDP, handshake](#11-ip-osi-tcp-vs-udp-handshake)
- [1.2 DNS, caching DNS, TTL](#12-dns-caching-dns-ttl)
- [1.3 HTTP/1.1, HTTP/2, HTTP/3 (QUIC), keep-alive](#13-http11-http2-http3-quic-keep-alive)
- [1.4 Proxies: forward vs reverse](#14-proxies-forward-vs-reverse)
- [1.5 TLS/SSL, mTLS](#15-tlsssl-mtls)
- [1.6 REST, GraphQL, gRPC, SOAP, diseño de APIs](#16-rest-graphql-grpc-soap-diseño-de-apis)
- [1.7 WebSockets, polling, SSE, webhooks](#17-websockets-longshort-polling-sse-webhooks)
- [1.8 API Gateway, BFF](#18-api-gateway-bff)
- [Cierre: qué pasa cuando escribís una URL en el navegador](#cierre-qué-pasa-cuando-escribís-una-url-en-el-navegador)

---

## 1.1 IP, OSI, TCP vs UDP, handshake

### IP (Internet Protocol)

Protocolo de la capa de red. Se encarga del **direccionamiento** y el **enrutamiento** de paquetes entre redes. Es *best effort*: no garantiza entrega, orden ni ausencia de duplicados. Eso lo resuelven las capas de arriba (TCP).

| | IPv4 | IPv6 |
|---|---|---|
| Tamaño | 32 bits | 128 bits |
| Ejemplo | `192.168.1.10` | `2001:db8::1` |
| Espacio | ~4.300 millones | ~3,4 × 10³⁸ |
| NAT | Muy usado (por escasez) | Casi innecesario |
| Fragmentación | Los routers pueden fragmentar | Solo el emisor (Path MTU Discovery) |

**Conceptos clave**

- **IP pública vs privada.** Rangos privados (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. No son ruteables en Internet.
- **CIDR** (`192.168.1.0/24`): el `/24` indica cuántos bits son de red. `/24` = 256 direcciones (254 usables), `/16` = 65.536, `/32` = un solo host.
- **NAT**: el router traduce IPs privadas a una pública (y puertos). Permite que muchos dispositivos compartan una IP, pero rompe la conectividad extremo a extremo (por eso existen técnicas como STUN/TURN en WebRTC).
- **Gateway**: el router por el que sale el tráfico que no es de tu red.
- **TTL (IP)**: contador de saltos. Cada router lo decrementa; al llegar a 0 se descarta el paquete (evita loops). Es lo que usa `traceroute`.
- **MTU**: tamaño máximo de un paquete en un enlace. En Ethernet es **1500 bytes**. Si lo superás, se fragmenta o se pierde (problema típico con VPNs y túneles).
- **ICMP**: protocolo de control y diagnóstico (`ping`, `traceroute`, errores tipo "destination unreachable").
- **ARP**: resuelve IP → MAC dentro de una red local (capa 2).

### Modelo OSI vs TCP/IP

| # | Capa OSI | Qué hace | PDU | Ejemplos |
|---|---|---|---|---|
| 7 | Aplicación | Protocolos que usa la app | Datos | HTTP, DNS, SMTP, SSH |
| 6 | Presentación | Formato, cifrado, compresión | Datos | TLS (parcialmente), JSON, UTF-8 |
| 5 | Sesión | Abrir/mantener/cerrar sesiones | Datos | Sesiones RPC, NetBIOS |
| 4 | Transporte | Comunicación proceso a proceso, puertos | Segmento / Datagrama | TCP, UDP, QUIC |
| 3 | Red | Direccionamiento y enrutamiento | Paquete | IP, ICMP, OSPF, BGP |
| 2 | Enlace de datos | Entrega en la red local, direcciones MAC | Frame | Ethernet, Wi-Fi, ARP |
| 1 | Física | Bits sobre el medio | Bits | Cable, fibra, radio |

**TCP/IP (lo que realmente se usa)** colapsa en 4 capas: *Aplicación* (OSI 5-7), *Transporte* (4), *Internet* (3) y *Acceso a red* (1-2).

**Encapsulamiento:** cada capa agrega su propio encabezado al bajar.

```
Datos HTTP
  └─ [Header TCP | Datos HTTP]               → Segmento
       └─ [Header IP | Segmento]             → Paquete
            └─ [Header Ethernet | Paquete | trailer]  → Frame
```

**Para qué sirve el modelo en la práctica:** diagnosticar. Un balanceador **L4** decide por IP/puerto (capa 4); uno **L7** decide por path, headers o cookies (capa 7). Un firewall puede filtrar por capa 3/4 o inspeccionar capa 7 (WAF).

### Puertos y sockets

- Un **puerto** (16 bits, 0–65535) identifica un proceso/servicio en un host.
- **Well-known**: 0–1023 (80 HTTP, 443 HTTPS, 22 SSH, 53 DNS, 25 SMTP). **Registrados**: 1024–49151. **Efímeros**: 49152–65535 (los asigna el SO al cliente).
- Una conexión TCP se identifica por la **4-tupla**: `(IP origen, puerto origen, IP destino, puerto destino)`.

### TCP vs UDP

| | **TCP** | **UDP** |
|---|---|---|
| Conexión | Orientado a conexión (handshake) | Sin conexión |
| Confiabilidad | Garantiza entrega, con ACKs y retransmisión | No garantiza nada |
| Orden | Entrega ordenada | Sin orden |
| Control de flujo | Sí (ventana deslizante) | No |
| Control de congestión | Sí | No (lo resuelve la app) |
| Overhead | Header de 20+ bytes, más estado | Header de 8 bytes |
| Latencia | Mayor (handshake, retransmisiones) | Menor |
| Modelo | Stream de bytes (sin límites de mensaje) | Datagramas (cada mensaje es independiente) |
| Broadcast/Multicast | No | Sí |
| Usos | HTTP/1.1, HTTP/2, SSH, SMTP, bases de datos, FTP | DNS, streaming/VoIP, juegos online, QUIC (HTTP/3), DHCP, NTP |

**Cuándo elegir cuál:** si perder datos es inaceptable, TCP. Si un dato viejo ya no sirve (una muestra de audio, la posición de un jugador hace 200 ms), UDP: retransmitir solo agregaría latencia.

### Handshake de TCP (3-way)

```
Cliente                         Servidor
   │ ── SYN (seq=x) ────────────▶ │   1. "Quiero conectar"       (SYN_SENT)
   │ ◀── SYN-ACK (seq=y, ack=x+1) │   2. "Ok, yo también"        (SYN_RECEIVED)
   │ ── ACK (ack=y+1) ──────────▶ │   3. "Confirmado"            (ESTABLISHED)
   │ ═══════ datos ═══════════════│
```

- Se intercambian **números de secuencia iniciales (ISN)**, que permiten ordenar, detectar pérdidas y evitar spoofing.
- Costo: **1 RTT** antes de enviar el primer byte útil. Con TLS encima se suman 1–2 RTT más.
- **SYN flood**: ataque que manda muchos SYN sin completar el handshake para llenar la cola de conexiones. Mitigación: *SYN cookies*, rate limiting, firewalls.

### Cierre de conexión (4-way)

```
Cliente ── FIN ──▶ Servidor      (FIN_WAIT_1)
Cliente ◀── ACK ── Servidor      (FIN_WAIT_2)
Cliente ◀── FIN ── Servidor      (CLOSE_WAIT → LAST_ACK)
Cliente ── ACK ──▶ Servidor      (TIME_WAIT → CLOSED)
```

- **TIME_WAIT**: el que cierra primero espera ~2×MSL (típicamente 60 s) por si algún paquete rezagado aparece. Si tenés miles de conexiones cortas, se acumulan sockets en `TIME_WAIT` y podés agotar puertos efímeros. Solución: **reutilizar conexiones** (keep-alive, connection pooling).
- **RST**: cierre abrupto (puerto cerrado, error, firewall).

### Mecanismos internos de TCP

- **Control de flujo:** el receptor anuncia su **ventana (rwnd)** para no ser desbordado.
- **Control de congestión:** el emisor mantiene una **ventana de congestión (cwnd)**. *Slow start* (crece exponencialmente) → *congestion avoidance* (crece lineal) → ante pérdida, reduce. Algoritmos: Reno, CUBIC, BBR.
- **Retransmisión:** por timeout (RTO) o por 3 ACKs duplicados (*fast retransmit*).
- **Nagle y delayed ACK:** agrupan paquetes chicos; pueden agregar latencia. `TCP_NODELAY` desactiva Nagle (se usa en apps de baja latencia).
- **Head-of-line blocking (HOL):** si se pierde un segmento, los siguientes esperan aunque hayan llegado. Es el problema que motivó QUIC (ver 1.3).

---

## 1.2 DNS, caching DNS, TTL

### Qué es

El **Domain Name System** traduce nombres (`api.ejemplo.com`) a IPs. Es una base de datos **distribuida y jerárquica**, normalmente sobre **UDP/53** (y TCP/53 para respuestas grandes o transferencias de zona).

### Jerarquía

```
                 .  (root, 13 grupos de root servers)
                 │
        ┌────────┼────────┐
       .com     .org     .ar        ← TLD servers
        │                  │
   ejemplo.com         gob.ar        ← Servidores autoritativos
        │
 api.ejemplo.com
```

### Actores

- **Stub resolver:** el cliente del SO/navegador. Pregunta y espera la respuesta final.
- **Resolver recursivo** (de tu ISP, `8.8.8.8`, `1.1.1.1`): hace el trabajo sucio y **cachea**.
- **Root, TLD y servidores autoritativos:** responden con referencias o con la respuesta definitiva.

### Resolución paso a paso (sin caché)

1. El navegador pide `api.ejemplo.com` al resolver recursivo.
2. El resolver pregunta a un **root server** → responde "preguntale a los servidores de `.com`".
3. Pregunta al **TLD `.com`** → responde "los NS de `ejemplo.com` son…".
4. Pregunta al **autoritativo de `ejemplo.com`** → responde con el registro `A`/`AAAA`.
5. El resolver **cachea** el resultado según el TTL y se lo devuelve al cliente.

*Recursiva* = "dame la respuesta final". *Iterativa* = "dame la mejor pista que tengas" (la que usa el resolver con los servidores).

### Tipos de registros

| Registro | Función | Ejemplo |
|---|---|---|
| **A** | Nombre → IPv4 | `api  A  203.0.113.10` |
| **AAAA** | Nombre → IPv6 | `api  AAAA  2001:db8::10` |
| **CNAME** | Alias a otro nombre | `www  CNAME  ejemplo.com.` |
| **NS** | Servidores autoritativos de la zona | `ejemplo.com  NS  ns1.proveedor.com.` |
| **MX** | Servidores de correo (con prioridad) | `MX 10 mail.ejemplo.com.` |
| **TXT** | Texto libre: SPF, DKIM, verificaciones | `"v=spf1 include:..."` |
| **SRV** | Host + puerto de un servicio | `_sip._tcp ...` |
| **PTR** | IP → nombre (DNS inverso) | |
| **SOA** | Metadatos de la zona (serial, TTLs) | |
| **CAA** | Qué CAs pueden emitir certificados | |

**Notas:** un CNAME **no puede convivir** con otros registros en el mismo nombre, y por eso no se puede poner en el apex (`ejemplo.com`). Los proveedores resuelven esto con `ALIAS`/`ANAME`/CNAME flattening.

### Caching DNS (en cada capa)

```
Navegador → SO (stub resolver) → Router/hosts locales → Resolver del ISP/público → ... → Autoritativo
  cache         cache                                          cache
```

1. **Caché del navegador** (Chrome mantiene la suya, corta).
2. **Caché del SO** (`systemd-resolved`, `dnscache` de Windows, `mDNSResponder` en macOS).
3. **Archivo `hosts`** (tiene prioridad sobre DNS).
4. **Resolver recursivo**: cachea para **todos** sus clientes, por eso es la caché más importante.

También existe **negative caching**: se cachea que un nombre **no existe** (NXDOMAIN), usando el campo *minimum* del SOA.

### TTL (Time To Live)

Es el tiempo, en segundos, que un resolver puede cachear un registro. Lo define el dueño de la zona **por registro**.

| TTL | Efecto |
|---|---|
| **Bajo** (30–300 s) | Los cambios se propagan rápido; más consultas y más latencia media; ideal antes de una migración o para failover |
| **Alto** (3600–86400 s) | Menos carga y menor latencia; los cambios tardan en verse; ideal para registros estables |

**Mal llamado "propagación DNS":** no se "propaga" nada. Lo que pasa es que las cachés **expiran cada una a su tiempo**. Una vez cambiado el registro, el peor caso es esperar el TTL **anterior** completo.

**Buenas prácticas de migración:**
1. Días antes, bajá el TTL (p. ej., de 86400 a 300).
2. Esperá a que expire el TTL viejo.
3. Hacé el cambio.
4. Verificá y, cuando esté estable, subí el TTL de nuevo.

> Algunos resolvers y clientes **ignoran o extienden** TTLs bajos. Además, la JVM históricamente cacheaba DNS por tiempo indefinido en algunas configuraciones: ojo con apps de larga vida.

### DNS en arquitectura de sistemas

- **DNS round-robin:** varios registros A para el mismo nombre; el resolver rota el orden. Balanceo básico, **sin health checks** ni conocimiento de carga.
- **GeoDNS / latency-based routing:** devuelve la IP del datacenter más cercano (Route 53, Cloudflare).
- **Failover por DNS:** health checks + TTL bajo. Limitado por las cachés.
- **Anycast:** la misma IP se anuncia desde muchas ubicaciones (BGP); así funcionan root servers y CDNs.
- **Service discovery:** en Kubernetes, CoreDNS resuelve `servicio.namespace.svc.cluster.local`.

### Seguridad y privacidad

- **DNS spoofing / cache poisoning:** inyectar respuestas falsas. Mitigación: **DNSSEC** (firma criptográfica de registros; autentica, no cifra).
- **DoH (DNS over HTTPS) / DoT (DNS over TLS):** cifran la consulta entre cliente y resolver.
- **DNS tunneling y amplificación DDoS** (por UDP + respuestas grandes) son vectores conocidos.

### Comandos útiles

```bash
dig api.ejemplo.com            # consulta A
dig +trace api.ejemplo.com     # sigue la jerarquía desde root
dig MX ejemplo.com
dig @1.1.1.1 api.ejemplo.com   # elegir resolver
nslookup api.ejemplo.com
```

---

## 1.3 HTTP/1.1, HTTP/2, HTTP/3 (QUIC), keep-alive

### Conceptos base de HTTP

- Protocolo **request/response**, **stateless** (cada request es independiente; el estado se maneja con cookies, tokens, etc.).
- Estructura de un request:

```http
GET /usuarios/42?expand=pedidos HTTP/1.1
Host: api.ejemplo.com
Accept: application/json
Authorization: Bearer eyJ...
```

- Respuesta:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=60
ETag: "abc123"

{"id": 42, "nombre": "Ana"}
```

**Métodos:** `GET` (leer), `POST` (crear/acción), `PUT` (reemplazar), `PATCH` (modificar parcialmente), `DELETE`, `HEAD`, `OPTIONS` (CORS preflight).

**Status codes:** `1xx` informativos · `2xx` éxito (200, 201, 204) · `3xx` redirección (301, 302, 304) · `4xx` error del cliente (400, 401, 403, 404, 409, 422, 429) · `5xx` error del servidor (500, 502, 503, 504).

### HTTP/1.1 (1997, RFC 9112 actual)

- **Formato de texto.**
- **Conexiones persistentes (keep-alive) por defecto.**
- **Header `Host` obligatorio** → permite virtual hosting (varios dominios en una IP).
- **Chunked transfer encoding**: permite enviar respuestas de largo desconocido.
- **Pipelining** (enviar varios requests sin esperar respuesta): existe en la spec pero está **prácticamente deshabilitado**, por problemas con proxies y HOL.

**Problemas:**
- **Head-of-line blocking a nivel HTTP:** en una conexión, las respuestas deben llegar **en orden**; un request lento bloquea a los siguientes.
- **Workaround:** los navegadores abren **~6 conexiones TCP en paralelo por host**, y los sitios usaron *domain sharding*, *sprites* y *bundling*. Cada conexión paga handshake TCP + TLS.
- **Headers repetitivos** y sin compresión (cookies enviadas en cada request).

### HTTP/2 (2015, RFC 9113)

Mismo modelo semántico (métodos, status, headers), **distinta forma de transportarlo**.

| Característica | Detalle |
|---|---|
| **Formato binario** | Frames en vez de texto; más eficiente y menos ambiguo |
| **Multiplexación** | Muchos *streams* simultáneos sobre **una sola** conexión TCP; elimina el HOL a nivel HTTP |
| **Compresión de headers (HPACK)** | Tabla dinámica + Huffman; los headers repetidos casi no cuestan |
| **Priorización de streams** | Se puede indicar qué recursos importan más |
| **Server push** | El servidor envía recursos antes de que se pidan. **Deprecado en la práctica** (Chrome lo eliminó) |
| **Control de flujo por stream** | Evita que un stream monopolice la conexión |

**Limitación importante:** sigue sobre **TCP**. Si se pierde **un** paquete, TCP retiene **todos** los streams hasta retransmitirlo → **HOL blocking a nivel TCP**. En redes con pérdida (móvil), HTTP/2 puede rendir peor que varias conexiones HTTP/1.1.

> En la práctica los navegadores solo usan HTTP/2 sobre TLS, negociado vía **ALPN** (`h2`).

### HTTP/3 (2022, RFC 9114) y QUIC

HTTP/3 es HTTP sobre **QUIC**, un protocolo de transporte construido **sobre UDP**.

```
HTTP/1.1, HTTP/2:   HTTP → TLS → TCP → IP
HTTP/3:             HTTP → QUIC (incluye TLS 1.3) → UDP → IP
```

**Qué resuelve QUIC:**

| Mejora | Cómo |
|---|---|
| **Sin HOL a nivel transporte** | Los streams son independientes; perder un paquete solo frena al stream afectado |
| **Handshake más rápido** | Combina transporte + TLS 1.3: **1 RTT** para una conexión nueva, **0-RTT** al reanudar |
| **Connection migration** | La conexión se identifica por un **Connection ID**, no por la 4-tupla; sobrevive al cambio Wi-Fi ↔ 4G |
| **TLS 1.3 obligatorio** | Todo viaja cifrado, incluso gran parte de los headers de transporte |
| **Evolución en espacio de usuario** | Se actualiza con la librería/app, sin esperar al kernel o middleboxes |
| **QPACK** | Compresión de headers adaptada a streams independientes (reemplaza HPACK) |

**Contras:** algunas redes bloquean o limitan UDP; mayor uso de CPU (cifrado por paquete, sin offloads maduros); **0-RTT es vulnerable a replay**, por eso solo debe usarse con requests idempotentes. Los clientes hacen *fallback* a HTTP/2 si QUIC falla. El servidor anuncia soporte con el header `Alt-Svc: h3=":443"`.

### Comparativa

| | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---|---|---|---|
| Transporte | TCP | TCP | QUIC (UDP) |
| Formato | Texto | Binario | Binario |
| Multiplexación | No (≈6 conexiones) | Sí | Sí |
| HOL blocking HTTP | Sí | No | No |
| HOL blocking transporte | Sí | **Sí** | No |
| Compresión de headers | No | HPACK | QPACK |
| TLS | Opcional | De facto obligatorio | Obligatorio (integrado) |
| Handshake (nueva conexión + TLS) | 2–3 RTT | 2–3 RTT | 1 RTT (0-RTT al reanudar) |
| Migración de conexión | No | No | Sí |

### Keep-alive (conexiones persistentes)

**Problema:** abrir una conexión por request cuesta handshake TCP (1 RTT) + TLS (1–2 RTT) + slow start de TCP.

**Solución:** reutilizar la misma conexión TCP para múltiples requests.

```http
Connection: keep-alive
Keep-Alive: timeout=5, max=1000
```

- En **HTTP/1.1 es el comportamiento por defecto**; para cerrar se manda `Connection: close`. En HTTP/1.0 había que pedirlo.
- En HTTP/2 y HTTP/3 la conexión es persistente por diseño (y el header `Connection` no se usa).
- **Parámetros típicos** (nginx): `keepalive_timeout 65s;`, `keepalive_requests 1000;`.

**Ojo con:**
- **Desajuste de timeouts** entre balanceador y backend: si el backend cierra una conexión idle justo cuando el LB la reutiliza, aparecen **502/reset esporádicos**. Regla: el timeout idle del **backend debe ser mayor** que el del LB/proxy que va delante.
- **Connection pooling** del lado cliente: en Node.js usá `http.Agent({ keepAlive: true })` (desde Node 19 es el default); en servicios que llaman a otros servicios, evita agotar puertos y reduce latencia.
- No confundir con **TCP keepalive** (SO_KEEPALIVE): son *probes* de la capa TCP para detectar peers muertos, no tiene que ver con el header HTTP.

### Headers de caché (relacionados, imprescindibles)

| Header | Uso |
|---|---|
| `Cache-Control: max-age=N, public/private, no-store, no-cache, immutable` | Política principal |
| `ETag` / `If-None-Match` | Validación condicional → `304 Not Modified` |
| `Last-Modified` / `If-Modified-Since` | Validación por fecha |
| `Vary: Accept-Encoding` | Define qué headers afectan la variante cacheada |

---

## 1.4 Proxies: forward vs reverse

Un **proxy** es un intermediario que recibe requests y los reenvía. La diferencia es **a quién representa**.

### Forward proxy (proxy "directo")

Representa al **cliente**. El servidor destino no ve al cliente real.

```
Clientes ──▶ [ Forward Proxy ] ──▶ Internet / Servidores
(red interna)
```

**Usos:**
- **Control de acceso y filtrado** corporativo (bloquear sitios, auditar).
- **Anonimato** / evasión de restricciones geográficas (VPN-like, Tor).
- **Caché** compartida para muchos clientes (ahorra ancho de banda).
- **Salida controlada** desde redes sin acceso directo a Internet.

**Cómo funciona con HTTPS:** el cliente le pide `CONNECT host:443` al proxy, que abre un **túnel TCP** y deja pasar los bytes cifrados sin leerlos. Solo si hay **inspección TLS (MITM corporativo)** el proxy descifra, usando un certificado de CA propia instalada en los equipos.

El cliente **sabe** que usa el proxy (está configurado explícitamente). Si no lo sabe, es un *transparent proxy*.

### Reverse proxy (proxy "inverso")

Representa al **servidor**. El cliente cree que habla con el servidor real.

```
Clientes (Internet) ──▶ [ Reverse Proxy ] ──▶ Backend 1
                                          ├─▶ Backend 2
                                          └─▶ Backend 3
```

**Usos:**
- **Balanceo de carga** (round robin, least connections, hash por IP o cookie).
- **Terminación TLS**: descifra en el borde y habla HTTP plano (o re-cifra) hacia adentro.
- **Caché** de respuestas y contenido estático (CDN = reverse proxies distribuidos globalmente).
- **Compresión** (gzip/brotli), **HTTP/2 y HTTP/3** hacia clientes aunque el backend hable HTTP/1.1.
- **Seguridad**: oculta la topología, WAF, rate limiting, protección DDoS.
- **Enrutamiento** por host o path (`/api` → servicio A, `/` → frontend).
- **Health checks** y failover.

**Ejemplos:** Nginx, HAProxy, Envoy, Traefik, Caddy, Cloudflare, AWS ALB/CloudFront.

### Comparativa

| | Forward | Reverse |
|---|---|---|
| Protege / representa a | Clientes | Servidores |
| Quién lo configura | El cliente (o la red del cliente) | El dueño del servicio |
| El destino ve | La IP del proxy | — |
| El cliente ve | — | La IP del proxy, no la del backend |
| Casos típicos | Filtrado corporativo, anonimato | Balanceo, TLS, caché, seguridad |

### Detalles importantes

**Preservar la IP del cliente.** Como el backend ve la IP del proxy, el proxy agrega headers:

```http
X-Forwarded-For: 203.0.113.7, 10.0.0.5
X-Forwarded-Proto: https
X-Forwarded-Host: api.ejemplo.com
Forwarded: for=203.0.113.7;proto=https      ← versión estándar (RFC 7239)
```

⚠️ Estos headers **pueden ser falsificados por el cliente**: solo confiá en los que agregan tus propios proxies (en NestJS/Express: `app.set('trust proxy', ...)`). Alternativa a nivel TCP: **PROXY protocol** (HAProxy).

**Balanceo L4 vs L7:**

| | L4 (TCP/UDP) | L7 (HTTP) |
|---|---|---|
| Decide por | IP + puerto | URL, headers, cookies |
| Velocidad | Muy alta, simple | Más costosa |
| Capacidades | Reenvío de conexiones | Routing por path, reescritura, auth, caché |
| Ejemplos | AWS NLB, HAProxy modo tcp | AWS ALB, Nginx, Envoy |

**Algoritmos de balanceo:** round robin, weighted round robin, least connections, IP hash, consistent hashing, random two choices.

**Ejemplo mínimo de Nginx como reverse proxy:**

```nginx
upstream backend {
    least_conn;
    server 10.0.0.11:3000;
    server 10.0.0.12:3000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.ejemplo.com;

    ssl_certificate     /etc/ssl/fullchain.pem;
    ssl_certificate_key /etc/ssl/privkey.pem;

    location /api/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Riesgos:** el reverse proxy es un **single point of failure** (se mitiga con múltiples instancias + IP virtual/anycast/DNS) y agrega un salto de latencia.

---

## 1.5 TLS/SSL, mTLS

### Qué es

**TLS (Transport Layer Security)** da tres garantías sobre un canal (normalmente sobre TCP):

1. **Confidencialidad:** nadie en el medio puede leer los datos (cifrado).
2. **Integridad:** nadie puede modificarlos sin ser detectado (MAC / AEAD).
3. **Autenticación:** se verifica la identidad del servidor (y opcionalmente del cliente) mediante certificados.

**SSL** es el nombre histórico. **SSL 2.0/3.0 y TLS 1.0/1.1 están obsoletos e inseguros.** Hoy se usa **TLS 1.2** y **TLS 1.3** (preferido). "HTTPS" = HTTP sobre TLS.

### Criptografía que combina TLS

| Tipo | Para qué | Ejemplos |
|---|---|---|
| **Asimétrica** (par de claves pública/privada) | Autenticar e intercambiar claves | RSA, ECDSA, ECDHE/X25519 |
| **Simétrica** (una clave compartida) | Cifrar los datos (rápido) | AES-GCM, ChaCha20-Poly1305 |
| **Hash / MAC** | Integridad, firmas | SHA-256, HMAC |

**Idea central:** la criptografía asimétrica es lenta, así que se usa **solo para acordar una clave de sesión simétrica**; el resto del tráfico se cifra con esa clave.

**Perfect Forward Secrecy (PFS):** con intercambio de claves efímero (ECDHE), cada sesión usa una clave distinta. Si en el futuro se filtra la clave privada del servidor, **no se pueden descifrar sesiones pasadas grabadas**. TLS 1.3 lo hace obligatorio.

### Certificados y cadena de confianza

Un **certificado X.509** liga una **clave pública** con una **identidad** (dominio) y está **firmado por una CA** (Autoridad Certificadora).

```
Root CA  (confiable, preinstalada en SO/navegador)
   └── Intermediate CA
          └── Certificado del servidor (api.ejemplo.com)
```

El cliente valida:
1. Que la cadena llegue a una **CA raíz confiable**.
2. Que el certificado **no esté vencido** ni **revocado** (CRL / OCSP / OCSP stapling).
3. Que el **dominio coincida** con el CN/SAN.
4. Que la firma sea válida.

Tipos de validación: **DV** (dominio), **OV** (organización), **EV** (extendida). **Let's Encrypt** emite DV gratis y automatizable (ACME, certbot). Los certificados modernos duran ≤ 398 días y la tendencia es acortarlos.

### Handshake TLS 1.2 (resumido, 2 RTT)

```
Cliente                                     Servidor
  │ ── ClientHello (versiones, ciphers, random) ──▶ │
  │ ◀── ServerHello, Certificate, ServerKeyExchange, ServerHelloDone │
  │ ── ClientKeyExchange, ChangeCipherSpec, Finished ─▶ │
  │ ◀── ChangeCipherSpec, Finished ────────────────── │
  │ ════════ datos cifrados ═════════════════════════ │
```

### Handshake TLS 1.3 (1 RTT)

```
Cliente                                     Servidor
  │ ── ClientHello + KeyShare ───────────────────▶ │
  │ ◀── ServerHello + KeyShare, {Certificate, Finished} (ya cifrado) │
  │ ── {Finished} ───────────────────────────────▶ │
  │ ════════ datos cifrados ═════════════════════ │
```

**Mejoras de TLS 1.3:** 1 RTT (y **0-RTT** al reanudar, con riesgo de replay); elimina algoritmos viejos e inseguros (RSA key exchange, CBC, RC4, SHA-1); cifra casi todo el handshake, incluido el certificado; PFS obligatorio.

### Extensiones que conviene conocer

- **SNI (Server Name Indication):** el cliente indica en el ClientHello **a qué dominio** quiere conectarse, para que un servidor con una IP y muchos certificados elija el correcto.
- **ALPN:** negocia el protocolo de aplicación (`h2`, `http/1.1`, `h3`).
- **Session resumption** (session tickets / PSK): evita repetir el handshake completo.
- **OCSP stapling:** el servidor adjunta la prueba de que su certificado no está revocado.
- **HSTS** (`Strict-Transport-Security: max-age=31536000; includeSubDomains`): fuerza al navegador a usar siempre HTTPS.
- **Certificate pinning:** el cliente fija qué certificado/clave espera (útil en apps móviles; difícil de mantener).

### Terminación TLS

| Estrategia | Descripción | Cuándo |
|---|---|---|
| **TLS termination** | El LB/proxy descifra; hacia el backend va HTTP plano | La más común; simple y permite inspección L7. Aceptable en red privada confiable |
| **TLS passthrough** | El LB reenvía los bytes cifrados (L4) | Cuando el backend debe ver el certificado o hay requisitos estrictos |
| **TLS re-encryption (end-to-end)** | Termina en el LB y vuelve a cifrar hacia el backend | Compliance (PCI, zero trust) |

### mTLS (mutual TLS)

En TLS normal **solo el servidor** se autentica. En **mTLS**, **ambos presentan certificado**: el servidor también exige y valida el certificado del cliente.

```
Cliente                                         Servidor
  │ ── ClientHello ─────────────────────────────▶ │
  │ ◀── ServerHello, Certificate, CertificateRequest │
  │ ── Certificate (cliente), CertificateVerify, Finished ─▶ │
  │ ◀── Finished ────────────────────────────────── │
  │ ═══════ canal con identidad mutua ═══════════ │
```

**Para qué sirve:**
- **Autenticación servicio-a-servicio** (zero trust): cada microservicio prueba quién es sin depender de tokens ni de la red.
- **Service mesh** (Istio, Linkerd, Consul): los sidecars hacen mTLS automático y rotan certificados.
- **APIs B2B / financieras** (Open Banking), dispositivos IoT, VPNs.

**Requisitos y costos:**
- Una **CA privada (PKI interna)** que emita certificados de cliente (HashiCorp Vault, step-ca, cert-manager en Kubernetes, SPIFFE/SPIRE).
- **Rotación automática** de certificados de vida corta (horas/días).
- Más complejidad operativa y de debugging; no aplica a navegadores de usuarios finales.

### Comandos útiles

```bash
openssl s_client -connect ejemplo.com:443 -servername ejemplo.com   # ver cadena y handshake
openssl x509 -in cert.pem -text -noout                              # inspeccionar certificado
curl -v https://ejemplo.com                                         # ver negociación TLS
curl --cert cliente.crt --key cliente.key --cacert ca.crt https://api.interna   # mTLS
```

### Errores comunes

- Certificado **vencido** o **cadena incompleta** (falta el intermedio).
- **Dominio no coincide** (CN/SAN).
- Desactivar la verificación (`rejectUnauthorized: false`, `curl -k`) "para que ande" en producción.
- Mezclar **contenido HTTP en página HTTPS** (mixed content).

---

## 1.6 REST, GraphQL, gRPC, SOAP, diseño de APIs

### REST

**REST** (Representational State Transfer) es un **estilo arquitectónico**, no un protocolo. Normalmente se implementa sobre HTTP + JSON.

**Restricciones de REST:**
1. **Cliente-servidor** (separación de responsabilidades).
2. **Stateless:** cada request contiene todo lo necesario; el servidor no guarda sesión.
3. **Cacheable:** las respuestas declaran si pueden cachearse.
4. **Interfaz uniforme:** recursos identificados por URI, manipulados mediante representaciones, mensajes autodescriptivos y, en teoría, **HATEOAS** (links para navegar).
5. **Sistema en capas** (proxies, gateways, CDNs transparentes).
6. *(Opcional)* Código bajo demanda.

**Modelo de Richardson:** nivel 0 (un endpoint, RPC sobre HTTP) → 1 (recursos) → 2 (verbos HTTP + status codes) → 3 (HATEOAS). La mayoría de las "APIs REST" reales están en el **nivel 2**.

**Convenciones de diseño:**

```
GET    /usuarios              → listar
POST   /usuarios              → crear                (201 + Location)
GET    /usuarios/42           → obtener
PUT    /usuarios/42           → reemplazar completo
PATCH  /usuarios/42           → actualización parcial
DELETE /usuarios/42           → eliminar             (204)
GET    /usuarios/42/pedidos   → sub-recurso
```

- Sustantivos **en plural**, no verbos (`/pedidos`, no `/crearPedido`). Para acciones que no encajan en CRUD: `POST /pedidos/42/cancelar`.
- Minúsculas con guiones (`/metodos-de-pago`).
- Filtrado/orden/campos por query: `?estado=activo&sort=-creado&fields=id,nombre`.

**Propiedades de los métodos:**

| Método | Seguro (no modifica) | Idempotente | Cacheable |
|---|---|---|---|
| GET | ✅ | ✅ | ✅ |
| HEAD / OPTIONS | ✅ | ✅ | ✅ / ❌ |
| PUT | ❌ | ✅ | ❌ |
| DELETE | ❌ | ✅ | ❌ |
| POST | ❌ | ❌ | Rara vez |
| PATCH | ❌ | No garantizado | ❌ |

**Status codes que conviene usar bien:**

| Código | Cuándo |
|---|---|
| 200 OK / 201 Created / 202 Accepted / 204 No Content | Éxito (202 = procesamiento asíncrono) |
| 301/308 | Redirección permanente · 304 No Modified |
| 400 | Request malformado · 422 error de validación semántica |
| 401 | No autenticado · 403 autenticado pero sin permiso |
| 404 | No existe · 409 conflicto (versión, duplicado) |
| 415 | Media type no soportado · 429 Too Many Requests |
| 500 / 502 / 503 / 504 | Error interno / bad gateway / no disponible / timeout |

### GraphQL

Lenguaje de consulta con **un único endpoint** (`POST /graphql`) donde el **cliente define exactamente qué datos necesita**.

```graphql
query {
  usuario(id: 42) {
    nombre
    pedidos(first: 5) { id total }
  }
}
```

- **Schema fuertemente tipado** (SDL), introspección.
- Operaciones: **Query** (leer), **Mutation** (escribir), **Subscription** (tiempo real, normalmente sobre WebSocket).
- **Resuelve** over-fetching (traer de más) y under-fetching (múltiples round trips).

**Costos y problemas:**
- **Problema N+1** en los resolvers → se resuelve con **DataLoader** (batching + caché por request).
- **Caché HTTP difícil** (todo es POST a una URL): se usan *persisted queries*, caché en cliente normalizada (Apollo) o CDN con GET.
- **Consultas abusivas / profundas:** limitar profundidad, calcular **costo/complejidad** de la query, timeouts, rate limiting por costo.
- Errores: casi siempre `200 OK` con un campo `errors` en el body, lo que complica el monitoreo.
- Desactivar introspección en producción si no querés exponer el schema.
- Subida de archivos y versionado (se evoluciona con `@deprecated`) tienen sus particularidades.

### gRPC

Framework **RPC** de Google. Usa **HTTP/2** y **Protocol Buffers** (serialización binaria).

```proto
syntax = "proto3";

service Usuarios {
  rpc ObtenerUsuario (UsuarioRequest) returns (Usuario);
  rpc ListarPedidos  (UsuarioRequest) returns (stream Pedido);
}

message UsuarioRequest { int32 id = 1; }
message Usuario        { int32 id = 1; string nombre = 2; }
```

- **Contrato primero** (`.proto`) y **generación de código** en muchos lenguajes.
- **4 modos de comunicación:** *unary*, *server streaming*, *client streaming*, *bidireccional*.
- Payload **compacto y rápido** de serializar; multiplexación de HTTP/2.
- Soporta **deadlines/timeouts**, cancelación, metadata, interceptores, TLS/mTLS.
- **Compatibilidad:** nunca cambiar ni reutilizar el número de un campo; agregar campos nuevos es seguro.

**Contras:** no se consume directo desde navegadores (requiere **gRPC-Web** + proxy), binario difícil de depurar a ojo (usar `grpcurl`), menos amigable para APIs públicas. **Ideal para comunicación interna entre microservicios.**

### SOAP

Protocolo basado en **XML**, con contrato formal **WSDL**.

```xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>…</soap:Header>
  <soap:Body>
    <ObtenerUsuario><id>42</id></ObtenerUsuario>
  </soap:Body>
</soap:Envelope>
```

- Independiente del transporte (HTTP, SMTP…), pero casi siempre HTTP `POST`.
- **WS-\*:** WS-Security, transacciones, mensajería confiable.
- Fuertemente tipado y con contrato estricto; verboso y pesado.
- **Aún vigente en banca, seguros, gobierno y sistemas legacy** (en Argentina, por ejemplo, los *web services* de ARCA/AFIP son SOAP).

### Comparativa

| | REST | GraphQL | gRPC | SOAP |
|---|---|---|---|---|
| Tipo | Estilo arquitectónico | Lenguaje de consulta | RPC | Protocolo |
| Formato | JSON (normalmente) | JSON | Protobuf (binario) | XML |
| Transporte | HTTP/1.1+ | HTTP | HTTP/2 | HTTP, SMTP, otros |
| Contrato | OpenAPI (opcional) | Schema (SDL) | `.proto` | WSDL |
| Streaming | Limitado (SSE, chunked) | Subscriptions | Nativo (4 modos) | No nativo |
| Caché HTTP | Excelente | Difícil | Difícil | Difícil |
| Performance | Buena | Buena | **Muy alta** | Baja |
| Curva | Baja | Media | Media | Alta |
| Navegador | ✅ | ✅ | ⚠️ gRPC-Web | ✅ (poco común) |
| Ideal para | APIs públicas, CRUD | Frontends con datos variados (mobile, BFF) | Microservicios internos, baja latencia | Integraciones legacy/empresariales |

### Diseño de APIs: versionado

Cambios **breaking** (borrar/renombrar campos, cambiar tipos o semántica) requieren una nueva versión. Cambios **aditivos** (nuevos campos/endpoints opcionales) no.

| Estrategia | Ejemplo | Pros / contras |
|---|---|---|
| **URI** | `/v1/usuarios` | Simple, visible, cacheable; la "URL" cambia |
| **Header custom** | `Api-Version: 2` | URLs limpias; menos visible |
| **Media type** | `Accept: application/vnd.ejemplo.v2+json` | Más "puro" REST; más complejo |
| **Query param** | `?version=2` | Fácil; ensucia la URL y la caché |

Buenas prácticas: versionar solo cuando sea inevitable, **mantener compatibilidad hacia atrás**, usar `Deprecation` y `Sunset` headers, comunicar un calendario de baja, y diseñar clientes **tolerantes** a campos desconocidos.

### Diseño de APIs: paginación

| Técnica | Ejemplo | Pros | Contras |
|---|---|---|---|
| **Offset/limit** | `?offset=40&limit=20` | Simple, permite saltar a una página | Lento con offsets grandes (`OFFSET 1000000`); inconsistente si hay inserciones/borrados durante la navegación |
| **Page/size** | `?page=3&size=20` | Igual que offset | Igual |
| **Cursor (opaco)** | `?after=eyJpZCI6MTAwfQ&limit=20` | Estable ante cambios, buen rendimiento | No se puede saltar a una página arbitraria |
| **Keyset (seek)** | `WHERE id > 100 ORDER BY id LIMIT 20` | Muy eficiente con índice | Requiere orden determinista (clave única) |

Respuesta típica con cursor:

```json
{
  "data": [ ... ],
  "paging": { "next_cursor": "eyJpZCI6MTIwfQ", "has_more": true }
}
```

Poné un **límite máximo** de `limit`, y definí un **orden estable** (desempatar con el `id`). Evitá devolver `COUNT(*)` total en tablas enormes salvo que sea necesario.

### Diseño de APIs: idempotencia

Una operación es **idempotente** si ejecutarla N veces deja el sistema en el mismo estado que ejecutarla una. Es fundamental porque **las redes fallan y los clientes reintentan** (timeout ≠ no se procesó).

- `GET`, `PUT`, `DELETE` son idempotentes por definición. **`POST` no**: un reintento puede crear duplicados (¡dos cobros!).
- **Idempotency-Key:** el cliente envía un identificador único (UUID) por operación; el servidor guarda el resultado asociado y, ante un reintento con la misma clave, **devuelve la respuesta original** sin volver a ejecutar.

```http
POST /pagos
Idempotency-Key: 7c9e6679-7425-40de-944b-e07fc1f90ae7
```

**Implementación:**
1. Tabla/Redis con `key → {request_hash, estado, respuesta}` y **TTL** (24–48 h).
2. Al llegar un request, **insertar la key con restricción de unicidad** (o `SET NX`) *antes* de procesar.
3. Si la key ya existe y está "en proceso" → `409`; si terminó → devolver la respuesta guardada.
4. Validar que el body coincida con el de la primera vez (si no, `422`).

Complementos: **reintentos con backoff exponencial + jitter** en el cliente, y **deduplicación** en el consumidor cuando hay mensajería (*at-least-once* delivery → consumidores idempotentes).

### Diseño de APIs: otros aspectos

- **Errores consistentes:** formato estándar **RFC 9457 (Problem Details)**:

```json
{
  "type": "https://api.ejemplo.com/errores/saldo-insuficiente",
  "title": "Saldo insuficiente",
  "status": 422,
  "detail": "El saldo es 30 y el monto es 50.",
  "instance": "/pagos/abc"
}
```

- **Rate limiting:** `429 Too Many Requests` + `Retry-After`; headers `RateLimit-*`. Algoritmos: token bucket, leaky bucket, fixed/sliding window.
- **Concurrencia optimista:** `ETag` + `If-Match` en `PUT/PATCH` → `412 Precondition Failed` si cambió.
- **Autenticación/autorización:** OAuth 2.0 / OIDC, JWT de vida corta, API keys para M2M; siempre sobre TLS.
- **Operaciones largas:** devolver `202 Accepted` con `Location` a un recurso de estado (`/jobs/123`), o usar webhooks.
- **Documentación y contrato:** **OpenAPI/Swagger**, ejemplos, generación de SDKs, tests de contrato.
- **Campos:** nombres consistentes (`camelCase` o `snake_case`, uno solo), fechas **ISO 8601 en UTC**, dinero en la unidad mínima (centavos) como entero, IDs opacos.
- **Seguridad:** validar entrada, no exponer IDs secuenciales sensibles, CORS bien configurado, evitar *mass assignment*.

---

## 1.7 WebSockets, long/short polling, SSE, webhooks

**El problema:** HTTP es request/response iniciado por el cliente. ¿Cómo notifico al cliente de algo nuevo? ¿Cómo notifico a otro sistema?

### Short polling

El cliente pregunta **cada X segundos** si hay novedades.

```js
setInterval(async () => {
  const r = await fetch('/api/estado'); // 200 con o sin cambios
}, 5000);
```

- ✅ Trivial, funciona con cualquier infraestructura y es cacheable.
- ❌ Latencia de hasta X segundos; **muchos requests vacíos**; carga innecesaria.
- Útil para: estados que cambian poco, o jobs asíncronos (`GET /jobs/123`) con intervalo creciente.

### Long polling

El cliente hace el request y el **servidor lo mantiene abierto hasta que haya datos** (o venza un timeout, p. ej. 30 s). Al recibir la respuesta, el cliente **vuelve a conectar de inmediato**.

```
Cliente ── GET /eventos ──▶ Servidor (espera...)
                           ... llega un evento ...
Cliente ◀── 200 {evento} ── Servidor
Cliente ── GET /eventos ──▶ (reconecta)
```

- ✅ Casi tiempo real sin tecnologías nuevas; funciona detrás de casi cualquier proxy.
- ❌ Cada mensaje implica cerrar y reabrir un request (headers repetidos); ocupa una conexión por cliente; el ordenamiento y la pérdida de eventos entre reconexiones requieren cuidado (usar un `lastEventId`).

### Server-Sent Events (SSE)

Stream **unidireccional servidor → cliente** sobre una conexión HTTP larga, con `Content-Type: text/event-stream`.

```
event: pedido-actualizado
id: 105
data: {"pedidoId": 42, "estado": "enviado"}

```

```js
const es = new EventSource('/api/eventos');
es.addEventListener('pedido-actualizado', e => console.log(JSON.parse(e.data)));
es.onerror = () => { /* el navegador reconecta solo */ };
```

- ✅ Muy simple; **reconexión automática** y reanudación con `Last-Event-ID`; funciona sobre HTTP normal (y multiplexado en HTTP/2); ideal para feeds, notificaciones, **streaming de respuestas de LLMs**.
- ❌ Solo texto y solo servidor → cliente (para el otro sentido, se usa un POST aparte); en HTTP/1.1 hay límite de ~6 conexiones por dominio; algunos proxies bufferean la respuesta (hay que desactivar el buffering, p. ej. `proxy_buffering off`).

### WebSockets

Canal **bidireccional y full-duplex** sobre una **única conexión TCP persistente**. Comienza como HTTP y se "promueve" con un *upgrade*:

```http
GET /chat HTTP/1.1
Host: ejemplo.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

A partir de ahí se intercambian **frames** (texto o binario) con muy poco overhead (2–14 bytes de header). URL: `ws://` o **`wss://`** (sobre TLS, lo único recomendable).

- ✅ Latencia mínima, bidireccional, ideal para **chat, juegos, colaboración en tiempo real, trading, dashboards en vivo**.
- ❌ **Conexiones con estado** → más difícil de escalar y balancear.

**Cómo escalar WebSockets:**
- Los servidores mantienen **miles de conexiones abiertas** (memoria y file descriptors; hay que subir `ulimit -n`).
- **Sticky sessions** o, mejor, servidores intercambiables con un **bus pub/sub (Redis, NATS, Kafka)** para que un mensaje llegue a clientes conectados a *otras* instancias (ej.: Socket.IO Redis adapter).
- **Heartbeats (ping/pong)** para detectar conexiones muertas y mantener vivos los NAT/proxies; **timeouts de idle** en LB/proxy configurados acordes.
- **Reconexión con backoff exponencial + jitter** en el cliente, y mecanismo para **recuperar mensajes perdidos** (offsets / último id visto).
- **Autenticación:** el navegador no permite headers custom en el handshake; se usa un token efímero en la query o en el primer mensaje, o cookies. Validar el header `Origin` (evita *Cross-Site WebSocket Hijacking*).
- **Backpressure:** controlar clientes lentos para no acumular buffers.
- WebSockets sobre HTTP/2 (RFC 8441) y sobre HTTP/3 (RFC 9220) existen pero tienen poca adopción; **WebTransport** es la evolución sobre QUIC.

Ejemplo mínimo en NestJS:

```ts
@WebSocketGateway({ cors: { origin: '*' } })
export class ChatGateway {
  @WebSocketServer() server: Server;

  @SubscribeMessage('mensaje')
  handle(@MessageBody() data: string, @ConnectedSocket() client: Socket) {
    this.server.emit('mensaje', data); // broadcast
  }
}
```

### Webhooks

Callbacks **HTTP de servidor a servidor**: en lugar de que vos consultes ("¿ya se pagó?"), **el otro sistema te llama** a una URL tuya cuando ocurre el evento. Es "*no nos llames, te llamamos*" ("reverse API").

```
1. Registrás tu endpoint:   https://tuapp.com/webhooks/pagos
2. Ocurre el evento en el proveedor (pago aprobado)
3. Proveedor ──POST /webhooks/pagos {evento, datos}──▶ Tu servidor
4. Tu servidor responde 2xx rápido
```

**Buenas prácticas (receptor):**
- **Verificar la firma** (HMAC-SHA256 del body con un secreto compartido, header tipo `X-Signature`) con comparación en **tiempo constante**; validar el **timestamp** (anti-replay).
- **Responder rápido (2xx)** y procesar **de forma asíncrona** (encolar en BullMQ/SQS, etc.). Si tardás, el emisor reintenta.
- **Idempotencia:** los emisores garantizan **at-least-once**, así que **vas a recibir duplicados** y fuera de orden. Deduplicá por `event_id`.
- **No confiar ciegamente en el payload:** ante duda, consultá la API del proveedor para confirmar el estado.
- Endpoint **HTTPS**, posible allowlist de IPs, rate limiting.

**Buenas prácticas (emisor):** reintentos con **backoff exponencial**, *dead letter queue*, panel de entregas con reintento manual, eventos versionados, secretos rotables, timeouts cortos.

### Comparativa

| | Short polling | Long polling | SSE | WebSocket | Webhook |
|---|---|---|---|---|---|
| Dirección | Cliente → Servidor | Cliente → Servidor | Servidor → Cliente | **Bidireccional** | Servidor → Servidor |
| Conexión | Nueva por request | Reabre tras cada evento | Persistente | Persistente | Una por evento |
| Latencia | Alta (intervalo) | Baja | Muy baja | **Mínima** | Baja |
| Complejidad | Muy baja | Media | Baja | Alta | Media |
| Reconexión | No aplica | Manual | **Automática** | Manual | Reintentos del emisor |
| Datos | Cualquiera | Cualquiera | Texto | Texto/binario | JSON/lo que defina el proveedor |
| Casos típicos | Estados lentos, jobs | Fallback legacy | Notificaciones, feeds, streaming de LLM | Chat, juegos, colaboración | Pagos, CI/CD, integraciones |

**Regla práctica:** ¿solo el servidor empuja datos al navegador? → **SSE**. ¿Mucha interacción bidireccional y baja latencia? → **WebSocket**. ¿Notificar a otro backend? → **Webhook**. ¿Simple y poco frecuente? → **polling**.

---

## 1.8 API Gateway, BFF

### API Gateway

Un **punto de entrada único** para todos los clientes hacia un conjunto de servicios backend. Es un reverse proxy con **funciones de gestión de APIs** (L7).

```
Web / Mobile / Terceros
          │
   ┌──────▼───────────────┐
   │     API Gateway      │  auth · rate limit · routing · caché · logging
   └──┬──────┬──────┬─────┘
      ▼      ▼      ▼
  Usuarios Pedidos Pagos   (microservicios)
```

**Responsabilidades (cross-cutting concerns):**
- **Routing / enrutamiento** a cada servicio según path, host, método o headers.
- **Autenticación y autorización** centralizada (validación de JWT, OAuth, API keys, integración con IdP).
- **Rate limiting, throttling y cuotas** por cliente/plan.
- **Terminación TLS**, y a veces mTLS hacia adentro.
- **Transformación**: traducción de protocolos (REST ↔ gRPC), reescritura de headers/paths, agregación de respuestas.
- **Caché** de respuestas.
- **Observabilidad:** logging, métricas, *tracing* (inyecta `traceparent` / correlation ID).
- **Resiliencia:** timeouts, reintentos, **circuit breaker**, balanceo.
- **Versionado y gestión del ciclo de vida** de APIs, portal para developers, monetización.
- **Seguridad:** WAF, validación de schema, bloqueo de IPs.

**Productos:** Kong, AWS API Gateway, Azure API Management, Apigee, NGINX/Envoy-based (Ambassador, Emissary), Traefik, KrakenD, Spring Cloud Gateway, Tyk.

**Ventajas:**
- Los clientes conocen **un solo endpoint** y los servicios internos pueden cambiar sin impacto.
- Las preocupaciones transversales **no se repiten** en cada microservicio.
- Mejor seguridad perimetral y control de tráfico.

**Desventajas / riesgos:**
- **Punto único de falla** y cuello de botella → desplegar redundante y con autoscaling.
- **Latencia extra** (un salto más).
- Riesgo de convertirse en un **"monolito de lógica"**: no pongas lógica de negocio en el gateway.
- Un componente más que operar y versionar.

### API Gateway vs. conceptos parecidos

| | Reverse proxy / LB | API Gateway | Service Mesh |
|---|---|---|---|
| Tráfico | Norte-sur | Norte-sur | **Este-oeste** (servicio a servicio) |
| Foco | Distribución de carga, TLS, caché | Gestión de APIs: auth, cuotas, transformación | mTLS, reintentos, observabilidad entre servicios |
| Nivel | L4/L7 | L7 | L4/L7 (sidecars) |
| Ejemplos | Nginx, HAProxy, ALB | Kong, Apigee, AWS API GW | Istio, Linkerd |

En la práctica las fronteras se difuminan: Nginx/Envoy pueden actuar como gateway con plugins. Un **gateway** maneja el tráfico que **entra**; un **mesh** el tráfico **entre** servicios.

**Patrón de *Gateway Aggregation*:** el gateway recibe un request del cliente, llama en paralelo a varios servicios y devuelve **una sola respuesta combinada**, reduciendo round trips (útil en mobile).

### BFF (Backend For Frontend)

Patrón en el que hay **un backend dedicado por tipo de cliente** (web, mobile, TV, terceros), en lugar de un único backend/gateway genérico para todos.

```
 Web app    ──▶  BFF Web     ──┐
 App móvil  ──▶  BFF Mobile  ──┼──▶  Microservicios (Usuarios, Pedidos, Pagos…)
 API pública ─▶  BFF Público ──┘
```

**Qué problema resuelve:** distintos clientes necesitan **datos, formatos y comportamientos distintos**. Mobile quiere payloads chicos, menos requests y menos batería; web quiere datos más ricos; un tercero necesita contratos estables. Un API "one-size-fits-all" termina con over-fetching, under-fetching y lógica condicional por cliente.

**Responsabilidades del BFF:**
- **Agregar y adaptar** datos de varios servicios a las necesidades exactas de la UI (*view model*).
- Reducir round trips y tamaño de respuesta.
- Manejar particularidades del cliente (autenticación por cookies/sesión en web, tokens en mobile; paginación; formatos).
- Ocultar la complejidad de los microservicios internos.

**Reglas clave:**
- **Un BFF por experiencia de cliente**, y lo ideal es que lo mantenga **el mismo equipo del frontend** (autonomía y velocidad de cambio).
- **Sin lógica de negocio central**: esa vive en los servicios de dominio. El BFF solo orquesta y adapta.
- Evitar duplicar demasiado código entre BFFs (extraer librerías compartidas o servicios comunes).

**Gateway vs BFF:**

| | API Gateway | BFF |
|---|---|---|
| Alcance | Transversal a todos los clientes | Específico de un cliente/experiencia |
| Foco | Infraestructura: seguridad, tráfico, routing | Adaptación de datos y UX |
| Quién lo posee | Plataforma/infra | Equipo de frontend/producto |
| Lógica | Genérica | Orientada a la vista |
| Cantidad | Uno (o pocos) | Uno por tipo de cliente |

**Se combinan:** lo habitual es `Cliente → API Gateway (auth, rate limit, WAF) → BFF → Microservicios`.

**Alternativas al BFF:** **GraphQL** como capa de agregación flexible (el cliente elige sus campos) o *federation* (Apollo Federation, que unifica varios servicios bajo un schema).

**Contras del BFF:** más servicios para desplegar y mantener, posible duplicación entre BFFs, un salto de red adicional. No tiene sentido si solo tenés **un** tipo de cliente simple.

---

## Cierre: qué pasa cuando escribís una URL en el navegador

Integra todo el bloque en un solo flujo (la clásica pregunta de entrevista):

1. **Parseo de la URL** (`https://api.ejemplo.com/usuarios`) y chequeo de HSTS/caché.
2. **DNS** (1.2): caché del navegador → SO → resolver recursivo → root → TLD → autoritativo. Devuelve una IP.
3. **TCP handshake** (1.1) hacia la IP:443 (o **QUIC** si hay HTTP/3 por `Alt-Svc`). Pasa por routers (IP, NAT, ARP en la red local).
4. **TLS handshake** (1.5): SNI, ALPN (`h2`/`h3`), validación del certificado, claves de sesión.
5. **Request HTTP** (1.3), reutilizando la conexión (keep-alive/multiplexación).
6. El request llega a un **CDN / reverse proxy / balanceador** (1.4) que termina TLS.
7. Pasa por el **API Gateway** (1.8): autenticación, rate limiting, routing → **BFF** → **microservicios** (REST/gRPC, 1.6).
8. El servicio consulta caché/base de datos y responde; la respuesta vuelve por el mismo camino, con headers de caché.
9. El navegador renderiza y, si hace falta tiempo real, abre un **WebSocket/SSE** (1.7); los sistemas externos se enteran vía **webhooks**.

---

## Resumen rápido (cheat sheet)

| Tema | Una línea para recordar |
|---|---|
| IP | Direcciona y rutea paquetes, *best effort*; CIDR, NAT, MTU, TTL |
| OSI | 7 capas; en la práctica TCP/IP de 4; L4 vs L7 define el tipo de balanceador |
| TCP / UDP | TCP: confiable, ordenado, con handshake. UDP: rápido, sin garantías |
| DNS | Jerarquía + cachés en cada capa; el TTL define cuánto tardan en verse los cambios |
| HTTP/1.1 → 2 → 3 | Texto + 6 conexiones → binario multiplexado sobre TCP → QUIC/UDP sin HOL |
| Keep-alive | Reutilizar la conexión; el timeout del backend > el del proxy |
| Proxy | Forward: protege al cliente. Reverse: protege/escala al servidor |
| TLS | Asimétrica para acordar clave, simétrica para los datos; 1.3 = 1 RTT y PFS |
| mTLS | Ambos lados con certificado; base de zero trust y service mesh |
| REST / GraphQL / gRPC / SOAP | Recursos / consultas flexibles / RPC binario interno / XML legacy |
| Versionado | `/v1/` en URI es lo más común; priorizar compatibilidad |
| Paginación | Cursor/keyset > offset a escala |
| Idempotencia | `Idempotency-Key` para que un reintento de `POST` no duplique |
| Polling / SSE / WS / Webhook | Pregunto / el servidor empuja / bidireccional / server-to-server |
| API Gateway | Entrada única: auth, rate limit, routing, observabilidad |
| BFF | Un backend por tipo de cliente, que adapta datos sin lógica de negocio |
