# ThreatHunting-Events

Bienvenido a `#ThreatHunting-Events`, un repositorio con técnicas y comandos esenciales para cazar amenazas en Windows y Linux. Este README recopila herramientas y comandos de labs prácticos, explicando su uso y propósito en threat hunting.

## Técnicas y Comandos de Threat Hunting

A continuación, se listan las técnicas y comandos extraídos de labs, con su momento de uso y utilidad.

### Volatility (Análisis de Memoria)

| Comando | Momento de Uso | Para Qué Sirve |
|---------|----------------|----------------|
| `vol.py -f <archivo>.vmem imageinfo` | Inicio de análisis de memoria | Identifica el perfil del sistema (ej. Win10x64_10586, WinXPSP2x86) para usar plugins correctamente |
| `vol.py -f <archivo>.vmem --profile=<perfil> pslist` | Revisar procesos activos | Lista procesos en ejecución; útil para encontrar procesos legítimos o sospechosos |
| `vol.py -f <archivo>.vmem --profile=<perfil> psscan` | Buscar procesos ocultos | Detecta procesos terminados u ocultos que `pslist` no muestra (ej. rootkits) |
| `vol.py -f <archivo>.vmem --profile=<perfil> psxview` | Confirmar procesos ocultos | Compara métodos de detección para identificar procesos ocultos por malware |
| `vol.py -f <archivo>.vmem --profile=<perfil> pstree` | Analizar jerarquía de procesos | Muestra relaciones padre-hijo para detectar anomalías (ej. cmd.exe como padre inusual) |
| `vol.py -f <archivo>.vmem --profile=<perfil> netscan` | Investigar conexiones de red | Lista conexiones TCP/UDP activas o cerradas; filtra con `grep` para PIDs específicos |
| `vol.py -f <archivo>.vmem --profile=<perfil> malfind -p <PID>` | Detectar inyecciones | Busca regiones de memoria sospechosas (ej. RWX, "MZ") en un proceso específico |
| `vol.py -f <archivo>.vmem --profile=<perfil> apihooks -p <PID>` | Buscar hooks de API | Detecta APIs modificadas (ej. NtCreateThread) por malware en un proceso |
| `vol.py --info` | Configuración inicial en Linux | Lista perfiles disponibles para imágenes Linux |
| `vol.py --plugins=plugins --profile=<perfil> linux_check_modules -f <archivo>.memory` | Buscar módulos ocultos (Linux) | Detecta Loadable Kernel Modules ocultos (ej. Diamorphine) |
| `vol.py --plugins=plugins --profile=<perfil> linux_volshell -f <archivo>.memory` | Inspección manual (Linux) | Permite comandos como `db` (bytes) o `dis` (ensamblador) para analizar memoria |
| `vol.py --plugins=plugins --profile=<perfil> linux_check_syscall -f <archivo>.memory` | Detectar hooks syscall (Linux) | Verifica modificaciones en `sys_call_table` (ej. sys_kill hookeado) |
| `vol.py --plugins=plugins --profile=<perfil> linux_hidden_modules -f <archivo>.memory` | Módulos ocultos avanzados (Linux) | Detecta módulos no listados (ej. Reptile) |
| `vol.py --plugins=plugins --profile=<perfil> linux_check_inline_kernel -f <archivo>.memory` | Hooks inline (Linux) | Busca instrucciones como `JMP` en funciones del kernel (ej. tcp4_seq_show) |
| `vol.py -f <archivo>.vmem --profile=<perfil> ssdt` | Detectar rootkits (Windows) | Lista hooks en la SSDT (ej. 00004A2A.sys) |
| `vol.py -f <archivo>.vmem --profile=<perfil> threads -L` | Analizar hilos (Windows/Linux) | Busca hilos asociados a drivers maliciosos |
| `vol.py -f <archivo>.vmem --profile=<perfil> modules` | Listar módulos cargados | Identifica drivers y sus direcciones base (ej. 0xff0d1000) |
| `vol.py -f <archivo>.vmem --profile=<perfil> moddump -b <base> --dump-dir <dir>` | Extraer drivers | Extrae un driver malicioso (ej. 00004A2A.sys) para análisis |

### Comandos del Sistema (Linux/Windows)

| Comando | Momento de Uso | Para Qué Sirve |
|---------|----------------|----------------|
| `strings <archivo>.vmem \| grep "patron"` | Análisis post-memoria | Extrae strings (ej. "Invoke-") para buscar comandos maliciosos |
| `cat /proc/kallsyms \| grep 'sys_getdents\|sys_kill'` | Verificación en Linux limpio | Compara direcciones syscall legítimas |
| `cat linux_check_syscall.txt \| grep -i hooked` | Filtrar salida de Volatility | Identifica syscalls hookeados en Linux |
| `mkdir <directorio>` | Preparar extracción | Crea directorio para guardar dumps (ej. Moddump) |

### Minjector (Inyección de Procesos)

| Comando | Momento de Uso | Para Qué Sirve |
|---------|----------------|----------------|
| `minjector.exe -m 1 -s <dll> -t <PID>` | Emular inyección estándar | Inyecta una DLL (ej. msimplepayload.dll) en un proceso (ej. notepad) |
| `minjector.exe -m 5 -s <dll> -t <PID>` | Emular Reflective DLL | Inyecta una DLL reflectiva (ej. reflective_dll.x64.dll) para pruebas avanzadas |

### Memhunter

| Comando | Momento de Uso | Para Qué Sirve |
|---------|----------------|----------------|
| `memhunter.exe -r` | Monitoreo en vivo | Detecta inyecciones en tiempo real usando ETW y heurísticas |

### PowerShell (Ejecución y Monitoreo)

| Comando | Momento de Uso | Para Qué Sirve |
|---------|----------------|----------------|
| `powershell -ep bypass` | Ejecutar scripts sin restricciones | Evita políticas de ejecución para emular ataques |
| `cd <ruta>; import-module <script>.ps1` | Cargar scripts maliciosos | Importa scripts (ej. ASBBypass.ps1, PPID-Spoof.ps1) |
| `.\Monitor.ps1` | Iniciar monitoreo con Captain | Hookea APIs para detectar inyecciones en tiempo real |
| `PPID-Spoof -ppid <PID> -spawnTo <exe> -dllpath <dll>` | Emular PPID spoofing | Crea proceso con padre falso (ej. notepad como hijo de explorer) |
| `Start-Eidolon -Target <file> -Mimikatz -Verbose` | Emular Process Doppelganging | Ejecuta Mimikatz disfrazado (ej. test.txt) |

### Herramientas de Detección (Windows)

| Comando | Momento de Uso | Para Qué Sirve |
|---------|----------------|----------------|
| `C:\...\AmsiPatchDetection.exe` | Detectar bypasses de AMSI | Verifica si `amsi.dll` está parcheado en memoria |
| `C:\...\detect-ppid-spoof.py` | Detectar PPID spoofing | Usa ETW para identificar procesos con padres falsos |
| `.\pe-sieve64.exe /pid <PID>` | Detectar Doppelganging | Escanea procesos y extrae código malicioso disfrazado |

---

## Cuándo y Por Qué Usar Cada Técnica

### Volatility
- **Inicio de Análisis**: `imageinfo` para establecer el perfil antes de cualquier plugin.
- **Procesos Ocultos**: `psscan`, `psxview` cuando sospechas de rootkits o malware que oculta procesos.
- **Red**: `netscan` para investigar tráfico C2 o exfiltración.
- **Inyecciones**: `malfind` para buscar código inyectado en procesos específicos.
- **Hooks**: `apihooks`, `ssdt` para detectar modificaciones maliciosas en APIs o tablas del sistema.
- **Linux Rootkits**: `linux_check_modules`, `linux_hidden_modules` para módulos ocultos; `linux_check_syscall`, `linux_check_inline_kernel` para hooks.
- **Extracción**: `moddump` para analizar drivers maliciosos fuera de memoria.

### Comandos del Sistema
- **Strings**: Post-análisis para buscar IOCs (ej. comandos PowerShell).
- **kallsyms**: Comparar sistemas limpios vs infectados en Linux.

### Minjector y Memhunter
- **Minjector**: Emular ataques de inyección para pruebas (modo 1: estándar, modo 5: reflectivo).
- **Memhunter**: Monitoreo en vivo cuando necesitas detección sin volcados de memoria.

### PowerShell
- **-ep bypass**: Siempre que emules ataques o ejecutes scripts en entornos controlados.
- **Captain**: Monitoreo proactivo para capturar inyecciones en tiempo real.
- **PPID Spoofing**: Probar detección de procesos falsificados.
- **Doppelganging**: Emular técnicas avanzadas de evasión.

### Herramientas de Detección
- **AmsiPatchDetection**: Verificar integridad de AMSI tras sospecha de bypass.
- **detect-ppid-spoof.py**: Buscar PPID spoofing en entornos con ETW habilitado.
- **PE Sieve**: Detectar Doppelganging cuando sospechas de procesos disfrazados.

---

## Notas Finales

- **Flexibilidad**: Ajusta PIDs y rutas según tu entorno.
