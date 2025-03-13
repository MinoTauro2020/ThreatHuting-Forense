# ThreatHuting-Forense

## Labs Disponibles

### Hunting in Memory Lab 1

**Objetivo**: Detectar procesos ocultos, conexiones sospechosas e inyecciones en memoria con Volatility.

#### Tareas
- **Task 1**: Buscar procesos ocultos en `Memory.vmem`.
- **Task 2**: Identificar conexiones de red sospechosas.
- **Task 3**: Detectar inyecciones en procesos.
- **Task 4**: Concluir el análisis y confirmar compromiso.

#### Pasos Clave
- Perfil: `Win10x64_10586`.
- Resultados: 
  - No procesos ocultos (falsos positivos por EPROCESS persistentes).
  - Conexiones de `powershell.exe` a puerto 80.
  - Inyecciones en `Powershell.exe` sin "MZ".
  - Compromiso con `Invoke-Mimikatz` y PowerShell Empire.

#### Comandos
| Comando | Descripción |
|---------|-------------|
| `vol.py -f /root/Memory.vmem imageinfo` | Identificar perfil de la imagen |
| `vol.py -f /root/Memory.vmem --profile=Win10x64_10586 psxview` | Buscar procesos ocultos |
| `vol.py -f /root/Memory.vmem --profile=Win10x64_10586 netscan \| grep -E 'Pid\|powershell.exe'` | Filtrar conexiones de PowerShell |
| `vol.py -f /root/Memory.vmem --profile=Win10x64_10586 malfind` | Detectar inyecciones |
| `strings /root/Memory.vmem \| grep "Invoke-"` | Buscar patrones maliciosos |
| `strings /root/Memory.vmem \| grep "powershell" > output` | Extraer comandos PowerShell |
| `vim output` | Revisar salida |

---

### Hunting in Memory Lab 2

**Objetivo**: Identificar rootkits Diamorphine y Reptile en imágenes Linux.

#### Tareas
- **Task 1**: Detectar Diamorphine en `infection1.memory`.
- **Task 2**: Detectar Reptile en `infection2.memory`.

#### Pasos Clave
- Perfil: `Linuxprofile-2_6_32-754_el6_x86_64x64`.
- Resultados:
  - Diamorphine: Módulo oculto y hooks en `sys_kill`, `sys_getdents`, `sys_getdents64`.
  - Reptile: Módulo oculto y hooks `JMP` en `tcp4_seq_show`, `fillonedir`.

#### Comandos
| Comando | Descripción |
|---------|-------------|
| `vol.py --info` | Listar perfiles disponibles |
| `vol.py --plugins=plugins --profile=Linuxprofile-2_6_32-754_el6_x86_64x64 linux_check_modules -f /root/memory_dump/infection1.memory` | Buscar módulos ocultos (Diamorphine) |
| `vol.py --plugins=plugins --profile=... linux_volshell -f /root/memory_dump/infection1.memory` | Inspeccionar módulo (`db(0xffffffffa0523740, 128)`) |
| `vol.py --plugins=plugins --profile=... linux_check_syscall -f /root/memory_dump/infection1.memory --output-file=linux_check_syscall.txt` | Verificar hooks syscall |
| `cat linux_check_syscall.txt \| grep -i hooked` | Filtrar hooks |
| `vol.py --plugins=plugins --profile=... linux_hidden_modules -f /root/memory_dump/infection2.memory` | Buscar módulos ocultos (Reptile) |
| `vol.py --plugins=plugins --profile=... linux_check_inline_kernel -f /root/memory_dump/infection2.memory` | Detectar hooks inline |
| `vol.py --plugins=plugins --profile=... linux_volshell -f /root/memory_dump/infection2.memory` | Comparar funciones (`dis(addrspace().profile.get_symbol("tcp4_seq_show"), length=11)`) |

---

### Hunting for Process Injection & Proactive API Monitoring

**Objetivo**: Detectar inyecciones con Memhunter, Minjector y Captain.

#### Tareas
- **Task 1**: Detectar inyección con Memhunter y Process Hacker 2.
- **Task 2**: Monitoreo proactivo con Captain.

#### Pasos Clave
- Resultados:
  - Inyección en `notepad.exe` con `msimplepayload.dll`.
  - Reflective DLL detectada en `events.json` con Captain.

#### Comandos
- **Task 1**:
  ```bash
  cd C:\Users\Administrator\Desktop\Tools\memhunter
  minjector.exe -m 1 -s C:\Users\Administrator\Desktop\Tools\memhunter\msimplepayload.dll -t PID_of_notepad_exe
  memhunter.exe -r

