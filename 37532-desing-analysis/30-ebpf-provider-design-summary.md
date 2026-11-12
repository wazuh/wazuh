# 30 — Resumen de diseño: el módulo `ebpf_provider`

Documento de contexto para una reunión de diseño. Responde a cuatro preguntas:

1. qué es `src/shared_modules/ebpf_provider` y cómo está estructurado;
2. en qué se diferencia del enfoque anterior (`modern.bpf.c` + el loader dentro de `ebpf_whodata.cpp`), ya retirado en esta rama;
3. qué hace falta para agregar un consumidor nuevo de los programas BPF;
4. qué configuraciones ofrece y cuáles son los puntos abiertos.

Todo lo afirmado aquí está respaldado por el árbol de la rama `37532-ebpf-engine`. El contenido se contrastó con una lectura independiente del módulo hecha con Codex; las discrepancias que esa lectura encontró entre el código y su propia documentación están recogidas en §30.10. La historia detallada de cómo se llegó a este estado está en [`27-modern-bpf-retirement-plan.md`](27-modern-bpf-retirement-plan.md) (fases P0–P6) y en [`11-ebpf-provider-import-plan.md`](11-ebpf-provider-import-plan.md).

---

## 30.1 Resumen ejecutivo

- El agente tiene **un solo programa BPF** (`bpf/rt_file.bpf.c` → `rt_file.bpf.o`) y **un solo loader** (`librt_engine`, estático) para toda la telemetría de archivos en tiempo real.
- La API pública para un consumidor son **tres funciones**: `rt_open()`, `rt_poll()`, `rt_close()`, más un puñado de llamadas opcionales de configuración. El motor **no sabe qué es FIM ni qué es un contenedor**: solo entrega registros `struct rt_file_event`.
- Hoy hay **dos consumidores** en el árbol, cada uno con su propio handle, su propia carga del objeto y su propio ring buffer:
  - **host FIM whodata** — `src/syscheckd/src/ebpf/src/ebpf_whodata.cpp`
  - **drain de eventos de contenedor** — `src/syscheckd/src/ebpf/src/container_event_drain.cpp`
- `modern.bpf.c` y su loader **ya no existen**: fueron eliminados en `620ce34c1a` ("refactor(fim): run whodata on the eBPF provider engine"), junto con `bpf_helpers.h`, `wrapper_bpf.h`, `dynamic_library_wrapper.h` y cuatro suites de tests que cubrían el loader eliminado (−2730 líneas, +472).
- El filtrado que antes se hacía íntegramente en el agente ahora puede hacerse **en el kernel**: allowlist de cgroups, máscara de campos a no calcular, y contabilidad de drops por cgroup.

**Dónde está el límite del módulo.** El motor es agnóstico del consumidor por diseño (ADR-001 del spike #37396). No resuelve rutas de instalación de Wazuh, no mapea niveles de log de Wazuh, no sabe qué es un contenedor. Todo eso lo inyecta el consumidor a través de `struct rt_filter`.

---

## 30.2 Arquitectura: tres capas

```
   consumidor (FIM whodata, container drain, …)
        |  rt_open / rt_poll / rt_close + struct rt_file_event
        v
   librt_engine   src/rt_engine.c            userspace, C puro
        |  dlopen("libbpf.so") en rt_open(), nunca -lbpf
        v
   libbpf  ->  rt_file.bpf.o                 kernel
```

| Capa | Archivo | Responsabilidad |
| --- | --- | --- |
| Contrato | `include/rt_event_contract.h` | **Una sola** definición de `struct rt_file_event`, incluida por el programa BPF *y* por userspace. Versionado `RT_ABI_MAJOR` / `RT_ABI_MINOR`. |
| API pública | `include/rt_engine.h` | `rt_filter`, las tres funciones de ciclo de vida, y las llamadas opcionales de cgroups/drops/ABI. |
| Loader | `src/rt_engine.c` (1268 líneas) | Selección de programas, escalera LSM→kprobe, configuración de mapas, ring buffer, guardia de ABI por evento, teardown. |
| Shim de tipos | `include/rt_libbpf_shim.h` | Sombras de los tipos opacos de libbpf, para no depender de los headers de desarrollo de libbpf en el build de userspace. |
| Programa BPF | `bpf/rt_file.bpf.c` (1176 líneas, 14 programas) | Hooks kprobe y LSM, resolución de rutas, filtrado en kernel, emisión al ring. |

### Decisiones estructurales que conviene conocer

**libbpf se resuelve por `dlopen()` en `rt_open()`, no se enlaza.** `fimebpf.so` está enlazado duro dentro de `wazuh-syscheckd`; una dependencia de link contra libbpf haría que el binario del agente se negara a arrancar en cualquier host sin libbpf instalado (`src/rt_engine.c:14-24`). Por eso el target CMake enlaza solo `dl` y `pthread`.

**`libbpf_path` debe pasarse explícitamente.** Ningún binario de Wazuh lleva RPATH, así que un `dlopen()` del soname pelado enlaza la libbpf **del host** — y en un host RHEL legacy esa es la 0.5.0, anterior a `bpf_program__set_autoload()`, con lo que falla la resolución obligatoria de símbolos. El agente empaqueta su propia libbpf precisamente para no depender de la del host; solo hay que pedírsela (`include/rt_engine.h`, campo `libbpf_path`).

**El binding de libbpf es a nivel de proceso y gana el primero.** Está serializado con un mutex desde P1, y un segundo `rt_open()` con un `libbpf_path` distinto loguea un WARN nombrando ambas rutas. `rt_engine` enlaza `pthread` explícitamente: en las imágenes de empaquetado (`centos:6`, `debian:7`, glibc < 2.34) `libc.so.6` exporta `pthread_mutex_lock/unlock` como stubs no thread-safe.

**Un consumidor = una carga del objeto = un ring buffer.** No hay provider compartido ni multiplexado (ADR-001). Dos consumidores pagan dos veces el coste de kernel, a cambio de que ninguno pueda frenar al otro ni imponerle su filtro. Hoy el agente carga **el mismo objeto dos veces**.

---

## 30.3 El contrato de evento y su versionado

`struct rt_file_event` es un registro de tamaño fijo, **12.424 bytes** en ABI 1.2, intercambiado por reinterpretación cruda de memoria. Campos: identidad del evento (`abi_major`, `event_type`, `flags`, `timestamp_ns`), proceso (`pid`, `ppid`, `uid`, `gid`, `euid`, `login_uid`, `comm`, `parent_comm`), objeto (`inode`, `dev`, `filename`), contexto (`cwd`, `parent_cwd`), y claves de correlación (`cgroup_id`, `mnt_ns`), más `dropped`.

**`dropped` no es un contador acumulado**, pese a lo que dice el comentario del campo en `rt_event_contract.h`. `take_drop_counter()` hace una lectura-y-resta atómica, así que el valor que lleva un evento es el **delta consumido** desde el evento anterior que lo leyó, y se acompaña de `RT_F_DROPS_BEFORE`. El comentario del contrato debería corregirse.

**Cobertura acotada, y conviene tenerlo presente.** Los hooks filtran por `is_regular_file()`: directorios, symlinks, sockets y dispositivos no generan evento. El walker de dentries tiene un tope de `MAX_PATH_COMPONENTS` = 320 y las cadenas del contrato son de 4096 bytes, y **no hay flag de truncamiento** en `rt_flags`. Un fallo de resolución de ruta sale sin evento y **sin** incrementar los contadores de drops, que solo cuentan ring lleno.

Clases de evento actuales: `RT_EV_FILE_OPEN` (creación o apertura con intención de escritura), `RT_EV_FILE_ATTR`, `RT_EV_FILE_UNLINK`, `RT_EV_FILE_RENAME`. Una clase futura (process-exec, red) tendría **su propia struct y su propio valor de tipo**, no un cambio a esta.

**Regla de versionado (ADR-003):**

| Cambio | Efecto |
| --- | --- |
| Agregar un campo al final | sube `RT_ABI_MINOR`. Consumidores viejos ignoran la cola. |
| Reordenar, cambiar tamaño o quitar un campo | sube `RT_ABI_MAJOR`. Un consumidor **debe negarse** a usar un motor con major distinto. |

La compatibilidad es **direccional**. Un consumidor viejo con motor nuevo funciona; un **motor nuevo con un `.bpf.o` viejo no**: el callback del ring rechaza todo registro cuyo `abi_major` no coincida o que sea más corto que el `sizeof` de este build, y lo reporta una vez por handle (`src/rt_engine.c:483-530`). Por eso **todo cambio al contrato obliga a regenerar los objetos prebuilt en el mismo commit**.

Un ejemplo concreto: al agregar `euid`/`login_uid` (ABI 1.1 → 1.2) el registro pasó de 12.416 a 12.424 bytes; un objeto sin regenerar emite registros cortos y el motor descarta **todos** los eventos.

---

## 30.4 Ciclo de vida de un handle

### `rt_open(const struct rt_filter*)`

1. **Valida el filtro**; `type_mask` vacío es error.
2. **Resuelve libbpf** por `dlopen()` (una vez por proceso, bajo mutex). Fallo pegajoso: si el primer bind falla no se reintenta.
3. **Detecta la jerarquía de cgroups del host** (`wz_cgroup_mode()`), y loguea el resultado tanto en el caso sano como en el malo — "¿en qué jerarquía creía estar el agente?" es la primera pregunta de cualquier bug de atribución.
4. **Abre el objeto** `bpf_object__open_file(bpf_obj_path)`. No hay skeleton generado.
5. **Selecciona programas** (`select_programs()`): recorre los 14 programas del objeto, mapea sección → bit de tipo de evento, y pone `bpf_program__set_autoload(false)` a todo lo que `type_mask` no pida o que no corresponda a la variante elegida. Segunda pasada para `kprobe/mnt_want_write`, que no emite eventos pero es **dependencia** de los kprobes de setattr/unlink/rename.
6. **Carga** (`bpf_object__load`). Esta carga **es** la prueba de capacidad: si falta `BPF_MAP_TYPE_RINGBUF`, BTF o CO-RE, falla aquí.
7. **Configura los mapas ANTES de attachear.** Crítico: en cuanto un programa se attachea empieza a escribir en el ring, y `event_is_wanted()` trata un modo no escrito como SUBMIT a propósito. Configurar después dejaría una ventana en la que entra todo el tráfico del host — exactamente lo que el consumidor que pidió ALLOWLIST quería evitar.
8. **Attachea** cada programa con autoload, guardando cada `bpf_link` (máximo `RT_MAX_LINKS` = 16; se niega a attachear lo que no podría desattachear).
9. **Crea el ring buffer** sobre el mapa `rb` (8 MiB, `1 << 23`).
10. Localiza `cgroup_drops_map` (opcional; su ausencia es WARN, no error).

**La escalera de tres peldaños** (`rt_open`, `src/rt_engine.c:764-791`):

```
LSM _dpath  --(falla bpf_object__load, o sea el verificador)-->  LSM _walk
            --(falla load O attach)----------------------------->  kprobes
```

No es cosmética. En Amazon Linux 2/2023 el `btf_allowlist_d_path` del kernel no permite `bpf_d_path()` desde `bpf_lsm_path_rename`, así que el build dpath falla **verificación**; y un kernel con `bpf` en la lista LSM activa pero sin `CONFIG_SECURITY_PATH` no tiene hooks `path_*` que attachear. Cada peldaño fallido se desarma completo (`rt_close()`) antes del siguiente.

Se rechazó enviar solo las variantes `_walk`: `bpf_d_path()` es la única resolución correcta respecto del mount namespace; el walker reconstruye desde la cadena de dentries y se equivoca con bind mounts y chroots.

**En fallo, `rt_open()` devuelve NULL y nunca aborta el proceso.** El consumidor debe degradar (FIM host cae al proveedor audit; el drain de contenedores cae a modo solo-admisión).

### `rt_poll(handle, sink, user, timeout_ms)`

Envoltorio fino sobre `ring_buffer__poll()`. Invoca `sink(ev, user)` una vez por evento. Devuelve el código de libbpf: negativo = error real, 0 o positivo = eventos procesados. **No es thread-safe** para dos hilos sobre el mismo handle.

El puntero `ev` es válido **solo durante la llamada**: libbpf lo invalida al retornar. Un consumidor que encola debe **copiar**.

### `rt_close(handle)`

Orden obligatorio, y el comentario lo dice: desattachear primero, luego liberar el ring, luego cerrar el objeto. Invertir los dos primeros deja programas attacheados escribiendo en un ring cuyo consumidor ya no existe. Seguro con `NULL`. Reporta en WARN el total de eventos rechazados por ABI durante la vida del handle.

---

## 30.5 Configuraciones disponibles

### `struct rt_filter` — lo que se fija al abrir

| Campo | Efecto | Quién lo usa hoy |
| --- | --- | --- |
| `type_mask` | Bitmask de `(1u << rt_event_type)`. **Solo se cargan y attachean los programas necesarios.** `RT_FILE_ALL_BITS` para todo. | Ambos consumidores usan `RT_FILE_ALL_BITS`. |
| `bpf_obj_path` | Ruta al `.bpf.o`. NULL cae a `"rt_file.bpf.o"` en el CWD — válido para el harness, **incorrecto para un servicio** (el CWD de un daemon de systemd no es su directorio de instalación). | whodata: `abspath("lib/rt_file.bpf.o")`. |
| `libbpf_path` | Ruta a la libbpf **preferida** para el primer binding. NULL = soname pelado = la del host. **Obligatorio en producción.** Matiz: si el `dlopen()` de esa ruta falla, el motor **cae igualmente a `libbpf.so.1` / `libbpf.so` del sistema** con un WARN; la ruta explícita no garantiza exclusividad. | whodata: `abspath("lib/libbpf.so")`. |
| `log` / `log_user` | Sink de diagnóstico. Sin él, el motor escribe a `stderr` — es decir, a ningún lado para un daemon, y un fallo de carga eBPF nunca llegaría a `ossec.log`. | Ambos lo conectan al logger de FIM. |
| `cgroup_mode` | `RT_CGROUP_MODE_ALL` (default) o `RT_CGROUP_MODE_ALLOWLIST`. | whodata: ALL. Drain: ALLOWLIST si está configurado. |
| `skip_mask` | Bitmask de trabajo por evento que el consumidor **no** quiere. Hoy solo `RT_SKIP_PROC_CONTEXT`. | whodata: 0. Drain: `RT_SKIP_PROC_CONTEXT`. |

**`RT_SKIP_PROC_CONTEXT`** omite `cwd`, `parent_cwd` y `parent_comm`: cuestan dos recorridos completos de dentries por evento, que en la ruta kprobe — la configuración mayoritaria — es el coste dominante. Los campos siguen presentes y terminados en NUL, simplemente llegan vacíos. `ppid`, `euid` y `login_uid` **no** se ven afectados: son lecturas de un campo, no recorridos.

Este mecanismo existe porque el registro lo comparten consumidores que leen partes muy distintas de él. El contexto de proceso se agregó para la atribución "quién" de whodata; un consumidor de contenedores que enruta por `cgroup_id` y `filename` lo pagaría en cada evento sin leer nada. El skip es por handle, así que un motor puede servir a ambos sin que el barato subsidie al caro.

### Filtrado de cgroups en kernel

| Llamada | Qué hace |
| --- | --- |
| `rt_allow_cgroup(h, id)` | Agrega un cgroup a la allowlist en kernel. Idempotente, se puede llamar en cualquier momento sobre un handle abierto — los contenedores nacen después del `rt_open()`. Mapa de 4096 entradas; lleno = error (los cgroups que no entraron quedan silenciosamente sin monitorear). |
| `rt_deny_cgroup(h, id)` | Lo quita, para que el mapa no crezca sin límite. Ignora el resultado de la syscall de borrado y devuelve 0 si el handle y el mapa existen: no distingue "no estaba" de otros errores de borrado (deliberado — ausente es el estado final deseado). |
| `rt_set_cgroup_mode(h, mode)` | Cambia el modo en caliente. |

En modo ALLOWLIST, un evento de un cgroup no listado es **invisible, no solo no atribuido**: se descarta en el kernel antes de intentar la reserva de 12.424 bytes en el ring. Eso **elimina** "llegó un evento de un cgroup que no conozco" como vía de descubrimiento — la que cubriría un contenedor creado después del arranque. Por eso la allowlist convierte un trigger de creación desde `container_instances` en prerequisito duro, no en optimización.

La secuencia recomendada es: abrir en ALL, sembrar, cambiar a ALLOWLIST. El drain de contenedores hace lo **contrario** a propósito (`container_event_drain.cpp:1533-1543`): abre ya filtrando, porque entre `rt_open()` y el cambio nadie está haciendo poll y todo el tráfico del host caería en el ring, haciendo que los primeros eventos que el drain ve lleguen con `RT_F_DROPS_BEFORE`.

### Hosts sin jerarquía unificada (cgroup v1)

`bpf_get_current_cgroup_id()` reporta el cgroup de la tarea en la jerarquía **unificada**; en un host que no la tiene, devuelve 1 para todas las tareas. Eso es un límite del *helper*, no del kernel.

- `rt_set_cgroup_v1_subsys(h, "memory", fallback_index)` apunta el programa a los cgroups de un controlador v1. El motor busca el enumerador en el BTF del kernel (autoritativo) y usa el `fallback_index` del llamador solo si el BTF no responde. Desde 6.12, `proc_cgroupstats_show()` omite controladores construidos sin archivos v1, así que la lectura de `/proc/cgroups` se desalinea; cuando ambas lecturas discrepan, el motor usa BTF y lo dice en WARN.
- **Se niega en hosts unificados o híbridos**: allí un controlador solo está habilitado donde un ancestro lo habilitó, así que la lectura podría atribuir los eventos de un contenedor a su slice padre con un número plausible.
- `rt_cgroup_id_is_usable(h)` es lo que un consumidor debe consultar para decidir si puede atribuir. `rt_host_cgroup_v1(h)` informa la jerarquía del host, que es otra pregunta.
- **Aviso:** el flag por evento `RT_F_CGROUP_V1` **no lo setea el programa BPF todavía**. `rt_host_cgroup_v1()` es la única fuente confiable.

### Contabilidad de drops

`rt_drain_drops(h, cb, user)` drena la contabilidad **por cgroup**, invocando `cb` una vez por cgroup que perdió eventos desde el drenaje anterior, y limpiando lo que reporta.

Existe porque el contador en banda (`ev->dropped` + `RT_F_DROPS_BEFORE`) hace la pérdida **visible pero no atribuible**. Medido en un nodo real: 203 eventos perdidos aparecieron como tres eventos con el flag. Un consumidor que tratara eso como "re-verificar todo" habría re-baselineado todos los contenedores tres veces por una pérdida del 0,1 % que pertenecía a un solo cgroup.

Es barato: solo toca los cgroups que efectivamente perdieron eventos, porque reportar un cgroup elimina su entrada. Llamarlo una vez por ciclo de poll está bien. Lote máximo por llamada: **512 claves**, sobre un mapa de hasta 4096.

Usa `bpf_map_lookup_and_delete_elem` si la libbpf enlazada lo tiene; en el camino de respaldo (lookup seguido de delete) hay una **carrera reconocida en el código** que pierde atribución — el contador global sigue siendo correcto, solo se pierde a qué cgroup pertenecía.

`rt_drain_drops()` **no dispara rescans ni recupera eventos**; eso es del consumidor. Y las pérdidas de la cola *userspace* del consumidor no entran en estos mapas: whodata detecta su cola llena por separado.

### Guardia de ABI

`rt_abi_major()` / `rt_abi_minor()`. Todo consumidor **debe** comparar `rt_abi_major() != RT_ABI_MAJOR` y negarse si difieren; ambos consumidores actuales lo hacen.

---

## 30.6 Cómo agregar un consumidor nuevo

El header lo dice explícitamente: agregar un consumidor, o que un consumidor quiera un subconjunto distinto de clases de evento, **no requiere cambiar nada en el motor**. Lo gobierna el `rt_filter` que se pasa a `rt_open()`.

### Pasos

1. **Build.** En el `CMakeLists.txt` del consumidor:
   ```cmake
   include_directories(${SRC_FOLDER}/shared_modules/ebpf_provider/include/)
   target_link_libraries(<tu_target> PRIVATE ... rt_engine)
   ```
   `rt_engine` es una librería estática con `POSITION_INDEPENDENT_CODE ON`, así que puede enlazarse dentro de una librería compartida. No agrega dependencias de link más allá de `dl` y `pthread`.

2. **Incluir** `rt_engine.h` (que arrastra `rt_event_contract.h`). Desde C++, el header ya trae `extern "C"`.

3. **Verificar la ABI** antes de abrir:
   ```c
   if (rt_abi_major() != RT_ABI_MAJOR) { /* negarse */ }
   ```

4. **Resolver las rutas de instalación.** El motor no tiene opinión sobre el layout de Wazuh. Hay que pasarle `abspath("lib/rt_file.bpf.o")` y `abspath("lib/libbpf.so")`.

5. **Conectar el sink de log** a `ossec.log`. Sin esto, un fallo de carga es indiagnosticable en campo.

6. **Elegir `type_mask` y `skip_mask`.** Pedir solo las clases que se consumen reduce programas attacheados; pedir `RT_SKIP_PROC_CONTEXT` si no se leen `cwd`/`parent_cwd`/`parent_comm`.

7. **Manejar `rt_open() == NULL`** como "eBPF no disponible aquí" y degradar. Es el caso esperado en cualquier host sin la capacidad, no un error del agente.

8. **Montar el loop de poll en su propio hilo**, copiando cada evento en el callback (el puntero muere al retornar), y **joinear el hilo antes de `rt_close()`**.

### Esqueleto mínimo

```c
#include "rt_engine.h"

static void sink(const struct rt_file_event* ev, void* user)
{
    /* COPIAR lo que haga falta: ev deja de ser válido al retornar. */
    (void)user;
    if (ev->event_type == RT_EV_FILE_UNLINK) { /* ... */ }
}

static void log_sink(int level, const char* msg, void* user)
{
    (void)user;
    wazuh_log(map_level(level), msg);   /* mapear RT_LOG_* al logger propio */
}

int start(void)
{
    if (rt_abi_major() != RT_ABI_MAJOR) return -1;

    struct rt_filter f;
    memset(&f, 0, sizeof(f));            /* zero = ALL + skip nada */
    f.type_mask     = RT_FILE_UNLINK_BIT | RT_FILE_RENAME_BIT;
    f.bpf_obj_path  = object_path;        /* abspath("lib/rt_file.bpf.o") */
    f.libbpf_path   = library_path;       /* abspath("lib/libbpf.so")     */
    f.log           = log_sink;
    f.skip_mask     = RT_SKIP_PROC_CONTEXT;

    rt_handle_t h = rt_open(&f);
    if (!h) return -1;                    /* degradar, no abortar */

    while (!stopping())
    {
        if (rt_poll(h, sink, NULL, 100) < 0) break;
    }
    rt_close(h);
    return 0;
}
```

El harness `test/rt_engine_harness.c` es exactamente esta demostración y existe para probar que un consumidor no necesita nada más.

### El seam de test

`ebpf_whodata.hpp` define una tabla de tres punteros a función inicializada con las reales:

```cpp
struct rt_engine_api_t {
    rt_handle_t (*open)(const struct rt_filter*) = rt_open;
    int        (*poll)(rt_handle_t, rt_sink_fn, void*, int) = rt_poll;
    void       (*close)(rt_handle_t) = rt_close;
};
```

Eso reemplazó 242 líneas de mocks de libbpf. El drain de contenedores usa el otro enfoque, `-Wl,--wrap=rt_open`. Ambos conviven sin colisionar.

---

## 30.7 Build y distribución

### Puerta de tres vías en `CMakeLists.txt`

```
¿hay prebuilt/<arch>/rt_file.bpf.o?       -> copiarlo  (PREFERIDO)
¿clang + headers libbpf + vmlinux.h?      -> compilarlo
en caso contrario                          -> saltarlo con diagnóstico
```

`librt_engine` **siempre** se construye, incluso sin toolchain BPF — los consumidores lo enlazan incondicionalmente. Que falte el objeto degrada a "eBPF no disponible en runtime"; que falle el `configure` rompe el build del agente entero. Por eso no se usa `find_program(... REQUIRED)`.

**Solo x86_64 y aarch64 producen objeto.** Antes, todo lo que no era aarch64 se mapeaba a x86, lo que entregaba a un build i386 de 32 bits un objeto compilado con `-D__TARGET_ARCH_x86` contra un `vmlinux.h` de x86_64: offsets de `pt_regs` incorrectos, instalado y fallando al cargar — indistinguible de "este host no tiene eBPF". Hoy cualquier otra arquitectura no recibe objeto, que es el resultado honesto.

### Por qué hay binarios commiteados

Las imágenes de empaquetado son `centos:6` y `debian:7`: no hay ruta a un clang suficientemente nuevo para CO-RE. Y el `vmlinux.h` vendorizado **no sirve**: es un dump reducido que no define ningún tipo de cgroup, así que `rt_file.bpf.c` nunca compiló contra él en ninguna arquitectura. De ahí `prebuilt/{x86,arm64}/`.

No es donde esto debería terminar. La ruta mejor es la que usaba `modern.bpf.o`: construirlo en la imagen fuera del repo y enviarlo dentro de `libbpf-bootstrap.tar.gz`. Ese tarball sigue existiendo y sigue llevando la `libbpf.so` que el motor hace `dlopen`. Requiere un cambio en el pipeline de deps y un bump de `DEPS_VERSION`, que no se puede hacer desde este repositorio. CMake queda deliberadamente prefiriendo el prebuilt, para que un objeto enviado por deps pueda tomar el relevo sin reordenar la puerta.

### Guardias

| Guardia | Qué protege |
| --- | --- |
| `rt_file.bpf.o.sources.sha256` | Digest de `rt_file.bpf.c` + `rt_event_contract.h`. Con `RT_BPF_STRICT_PREBUILT=ON` (**default**), un digest desactualizado es `FATAL_ERROR` en configure. Sin esto, editar el `.bpf.c` seguiría enviando el binario viejo en silencio, porque el prebuilt se **prefiere** sobre compilar. |
| `rt_file.bpf.o.provenance` | Versión de clang y BTF de kernel usados. **No** entra en el digest (son propiedades de la máquina que lo produjo). Sirve para reproducir. |
| `tools/check_bpf_symbols.sh` | Verifica que clang inlineó todos los helpers y dejó fuera de línea solo `rt_walk_dentry`. Es una decisión del compilador: si sale mal, el objeto carga en todos lados menos en un kernel RHEL legacy, que ningún job de CI prueba cargando. Corre en **ambas** ramas (prebuilt y compilada). |
| Guardia de ABI por evento | En `ringbuf_sample_cb()`, ya descrita. |

**Límite del guardia de digest:** compara las fuentes contra un archivo declarativo; **no demuestra** que el binario se haya compilado con ellas. Y `tools/rebuild_prebuilt.sh` refresca los digests de **ambas** arquitecturas aunque solo reconstruya una — el propio script lo advierte, pero significa que el objeto no reconstruido queda marcado como más fresco de lo que es.

`-DRT_BPF_STRICT_PREBUILT=OFF` es el opt-out, para un desarrollador a mitad de una edición que aún no refrescó el digest. **Ese es el modo de fallo a vigilar**, no la ruta por defecto.

### Lo que se instala

`src/init/inst-functions.sh` instala `build/lib/rt_file.bpf.o` en `/var/ossec/lib/` con modo 0750, root:wazuh, si el build lo produjo. Tamaños registrados en los manifiestos `check_files`: 1.670.456 (amd64), 1.569.208 (arm64).

### Build y tests standalone

El `Makefile` del módulo permite iterar sin el build completo de Wazuh:

```
make                 # objeto BPF + motor + harness
make check           # tests de contrato y loader: sin kernel, sin root
make check-kernel    # leak, drops, filter, creds, skip, paths: necesita root
make run             # harness, necesita root
```

---

## 30.8 Diferencias concretas con `modern.bpf.c`

`modern.bpf.c` (1087 líneas) y el loader embebido en `ebpf_whodata.cpp` (que pasó de 1003 a 575 líneas) fueron eliminados en `620ce34c1a`. La comparación es con el estado **previo** a esa eliminación.

| Aspecto | `modern.bpf.c` + `ebpf_whodata.cpp` | `rt_file.bpf.c` + `rt_engine.c` |
| --- | --- | --- |
| **Acoplamiento** | El loader vivía dentro de FIM, con tipos FIM, un singleton de registro de callbacks y un set de hooks fijo. | Motor sin tipos de dominio. El set de hooks lo elige `type_mask`. |
| **Consumidores** | Uno solo posible (FIM whodata). El drain de contenedores habría necesitado su propio loader. | N consumidores, cada uno con su handle, filtro y ring. |
| **Contrato de evento** | Struct interna de FIM, sin versionado explícito ni verificación en runtime. | `rt_event_contract.h` compartido por kernel y userspace, con `RT_ABI_MAJOR/MINOR` y rechazo por evento de registros incompatibles. |
| **Filtrado** | Ninguno en kernel; todo evento del host sube al agente y se descarta allí. | Allowlist de cgroups en kernel, `skip_mask` por handle, drops contabilizados por cgroup. |
| **Resolución de libbpf** | 13 símbolos por `dlsym` en `bpf_helpers.h`, sin sincronización. | Tabla de despacho única, resuelta una vez bajo mutex, con WARN si dos consumidores piden libbpf distintas. |
| **Escalera de fallback** | LSM-dpath → LSM-walk → kprobe, dentro de FIM. | La misma escalera, ahora en el motor y reusable. |
| **Tipos de libbpf** | `wrapper_bpf.h` sombreaba tipos de skeleton. | `rt_libbpf_shim.h` hace lo mismo, ahora propiedad del motor. |
| **Tests** | 4 suites (`init_libbpf`, `init_bpf_obj`, `init_ring_buffer`, `close_libbpf`) + 242 líneas de mocks de libbpf, probando el plumbing. | Suites en C del módulo (contract, loader, paths, leak, drops, filter, creds, skip) + el seam de 3 funciones en FIM. |
| **Objetos BPF en el agente** | `modern.bpf.o` **y** `rt_file.bpf.o`. | Solo `rt_file.bpf.o`, cargado dos veces. |

### Lo que se portó *desde* `modern.bpf.c` antes de borrarlo

Punto importante para la reunión: **no fue una migración en una sola dirección**. El provider tenía mejor estructura y peor implementación. Tres defectos vivos se corrigieron portando lógica probada desde `modern.bpf.c` (fase P0):

1. **Layout de `renamedata` hardcodeado a 6.18.** En kernels 5.12–6.17 `new_dentry` está en offset 40, no 32; la lectura devolvía un `struct inode*` que se recorría como dentry. En aarch64/6.8 el resultado era **no emitir ningún evento de rename**, en silencio — la mayoría del rango soportado. Corregido con el par `renamedata___local` / `renamedata___v618` y `bpf_core_field_exists()`.
2. **`sb->s_fs_info` tratado como `struct mount*`** en setattr, unlink y rename. Es dato privado del filesystem (`ext4_sb_info`, `ovl_fs`), así que se leía un offset arbitrario. Reemplazado por `kprobe/mnt_want_write` + `write_mnt_map` + `get_write_mnt()`. Además, `rt_walk_dentry()` omitía `mnt = mnt_parent;` al cruzar un mount, de modo que nunca detectaba el siguiente: rutas truncadas en silencio con mounts anidados o apilados.
3. **Argumento de `security_inode_setattr` elegido por versión de kernel.** Los kernels enterprise backportean la firma de 6.0 (RHEL 9 la trae en 5.14), así que allí se leía un `mnt_idmap*` como dentry. Reemplazado por `resolve_dentry()`, que valida el candidato comparando `d_inode->i_sb == dentry->d_sb`.
4. **`login_uid` por defecto 0 en lugar de `-1`.** `ebpf_pop_events()` compara contra `(uint32_t)-1` antes de emitir los campos de auditoría, así que un default de 0 reporta todo evento como auditado por root en kernels sin `CONFIG_AUDIT`.

Tres de esos cuatro eran **fixes liberados en 4.14.11 / 5.0.x que `main` todavía no lleva**. Cualquier trabajo de eBPF ramificado desde `main` empieza sin ellos — que es exactamente lo que pasó en los dos intentos previos de extracción.

### Una diferencia de comportamiento decidida explícitamente

`modern.bpf.c` disparaba su `kprobe/vfs_open` **solo en creación** (`FMODE_CREATED | O_CREAT`), mientras sus hooks LSM incluían `O_ACCMODE`. Era inconsistente consigo mismo: capturaba escrituras a archivos existentes en hosts LSM y las perdía en hosts kprobe — la configuración mayoritaria.

`rt_file.bpf.c` incluye `O_ACCMODE` en ambas rutas. **Decidido: se mantiene.** Medido: 2.000 escrituras a archivos preexistentes abiertos `O_RDWR` sin `O_CREAT` produjeron 2.000 eventos OPEN, cero drops. Un filtro solo-creación no habría reportado ninguna. La medición es una ráfaga, no un soak: carga sostenida de varias horas sigue sin probarse.

### Una lección que solo un kernel real podía encontrar

`rt_walk_dentry` es un subprograma BPF-to-BPF `noinline` que toma `__u64`. Los programas kprobe llegan con escalares de `bpf_probe_read_kernel()` y cargan bien; los argumentos de un programa LSM son **punteros BTF confiables**, y el verificador se niega a pasarlos a un parámetro escalar. Un cast de C no cambia el tipo que el verificador rastrea.

```
R1 is not a scalar
Caller passes invalid args into func#1 ('rt_walk_dentry')
libbpf: prog 'path_unlink_walk': failed to load: -22
```

Regla permanente para este archivo: **todo lo que llegue a `rt_walk_dentry` desde un programa LSM debe lavarse a escalar primero**, vía `bpf_probe_read_kernel()`. `modern.bpf.c` nunca se topó con esto porque su walker era `statfunc`, siempre inlineado. Es invisible para cualquier verificación que no cargue el objeto en un kernel.

---

## 30.9 Consumidores actuales

| | host FIM whodata | drain de contenedores |
| --- | --- | --- |
| Archivo | `ebpf_whodata.cpp` | `container_event_drain.cpp` |
| `type_mask` | `RT_FILE_ALL_BITS` | `RT_FILE_ALL_BITS` |
| `cgroup_mode` | `ALL` (no es container-scoped: debe ver el nodo entero) | `ALLOWLIST` si está configurado, con retry a `ALL` |
| `skip_mask` | `0` (necesita el contexto de proceso para la atribución "quién") | `RT_SKIP_PROC_CONTEXT` |
| Drops | flag en banda | `rt_drain_drops()` por ciclo de poll |
| cgroup v1 | no aplica | `rt_set_cgroup_v1_subsys()` + `rt_cgroup_id_is_usable()` |
| Particularidad | Healthcheck de 4 acciones (crear / modificar contenido / modificar metadatos / borrar) que **comparte el handle** con el loop de poll posterior — reabrir desattachearía y reattachearía todo, perdiendo los eventos del intervalo. | Abre ya filtrando; si el objeto no tiene mapas de filtrado, `rt_open()` **se niega**, y el consumidor reintenta en `ALL` con un WARN explícito. |

El drain reintenta porque `rt_file.bpf.o` **no está en ningún manifiesto de empaquetado de deps**: un objeto más viejo que el agente en ejecución es una configuración real, no hipotética.

---

## 30.10 Riesgos, límites conocidos y puntos abiertos para la reunión

### Abiertos con impacto en diseño

1. **Binarios BPF commiteados en el repositorio.** Funciona y está guardado por digest + provenance + chequeo de símbolos, pero la ruta correcta es enviarlos por `libbpf-bootstrap.tar.gz`. Requiere cambio de pipeline de deps y bump de `DEPS_VERSION`, fuera del alcance de este repo. **¿Se planifica?**

2. **Dos cargas del mismo objeto.** ADR-001 lo sanciona explícitamente, y es la razón por la que host whodata y contenedores no se frenan entre sí. Pero el agente paga dos veces los probes de kernel, dos rings de 8 MiB, y dos hilos de poll. **¿Se acepta como estado final, o hay un caso para un modo multiplexado más adelante?**

3. **El binding de libbpf es a nivel de proceso y gana el primero.** Se hizo observable (WARN nombrando ambas rutas) pero no se cambió. Con dos consumidores como caso normal, **¿es suficiente?**

4. **`RT_F_CGROUP_V1` no lo setea el programa BPF.** Necesita un mapa de configuración escrito por userspace al cargar y releído por el programa. Hasta entonces, `rt_host_cgroup_v1()` es la única fuente, y un consumidor que testee `ev->flags` se equivoca en silencio.

5. **La allowlist elimina el descubrimiento por evento.** Un contenedor creado después del arranque y no sembrado en la allowlist es invisible. Eso convierte el trigger de creación desde `container_instances` en prerequisito duro. **¿Está ese trigger garantizado en todos los runtimes soportados?**

6. **Mapa de allowlist y de drops: 4096 entradas fijas.** Un nodo con más cgroups activos que eso tiene cgroups silenciosamente sin monitorear (se reporta como error, pero el límite es de compilación).

7. **Caché de mounts sin limpieza al salir.** `write_mnt_map` guarda direcciones de `vfsmount` sin referencia y sin limpieza en exit. Los chequeos de namespace y superblock hacen improbable un hit stale, pero **no prueban frescura** bajo reuso de PID o churn de mounts. Portado intacto desde `modern.bpf.c`; el churn no se probó explícitamente.

8. **Rename emite dos eventos** (origen y destino), sin orden garantizado, desde dos programas independientes. Peor: **no hay correlación explícita entre las dos mitades** — ni identificador de operación ni indicador origen/destino; ambas comparten `RT_EV_FILE_RENAME`, y una puede perderse sin que la otra lo indique. El drain de contenedores llama `router.onRename(cgroup_id)` sin hacer `lstat`, así que **dos eventos disparan la reconciliación dos veces**. Verificar que el router coalesce, y decidir qué garantías necesita cada consumidor.

9. **Los eventos señalan intentos, no operaciones confirmadas.** Los hooks son de entrada / de seguridad y no comprueban el retorno final de la operación. No existe un evento de "contenido escrito": una apertura con intención de escritura puede no escribir nada. Eso favorece tratarlos como **disparadores de reconciliación**, no como registro transaccional de cambios.

10. **La comprobación de ABI solo cubre major.** `rt_abi_major() != RT_ABI_MAJOR` protege contra cambios de layout, pero un consumidor construido contra MINOR 2 enlazado a un motor MINOR 1 leería `euid`/`login_uid` que ese motor nunca llena, y nada lo detecta — el guardia del ring protege al motor frente al **objeto**, no al consumidor frente al **motor**. Además, el callback lee `ev->abi_major` *antes* de verificar que el registro tenga siquiera ese campo. **¿Endurecemos el orden de validación y añadimos una comprobación de minor?**

11. **El descuento del contador global de drops bajo concurrencia no está demostrado.** `take_drop_counter()` lee el valor y resta exactamente lo leído; dos CPUs que lean el mismo valor antes de restar lo descontarían dos veces. Es un riesgo **inferido del algoritmo**, no un fallo reproducido. Vale la pena probarlo con varios productores y contrastar contra el mapa por cgroup.

12. **Identidad de cgroup en RHEL 8 arrancado con jerarquía unificada.** El camino v1 enmascara la generación de `kernfs` y el helper v2 no. El propio código sospecha una discrepancia contra `stat().st_ino` en esa configuración y dice que **no se midió**.

### Documentación interna desactualizada (hallazgos de la lectura cruzada)

Afectan decisiones, así que conviene arreglarlos antes de que alguien los use como referencia:

| Dónde | Qué dice | Qué es cierto |
| --- | --- | --- |
| `prebuilt/README.md` | La verificación de carga debe "pin all **five** programs". | Son **14** programas desde P3. |
| `prebuilt/README.md` | "Hay dos manifiestos hoy, `deb_linux_agent_amd64.csv` y `rpm_linux_agent_amd64.csv`, así que solo el objeto x86 tiene filas". | Los **cuatro** manifiestos (deb/rpm × amd64/arm64) llevan fila de `rt_file.bpf.o` desde P5. |
| `prebuilt/README.md` | "Una ABI de evento no coincidente se rechaza en `rt_open()`". | Se rechaza **por evento, en el callback del ring** durante `rt_poll()`, no al abrir. |
| `prebuilt/README.md` (tabla de directorios) | `x86/` ← "cualquier cosa que no sea aarch64". | Solo `x86_64|amd64|AMD64`; cualquier otra arquitectura **no recibe objeto**. |
| `CMakeLists.txt` y comentarios de test | "Falta un libbpf falso para cubrir los caminos de `rt_open`". | `test/rt_engine_loader_test.c` ya existe (vía `-Wl,--wrap` sobre `dlopen`/`dlsym`/`dlclose`/`fopen`) y cubre binding concurrente, fallo pegajoso y el aviso de ruta discrepante. Lo que sí sigue siendo cierto es que **CMake solo registra `rt_engine_contract_test` en ctest**: el loader test solo corre por el `Makefile` standalone, así que CI no lo ejecuta. |

Además, `prebuilt/x86/rt_file.bpf.o.provenance` dice explícitamente que la verificación de carga en **4.18 (CentOS Stream 8)** registrada para el objeto anterior **no se repitió** para el actual — solo se probó en 7.0.0-42-generic. Ese es exactamente el kernel donde importan las decisiones de inlining que vigila `check_bpf_symbols.sh`. El mismo archivo mezcla "7.0.0-42-generic" en `load_verified` con una referencia posterior a "6.17 host", que conviene desambiguar.

### No verificado

- **Carga sostenida.** La decisión de G6 (`O_ACCMODE`) se midió con una ráfaga de 2.000 escrituras, no con un soak de horas en un host ocupado. Con `skip_mask = 0` en whodata, cada evento cuesta dos recorridos de dentries y 12.424 bytes del ring de 8 MiB.
- **Entrega sostenida en el agente real.** La validación de P4 corrió en un agente no enrolado, que reenvía solo el primer mensaje por arranque; cada operación se validó en su propio arranque. Falta la comparación campo a campo contra una captura pre-cutover en un agente con manager.
- **`resolve_dentry()` en su caso de uso real.** Existe por la firma 6.0 backporteada en kernels enterprise; ninguno de los dos hosts de prueba (6.8, 6.17) la tiene. Lo medido prueba que los eventos de atributo siguen funcionando, no que el caso del backport esté arreglado. **Necesita un host RHEL 9.**
- **El peldaño LSM-walk** está cubierto por el verificador y por tests con libbpf falsa, pero no se ejecutó en vivo: forzarlo requiere un kernel que rechace `bpf_d_path` para esos hooks (Amazon Linux 2/2023).
- **Layout `renamedata` de 6.19+**: solo cobertura en tiempo de compilación, sin host disponible.

### Pendiente de release

`deps.py pool-check` no pasa: el rekey del lock de P5 dejó los tarballs `libbpf-bootstrap` recién claveados sin publicar en el pool. Alguien debe construirlos y publicarlos. Tampoco se corrieron builds de paquete, `check_files` sobre un árbol instalado, ni una verificación de upgrade sin huérfanos.

---

## 30.11 Referencias en el árbol

| Qué | Dónde |
| --- | --- |
| API pública | `src/shared_modules/ebpf_provider/include/rt_engine.h` |
| Contrato de evento | `src/shared_modules/ebpf_provider/include/rt_event_contract.h` |
| Loader | `src/shared_modules/ebpf_provider/src/rt_engine.c` |
| Programa BPF | `src/shared_modules/ebpf_provider/bpf/rt_file.bpf.c` |
| Puerta de build | `src/shared_modules/ebpf_provider/CMakeLists.txt` |
| Build standalone | `src/shared_modules/ebpf_provider/Makefile` |
| Objetos prebuilt y su política | `src/shared_modules/ebpf_provider/prebuilt/README.md` |
| Consumidor mínimo de ejemplo | `src/shared_modules/ebpf_provider/test/rt_engine_harness.c` |
| Consumidor: host whodata | `src/syscheckd/src/ebpf/src/ebpf_whodata.cpp` |
| Consumidor: contenedores | `src/syscheckd/src/ebpf/src/container_event_drain.cpp` |
| Plan de retiro de `modern.bpf.c` | `37532-desing-analysis/27-modern-bpf-retirement-plan.md` |
| Plan de importación del provider | `37532-desing-analysis/11-ebpf-provider-import-plan.md` |
