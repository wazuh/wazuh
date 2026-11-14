# 34 — Hallazgos del `ebpf_provider`: impacto funcional y remediación

Complemento operativo del [doc 33](33-ebpf-provider-review-findings.md). Aquel documento verifica las seis observaciones de revisión y emite veredictos; **este responde a otras dos preguntas por hallazgo: qué se rompe en ejecución, y cuál es el cambio más pequeño que lo arregla.**

Orden: severidad decreciente, la misma de [§33.0](33-ebpf-provider-review-findings.md). Cada entrada lleva: síntoma observable, cadena causal, alcance, arreglo con código, y la trampa del arreglo.

Nada de lo que sigue está medido. Son diferencias de código verificadas contra el árbol de `37532-ebpf-engine` y contra `origin/4.14.11` (`2a471dc679`), más conteos de operaciones.

**Todos los hallazgos pasaron por una verificación independiente con Codex, que corrigió siete afirmaciones de la primera versión de este documento.** Las correcciones están incorporadas en el texto; §34.12 lleva el estado de implementación.

---

## 34.0 Tabla de decisión

| # | Hallazgo | Síntoma | Clase | Esfuerzo | ¿Cambia ABI? | ¿Regenera prebuilts? |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | Mount no capturado en operaciones por `fd` | Rutas erróneas en alertas FIM | Correctitud, silencioso | Bajo | No | Sí |
| F2 | Sin semántica de operación completada | Borrados/reconciliaciones por operaciones fallidas | Correctitud | Medio (alto si se hace completo) | Sí (MINOR) | Sí |
| F3 | `m_ownersGeneration` escrito desde IPC | Atribución de owner obsoleta + carrera de datos | Correctitud | Trivial | No | No |
| F4 | Registro fijo de 12.424 bytes | Pérdida de eventos bajo ráfaga | Capacidad | Medio — menos de lo estimado, ver §34.4 | Sí, `RT_ABI_MAJOR` 2 | Sí |
| F5 | Sin filtro de rutas en kernel | CPU de kernel y presión de ring evitables | Rendimiento | Medio | No | Sí |
| F6 | Rename sin marca de extremo | Reconciliación completa de contenedor por rename | Rendimiento | Bajo | Sí (MINOR, sin cambio de tamaño) | Sí |
| F7 | Ráfaga de rutas irrelevantes desborda staging | Re-walk completo de contenedor | Rendimiento | Bajo-medio | No | No |
| F8 | Filtro de cgroup después del walk de rutas | CPU de kernel evitable | Rendimiento | Bajo | No | Sí |
| F9 | Constantes duplicadas kernel/userspace | Riesgo futuro, sin fallo hoy | Mantenimiento | Trivial | No | **Sí** — el digest cubre `rt_event_contract.h` |

**F3 y F7 no tocan BPF.** Se pueden aterrizar sueltos. F9 no cambia instrucciones pero sí el digest de las fuentes, así que comparte el commit de regeneración con F1 y F8.

---

## 34.1 F1 — Mount no capturado en operaciones por descriptor de archivo

**Severidad: la más alta del lote. Produce datos erróneos sin ninguna señal.**

### Síntoma

Un `fchmod(fd, …)`, `fchown(fd, …)`, `ftruncate(fd, …)` o `futimens(fd, …)` sobre un archivo monitorizado genera un evento `RT_EV_FILE_ATTR` cuyo `filename` es **relativo al filesystem, no absoluto al mount**. Sobre un `/var` montado aparte, `/var/log/app.log` llega como `/log/app.log`.

Consecuencia aguas arriba: el sink de whodata filtra por `confFn(e->filename)` ([`ebpf_whodata.cpp:156`](../src/syscheckd/src/ebpf/src/ebpf_whodata.cpp)). Una ruta que no empieza por el directorio configurado **se descarta en silencio**: no es una alerta con ruta fea, es una alerta que no existe. En el drain de contenedores la ruta entra al staging y dispara trabajo contra una ruta que no corresponde.

### Cadena causal

1. El VFS tiene dos puertas para declarar intención de escritura. `mnt_want_write(struct vfsmount*)` para el camino por ruta, y `mnt_want_write_file(struct file*)` para el camino por descriptor.
2. El provider hookea sólo la primera ([`rt_file.bpf.c:1010`](../src/shared_modules/ebpf_provider/bpf/rt_file.bpf.c)). `write_mnt_map` no recibe entrada por ese camino.
3. `get_write_mnt()` devuelve `NULL` (`:1023-1033`) — **o algo peor**. La entrada no se consume nunca, así que una operación anterior del mismo hilo puede dejar un mount cacheado que pasa la validación de superbloque y se usa como si fuera el de esta operación. Por eso el defecto es "adquisición de mount no fiable" y no "siempre `NULL`": un mount correcto cacheado, o un filesystem montado en `/`, dan la ruta buena. Cuál de los dos ocurre no se sabe sin instrumentar.
4. El comentario de `:1019-1021` dice qué significa ese `NULL`: *"NULL lets the walker stop at the filesystem root."* El walker se detiene en la raíz del superbloque.
5. 4.14.11 tenía **dos** defensas en este camino, y el provider no tiene ninguna:
   - `kprobe/mnt_want_write_file` (`modern.bpf.c:653-659`).
   - El override `if (attr->ia_valid & ATTR_FILE) path.mnt = attr->ia_file->f_path.mnt;` (`:726-728`). El setattr del provider (`:1038-1061`) **nunca lee `struct iattr`**: descarta `PT_REGS_PARM2`/`PARM3` tras usarlos para localizar el dentry.

No hay flag de error en el evento, no se incrementa ningún contador de drop, y el log no dice nada. **Un consumidor no puede distinguir una ruta truncada de una ruta correcta.**

### Alcance

Toda la clase `RT_EV_FILE_ATTR` originada por descriptor, en ambos consumidores. El camino por ruta (`chmod`, `chown`, `truncate`, `utimensat`) no está afectado.

### Arreglo

Dos piezas en `rt_file.bpf.c`, más el gating en el loader. Las dos son independientes y conviene aplicar ambas: la primera cubre el camino genérico, la segunda es exacta para `setattr`.

**Pieza 1 — restaurar la sonda auxiliar:**

```c
SEC("kprobe/mnt_want_write_file")
int kprobe__mnt_want_write_file(struct pt_regs* ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 mnt = (__u64)BPF_CORE_READ((struct file*)PT_REGS_PARM1(ctx), f_path.mnt);
    bpf_map_update_elem(&write_mnt_map, &id, &mnt, BPF_ANY);
    return 0;
}
```

**Pieza 2 — override por `ATTR_FILE`.** `ATTR_FILE` no está en BTF, es un `#define` de `fs.h`; hay que redeclararlo como hacía `modern.bpf.c:21`. Y hay que llevar el `iattr` **en paridad con la posición desde la que se resolvió el dentry**:

```c
#define ATTR_FILE (1 << 13)

    struct dentry* dentry = resolve_dentry((struct dentry*)PT_REGS_PARM1_CORE(ctx));
    struct iattr* attr = (struct iattr*)PT_REGS_PARM2_CORE(ctx);
    if (!dentry)
    {
        dentry = resolve_dentry((struct dentry*)PT_REGS_PARM2_CORE(ctx));
        attr = (struct iattr*)PT_REGS_PARM3_CORE(ctx);
    }
    …
    struct vfsmount* mnt = get_write_mnt(BPF_CORE_READ(d_inode, i_sb));
    if (bpf_core_field_exists(attr->ia_file) && (BPF_CORE_READ(attr, ia_valid) & ATTR_FILE))
        mnt = BPF_CORE_READ(attr, ia_file, f_path.mnt);
```

El `bpf_core_field_exists()` es la guarda que el comentario de 4.14.11 pedía explícitamente y que aquel código no llegó a poner.

**Pieza 3 — el gating del loader, y aquí está la trampa.**

[`rt_engine.c:438`](../src/shared_modules/ebpf_provider/src/rt_engine.c) y `:476` comparan con `strcmp(sec, "kprobe/mnt_want_write") == 0`, comparación exacta. Una sección nueva `kprobe/mnt_want_write_file` **no coincide**, cae al camino normal, `type_bit_for_section()` no le da bit, y queda con `autoload=false` **para siempre**. La sonda se compilaría en el objeto y no se attachearía nunca; el síntoma sería idéntico al de hoy. Hay que reconocer ambas secciones en los dos puntos:

```c
static int is_write_mnt_probe(const char* sec)
{
    return sec && (strcmp(sec, "kprobe/mnt_want_write") == 0 ||
                   strcmp(sec, "kprobe/mnt_want_write_file") == 0);
}
```

### Trampa del arreglo: el fallo de attach es fatal

`rt_engine.c:724-737` trata cualquier fallo de attach como fatal: `*failure = 2`, `abort_open()`, y el handle cae al siguiente peldaño de la escalera. Si `mnt_want_write_file` estuviera inlined o ausente en algún kernel, añadir la sonda **tumbaría la apertura entera** y, tras agotar la escalera, dejaría al agente sin motor. El síntoma sería mucho peor que el que se arregla.

En el kernel 6.6 de esta máquina ambos símbolos existen y son globales:

```
0000000000000000 T mnt_want_write
0000000000000000 T mnt_want_write_file
```

Aun así, la sonda auxiliar **no emite eventos** y su pérdida sólo degrada la resolución de rutas. Debe attachearse en modo best-effort: si falla, registrar un `RT_LOG_WARN` y seguir, sin incrementar `*failure` ni abortar. Es una excepción acotada al camino fatal, no un cambio de la política general.

`RT_MAX_LINKS` es 16 y hoy se attachean como máximo 6; con la sonda nueva, 7. No hace falta tocarlo.

---

## 34.2 F2 — Sin semántica de operación completada

### Síntoma

Un `unlink()` que **falla** — `EACCES`, `EPERM`, `EBUSY`, `EROFS` — produce igualmente un evento `RT_EV_FILE_UNLINK`, y [`container_event_drain.cpp:714`](../src/syscheckd/src/ebpf/src/container_event_drain.cpp) lo trata como borrado consumado. El archivo sigue en disco y el estado del consumidor dice que no.

**Whodata del host NO tiene este problema**, al contrario de lo que decía la primera versión de este documento. `handle_event()` ([`ebpf_whodata.cpp:159-172`](../src/syscheckd/src/ebpf/src/ebpf_whodata.cpp)) descarta `event_type` al construir el `dynamic_file_event`, y `fim_whodata_event()` ([`fim_scan.c:170-185`](../src/syscheckd/src/fim_scan.c)) hace `w_lstat()`: si el archivo está, va por add/modify, y sólo la rama de ruta ausente llama a `fim_process_missing_entry()`. Whodata ya confirma la ausencia antes de tratar algo como borrado. **El problema está confinado al drain de contenedores**, que no lo hacía.

Tampoco todo `unlink` fallido llega a estos hooks: la lista `EACCES`/`EPERM`/`EBUSY`/`EROFS` de la primera versión no está establecida por el código. Lo que sí lo está es que un fallo posterior al hook no se reporta.

### Cadena causal

Todos los hooks emisores son de **entrada** (kprobe de entrada o hook LSM de autorización). Reportan intención, y ningún camino comprueba el retorno. El contrato (`rt_event_contract.h`) no tiene `tid`, ni operación de cierre, ni estado de retorno, así que **el consumidor no tiene forma de saberlo**: no es que elija ignorar el resultado, es que no está en el registro.

Hay un agravante propio del hook LSM: un `lsm/path_unlink` se ejecuta *antes* de que otros módulos de seguridad —SELinux, AppArmor— puedan denegar. Un entorno con MAC estricto produce más eventos fantasma, no menos.

4.14.11 cerraba el ciclo: `OP_PENDING`/`OP_DONE`, `inflight_map` keyeado por tid, el campo `tid` en el registro, y **tres return probes** que reportan `ret` (`modern.bpf.c:35-37, 46-65, 519-551`).

### Arreglo: registro de longitud variable, `RT_ABI_MAJOR` 2 — **implementado**

`bpf_ringbuf_reserve()` exige tamaño constante para el verificador, así que no se puede cambiar el tamaño de la reserva y ya está. El registro se arma en un scratch per-CPU y se emite con `bpf_ringbuf_output()`, que copia `size` bytes:

```c
const __u64 size = (__u64)RT_WIRE_HEAD_SIZE + off;
if (size > sizeof(*evt) || bpf_ringbuf_output(&rb, evt, size, 0) != 0)
```

**Lo que se hizo, y por qué no costó lo que decía la primera versión de este documento.**

Esa versión planteaba dos pasos —truncar en frontera de campo primero, empaquetar después— y afirmaba que ambos necesitaban propagar `size` al sink, tocando a todos los consumidores. Codex señaló la salida: **decodificar dentro del motor**. Hay dos structs:

| Struct | Quién lo ve | Forma |
| --- | --- | --- |
| `rt_file_event_wire` | sólo el programa BPF y `rt_engine.c` | cabecera fija de 136 bytes + `paths[]` con tres cadenas NUL-terminadas pegadas |
| `rt_file_event` | **todos los consumidores** | idéntico a ABI 1, con sus tres `char[4096]` |

`ringbuf_sample_cb()` valida el registro de cable y lo expande a un `rt_file_event` antes de llamar al sink. **Ningún consumidor cambió ni una línea**, ni `ebpf_whodata.cpp` ni `container_event_drain.cpp`. Y el paso intermedio sobra: se fue directo al empaquetado completo.

Detalles que importan:

- **Siempre viajan tres cadenas**, aunque estén vacías (un solo NUL). El decodificador nunca tiene que adivinar cuál falta en un registro corto, que es el error fácil de este formato. Con `RT_SKIP_PROC_CONTEXT` eso son 2 bytes en vez de 8.192.
- **El guard de ABI se replanteó.** Bajo ABI 1 un registro corto significaba objeto desactualizado, porque todos medían lo mismo; bajo ABI 2 corto es el caso normal. La longitud ya no dice nada sobre la antigüedad del objeto y `abi_major` lo carga solo. El guard ahora comprueba `size >= RT_WIRE_MIN_SIZE` **antes** de leer `abi_major`, y `size <= sizeof(wire)` después.
- **El decodificador está acotado por `size`, no por lo que digan las cadenas.** Una última cadena sin terminar —copia truncada, u objeto que no coincide— sale truncada, no leyendo más allá de la muestra.
- **El contador de drops se devuelve si la copia falla.** `take_drop_counter()` se llama justo antes del `bpf_ringbuf_output()`; si la copia falla, `restore_drop_counter()` devuelve lo tomado antes de contar la pérdida de este evento. Si no, un ring lleno reportaría un drop en vez de todos.

**Coste:** un `BPF_MAP_TYPE_PERCPU_ARRAY` nuevo de un `rt_file_event_wire` (12.424 B por CPU). Per-load per-CPU pasa de 68 KiB a ~80 KiB, contra 8 MiB de ring que ahora rinde ~38×.

### Medido

`rt_engine_drops_test`, 80.000 eventos contra un ring sin consumir: **54.400 drops, ~25.600 registros entregados** antes de desbordar. Antes eran ~674. **~38×**, que es lo que predecía la aritmética de tamaños.

El propio test hubo que re-sintonizarlo: con 4.000 eventos por hijo ya no desborda nada, que es precisamente el arreglo funcionando. Ahora son 40.000, con la aritmética escrita en el comentario para que el próximo que lo vea fallar mire primero el tamaño del registro.

### Nota sobre el doc 32

Toda la aritmética de presión de ring del [doc 32](32-single-load-vs-multi-load-comparative-design.md) está calculada sobre los 12.424 bytes fijos, así que con un registro compacto esos números caen ~41×.

**Esto no abre ninguna decisión de diseño.** El diseño es N cargas (opción A) y sigue siéndolo; el doc 32 es exploratorio y ya concluye lo mismo. El efecto de F4 es que el argumento que aquel documento construye para B2 queda aún más débil.

---

## 34.5 F5 — Sin filtro de rutas en kernel

### Síntoma

Actividad de archivos completamente ajena a lo monitorizado —compilaciones en `/tmp`, bases de datos, caches— paga el ciclo completo: walk de dentries, recolección de metadatos, 12.424 bytes de ring, wakeup del consumidor, y descarte en userspace. En un host ocupado es el grueso de los eventos.

### Cadena causal

El provider filtra por cgroup y nada más. 4.14.11 tenía un LPM trie de hasta **16.384 prefijos** con claves de 256 bytes, consultado antes de construir el evento (`modern.bpf.c:147-173, 422-447`), que userspace mantenía sincronizado con `sync_monitored_dirs()`.

### Arreglo

Un `BPF_MAP_TYPE_LPM_TRIE` opcional por handle, poblado desde userspace. **No puede consultarse en el punto donde se evalúa la admisión por cgroup (F8)**: necesita la ruta ya resuelta. Ahorra la construcción del evento y el transporte, no el walk disparador — que es la diferencia con F8 y la razón de que no sean el mismo arreglo. Que sea opcional importa: whodata y el drain tienen conjuntos de rutas distintos, y un handle sin reglas debe comportarse como hoy.

### Trampa del arreglo

Los 256 bytes de clave son la elección de 4.14.11 (`modern.bpf.c:153-157`), no un límite del kernel verificado aquí. Sea cual sea el tope, un prefijo más largo se trunca y define un **superconjunto** de lo pedido. El filtro de kernel es por tanto una optimización, nunca la autoridad: **la validación en userspace tiene que seguir corriendo**. Quitarla porque "ya filtra el kernel" convierte un ahorro de CPU en un fallo de alcance.

---

## 34.6 F6 — Rename sin marca de extremo

### Síntoma

Cada rename dentro de un contenedor escala a **re-walk completo** del árbol monitorizado de ese contenedor, en vez de actualizar dos rutas conocidas.

### Cadena causal

El engine **sí** emite ambos extremos en las tres implementaciones (LSM dpath `:944`/`:952`, LSM walker `:976`/`:984`, kprobe `:1164`/`:1170`), y el contrato lo documenta (`rt_event_contract.h:51`). Pero no hay forma de saber cuál es cuál: no existe bit de origen/destino.

Los comentarios del consumidor siguen afirmando que el origen no se reporta. Verbatim en [`container_event_router.hpp:92`](../src/syscheckd/src/ebpf/include/container_event_router.hpp): `/* renames escalated (source path is never reported) */`. El bloque de `:205-225` razona sobre esa premisa falsa, y `container_event_drain.cpp:700-706` descarta la ruta de ambos extremos y escala.

**Corrección a la observación original:** "dos veces por rename" no se sostiene. Hay dos llamadas de escalada, pero `container_event_staging.hpp:349` deduplica contenedores sospechosos en un set: ambos registros antes del consumo producen **un** re-walk. Dos sólo si el consumo los separa.

### Arreglo

Un bit en `flags`. Hoy se usan 2 de 16, **y no cambia el tamaño del registro**. La propuesta que estaba escrita en el comentario del router —anexar la ruta origen— era ~4 KiB por evento con el registro fijo; con ABI 2 es sólo la longitud real de la ruta, pero sigue siendo una cuarta cadena en todos los eventos de todas las clases para arreglar una.

El arreglo completo es: marcar los registros de origen, conservar las rutas de destino, enseñar a los consumidores a reconciliar ambos extremos, y **preservar la escalada como respaldo** para registros antiguos o sin marcar.

### Trampa del arreglo

**Un bit solo no alcanza para hacer lo que uno quiere hacer con él.** No se puede rutear el registro de origen a un borrado incondicional: son hooks de entrada, la operación puede fallar, y los extremos no tienen orden garantizado. Un borrado dirigido seguro **depende de F2**. Sin F2, el bit sirve para acotar el alcance de la reconciliación a dos rutas, no para borrar.

Y hay que borrar los comentarios desactualizados en el mismo commit. Ahora mismo describen un engine que no existe, y el siguiente que los lea diseñará contra ellos.

---

## 34.7 F7 — Ráfaga de rutas irrelevantes desborda el staging

### Síntoma

Actividad **enteramente fuera de los directorios monitorizados** consume memoria de staging y, al desbordar, fuerza un re-walk de los directorios configurados del contenedor. No se escanea `/tmp`: se escanea de más lo que sí está configurado, por culpa de lo que no lo está.

### Cadena causal

El drain reenvía rutas sin filtrar por directorio monitorizado (`container_event_drain.cpp:708-727`) y el router las stagea directamente (`container_event_router.hpp:122, 153`). Whodata, en cambio, sí filtra en su sink antes de encolar (`ebpf_whodata.cpp:157`). Al desbordar, `container_event_staging.hpp:250-258` tira el set y marca Suspect.

**Dos correcciones a la observación original:**

1. **El filtro existe, sólo que más tarde**: `SelectReconcilePaths` en [`container_baseline_fim.cpp:1245`](../src/syscheckd/src/ebpf/src/container_baseline_fim.cpp), invocado después del staging en `:1460`. "Va después del staging" es exacto; "el drain no filtra" sería incorrecto.
2. **El umbral es 4.097 para rutas ordinarias, y no aplica igual a los unlinks.** El presupuesto es `max_paths_per_container{4096}` (`container_event_drain.hpp:86`). Para rutas ordinarias `staging:237-260` deduplica **primero** y comprueba capacidad después: entran 4.096 distintas y la 4.097ª escala. Para unlinks, `staging:317-328` comprueba capacidad **antes** de intentar insertar, así que con 4.096 en el set **hasta un unlink duplicado escala**. En ambos casos tienen que acumularse **para el mismo contenedor antes de que el consumo retire trabajo**: 4.096 rutas a lo largo del tiempo no garantizan un walk.

### Arreglo

Un snapshot cacheado y thread-safe de las reglas de ruta configuradas del contenedor, consultado antes de stagear, aplicado tanto a rutas modificadas como borradas.

### Trampa del arreglo

El hilo del drain **no puede recolectar configuración ni tocar el filesystem**: es el hilo que vacía el ring, y bloquearlo ahí se paga en eventos perdidos. Por eso el arreglo es un snapshot cacheado y no una consulta. Y el manejo de pérdida se mantiene aparte: filtrar rutas irrelevantes no debe filtrar la señal de desbordamiento.

---

## 34.8 F8 — Filtro de cgroup después del walk de rutas

### Síntoma

En modo allowlist, un evento de un cgroup no admitido paga la resolución de la ruta disparadora —hasta 320 iteraciones del walker— antes de descartarse.

### Cadena causal

`event_is_wanted()` se evalúa sólo dentro de `submit_event()` (`:671-673`), y todos los sitios de llamada ya resolvieron la ruta: open `:803`→`:809`, LSM open `:832`→`:837`, rename `:967`→`:972`, setattr `:1056`→`:1062`, unlink `:1089`→`:1095`.

**Matiz que la observación omite:** el filtro ahorra más que la reserva. Un cgroup rechazado también se ahorra la recolección de metadatos, la copia, y **hasta dos walks adicionales de `cwd`** (`:685-759`). Lo que no se ahorra es el walk disparador, que es el dominante.

### Arreglo

Es viable y pequeño. `current_container_cgroup_id()` hace algo más que leer `filter_cfg` y llamar a `bpf_get_current_cgroup_id()` —su rama de cgroup v1 camina el estado task/cgroup en `:350-379`— pero **no depende de la ruta resuelta**, que es lo único que el hoisting necesita. Se evalúa la admisión después de los chequeos baratos propios de cada hook —apertura de sólo lectura, no-regular, dentry inválido— y antes de resolver la ruta, pasando el `cgroup_id` ya resuelto a `submit_event()` para no calcularlo dos veces.

### Trampa del arreglo

Hay que aplicarlo a **todas** las variantes emisoras —dpath y walker, LSM y kprobe— o quedan caminos con semántica distinta según el peldaño de la escalera en que arrancó el host, que es la clase de bug que sólo aparece en un kernel concreto de un cliente concreto.

Y el hook de bookkeeping `mnt_want_write` **no debe filtrarse**: no emite evento, y su entrada en `write_mnt_map` la necesita después un hook que sí emite. (El mapa está keyeado por `pid_tgid`, así que el argumento de "podría ser de otro cgroup" que daba la primera versión no se sostiene; la razón buena es más simple: el mecanismo auxiliar tiene que seguir funcionando con independencia de la admisión del emisor.) Filtrarlo reintroduciría F1 por otra vía.

Esto corrige de paso la imprecisión del [doc 30 §30.5](30-ebpf-provider-design-summary.md): el evento se descarta antes de la reserva de 12.424 bytes, cierto, pero el walk dominante ya se pagó.

---

## 34.9 F9 — Constantes duplicadas kernel/userspace

### Síntoma

Ninguno hoy. **Las siete coinciden**, verificadas una a una en [§33.6](33-ebpf-provider-review-findings.md). Es riesgo, no fallo.

El riesgo concreto: son claves de mapa, cotas e interpretación de modo. Un desajuste no produce un error de compilación ni un fallo de carga; produce un filtro que lee la clave equivocada. Y el guard de ABI por evento **no lo detectaría**: comprueba layout del registro, no acuerdo sobre claves de mapa.

### Arreglo

Mover los macros enteros y el **`enum rt_cgroup_mode` completo** a `rt_event_contract.h`, que ya incluyen ambos lados, y borrar los duplicados. Macros enteros y enums de C no requieren `stdint.h` ni biblioteca hospedada, así que son seguros para la compilación freestanding con `clang -target bpf` descrita en `rt_event_contract.h:9-18`. No hay cambio de layout ni de versión de ABI.

**Pero sí cambia el digest de los prebuilts, y eso rompe el build.** `CMakeLists.txt:171-172` hashea `bpf/rt_file.bpf.c` **y** `include/rt_event_contract.h`; tocar cualquiera de los dos deja `prebuilt/<arch>/rt_file.bpf.o` marcado STALE, y `RT_BPF_STRICT_PREBUILT` está **ON por defecto** (`:206`): es `FATAL_ERROR`, no warning. La tabla de §34.0 decía "No" en la columna de prebuilts y es incorrecto. "Tanda 1" significa "sin cambio de comportamiento en BPF", no "sin tocar fuentes de BPF".

### Trampa del arreglo

`RT_CGROUP_MODE_ALL` y `RT_CGROUP_MODE_ALLOWLIST` son `#define` del lado BPF (`rt_file.bpf.c:192-193`) y **enumeradores** en `rt_engine.h:115, 129`. Añadir los macros al header compartido dejando los enumeradores con el mismo nombre **rompe la declaración del `enum` por sustitución de macro**: el preprocesador convierte `RT_CGROUP_MODE_ALL = 0` en `0 = 0`. Hay que **mover el enum**, no duplicarlo como macros.

---

## 34.10 Orden de remediación

Tres tandas. El criterio es el acoplamiento al artefacto BPF, no la severidad.

**Tanda 1 — sin tocar BPF, aterriza sola.**

1. F3: borrar `kubernetes_connector.cpp:287`.
2. F2 paso 1: el drain deja de tratar el `unlink` de entrada como borrado consumado.
3. F7: snapshot cacheado de reglas de ruta antes de stagear.
4. F9: mover macros y enum al header compartido.
5. Borrar los comentarios desactualizados: `container_event_router.hpp:92` y su bloque de `:205-225`, `container_event_drain.cpp:700-706`, y los que citan 12.416 bytes y ~675 registros (el valor real es 12.424 y ~674).

**Tanda 2 — correctitud en BPF, un commit con regeneración de prebuilts.**

6. F1 completo: sonda `mnt_want_write_file` con attach best-effort, override por `ATTR_FILE` con `bpf_core_field_exists()`, y el gating de ambas secciones en el loader.
7. F8: hoisting de la admisión por cgroup en todas las variantes emisoras.

**Tanda 3 — cambios de contrato, cada uno con su regeneración.**

8. ~~F4~~ **hecho**: registro de cable empaquetado, decodificación en el motor, guard replanteado.
9. F6: bit de extremo de rename, consumidores reconciliando ambos extremos, escalada conservada como respaldo.
10. F2 paso 2: `tid`, `inflight_map`, return probes, liberación sólo tras éxito.
11. ~~F4 paso 2~~ **hecho** — y sin el paso 1, que resultó innecesario.
12. F5: LPM trie opcional por handle, con la validación en userspace intacta.

F4 desactualiza los números del doc 32, que están construidos sobre los 12.424 bytes fijos: medido, el ring rinde ~38× más. No hay nada que decidir ahí — el diseño es N cargas y aquel documento es exploratorio.

---

## 34.12 Estado de implementación

Rama `37532-ebpf-provider-review-fixes`, desde `37532-ebpf-engine` en `351f268b6d`.

| # | Estado | Dónde |
| --- | --- | --- |
| F1 | **Hecho** | `rt_file.bpf.c`: sonda `kprobe/mnt_want_write_file`, `#define ATTR_FILE`, captura de `iattr` en paridad de argumento y override guardado con `bpf_core_field_exists`. `rt_engine.c`: helper `is_write_mnt_probe()` en los dos puntos de gating, y attach best-effort para las auxiliares. |
| F2 paso 1 | **Hecho** | `container_baseline_fim.cpp`: `ConfirmUnlinkedPaths()`. La rama `deletePaths` se trata antes del resto y en su propio ámbito de lock, para pedir el re-walk con el lock liberado. |
| F3 | **Hecho** | `kubernetes_connector.cpp`: borrada la escritura cruzada; el comentario dice por qué no vuelve. |
| F7 | **Hecho** | `PathIsUnder` movida a `container_event_drain.hpp` (una sola definición, la del baseline ahora es un `using`), `DrainConfig::monitored_roots` poblado en `fim_container_events_start()` desde la colecta que ya se hacía, y el filtro en `onEvent` **después** de la rama de pérdida. |
| F8 | **Hecho** | `rt_file.bpf.c`: helper `rt_admit()`, admisión antes de los 10 sitios de resolución de ruta, y `submit_event()` recibe el `cgroup_id` en vez de resolverlo. |
| F9 | **Hecho** | Claves, `RT_V1_SUBSYS_MAX`, `RT_SKIP_PROC_CONTEXT` y el `enum rt_cgroup_mode` completo viven ya sólo en `rt_event_contract.h`. |
| Comentarios | **Hecho** | Rename (router y drain), 12.416→12.424, ~675→~674, y la aritmética de ráfaga, que estaba mal por 30× (ver abajo). |
| F4 | **Hecho** | `rt_event_contract.h`: `rt_file_event_wire` + `RT_ABI_MAJOR` 2. `rt_file.bpf.c`: `wire_map`, `append_task_cwd()`, `bpf_ringbuf_output()`, `restore_drop_counter()`. `rt_engine.c`: `decode_event()` y guard replanteado. Consumidores sin tocar. |
| F5 | **Pendiente** | Capacidad nueva. |
| F6 | **Pendiente** | Cambio de contrato, y depende de F2 paso 2 para servir de algo. |
| F2 paso 2 | **Pendiente** | Cambio de contrato. |

### Bug extra encontrado al arreglar los comentarios

"~675 registros de 12.416 bytes — unos **2,4 segundos** de una ráfaga medida a 8.400 eventos/s" aparecía en `container_event_staging.hpp:14-16` y `container_event_drain.hpp:19-20`. La división no da eso: 674 / 8.400 = **0,080 s**. El comentario estaba equivocado por un factor de 30, y en la dirección cómoda. Corregido, junto con los dos argumentos que se apoyaban en la cifra (`drain.hpp:27`, `staging.hpp:561`); sus conclusiones aguantan, la del `drain.hpp` incluso se refuerza — 2 s de bloqueo contra 80 ms de ring son 25×.

Esto era, además, el mejor argumento para F4 que había en el repositorio: con el registro fijo el ring absorbía **80 ms**, no 2,4 s.

Y F4 lo volvió a mover, esta vez hacia arriba: medido, el ring ahora aguanta ~25.600 registros, unos **3 s** a 8.400 eventos/s. Los comentarios quedaron recalculados con ese número. De paso cae un argumento: el de `container_event_drain.hpp:27` decía que 2 s de bloqueo contra 80 ms de ring eran 25× de exceso; contra 3 s son dos tercios del presupuesto. La conclusión —no compartir el hilo— se sostiene igual, con menos dramatismo.

### Verificación ejecutada

Con `make deps TARGET=agent TEST=1` ya corrido, árbol configurado con `cmake .. -DTARGET=agent -DUNIT_TEST=ON -DRT_BPF_STRICT_PREBUILT=OFF`.

**Suites de ctest — 14/14 pasan.**

```
#40 container_instances_unit_test   #76 container_event_staging_test
#41 container_baseline_unit_test    #77 cgroup_container_map_test
#64 rt_engine_contract_test         #78 container_event_router_test
#72 ebpf_whodata_test               #79 container_reconcile_plan_test
#80 resolver_wait_test              #81 container_sweep_schedule_test
#82 container_doc_budget_test       #83 container_row_budget_test
#84 container_reporting_test
```

**Suites standalone de `syscheckd/src/ebpf/tests` — 4/4 `ALL OK`:** `unlink`, `txn`, `settle`, `alert`. La de `unlink` importa especialmente: sigue afirmando que un unlink planifica `deletePaths` y nunca autoriza borrado por lectura fallida, que es la invariante que F2 no debía tocar.

**Suites del provider.** `make check` (contrato + loader, sin kernel ni root): pasan. Y con un `rt_file.bpf.o` recién compilado de estas fuentes, cargado en el kernel 6.6 de esta máquina con `sudo`:

| Test | Resultado |
| --- | --- |
| `rt_engine_leak_test` | pasa |
| `rt_engine_drops_test` | pasa, **re-sintonizado**: con 4.000 eventos por hijo ABI 2 ya no desborda el ring. A 40.000 mide 54.400 drops y ~25.600 registros entregados, contra los ~674 de ABI 1 |
| `rt_engine_filter_test` | pasa |
| `rt_engine_skip_test` | pasa — y con ABI 2 confirma la decodificación: con `skip` puesto, `cwd`/`parent_cwd`/`parent_comm` llegan vacíos y `filename` lleno |
| `rt_engine_paths_test` | **pasa** — `ALL OK` sobre los fixtures de bind mount, las cuatro clases de evento con ruta absoluta al mount, y las dos mitades del rename |
| `rt_engine_creds_test` | **falla** — preexistente, ver abajo |

`rt_engine_paths_test` es la que vale: carga el objeto con F1 y F8 dentro y comprueba que las rutas siguen siendo absolutas al mount cruzando bind mounts. El hoisting de la admisión no perdió eventos y el cambio del setattr no rompió la resolución.

### El fallo de `rt_engine_creds_test` es preexistente

`FAIL test/rt_engine_creds_test.c:232: no event was seen from uid 65534 — the test proved nothing`. El hijo baja privilegios a `nobody` y su `open` no genera evento en este host.

Reproducido **idéntico** sobre una copia pristina de `HEAD` (`git archive HEAD`, objeto y motor recompilados desde esas fuentes). No lo causan estos cambios.

### El test del loader hubo que cambiarlo, y era necesario

Con el attach best-effort, 111 asserts del loader fallaban: `expected 2 rungs, got 1`. El fake de libbpf tiene `kprobe/mnt_want_write` como **primera** entrada de su tabla, y los escenarios de escalera 4-6 fallan el attach del programa en el índice 0 — que pasó a ser no fatal. El test codificaba el contrato viejo.

Cambios en `test/rt_engine_loader_test.c`:

- `kprobe/mnt_want_write_file` añadido a la tabla del fake, **al final**: `bits[]` y las condiciones de `fake_load()` son posicionales e insertarlo en medio habría renumerado todo. La selección de la sección nueva se afirma igual que la del índice 0.
- `fake_attach()` ya no cuenta las sondas auxiliares, así que el fallo designado cae sobre un programa emisor y las escaleras 4-6 vuelven a comprobar lo que comprobaban.
- **Escalera 10 nueva**: fallan sólo las sondas auxiliares. Afirma handle no nulo, un solo peldaño, cero líneas de ERROR, y el WARN exactamente cuando la máscara trae `RT_FILE_ATTR_BIT` — que es cuando la sonda llega a seleccionarse.

Sin esto, el gating de la sección nueva —la trampa descrita en §34.1— no tendría ninguna cobertura.

### Tres defectos de tooling que aparecieron por el camino

1. **`shared_modules/ebpf_provider/Makefile`: el target `vmlinux.h` escribía en `bpf/vmlinux.h`.** El nombre del target no es el archivo que produce, así que make lo reejecutaba en cada build y, en un host cuyo `bpftool` no puede volcar BTF, fallaba el build entero **y truncaba a 0 bytes un `bpf/vmlinux.h` perfectamente válido** por la redirección. Arreglado: el target es `bpf/vmlinux.h` y escribe en `$@`.
2. **El googletest vendorizado no configura con CMake 4.** `cmake_minimum_required` de 2.8.12 contra CMake 4.4.2: `Compatibility with CMake < 3.5 has been removed`. Es exactamente lo que anticipa el comentario de `CMakeLists.txt:326-330` del provider. Salida: `export CMAKE_POLICY_VERSION_MINIMUM=3.5` antes del build.
3. **La suite `alert` no enlaza contra una `libsyscheckd_lib.a` construida con `UNIT_TEST=ON`**: `undefined reference to '__gcov_init'`. Salida: `make check EXTRA_LIBS=-lgcov`. No lo arreglé en el Makefile porque la variable ya existe para esto.

### Verificación NO ejecutada, y qué falta

1. **Los objetos prebuilt siguen sin regenerar, y el build falla hasta que lo estén.** F1, F8 y F9 tocan `rt_file.bpf.c` o `rt_event_contract.h`, y el digest de `CMakeLists.txt:171-172` cubre ambos. Todo lo de arriba se hizo con `-DRT_BPF_STRICT_PREBUILT=OFF`. No se pueden regenerar aquí: hace falta un `bpftool btf dump` del kernel del host —esta máquina no tiene `bpftool` funcional— y la verificación de carga sobre la matriz de kernels que registra `prebuilt/x86/rt_file.bpf.o.provenance`. El `vmlinux.h` vendorizado no sirve y nunca ha servido (`prebuilt/README.md`).
2. **El objeto con el que corrieron los tests de kernel se compiló contra un `vmlinux.h` prestado** (el de los selftests de libbpf en otro árbol), no contra el que registra el `.provenance`. Compila, pasa `check_bpf_symbols.sh`, carga y attachea en 6.6 — pero no es el artefacto que se publicaría.
3. **Sólo se probó en un kernel.** 6.6 de WSL2, cgroup v2 unificado, sin BPF LSM activo: el peldaño ejercitado fue el de kprobes. Ni la rama de `bpf_d_path`, ni la de LSM walk, ni cgroup v1, ni los kernels de la familia RHEL.
4. **Nada medido.** Ni el coste del hoisting de F8, ni la frecuencia real del camino por descriptor de F1, ni el coste de la confirmación de F2.

### Tests que estos cambios deberían llevar y no llevan

- **F1**: el gating de la sección nueva y la regla best-effort **ya están cubiertos** (escalera 10 del loader). Falta el caso de kernel: un `fchmod`/`ftruncate` **por descriptor** sobre un filesystem montado aparte, en `test/rt_engine_paths_test.c`. Hoy sus fixtures cambian atributos por ruta, así que pasan igual con el arreglo y sin él — es decir, **no habrían detectado F1**.
- **F2 paso 1**: un `unlink` fallido no debe borrar la fila. Necesita un connector falso que siga reportando el archivo; la suite `tests/alert` ya tiene ese andamiaje y es donde encaja. Las suites `unlink` y `alert` pasan, pero ninguna llega a `ConfirmUnlinkedPaths()`: cubren el planificador y el camino de alerta, no la confirmación.
- **F3**: reconcile en la generación N, publicar N+1, llamar `refreshOne()`, y comprobar que el reconcile completo todavía ocurre. `ci_impl/tests/query_service_test.cpp` usa un refresher falso reducido, así que **no** cubriría esto: hace falta un test del conector de Kubernetes, que no existe.
- **F7**: 4.097 rutas irrelevantes no deben escalar; `/etcpasswd` no debe pasar por `/etc`; una ruta relevante sí; y un reporte de pérdida con nombre irrelevante debe seguir escalando. El filtro vive en `Impl::onEvent`, que ningún test instancia: el fixture de `container_event_router_test` sólo tiene map, staging y router (`:58-63`). (El `PathIsUnder` movido sí quedó comprobado, con asserts.)

---

## 34.11 Lo que no se verificó

- **Nada está medido.** Las pérdidas de resolución de mount son diferencias de código verificadas; con qué frecuencia el VFS toma el camino por descriptor en una carga real, no.
- **El attach de `mnt_want_write_file` se comprobó por símbolo**, no attacheando. `/proc/kallsyms` del 6.6 de esta máquina lo da como `T` global; que libbpf lo attachee sin problema en los kernels soportados está sin probar, y de ahí la recomendación de best-effort.
- **El unroll del walker**: que `#pragma unroll` (`:514`) sea más débil que el unroll forzado de 4.14.11 (`:299-301`) no se probó inspeccionando instrucciones generadas. Queda fuera de esta lista por eso.
- **El provider conserva** ambos caminos de rename, las variantes LSM dpath/walker, la travesía de mounts, credenciales, `login_uid` y el contexto de proceso y padre. No son pérdidas.
