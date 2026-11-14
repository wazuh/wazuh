# 33 — Revisión del `ebpf_provider`: verificación de seis observaciones

Respuesta a seis observaciones de revisión sobre `src/shared_modules/ebpf_provider` y sus consumidores. Cada una se verificó contra el árbol de `37532-ebpf-engine` y, donde correspondía, contra `origin/4.14.11` (`9e60fd2567`), la última release de la línea 4.X.

Contrastado con una lectura independiente hecha con Codex. **Dos de los hallazgos más graves los encontró esa lectura, no la observación original ni la primera lectura de este documento.** Nada está medido: son diferencias de código verificadas y conteos de operaciones, no benchmarks.

---

## 33.0 Resumen

| # | Observación | Veredicto | Clase |
| --- | --- | --- | --- |
| C1 | Registro de longitud fija | **Confirmada, y muy por debajo del problema real** | correctitud + capacidad |
| C2 | Filtro después del walk de rutas | **Confirmada** | rendimiento |
| C3 | Rename desfasado entre engine y consumidor | **Parcialmente confirmada** — el "dos veces por rename" no se sostiene | rendimiento |
| C4 | Filtro de directorios después del staging | **Parcialmente confirmada** — el umbral es 4.097, y el filtro existe más tarde | rendimiento |
| C5 | Carrera en `m_ownersGeneration` | **Confirmada, y es peor que una carrera** | correctitud |
| C6 | Constantes duplicadas kernel/userspace | **Confirmada** — hoy coinciden todas | mantenimiento |

### Severidad real, de mayor a menor

1. **Rutas incorrectas en cambios de atributo por descriptor de archivo** (derivado de C1). Datos erróneos, en silencio.
2. **Sin semántica de operación completada** (derivado de C1). El drain trata un `unlink` de entrada como borrado consumado.
3. **C5** — carrera de datos más un reconcile perdido.
4. **Registro fijo de 12.424 bytes** (C1 tal como se enunció). ~41× de presión de ring innecesaria.
5. **Sin filtro de rutas en kernel** (derivado de C1).
6. **C3** — renames escalan reconciliación de contenedor; el coalescing acota la amplificación.
7. **C4** — ráfagas de rutas irrelevantes fuerzan reconciliación amplia.
8. **C2** — CPU de kernel evitable para cgroups filtrados.
9. **C6** — sólo riesgo de mantenimiento.

---

## 33.1 C1 — Registro de longitud fija: **confirmada, y el problema es mayor**

### Lo que dice la observación

Correcto. [`rt_file.bpf.c:678`](../src/shared_modules/ebpf_provider/bpf/rt_file.bpf.c) reserva `sizeof(*evt)`, y el contrato tiene tres arrays de 4096 bytes. El registro son **12.424 bytes**; con la cabecera de 8 bytes del ring, los 8 MiB alojan **~674 registros**. Los comentarios que dicen 12.416 bytes y ~675 registros están desactualizados.

`modern.bpf.c` en 4.14.11 empaqueta las tres cadenas contiguas y NUL-terminadas en `char paths[3 * MAX_PATH_LEN]`, y envía sólo lo usado:

```c
__u64 size = offsetof(struct file_event, paths) + off;
if (size > sizeof(*evt) || bpf_ringbuf_output(&rb, evt, size, 0))
    return;
```

La cabecera son 112 bytes. Con tres cadenas de 64 bytes, el registro histórico eran **304 bytes contra los 12.424 de hoy: ~41×**.

El cambio no es sustituir el tamaño de la reserva: `bpf_ringbuf_reserve()` exige tamaño constante para el verificador. Hay que armar el registro en un scratch per-CPU (4.14.11 usa `event_heap`) y emitirlo con `bpf_ringbuf_output()`, que copia `size` bytes en vez de comprometer 12.424.

### Lo que la observación no dice: cinco capacidades más que el provider perdió

El plan de retiro de `modern.bpf.c` ([doc 27](27-modern-bpf-retirement-plan.md), resumido en [doc 30 §30.8](30-ebpf-provider-design-summary.md)) registró cuatro **arreglos de defectos** portados *desde* `modern.bpf.c`. No registró que el provider **perdía** estas:

| Capacidad perdida | Evidencia en 4.14.11 | Estado actual e impacto |
| --- | --- | --- |
| **Captura de mount por `mnt_want_write_file`** | `modern.bpf.c:653-659`: lee `f_path.mnt` de un `struct file*` | **No existe en el provider.** Sólo se hookea `kprobe/mnt_want_write` (`rt_file.bpf.c:1010`), que recibe un `vfsmount*`. El VFS llama a una u otra según el camino. |
| **Override de mount por `ATTR_FILE`** | `:726-728`: `if (attr->ia_valid & ATTR_FILE) path.mnt = attr->ia_file->f_path.mnt;` | **No existe.** El setattr del provider (`:1038-1054`) resuelve sólo el dentry y **nunca lee `struct iattr`**; depende por completo de `get_write_mnt()`. |
| **Operación completada, código de retorno y `tid`** | `:35-37, 46-65, 519-551`: `OP_PENDING`/`OP_DONE`, `inflight_map`, `tid` y **tres return probes** que reportan `ret` | **No existe.** El contrato no tiene `tid`, ni operación de cierre, ni estado de retorno. Los hooks reportan intención en la entrada. |
| **Filtro de prefijos de directorio en kernel** | `:147-173, 422-447`: LPM trie, claves de 256 bytes, hasta **16.384 prefijos**, consultado antes de construir el evento | **No existe.** El provider filtra por cgroup, no por ruta. Userspace lo mantenía sincronizado con `sync_monitored_dirs()`. |
| **Unroll forzado del bucle del walker** | `:299-301` | El provider usa `#pragma unroll` (`:514`). Salvaguarda de compilador más débil; **no** es pérdida de capacidad probada sin inspeccionar las instrucciones generadas. |

### Las dos primeras son un fallo de correctitud, no de rendimiento

`mnt_want_write_file()` es el camino del VFS para operaciones **por descriptor de archivo**. Sin ese hook, `write_mnt_map` no tiene entrada para ese tid, `get_write_mnt()` devuelve `NULL`, y el comentario de `rt_file.bpf.c:1021` dice qué pasa entonces: *"NULL lets the walker stop at the filesystem root."*

El resultado es una **ruta relativa al filesystem en lugar de absoluta al mount**, en silencio, sin flag de error y sin contar drop. Y como el provider tampoco tiene el override de `ATTR_FILE`, el camino queda sin ninguna de las dos protecciones que 4.14.11 tenía.

Operaciones afectadas: `fchmod(fd)`, `fchown(fd)`, `ftruncate(fd)`, `futimens(fd)` — es decir, buena parte de la clase `RT_EV_FILE_ATTR`.

### La tercera también

[`container_event_drain.cpp:714`](../src/syscheckd/src/ebpf/src/container_event_drain.cpp) trata un `unlink` de entrada como un borrado consumado. Los hooks son de entrada o de seguridad y no comprueban el retorno, así que **una operación fallida puede provocar una reconciliación o un borrado incorrectos**. 4.14.11 cerraba el ciclo con `OP_DONE` y el valor de retorno desde las return probes.

Esto convierte lo que el [doc 31 §31.4.2](31-ebpf-engine-as-platform-open-questions.md) planteaba como pregunta abierta de diseño en **una regresión con implementación de referencia funcionando**.

### Arreglo mínimo

Por orden de severidad, no de esfuerzo:

1. Restaurar `kprobe/mnt_want_write_file` y su gating en el loader (`rt_engine.c:438, 476` nombran sólo `mnt_want_write`).
2. Restaurar la extracción de `iattr` consciente de la posición del argumento, y el override de mount por `ATTR_FILE`.
3. Restaurar el reporte de completado y el `tid`; liberar la operación pendiente sólo tras un completado exitoso. **Un timeout no establece éxito.**
4. Registro compacto: armarlo en scratch per-CPU y emitir la longitud usada. Cambiar decodificación y ABI juntos; tocar sólo el tamaño de la reserva es incorrecto.
5. Filtro de prefijos opcional por handle, conservando la validación en userspace: un prefijo truncado define un superconjunto.

El punto 4 obliga a regenerar los objetos prebuilt en el mismo commit.

---

## 33.2 C2 — El filtro corre después del walk: **confirmada**

`event_is_wanted()` sólo se evalúa dentro de [`submit_event()`](../src/shared_modules/ebpf_provider/bpf/rt_file.bpf.c) (`:671-673`), y todos los sitios de llamada ya resolvieron la ruta: open `:803`→`:809`, LSM open `:832`→`:837`, rename `:967`→`:972`, setattr `:1056`→`:1062`, unlink `:1089`→`:1095`.

**Matiz que la observación omite:** el filtro ahorra más que la reserva. Un cgroup rechazado también se ahorra la recolección de metadatos, la copia, y **hasta dos walks adicionales de `cwd`** (`:685-759`). Lo que sí paga es la resolución de la ruta disparadora — hasta 320 iteraciones del walker.

El hook de bookkeeping `mnt_want_write` no hace walk ni submit, y los hooks rechazan aperturas de sólo lectura, no-regulares y entradas inválidas antes de caminar. El coste es real; su magnitud no está medida.

**Arreglo mínimo, y es viable:** `current_container_cgroup_id()` (`:338-348`) lee sólo `filter_cfg` y `bpf_get_current_cgroup_id()` — **no depende de la ruta resuelta**. Se puede evaluar la admisión después de los chequeos baratos propios de cada hook y antes de resolver la ruta, pasando el `cgroup_id` ya resuelto a `submit_event()`. Hay que aplicarlo a todas las variantes emisoras y dejar intacto el bookkeeping de mounts.

Esto además corrige la imprecisión del [doc 30 §30.5](30-ebpf-provider-design-summary.md), que dice que el evento se descarta "antes de intentar la reserva de 12.424 bytes": cierto sobre la reserva, pero el walk dominante ya se pagó.

---

## 33.3 C3 — Rename desfasado: **parcialmente confirmada**

### Lo confirmado

El engine emite ambos extremos en las tres implementaciones: LSM dpath `:944` y `:952`, LSM walker `:976` y `:984`, kprobe `:1164` y `:1170`. El contrato lo documenta explícitamente (`rt_event_contract.h:51`: dos registros sin orden garantizado).

Pese a eso, los comentarios del router siguen afirmando lo contrario. Verbatim en [`container_event_router.hpp:92`](../src/syscheckd/src/ebpf/include/container_event_router.hpp): `/* renames escalated (source path is never reported) */`, y el bloque largo alrededor de `:205-225` razona sobre la misma premisa. [`container_event_drain.cpp:700-706`](../src/syscheckd/src/ebpf/src/container_event_drain.cpp) descarta la ruta de ambos extremos y escala.

No hay flag de extremo. **Un bit entra en los 16 de `flags`** — hoy se usan 2 — sin cambiar los 12.424 bytes. También está `_reserved0` entero libre.

### La corrección cuantitativa

**"Dos veces por rename" no se sostiene.** Hay dos llamadas de escalada y dos incrementos de contador, pero [`container_event_staging.hpp:349`](../src/syscheckd/src/ebpf/include/container_event_staging.hpp) deduplica contenedores sospechosos en un set. Si ambos registros llegan antes de que el consumidor consuma, producen **un** re-walk. Dos son posibles sólo si el consumo los separa; no están garantizados.

El propio bloque de comentario del router ya lo explica: *"Suspect is a set keyed by container in the staging buffer, so any number of renames between two consumer batches coalesces into one re-walk."*

### El arreglo propuesto es insuficiente tal cual

El comentario del router propone un arreglo **peor**: anexar la ruta origen al registro, lo que lo llevaría de 12.416 a ~16.512 bytes. El bit es mejor. Pero un bit solo no alcanza:

**No se puede rutear el registro de origen a un borrado incondicional.** Son hooks de entrada, la operación puede fallar, y los extremos no tienen orden. Un borrado dirigido seguro necesita semántica de completado y éxito — es decir, depende del punto 3 de §33.1 — o una reconciliación de alcance acotado capaz de establecer ausencia.

Arreglo mínimo correcto: marcar los registros de origen, conservar las rutas de destino, enseñar a los consumidores a reconciliar ambos extremos, y **preservar la escalada como respaldo** para registros antiguos o sin marcar.

---

## 33.4 C4 — Filtro de directorios después del staging: **parcialmente confirmada**

### Lo confirmado

El drain reenvía rutas sin filtrar por directorio monitorizado (`container_event_drain.cpp:708-727`); el router las stagea directamente (`container_event_router.hpp:122, 153`). Whodata sí filtra en su sink, antes de encolar (`ebpf_whodata.cpp:157`).

Al desbordar, se tira el set y se marca el contenedor como Suspect, lo que fuerza un re-walk completo (`container_event_staging.hpp:250-258`).

### Las dos correcciones

1. **El filtro existe, sólo que más tarde.** Corre en la reconciliación del consumidor: `SelectReconcilePaths` en [`container_baseline_fim.cpp:1245`](../src/syscheckd/src/ebpf/src/container_baseline_fim.cpp), invocado después del staging en `:1460`. La observación dice "va después del staging", que es exacto; decir que el drain no filtra sería incorrecto.

2. **El umbral es 4.097, no 4.096.** El presupuesto por defecto es `max_paths_per_container{4096}` (`container_event_drain.hpp:86`), y `staging:250` compara el tamaño **antes** de insertar: 4.096 rutas pendientes distintas entran, la 4.097ª escala. Además tienen que **acumularse para el mismo contenedor antes de que el consumo retire trabajo**. Generar 4.096 rutas a lo largo del tiempo no garantiza un walk.

**Precisión sobre el impacto:** actividad enteramente fuera de directorios monitorizados puede consumir memoria de staging y forzar un walk de los directorios configurados del contenedor. Es trabajo innecesario — no es que se escanee `/tmp`.

**Arreglo mínimo:** un snapshot cacheado y thread-safe de las reglas de ruta configuradas del contenedor, para rechazar rutas irrelevantes antes de stagear. Aplicarlo a rutas modificadas y borradas, conservando el manejo de pérdida por separado, y sin recolectar configuración ni tocar el filesystem desde el hilo del drain.

---

## 33.5 C5 — Carrera en `m_ownersGeneration`: **confirmada, y es peor**

[`kubernetes_connector.hpp:59-64`](../src/wazuh_modules/container_instances/ci_impl/src/kubernetes/kubernetes_connector.hpp) declara el bloque como *"Connector-thread state (watch sink and reconcile run on it exclusively)"*, y `m_ownersGeneration` es un `std::uint64_t` plano dentro de él.

Su significado es **la generación de ownership con la que la reconciliación completa reconstruyó el set entero de records**:

| Línea | Hilo | Qué hace |
| --- | --- | --- |
| `:94` | conector | reconcile completo registra la generación antes de leer el snapshot |
| `:153` | conector | el watch detecta una generación mayor y marca `m_reconcilePending` |
| `:203` | conector | en arranque, detecta actualizaciones y llama `reconcile()` |
| `:287` | **IPC** | `refreshOne()` **pisa la marca** refrescando un solo contenedor |

Los workers IPC llegan por `ipc_server.cpp:180-195, 234` → [`query_service.cpp:215`](../src/wazuh_modules/container_instances/ci_impl/src/ipc/query_service.cpp) → `refreshOne()`. La línea 287 corre por tanto contra los accesos del hilo del conector, y potencialmente contra otros refrescos IPC.

**Más allá de la carrera de datos, hay un bug lógico independiente.** Si el reconcile completo contabilizó la generación N, un refresco IPC en N+1 deja la marca en N+1 mientras los demás contenedores siguen en N. Los chequeos de igualdad de `:153` y `:203` dan falso y **se pierde el reconcile completo**: los demás contenedores quedan con atribución de owner obsoleta hasta que la generación vuelva a moverse.

**Arreglo mínimo: borrar la línea 287.** `refreshOne()` sigue leyendo `latest()` para su propio record; sólo la reconciliación completa debe avanzar la marca. Hacer el campo atómico eliminaría la carrera y **dejaría el bug lógico intacto** — no es el arreglo.

---

## 33.6 C6 — Constantes duplicadas: **confirmada, hoy coinciden**

| Constante | BPF | Userspace | ¿Coinciden? |
| --- | --- | --- | --- |
| `FILTER_CFG_KEY_MODE` | `rt_file.bpf.c:198` | `rt_engine.c:47` | 0 = 0 |
| `FILTER_CFG_KEY_SKIP` | `:199` | `:48` | 1 = 1 |
| `FILTER_CFG_KEY_V1_SUBSYS` | `:209` | `:52` | 2 = 2 |
| `RT_V1_SUBSYS_MAX` | `:214` | `:53` | 64 = 64 |
| `RT_SKIP_PROC_CONTEXT` | `:217` | `rt_engine.h:109` | `1u << 0` |
| `RT_CGROUP_MODE_ALL` | `:192` | `rt_engine.h:115` | 0 = 0 |
| `RT_CGROUP_MODE_ALLOWLIST` | `:193` | `rt_engine.h:129` | 1 = 1 |

No hay desajuste de comportamiento verificado hoy. Es riesgo de mantenimiento sobre claves de mapa, cotas y la interpretación del modo.

**Arreglo mínimo, con una trampa concreta.** Mover los macros enteros y el **`enum rt_cgroup_mode` completo** al header compartido, borrando los duplicados. La trampa: `RT_CGROUP_MODE_*` son `#define` del lado BPF y **enumeradores** en `rt_engine.h`. Añadir los macros al header compartido dejando los enumeradores con el mismo nombre rompe la declaración del `enum` por sustitución de macro. Hay que mover el enum, no duplicarlo como macros.

Macros enteros y enums de C no requieren `stdint.h` ni biblioteca hospedada, así que los movimientos son seguros para la compilación freestanding con `clang -target bpf` descrita en `rt_event_contract.h:9-18`. No hay cambio de layout ni de versión de ABI.

---

## 33.7 Correcciones a documentos previos de esta serie

1. **[Doc 30 §30.5](30-ebpf-provider-design-summary.md)** sobredeclara lo que ahorra el modo allowlist: ver §33.2.
2. **Doc 30 §30.8** presenta el retiro de `modern.bpf.c` como una migración que portó sus arreglos. Portó cuatro arreglos de defectos y **perdió cinco capacidades**, tres de ellas con consecuencias de correctitud: ver §33.1.
3. **[Doc 31 §31.1.2](31-ebpf-engine-as-platform-open-questions.md)** plantea el registro de tamaño variable como decisión de diseño a futuro. Es una regresión a recuperar.
4. **Doc 31 §31.4.2** plantea "intentos vs operaciones confirmadas" como pregunta abierta. 4.14.11 ya lo resolvió.
5. **[Doc 32](32-single-load-vs-multi-load-comparative-design.md)** calcula toda la presión de ring sobre el registro fijo de 12.424 bytes, así que con un registro compacto esos números caen ~41×. No cambia nada de diseño: aquel documento es exploratorio y ya concluye quedarse en N cargas (opción A), que es el diseño vigente. Lo que cambia es que el argumento que allí se construye para B2 se debilita todavía más.
6. **Comentarios desactualizados** que citan 12.416 bytes y ~675 registros: el valor actual es 12.424 y ~674.

---

## 33.8 Lo que no se verificó

- **Nada está medido.** Las pérdidas de resolución de mount son diferencias de código verificadas; su frecuencia depende del camino de llamada del kernel y de la carga, y no se midió.
- **El unroll del walker**: que `#pragma unroll` sea más débil que el unroll forzado de 4.14.11 no se probó inspeccionando las instrucciones generadas.
- **El provider conserva** ambos caminos de rename, las variantes LSM dpath/walker, la travesía de mounts, credenciales, `login_uid` y el contexto de proceso y padre. Esas no son pérdidas.
