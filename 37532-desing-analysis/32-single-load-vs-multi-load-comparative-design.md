# 32 — Diseño comparativo: una carga compartida vs N cargas

Documento de decisión. Compara el diseño actual del motor `ebpf_provider` — **una carga del objeto BPF por consumidor** (spike #37396 ADR-001) — contra la alternativa de **una sola carga compartida** por todos los consumidores.

El estado actual está en [`30-ebpf-provider-design-summary.md`](30-ebpf-provider-design-summary.md); los puntos abiertos a escala de plataforma, en [`31-ebpf-engine-as-platform-open-questions.md`](31-ebpf-engine-as-platform-open-questions.md) §31.2. Este documento resuelve §31.2.1 y §31.2.3 hasta donde se puede sin medir.

Todo lo afirmado viene de leer el árbol de `37532-ebpf-engine`. El contenido se contrastó con una lectura independiente hecha con Codex, lanzada sin las conclusiones de esta lectura para que no quedara anclada. **Nada de esto está medido**: son conteos de operaciones y capacidades declaradas de mapas, no tiempos de CPU ni asignación real de kernel.

---

## 32.1 No son dos opciones, son tres

| | |
| --- | --- |
| **A — N cargas** (actual) | Cada consumidor llama `rt_open()` y recibe su propia carga del objeto, sus propias instancias de todos los mapas, sus propios programas attacheados y su propio ring buffer. |
| **B1 — Carga única ingenua** | Un `rt_open()`, un handle compartido, un hilo de poll, fan-out en userspace. La configuración de filtro es una sola para todos. |
| **B2 — Carga única con filtrado por suscriptor** | Un load, programas attacheados una vez, pero `filter_cfg` y `rb` dejan de ser globales y pasan a ser por suscriptor. Requiere cambiar el programa BPF. |

Separarlas importa porque **B1 y B2 tienen signos opuestos**: B1 es una regresión, B2 es una mejora. Tratarlas como "la opción de carga compartida" lleva a la decisión equivocada.

---

## 32.2 El hecho que estructura la comparación

`filter_cfg` es un `BPF_MAP_TYPE_ARRAY` de **3 entradas globales, una instancia por carga del objeto**, leído en cada evento ([`rt_file.bpf.c:198-209`](../src/shared_modules/ebpf_provider/bpf/rt_file.bpf.c)):

| Clave | whodata | drain |
| --- | --- | --- |
| `FILTER_CFG_KEY_MODE` (0) | `RT_CGROUP_MODE_ALL` | `ALLOWLIST` (default `true`, con retry a `ALL`) |
| `FILTER_CFG_KEY_SKIP` (1) | `0` | `RT_SKIP_PROC_CONTEXT` |
| `FILTER_CFG_KEY_V1_SUBSYS` (2) | nunca lo escribe | lo escribe en hosts v1 puros |

Fuentes: `ebpf_whodata.cpp:501-507`, `container_event_drain.cpp:1523-1553`, `container_event_drain.hpp:154`.

Una carga compartida tiene **un solo valor de cada clave**, y en las dos primeras los consumidores piden cosas incompatibles. La regla que resulta es la misma en ambos casos, aunque la operación lógica sea distinta:

- **`MODE` es la unión de las admisiones.** `ALL` domina mientras whodata esté suscrito. El drain **pierde el filtrado en kernel** y su allowlist se degrada a un filtro de userspace.
- **`SKIP` es la intersección de las máscaras.** Sólo se puede omitir trabajo que *nadie* necesita. El `0` de whodata domina. Todo evento paga los dos walks de dentries de `cwd` y `parent_cwd`, incluidos los que sólo lee el drain — que es exactamente lo que `skip_mask` existe para evitar.

En las dos, **gana la política más cara**.

### Un riesgo de corrección, no sólo de rendimiento

Con un handle compartido ingenuo, el drain llamando `rt_set_cgroup_mode(ALLOWLIST)` escribe el mapa global y **deja ciego a host whodata en silencio**: whodata dejaría de recibir todo evento fuera de la allowlist de contenedores. Hoy no puede pasar porque cada handle tiene su propio mapa. Cualquier B1 tiene que convertir esa llamada en "cambiá tu suscripción", no "escribí el modo del kernel".

`rt_set_cgroup_v1_subsys()` tiene el mismo problema en menor grado: pasa a ser política de identidad de cgroup de todo el proveedor. Hoy whodata no lee `cgroup_id` (`ebpf_whodata.cpp:157-172`), así que los dos consumidores actuales lo toleran, pero el arranque tendría que impedir que el drain reciba registros creados antes de instalar esa política.

---

## 32.3 Coste por evento

Para una operación de archivo en el nodo, con los dos consumidores activos y el allowlist **admitiendo** el evento:

| | walks disparadores | walks de proc-context | reservas de 12.424 B |
| --- | --- | --- | --- |
| **A (hoy)** | 2 — un hook attacheado por carga | 2 (sólo la instancia de whodata) | 2 |
| **B1** | 1 | 2 (`SKIP` intersecado a 0) | 1 |
| **B2** | 1 | 2, sólo para el suscriptor que no hace skip | 1 por suscriptor que lo quiera |

**En la ruta de walker manual, B reduce las invocaciones de walk en 25 %, no en 50 %**: de 4 a 3. El drain ya se ahorra los dos walks de `cwd` con `RT_SKIP_PROC_CONTEXT`, así que lo único duplicado es el walk disparador.

Cuando el allowlist **rechaza** el evento, A ya hace una sola reserva — pero **resuelve el nombre de archivo dos veces igual**, por la razón de §32.7.

Son conteos de operaciones, no porcentajes de CPU. La profundidad de ruta, el coste de los helpers, la contención y la mezcla de eventos necesitan medición. B además agrega despacho en userspace y posiblemente copias de cola.

---

## 32.4 Memoria de kernel por carga

| Mapa | Tipo | Capacidad declarada |
| --- | --- | --- |
| `rb` | `RINGBUF`, `1 << 23` | **8 MiB** |
| `heaps_map` | `PERCPU_ARRAY`, 2 × 32 KiB | **64 KiB × CPUs posibles** |
| `dpath_map` | `PERCPU_ARRAY`, 1 × 4 KiB | **4 KiB × CPUs posibles** |
| `write_mnt_map` | `LRU_HASH`, 16.384 × (8+8) | 256 KiB |
| `cgroup_drops_map` | `HASH`, 4.096 × (8+4) | 48 KiB |
| `cgroup_allow_map` | `HASH`, 4.096 × (8+1) | 36 KiB |
| `filter_cfg`, `drops_map`, `dpath_map` | `ARRAY` | triviales |

**`8 MiB + 68 KiB × CPUs posibles` por carga.** Son *CPUs posibles*, no online: los mapas per-CPU reservan para `num_possible_cpus()`, que en muchas VMs excede a los online.

Con 64 CPUs posibles, 12,25 MiB por carga:

| | 2 consumidores |
| --- | --- |
| A | ~24,5 MiB |
| B1 | ~12,25 MiB |
| B2 | ~16,5 MiB — un scratch compartido, pero **dos rings de 8 MiB** |

B2 no ahorra los rings a propósito: rings separados son lo que impide que un consumidor lento frene al otro.

Son capacidades declaradas. Faltan metadata de hash, alineación, redondeo de página, páginas de control del ring, mapas internos generados y memoria de programa/JIT.

---

## 32.5 Mecánica de entrega: lo que el ring buffer permite

`BPF_MAP_TYPE_RINGBUF` es **multi-productor, consumidor único**: muchas CPUs producen en un ring, pero hay **una sola posición de consumidor**. No ofrece cursores independientes por suscriptor, ni acuses, ni replay. Dos lectores de libbpf sobre el mismo mapa **no son una suscripción broadcast**: un lector serializado avanza la posición para todos, y lectores concurrentes no establecen semántica de multicast soportada.

De ahí se sigue lo único que no es negociable: **B necesita un lector del ring que haga fan-out explícito**. No existe la opción "que cada consumidor lea el mismo ring".

Para B1 hay dos formas de despachar:

| Despacho | Beneficio | Coste |
| --- | --- | --- |
| Llamar los sinks de todos los suscriptores sincrónicamente | implementación chica; un registro lo inspecciona cada sink | **cualquier sink lento frena al lector compartido** |
| Encolar por suscriptor | backpressure acotado y poll independiente | capacidad de cola, propiedad, sincronización y contabilidad de pérdida por suscriptor |

El puntero al ring mapeado no sobrevive al retorno del callback, así que la entrega asincrónica necesita copia o almacenamiento propio.

Los dos consumidores actuales ya mueven el trabajo aguas abajo — whodata copia campos a `kernelEventQueue` (`ebpf_whodata.cpp:157-180`), el drain enruta desde su callback (`container_event_drain.cpp:687-727`) — lo que hace plausible el despacho sincrónico. **Pero eso no demuestra que los callbacks estén lo bastante acotados como para preservar la garantía de aislamiento de ADR-001.**

B2 no tiene este problema: el kernel hace N reservas, una por suscriptor interesado, y cada uno lee su propio ring. Cero copias en userspace.

---

## 32.6 Drops y atribución

En A la pérdida de kernel es independiente por handle: fallo de reserva incrementa `drops_map` e intenta la contabilidad por cgroup; un evento posterior lee-y-resta el contador global y lleva `dropped` + `RT_F_DROPS_BEFORE`. `rt_drain_drops()` drena destructivamente hasta 512 claves por llamada.

Los dos consumidores ya tratan la pérdida de forma **asimétrica**: el drain drena por cgroup y enruta para reconciliación; whodata no lee ningún campo de drop del kernel y sólo loguea una vez el desborde de su propia cola.

Para B:

- Una pérdida por fallo de reserva en el kernel afecta a **todos** los suscriptores interesados.
- **Exactamente un dueño** puede drenar el mapa de drops. Darles a los dos el drenaje destructivo de hoy haría que uno consumiera la evidencia del otro.
- El desborde de cola de un suscriptor debe contarse aparte de la pérdida compartida de kernel, y no debe marcar a otro suscriptor como habiendo perdido el evento.
- Una pérdida de kernel en cgroups que sólo le interesan a whodata **no debe disparar recuperación en el drain**.
- Los contadores por cgroup actuales no llevan tipo de evento, ruta ni identidad de suscriptor, así que no pueden atribuir con exactitud para suscripciones futuras por tipo o por ruta.

Límites que siguen en pie en cualquier opción: un mapa por cgroup lleno pierde atribución, y el camino de respaldo lookup-seguido-de-delete puede perder incrementos concurrentes.

---

## 32.7 Aislamiento de fallos, ciclo de vida y concurrencia

En A cada handle tiene objeto, ring, links y estado de callback propios. Un `rt_open()` fallido desarma sólo ese handle. Hoy el drain, si el objeto no trae los mapas de filtrado, **se niega a abrir y reintenta en `ALL`** sin tocar a whodata.

El aislamiento ya tiene límites: ambos comparten proceso, presupuesto de recursos de kernel y el binding de libbpf a nivel de proceso (bajo mutex, gana el primero, fallo pegajoso). Un crash en un callback ya se lleva a los dos.

Ninguna función de la API se vuelve segura por compartir un puntero:

- `rt_poll()` sobrescribe `current_sink` / `current_user` y entra al lector del ring **sin lock**; el poll concurrente sobre un handle está explícitamente no soportado.
- `rt_drain_drops()` muta estado del handle y drena destructivamente; concurrente tampoco.
- `rt_close()` no coordina con operaciones en vuelo.

B necesita por eso separar **propiedad del proveedor** de **propiedad de la suscripción**: inicialización serializada, referencias de suscripción, protección de callbacks en vuelo, baja que espere a que el callback termine, y teardown final sólo después del último suscriptor. **Un refcount solo no evita la carrera close-contra-callback.**

Un detalle con nombre propio: el **healthcheck de whodata** comparte handle con su loop de poll a propósito, porque reabrir desattachearía y perdería los eventos del intervalo. Con carga compartida, sus cuatro acciones sintéticas se entregarían también al drain, que vería los archivos sonda. Y mientras espera su sonda, whodata no debe drenar los registros del drain. B2 lo resuelve con filtro por suscriptor; B1 necesita una excepción explícita.

---

## 32.8 Escalera de fallback

La escalera real es más precisa que "probar tres variantes":

1. Si `bpf` no está en la lista de LSM activos → directamente kprobes.
2. Si está → LSM d_path.
3. Un **rechazo de carga** (verificador) habilita el reintento con LSM walk.
4. Un **fallo de attach** salta ese reintento intermedio y va a kprobes.
5. Cada intento fallido se desarma antes del siguiente.

Todas las variantes mantienen el requisito de ring buffer: no hay respaldo a perf buffer. El éxito en LSM conserva igual los kprobes de setattr y `mnt_want_write`.

En A cada apertura negocia por separado. En B el proveedor negocia **una vez**, para la unión de programas. Ganancia pequeña: también garantiza que todos los consumidores corran sobre el mismo peldaño, hoy no garantizado por construcción.

Contrapartida futura: con máscaras distintas, un hook nuevo no soportado podría forzar un fallback de todo el proveedor y una recarga. Cambiar el set vivo necesita una política explícita de hueco de eventos y recuperación; mutar el autoload de un objeto ya cargado **no** implementa esa transición.

---

## 32.9 Qué hay que construir

| Área | B1 (mínimo) | B2 |
| --- | --- | --- |
| `rt_file.bpf.c` | **Ningún cambio.** El superconjunto de los dos consumidores de hoy es: cargar todas las clases, modo `ALL`, computar contexto de proceso. | `filter_cfg` por suscriptor; `rb` pasa a `ARRAY_OF_MAPS` de ringbufs; `submit_event()` itera suscriptores con un límite visible al verificador; `cgroup_allow_map` y `cgroup_drops_map` por suscriptor. |
| `rt_engine.h` | Semántica proveedor vs suscripción; revisar la promesa de cargas independientes; especificar propiedad de callbacks, filtrado, poll, cierre, drenaje de drops y comportamiento ante fallo compartido. | Lo mismo, más id de suscriptor en toda llamada que hoy escribe `filter_cfg` o los mapas de cgroups. |
| `rt_engine.c` | Registro y propiedad del proveedor, un lector del ring, despacho a suscripciones, agregación de configuración, propiedad de la allowlist, colas por suscriptor o contrato de callback acotado, distribución de pérdida, teardown seguro. | Lo mismo, más refcount de carga y `rt_open()` dividido en "cargar si hace falta" + "suscribir". |
| Consumidores | Reemplazar propiedad del ring por propiedad de la suscripción, preservando la secuencia del healthcheck de whodata y el arranque/filtro/fallback del drain. | Igual. |
| ABI | **No cambia** para el diseño mínimo. | Cambio de contrato de mapas con el objeto → regenerar los prebuilts en el mismo commit. |

El B1 mínimo puede vivir **dentro de `libfimebpf.so`**: un broker que abre un handle del motor existente y despacha a los caminos de consumidor que ya existen, sin tocar la API pública ni el programa BPF. Sigue necesitando ciclo de vida de suscriptores, ruteo de drops y una decisión explícita sobre el acoplamiento sincrónico de callbacks.

---

## 32.10 Las dos mejoras pequeñas que no requieren decidir nada de esto

**1. Admisión temprana — la mejora de CPU más barata, y conserva A.**

Hoy `event_is_wanted()` corre **dentro** de `submit_event()` (`rt_file.bpf.c:673`), y todos los sitios de llamada ya resolvieron `full_path` antes de llamarlo. El walk de dentries que dispara el evento **ya se pagó** cuando el filtro decide descartar.

`current_container_cgroup_id()` (`rt_file.bpf.c:338-348`) lee sólo `filter_cfg` y `bpf_get_current_cgroup_id()`: **no depende del nombre de archivo resuelto**. Mover el chequeo de admisión al principio de cada hook, antes del walk, es por lo tanto viable.

Con una allowlist dispersa, eso elimina casi todos los walks redundantes del drain sobre tráfico rechazado — que es el principal walk extra que B eliminaría. No ahorra memoria de mapas ni invocaciones de hook, y el beneficio se encoge a medida que sube la fracción admitida.

**Esto además corrige una imprecisión del doc 30 §30.5**, que dice que en modo allowlist el evento se descarta "antes de intentar la reserva de 12.424 bytes". Es cierto respecto de la reserva, pero se lee como si se evitara todo el coste, y el coste dominante en la ruta kprobe es el walk que ya se hizo.

**2. Dimensionar el ring por consumidor.**

`bpf_map__set_max_entries` no se usa en ninguna parte del motor: el ring son 8 MiB fijos para todos. Whodata (`skip_mask = 0`, todo el nodo) y el drain (filtrado en kernel) tienen necesidades muy distintas. Una llamada entre `bpf_object__open_file()` y `bpf_object__load()`, más un campo `ring_bytes` en `rt_filter`, lo resuelve sin tocar nada de lo anterior.

---

## 32.11 Recomendación

**Quedarse en A.** Y hacer la admisión temprana si la duplicación de walks preocupa.

- **B1 no es una mejora.** Cambia un walk disparador por evento (25 %) por: pérdida del filtrado en kernel del drain, `skip_mask` neutralizado, drops no atribuibles por consumidor, un sink lento que frena a todos, y el riesgo de que una llamada del drain deje ciego a whodata. Compartir el handle de hoy sin implementar fan-out sacrifica corrección y aislamiento sin comprar nada.
- **B2 sí es mejor que A en todos los ejes salvo complejidad del programa BPF**, pero sólo se paga si N crece.

**La condición que invierte la respuesta** es cuantitativa y hoy no está medida: cuántos consumidores solapados habrá, y cuánto cuesta realmente un hook attacheado de más por evento en un host ocupado. Con N=2 el ahorro de B2 es un walk disparador por evento y ~8,25 MiB. Con N=5 son cuatro walks por evento y ~49 MiB, y la respuesta probablemente se invierte — siempre que el diseño incluya backpressure acotado por suscriptor y entrega explícita de la pérdida.

---

## 32.12 Hallazgos secundarios de esta lectura

1. **Doc 30 §30.5** sobredeclara lo que ahorra el modo allowlist: ver §32.10.
2. **`container_event_drain.cpp:702`** lleva un comentario obsoleto: *"The event names the destination only; the source path is never reported by anything."* El productor actual emite **dos** registros de rename, origen y destino, desde programas independientes (`rt_event_contract.h:51`, `rt_file.bpf.c:944-1173`). El callback escala cualquiera de los dos por cgroup.
3. **`dropped` no es un contador acumulado**, pese al comentario del campo: `take_drop_counter()` hace lectura-y-resta, así que es el delta consumido desde el evento anterior que lo leyó.
