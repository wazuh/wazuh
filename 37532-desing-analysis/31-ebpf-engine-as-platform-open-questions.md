# 31 — `ebpf_provider` como plataforma: preguntas y definiciones de diseño pendientes

Documento de preparación para una reunión de diseño. Parte de una hipótesis explícita:

> `librt_engine` deja de ser el loader de FIM y pasa a ser **el único punto de generación de eventos BPF del agente**, consumido por todos los módulos que necesiten telemetría de kernel (FIM, contenedores, inventario / IT Hygiene, SCA, detección de ejecución, red, respuesta activa, …).

El estado actual está descrito en [`30-ebpf-provider-design-summary.md`](30-ebpf-provider-design-summary.md); este documento **no lo repite**. Los puntos abiertos de §30.10 son los del módulo tal como está hoy, con dos consumidores dentro de `wazuh-syscheckd`. Lo que sigue son las preguntas que **sólo aparecen al escalar a N módulos** y que hoy no tienen respuesta en el árbol.

Cada entrada lleva: la pregunta, el hecho del código que la hace inevitable, y qué hay que decidir.

---

## 31.0 Decisiones que caducan

Estas son baratas hoy y caras después de que exista el segundo o tercer módulo consumidor. Si la reunión sólo alcanza para algunas, son éstas:

| # | Decisión | Por qué caduca |
| --- | --- | --- |
| 31.1.2 | Forma del registro: tamaño fijo por clase vs. cabecera + payload variable | Cambiar el layout es `RT_ABI_MAJOR`, y cada major obliga a recompilar y re-liberar todos los consumidores a la vez |
| 31.4.1 | Flag de truncamiento / contador de fallos de resolución de ruta | Es aditivo (`rt_flags` + un contador): hoy sube `MINOR`; después de que un módulo infiera "sin evento = sin cambio", es un cambio de semántica |
| 31.5.1 | Chequeo de `MINOR` en `rt_open()` | Con un consumidor por módulo, el skew de minor pasa a ser el caso normal; agregar el campo al `rt_filter` ahora es aditivo |
| 31.2.1 | ADR-001 (una carga por consumidor) como estado final o como etapa | Determina si la API debe prever hoy un identificador de consumidor; retrofitearlo toca todas las firmas |
| 31.6.1 | Dueño del contrato y proceso de cambio | Sin dueño declarado, el primer módulo nuevo lo extiende para su caso y fija el precedente |

---

## 31.1 Alcance y forma del contrato de evento

**31.1.1 — ¿Qué clases de evento entran, y en qué orden?**
`rt_event_contract.h` declara el alcance actual como "FILE event classes only", y dice que process-exec y red son "a separate issue's scope". Si el motor es la plataforma, esa lista deja de ser una nota y pasa a ser el roadmap. Candidatas obvias: `EXEC`, `CONNECT`/`ACCEPT`, `DNS`, `MODULE_LOAD`, `PTRACE`/`BPF` (auto-protección), cambios de credenciales.
**Decidir:** la lista, el orden, y qué módulo es el consumidor de referencia de cada una (una clase sin consumidor concreto se diseña mal).

**31.1.2 — ¿Registro de tamaño fijo por clase, o cabecera común + payload variable?**
Hoy `struct rt_file_event` son **12.424 bytes fijos**, de los cuales **12.288 son tres buffers `char[4096]`** (`filename`, `cwd`, `parent_cwd`). El contrato dice que una clase futura tendría "su propia struct y su propio valor de tipo". Eso funciona para FILE; para `EXEC` con `argv`/`envp`, o para una clase de red de ~64 bytes útiles, el patrón de tamaño fijo es malo en los dos extremos: el registro de red desperdicia el ring, y `argv` no tiene cota natural.
**Decidir:** ¿se mantienen structs fijas por clase, o se pasa a `struct rt_event_header` + payload variable (longitud declarada) antes de que haya más de una clase viva? Es la decisión de ABI más cara de revertir.

**31.1.3 — ¿Un `.bpf.o` por dominio, o uno monolítico?**
Hoy hay un objeto con **14 programas**. `select_programs()` apaga con `set_autoload(false)` lo que el `type_mask` no pide, pero `bpf_object__open_file()` sigue parseando el objeto entero y los mapas de todas las clases se crean igual. Con exec + red + file en un solo `.bpf.o`, cada consumidor paga el open y los mapas de todo.
**Decidir:** granularidad del artefacto. Afecta directamente a 31.7 (prebuilts: hoy son dos binarios commiteados; con cuatro dominios son ocho).

**31.1.4 — `RT_MAX_LINKS` es 16 y es una constante de compilación.** *(prioridad baja)*
`src/rt_engine.c:320` fija la capacidad del array de `bpf_link` del handle. El objeto tiene 14 programas, pero `select_programs()` deja con autoload sólo una variante, así que el **máximo attacheado por handle hoy es 6** en ambos modos:

- kprobe: `vfs_open`, `security_inode_setattr`, `vfs_unlink`, `vfs_rename` ×2, `mnt_want_write`
- LSM: `file_open_*`, `path_unlink_*`, `path_rename_*` ×2, más `kprobe/security_inode_setattr` (ATTR no tiene variante LSM) y `mnt_want_write`

Quedan **10 slots libres**, así que no es urgente. Lo que importa es el modo de fallo: pasarse no degrada, hace que `rt_open()` devuelva NULL (`abort_open()`), y la constante sólo se puede cambiar recompilando el motor. Un dominio nuevo con muchos hooks (red, con su propio par por variante) lo agotaría de golpe.
**Decidir:** subirlo preventivamente, hacerlo dinámico, o declarar que cada dominio va en su propio objeto/handle (31.1.3), en cuyo caso el límite por handle deja de ser el binding.

---

## 31.2 Modelo de proceso: N cargas vs. multiplexado

**31.2.1 — ADR-001 ("un consumidor = una carga = un ring buffer"): ¿estado final?**
Es la decisión estructural más consecuente del módulo. Con dos consumidores el coste ya es: dos cargas del mismo objeto, dos ring buffers de **8 MiB** (`1 << 23`), dos juegos de probes attacheados al mismo kprobe, dos hilos de poll. Con seis módulos son ~48 MiB de ring sólo en buffers, y **cada attach adicional al mismo kprobe multiplica el coste por evento en el kernel para todo el nodo**, lo consuma ese módulo o no.
**Decidir:** ¿cuál es el presupuesto de RAM y de overhead por evento del agente, y a partir de qué N se cruza? Sin ese número, "¿multiplexamos?" no se puede responder.

**31.2.2 — Si se multiplexa: ¿dónde vive el multiplexor?**
Hoy los dos consumidores comparten proceso (`fimebpf.so` dentro de `wazuh-syscheckd`), así que compartir un handle sería un refactor local. Un consumidor en **otro proceso** (syscollector, modulesd) no puede compartir un `rt_handle_t`: haría falta un daemon propietario del BPF más un transporte (unix socket, shm ring) y un versionado de ese transporte, que es una segunda ABI que mantener.
**Decidir:** ¿se acepta que todo consumidor BPF viva en el mismo proceso, se crea un broker, o se mantiene N cargas precisamente para evitar el broker? Incluye: aislamiento de fallos (hoy un módulo que crashea no se lleva a los otros) y privilegios (31.8.1).

**31.2.3 — Si se multiplexa: ¿cómo se preserva `skip_mask`?**
`skip_mask` existe explícitamente para que "el consumidor barato no subsidie al caro" (el header lo dice así). En un ring compartido, el filtro efectivo es la **unión** de lo que piden todos: basta un consumidor con `skip_mask = 0` para que todos los eventos paguen los dos recorridos de dentries. La propiedad que justificaba el mecanismo se pierde.
**Decidir:** ¿filtrado en kernel por suscriptor (bitmask de consumidor en el evento, mapa de suscripción) o se acepta la degradación?

**31.2.4 — Binding de libbpf process-wide, gana el primero.**
Serializado con mutex y con WARN nombrando ambas rutas, pero sin resolución. Con dos consumidores del mismo módulo es benigno porque ambos pasan el mismo `abspath("lib/libbpf.so")`. Con N módulos empaquetados y versionados por separado deja de serlo.
**Decidir:** ¿se centraliza la resolución de `libbpf_path` en una capa común del agente (31.7.1), o el motor pasa a rechazar un segundo bind discrepante en lugar de avisar?

---

## 31.3 Equidad, backpressure y modelo de hilos

**31.3.1 — ¿Qué pasa cuando un consumidor es lento?**
Hoy cada handle tiene su propio ring, así que un consumidor lento sólo se perjudica a sí mismo — ésa es la contrapartida que paga ADR-001. En un modelo compartido, el lento provoca drops para todos.
**Decidir:** política de backpressure y de contabilidad de pérdida por consumidor, **antes** de multiplexar.

**31.3.2 — Modelo de hilos no documentado para N consumidores.**
`rt_poll()` y `rt_drain_drops()` no son thread-safe sobre el mismo handle; el bind de libbpf sí está bajo mutex. No existe un enunciado de qué es seguro llamar concurrentemente a nivel de proceso con varios handles abiertos.
**Decidir:** escribir el contrato de concurrencia como parte del header, no como folclore.

**31.3.3 — Reconfiguración en caliente, sólo parcial.**
Mutables: allowlist de cgroups y `cgroup_mode`. **No** mutables: `type_mask` y `skip_mask`. Cambiarlos exige reabrir, y reabrir desattachea y reattachea todo — que es justo lo que el healthcheck de whodata evita compartiendo handle con el loop de poll.
**Decidir:** si un módulo puede activarse/desactivarse por configuración en runtime, ¿necesita `type_mask` mutable? Si varios módulos comparten handle (31.2.2), el `type_mask` es la unión y cambia cada vez que un módulo arranca o para.

---

## 31.4 Pérdida, truncamiento y semántica del evento

**31.4.1 — Pérdida silenciosa por fallo de resolución de ruta.**
El walker tiene tope `MAX_PATH_COMPONENTS` = 320, las cadenas son de 4096 bytes, y **no hay flag de truncamiento en `rt_flags`**. Un fallo de resolución sale **sin evento y sin incrementar ningún contador de drops** (los drops sólo cuentan ring lleno). Para FIM, que ya reconcilia, es tolerable. Para un módulo que trate la ausencia de evento como "no pasó nada", es un falso negativo indistinguible de la normalidad.
**Decidir:** agregar `RT_F_TRUNCATED` y un contador de fallos de resolución (aditivo, sube `MINOR`). Entra en 31.0 porque después deja de ser aditivo en la práctica: habrá consumidores que ya asumieron lo contrario.

**31.4.2 — Los eventos son intentos, no operaciones confirmadas.**
Los hooks son de entrada / de seguridad y no comprueban el retorno. Una apertura con intención de escritura puede no escribir. FIM lo absorbe porque usa el evento como disparador de reconciliación. Un módulo de detección que alerte directamente sobre el evento estaría alertando sobre intentos — que puede ser lo correcto, pero debe ser una decisión, no un accidente.
**Decidir:** documentar por clase si el evento es pre- o post-operación, y si la plataforma se compromete alguna vez a emitir eventos confirmados (implicaría hooks de retorno, con su coste).

**31.4.3 — Rename sin correlación entre sus dos mitades.**
Dos eventos, orden no garantizado, mismo `RT_EV_FILE_RENAME`, sin identificador de operación ni indicador origen/destino, y una mitad puede perderse sin que la otra lo señale. Cada consumidor nuevo re-descubre el problema y lo resuelve a su manera (el drain hoy dispara la reconciliación dos veces).
**Decidir:** ¿se agrega un id de operación al contrato (aditivo) o se declara que coalescer es responsabilidad del consumidor y se documenta como tal? La misma pregunta volverá con cualquier clase futura que emita pares (exec/exit, connect/close).

**31.4.4 — Granularidad de la contabilidad de drops.**
`rt_drain_drops()` contabiliza **por cgroup**, global al handle. Con un handle por módulo eso coincide con "por consumidor". Si se multiplexa, o si un módulo consume varias clases, la pregunta "¿qué tengo que re-leer?" necesita drops por (cgroup × clase) o por (consumidor × clase): re-escanear rutas y re-enumerar paquetes no son la misma recuperación.
**Decidir:** granularidad objetivo antes de que haya un tercer consumidor.

**31.4.5 — Mapas de 4096 entradas fijas (allowlist y drops).**
Límite de compilación. Un nodo con más cgroups activos deja cgroups sin monitorear (se reporta como error, pero no se recupera). Con más módulos usando allowlist, la presión sobre el mapa sube.
**Decidir:** ¿tamaño por configuración en el load, o política de evicción?

---

## 31.5 ABI y versionado a escala

**31.5.1 — Sólo se verifica `MAJOR`.**
Un consumidor compilado contra `MINOR 2` enlazado a un motor `MINOR 1` leería `euid`/`login_uid` que ese motor nunca rellena, y nada lo detecta: el guardia del ring protege al motor frente al **objeto**, no al consumidor frente al **motor**. Hoy no se manifiesta porque todo se compila junto. Con un consumidor por módulo, cada uno con su cadencia de release, el skew de minor pasa a ser el caso normal.
**Decidir:** agregar `abi_minor` al `struct rt_filter` y que `rt_open()` rechace un consumidor que pida más de lo que el motor da. Es aditivo hoy.

**31.5.2 — Orden de validación en el callback del ring.**
El callback lee `ev->abi_major` *antes* de comprobar que el registro tenga siquiera ese campo. Con un único productor controlado es teórico; como plataforma, con objetos `.bpf.o` que pueden venir de deps y desincronizarse del agente (caso real, no hipotético: el drain ya reintenta por eso), conviene endurecerlo.

**31.5.3 — ¿Quién es el dueño del contrato?**
Todo cambio a `rt_event_contract.h` obliga a regenerar los prebuilts **en el mismo commit**, y un objeto desactualizado hace que el motor descarte **todos** los eventos. Con N módulos queriendo campos nuevos, hace falta un dueño, un proceso (¿RFC? ¿revisores obligatorios?) y una regla de deprecación.
**Decidir:** propiedad y proceso. Sin esto, el primer módulo nuevo extiende el contrato para su caso y fija el precedente.

**31.5.4 — ¿El contrato es API interna o API pública?**
Hoy es interno al repo. Si un módulo fuera de este árbol (o escrito en otro lenguaje) debe consumirlo, hace falta decidir si se estabiliza con semver real y si se publican bindings, o si la frontera es siempre C dentro de este repositorio.

---

## 31.6 Reutilización del código de pegado

**31.6.1 — El "pegado Wazuh" ya está duplicado dos veces.**
El motor es agnóstico por diseño (ADR-001), así que cada consumidor resuelve por su cuenta: `abspath("lib/rt_file.bpf.o")`, `abspath("lib/libbpf.so")`, el mapeo de `RT_LOG_*` al logger, el chequeo de ABI, el hilo de poll, la copia del evento en el sink, y la degradación cuando `rt_open()` devuelve NULL. Son seis cosas que **todo** consumidor debe hacer igual y que hoy están escritas dos veces.
**Decidir:** una capa fina de pegado (fuera del motor, para no romper el agnosticismo) que haga esto una vez. Es lo más barato de esta lista y lo que más se paga con cada módulo nuevo.

**31.6.2 — ¿Quién decide si eBPF está habilitado?**
Hoy es una decisión de FIM (`ossec.conf`, whodata). Si inventario también lo quiere, ¿hay un interruptor global, uno por módulo, o ambos? ¿Qué pasa cuando un módulo lo pide y otro lo tiene deshabilitado — se carga igual?

**31.6.3 — Orden de arranque y parada.**
Con N módulos abriendo handles no hay secuencia definida. El healthcheck de whodata comparte handle con el loop de poll **a propósito**, porque reabrir pierde los eventos del intervalo. Cada módulo nuevo va a inventar su propia variante de ese problema.

---

## 31.7 Build, distribución y cadena de suministro

**31.7.1 — Binarios BPF commiteados, multiplicados por dominio.**
Hoy son dos (`x86`, `arm64`) con digest de fuentes, provenance y chequeo de símbolos. Con un objeto por dominio (31.1.3) son 2×N. Y el digest **compara fuentes contra un archivo declarativo; no demuestra que el binario se compiló con ellas**. Además `tools/rebuild_prebuilt.sh` refresca los digests de ambas arquitecturas aunque sólo reconstruya una.
**Decidir:** la migración a `libbpf-bootstrap.tar.gz` (ya pendiente en §30.10.1) deja de ser deseable y pasa a ser bloqueante al escalar. ¿Se planifica con fecha?

**31.7.2 — Integridad del objeto en kernel.**
Un `.bpf.o` es código que se ejecuta en el kernel. Como plataforma, ¿hay verificación de integridad en el agente más allá del digest de fuentes en tiempo de configure?

**31.7.3 — Arquitecturas sin objeto.**
Sólo x86_64 y aarch64 producen `.bpf.o`; cualquier otra arquitectura queda sin eBPF (que es el resultado honesto, y mejor que el anterior). Pero si todos los módulos dependen del motor, esas arquitecturas pierden funcionalidad **en bloque**, no sólo whodata.
**Decidir:** ¿el fallback no-eBPF es obligatorio para todo módulo que adopte el motor? Si la respuesta es sí, hay que decirlo ahora; si es no, hay que decir qué plataformas se degradan.

**31.7.4 — El motor es Linux-only.**
`CMakeLists.txt` se salta el módulo en cualquier otro sistema. Un módulo multiplataforma que lo adopte necesita una abstracción por encima o mantener dos caminos.

---

## 31.8 Privilegios y seguridad

**31.8.1 — Superficie de privilegio.**
Cargar y attachear BPF exige `CAP_BPF`/`CAP_SYS_ADMIN`. Hoy eso vive en `wazuh-syscheckd`. Si cada módulo enlaza `librt_engine` y abre su propio handle, **cada uno de esos procesos pasa a necesitar el privilegio**. Un broker (31.2.2) lo concentraría en uno.
**Decidir:** concentrar o distribuir. Es un argumento a favor del broker independiente del coste.

**31.8.2 — Contenido sensible en el registro.**
Los eventos llevan `filename`, `cwd`, `parent_cwd`, `comm`, `uid`/`euid`/`login_uid`. Con un solo consumidor es un detalle; con N módulos de propósitos distintos, un módulo de inventario no tiene por qué ver `login_uid`. `skip_mask` ya es el mecanismo técnico para no computarlos.
**Decidir:** ¿se vuelve obligatorio declarar el mínimo necesario, o queda a criterio de cada módulo?

**31.8.3 — Límites del sistema con N cargas.**
`RLIMIT_MEMLOCK`, `bpf_jit_limit`, número máximo de programas attacheados por hook. Con dos cargas no se han tocado; no hay medición de dónde está el techo.

---

## 31.9 Pruebas y CI

**31.9.1 — CI no corre casi nada del módulo.**
Sólo `rt_engine_contract_test` está registrado en ctest. El loader test y las suites que requieren kernel (`leak`, `drops`, `filter`, `creds`, `skip`, `paths`) corren únicamente por el `Makefile` standalone. Como loader de un módulo es una deuda; como plataforma del agente es inaceptable.

**31.9.2 — Matriz de kernels.**
Las decisiones del motor dependen del kernel: la escalera LSM-dpath → LSM-walk → kprobe, el layout de `renamedata` por rango de versión, `resolve_dentry()` para la firma 6.0 backporteada, el inlining que vigila `check_bpf_symbols.sh`. Hoy hay huecos declarados sin cubrir: **RHEL 9** (nunca probado, es justo el caso que motiva `resolve_dentry()`), **Amazon Linux 2/2023** (único modo de ejercitar el peldaño LSM-walk en vivo), **4.18 / CentOS Stream 8** (la verificación de carga no se repitió para el objeto actual), **6.19+** (sólo cobertura en compilación).
**Decidir:** quién construye y paga esa matriz. Un motor que sirve a un módulo puede vivir con huecos; uno que sirve a todos, no.

**31.9.3 — Carga sostenida nunca medida.**
La decisión de incluir `O_ACCMODE` se validó con una ráfaga de 2.000 escrituras, no con un soak. Con `skip_mask = 0` cada evento cuesta dos recorridos de dentries y 12.424 bytes de un ring de 8 MiB. Multiplicar consumidores sin ese número es comprometerse a ciegas.

**31.9.4 — ¿Test de conformidad para consumidores?**
Un consumidor nuevo debe: chequear ABI, copiar el evento dentro del sink (el puntero muere al retornar), degradar ante `rt_open() == NULL`, y joinear su hilo antes de `rt_close()`. Nada lo verifica. El harness demuestra el camino feliz.
**Decidir:** ¿una suite de conformidad que cada consumidor deba pasar?

---

## 31.10 Observabilidad y riesgo operativo

**31.10.1 — Diagnóstico sólo por log.**
Toda la información del motor sale por el `rt_log_fn`: qué peldaño de la escalera se eligió, qué jerarquía de cgroups se detectó, cuántos eventos se rechazaron por ABI, si el bind de libbpf discrepó. Con un módulo, leer `ossec.log` alcanza. Con N, hace falta telemetría estructurada y consultable (contadores por clase, drops, fallos de resolución, peldaño activo).
**Decidir:** ¿el motor expone contadores, o cada consumidor los deriva?

**31.10.2 — Punto único de fallo.**
Si el motor no carga, hoy degrada whodata. Como plataforma, degrada **todos los módulos a la vez, por la misma causa**, en el mismo arranque.
**Decidir:** ¿se acepta? ¿Hay un modo de activación gradual por módulo para que un fallo nuevo no apague toda la telemetría del nodo?

**31.10.3 — Qué significa "el motor está sano".**
Whodata tiene un healthcheck de cuatro acciones que comparte handle con el loop de poll. No hay una noción de salud a nivel de motor que un módulo pueda consultar antes de confiar en él.

---

## 31.11 Lo que esta lista asume

Conviene decirlo en la reunión antes de discutir las respuestas:

- Asume que los módulos consumidores pueden vivir en procesos distintos. Si la respuesta es "todo consumidor BPF vive en `wazuh-syscheckd`", desaparecen 31.2.2, 31.8.1 y buena parte de 31.6, y la discusión se simplifica mucho.
- Asume que llegarán clases de evento que no son de archivo. Si el alcance se congela en FILE, 31.1.2 y 31.1.4 dejan de ser urgentes.
- No cuestiona ADR-001 por defecto: lo que pide es el **número** (presupuesto de memoria y de overhead por evento) que permita saber cuándo deja de servir.
