# 26 — Verificación de comentarios y plan de corrección

## Alcance y resultado

- Fecha: 2026-10-23.
- Rama: `37532-normalize-container-context`.
- Commit examinado: `315d0d0934`.
- Árbol de trabajo inicialmente limpio.
- Objetivo original: verificar los 15 comentarios y proponer correcciones. El plan
  se mantiene como registro del trabajo y sus decisiones pendientes.
- Evidencia: lectura del código, pruebas existentes e historial local; reproducción
  de los scripts reales de migración con SQLite en memoria.
- No se compiló el agente, no se ejecutaron sus suites y no se reprodujeron carreras
  ni alertas end-to-end. Las confirmaciones por inspección no equivalen a esas pruebas.
- Reverificación independiente (2026-10-23, mismo commit): se reconfirmaron los 15
  comentarios contra el código y se volvió a reproducir la migración v2→v3 con los
  scripts literales. Resultado: los 15 se sostienen y la tabla de §4 se reprodujo igual.
  Esa pasada corrigió anclas de línea, precisó un hecho en §2 y documentó el método de §4.
- Rebase (2026-10-26) sobre `origin/37532-nfr3-container-limits` (`8171b54b5a`):
  las anclas se recalcularon contra el nuevo HEAD. nfr3 no cambia esquemas, así que
  #4 y #15 se mantienen. La resolución de conflictos corrigió #12 (§2) y conservó el
  orden de nfr3 en el baseline FIM: listar y admitir antes del recorrido, barrer
  después. La integración requirió dos commits: `59632ac1c1` adapta los wrappers de
  tests de nfr3 a la firma con `context_sink`, y `f28f96d46a` evita que el prune de
  contextos borre el de un contenedor descubierto durante el recorrido. Los demás
  veredictos no cambian.
- Continuación de implementación (2026-10-26): #9 compara conjuntos de identidades,
  #14 omite `syncRow` para contextos completos sin cambios y #15 congela el SQL
  v1→v2. Se recompiló el agente con `TEST=yes`; pasaron `container_reporting_test`,
  `container_reconcile_plan_test` y `fim_db_upgrade_test`. Los cambios se publicaron
  en `a5c796dddb8`.
- Decisión de producto (2026-10-26): para #8, el contexto de un documento es el último
  contexto conocido al emitirlo. Un cambio posterior de metadatos no reescribe
  retroactivamente documentos ya indexados ni, por sí solo, genera una reemisión.
- Implementación #2/#13 (2026-10-26): container_instances ahora certifica snapshots
  solo cuando todas las fuentes configuradas terminaron una enumeración satisfactoria;
  los IDs conocidos incluyen contenedores running aún sin cgroup resuelto. La señal y
  esos IDs llegan por IPC y por el API extendido de baseline. FIM, Syscollector y el
  drain eBPF no usan una lista incompleta para barrer o reemplazar su estado. Syscollector
  fuerza un pase completo al observar la transición a completitud. Las altas delta de
  FIM actualizan la admisión individual antes del walk, sin pedir un sweep global.
  Se compiló con `TEST=yes` y pasaron las cuatro suites focalizadas de container_instances,
  container_baseline, container_reporting y Syscollector.

**Conclusión:** los 15 comentarios identifican comportamientos presentes en el código,
pero no tienen todos el mismo alcance ni justifican aplicar literalmente la solución
propuesta. Priorizar seguridad de memoria, autoridad para borrar y conservación del
contexto ante errores. La política de rollback sigue pendiente; el contrato de #8 ya
está acordado como snapshot del último contexto conocido al emitir, sin convergencia
retroactiva del inventario indexado.

## 1. Resumen de decisiones y esfuerzo

Estimaciones en **días-persona de ingeniería**, incluyendo implementación y regresiones
focalizadas. No incluyen esperas de revisión ni una campaña completa de integración.
No deben sumarse directamente: varias correcciones comparten cambios y pruebas.

Prioridades:

- **P0:** primera tanda; riesgo de memoria o borrado incorrecto de estado.
- **P1:** antes de integrar la funcionalidad o declarar soportado el escenario.
- **P2:** eficiencia o prevención de regresiones futuras.

| # | Veredicto | Prioridad recomendada | ¿Conviene corregir? | Esfuerzo |
| --- | --- | --- | --- | --- |
| 1 | UAF confirmado por inspección | P0 | Sí, independientemente del cierre del daemon | 0,5–1 |
| 2 | **Corregido**: las listas incompletas no autorizan sweeps | Hecho | IDs conocidos y completitud por fuente; los consumidores conservan el estado hasta un snapshot completo | — |
| 3 | Bloqueo de inicialización confirmado; política deliberada | P1 si se soporta rollback | Sí, definir recuperación; no recrear globalmente sin garantías | 1–3 |
| 4 | Colisión reproducida; solo en esquemas intermedios de desarrollo, no en el publicado | P1; bloqueante para actualizar esos nodos | Sí; definir compatibilidad de bases de desarrollo | 1–3 con recreación explícita; 3–5 preservándolas |
| 5 | Prune inseguro tras fallo de lectura | P0 | Sí, junto con #6 | 0,25–0,5 |
| 6 | Limpieza de contexto y presupuesto sin confirmar el borrado | P0 | Sí; propagar resultados y conservar estado ante fallos | 1–2 |
| 7 | **Ya corregido**: consume notificaciones con el intervalo cero y conserva la cadencia host | Hecho | Verificado con test de lifecycle en modo acoplado | — |
| 8 | Contrato acordado: snapshot del último contexto conocido al emitir | Resuelta por decisión de producto | No; los documentos ya emitidos no se reescriben retroactivamente | 0 |
| 9 | **Corregido**: compara identidades, no cardinalidades | Hecho | Detecta reemplazos con igual cardinalidad; no barre estados estables | 0,25 |
| 10 | Memoización sobrevive al reemplazo de la DB | P1 | Sí; invalidar al cambiar la base | 0,5–1 |
| 11 | Escritura no ejecutada se informa como exitosa | P1 | Sí; corregir el contrato de persistencia | 0,5–1,5 |
| 12 | **Corregido y probado**: libera la fila poseída en todas las salidas | Hecho | Callback no registrado probado | — |
| 13 | **Corregido**: las altas delta no piden sweep global | Hecho | Actualización incremental de admisión antes del walk; el sweep periódico sigue como backstop | — |
| 14 | **Corregido**: omite `syncRow` si el contexto completo no cambió | Hecho | Integrado al ciclo de vida de caché de A | 0,5 |
| 15 | **Corregido**: v1→v2 usa SQL literal en ambos esquemas | Hecho | Upgrade FIM probado; Syscollector compila | 0,25 |

## 2. Verificación individual

### 1. UAF en la carga de la caché FIM

**Confirmado por inspección.** En
[fim_db_get_container_context](../src/syscheckd/src/db/src/db.cpp#L916), el miss
obtiene un `cJSON*`, transfiere su propiedad a `store()` y luego lo duplica.
`store()` ya liberó su mutex cuando vuelve; `clear()`, `erase()` u otro `store()`
pueden liberar ese árbol antes de `cJSON_Duplicate`.
El hit, en cambio, duplica bajo el mutex y no tiene esa ventana.

El cierre es un escenario plausible: [DB::teardown](../src/syscheckd/src/db/src/db.cpp#L71)
limpia la caché, y el shutdown waiter la alcanza por
[fim_db_teardown](../src/syscheckd/src/main.c#L165) tras esperar solo al hilo de
sincronización: su única guarda es un `trylock` sobre `fim_scan_mutex`, que no dice
nada del consumidor de contenedores ni demuestra que haya terminado antes. El
[destructor del drain](../src/syscheckd/src/ebpf/src/container_event_drain.cpp#L768)
expresamente no hace join. El camino POSIX normal termina mediante `_exit`, por lo
que no debe confundirse esa carrera con la ejecución obligatoria del destructor.

**Corrección:** duplicar mientras el bloque siga siendo propiedad local, antes de
publicarlo, o encapsular publicación y duplicación bajo el mismo mutex. Usar ownership
que no filtre memoria si falla una asignación. No sustituirlo por `store(); duplicate(id)`:
evita usar el puntero liberado, pero otra operación puede cambiar o borrar esa entrada
entre ambas llamadas. La coordinación del cierre debe impedir también repoblar una
caché de una base ya cerrada; no basta con invertir dos líneas.

### 2. Sweep con lista incompleta después de resync

**Confirmado como riesgo de borrado incorrecto; no ocurre necesariamente en cada resync.**
[refreshContainerList](../src/syscheckd/src/ebpf/src/container_event_drain.cpp#L479)
solicita un sweep ante `resyncRequired`. Ese estado también puede deberse a un cursor
expulsado del journal, no solo a un reinicio de modulesd.

El fallo de fondo está en
[MetadataStore::listContainers](../src/wazuh_modules/container_instances/ci_impl/src/cache/metadata_store.cpp#L121):
omite contenedores running con `hostKey == 0`. Una respuesta IPC correcta no garantiza
por ello un conjunto completo de contenedores existentes.
[ListAndSweep](../src/syscheckd/src/ebpf/src/container_baseline_fim.cpp#L879)
solo comprueba que haya respuesta y usa sus IDs como autoridad para borrar.
El [warm-up del scanner](../src/wazuh_modules/container_baseline/container_baseline_impl/src/container_baseline_scanner.cpp#L181)
tiene reintentos y latches, pero no certifica completitud y **no se rearma**: tanto la
ventana de warm-up (`g_warmupWindowClosed`) como la quiescencia se enclavan una sola vez
por proceso. Esos latches viven en la copia del scanner enlazada en syscheckd, que no se
reinicia cuando lo hace modulesd; tras ese reinicio la lista se pide con un único intento
y sin comprobación de estabilidad, justo en el momento en que está incompleta.

También afecta al
[sweep por ausencia de Syscollector](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L2872),
que consume el mismo tipo de lista. No limitar el arreglo al disparador eBPF.

**Corrección:** distinguir existencia, resolución de cgroup y autorización para borrar.
Publicar IDs conocidos aunque no estén resueltos y una indicación fiable de snapshot
completo por epoch/fuente. Durante redescubrimiento, no inferir bajas por ausencia.
Conservar las bajas explícitas del journal según su contrato y el sweep periódico
como backstop cuando exista autoridad. Un sleep mayor o suprimir solo el sweep del
resync no arreglan la causa.

**Implementado:** `MetadataStore` registra las fuentes esperadas y las que ya
publicaron snapshots completos; una reconexión o un evento que invalida el snapshot
retira temporalmente esa autoridad. Las respuestas de lista incluyen
`snapshot_complete` y `known_container_ids`, capturados con los registros bajo el
mismo lock. El API extendido del baseline conserva ambos datos, mientras el API viejo
se mantiene por compatibilidad y no certifica completitud. El drain no instala una
lista ni avanza un cursor de resync mientras falte completitud. Los sweeps FIM y
Syscollector usan los IDs conocidos (incluidos los unresolved) y se omiten hasta que
el snapshot esté completo. Syscollector recuerda la completitud y ejecuta un pase
completo al recuperarla, para cubrir cambios que ocurrieron durante el redescubrimiento.

**Regresiones:** el store y QueryService verifican que una fuente pendiente haga el
snapshot incompleto, que un ID unresolved siga conocido y que la recuperación de todas
las fuentes restablezca la autoridad. Syscollector verifica que una lista alcanzable
pero incompleta no borre filas. Las suites focalizadas de container_instances,
container_baseline, container_reporting y Syscollector pasan con `TEST=yes`.

### 3. Bases de versión superior bloquean los módulos

**Comportamiento confirmado; recomendación original incompleta.**
[SQLiteDBEngine::initialize](../src/shared_modules/dbsync/src/sqlite/sqlite_dbengine.cpp#L684)
lanza `DB_VERSION_AHEAD_OF_SCHEMA`. La rama actual espera versión 3 para FIM y 15
para Syscollector; versiones 4 y 16 son ejemplos que activarían el rechazo.
[fim_initialize](../src/syscheckd/src/syscheck.c#L528) deshabilita FIM si falla la
inicialización. [Syscollector::init](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L1013)
propaga la excepción al
[wrapper C](../src/wazuh_modules/syscollector/src/syscollector.cpp#L108), que la
registra y deja el módulo sin inicializar.

Dos precisiones:

1. No se escribe una deshabilitación permanente en la configuración: la misma base
   vuelve a fallar en cada inicio mientras persista la incompatibilidad.
2. El código inmediatamente anterior al commit `3447926460` **no recreaba** una base
   más nueva: entraba en el caso final y la usaba sin rechazar su versión.
   Por tanto, no es una regresión respecto de una recuperación automática existente.

El rechazo es deliberado y tiene una
[prueba explícita](../src/shared_modules/dbsync/tests/interface/dbsync_test.cpp#L2640).
No convertir un motor compartido en un borrador automático de cualquier DB incompatible.

**Corrección propuesta:** política explícita para las bases reconstruibles de estos
consumidores: registrar incompatibilidad, cerrar handles, respaldar si corresponde,
recrear de manera controlada e iniciar reconciliación completa con el manager.
Conservar rechazo para consumidores sin esa política. Incluir permisos insuficientes,
fallo de recreación y coherencia con estado de sincronización y presupuestos.
Una migración SQL descendente genérica no es una alternativa segura.

**Actualización (reanálisis de integración, 2026-10-23):** upstream ya resolvió esta
política. El commit `70666bdb5b`, presente en `origin/5.0.0`, `5.0.1` y `main` pero no
en el merge-base de esta rama, modificó `SQLiteDBEngine::initialize` para:

- recrear la base cuando `user_version` es mayor que la del build;
- recrear cuando un paso de upgrade falla por esquema (`SQLITE_ERROR` o
  `STEP_ERROR_UPDATE_STMT`), relanzando los errores transitorios (busy, locked, I/O);
- estampar `user_version` solo después de crear todas las tablas;
- exponer `DBSync::recreateReason()`, que Syscollector registra como `LOG_WARNING`.

`DB_VERSION_AHEAD_OF_SCHEMA` y su prueba contradicen ese comportamiento publicado.
Al integrar `main`, hay que adoptar la versión upstream y retirar el throw, la
constante y su prueba. También hay que:

- conservar `execute()` (scripts de varios statements) y el bump de versión dentro
  de la transacción;
- mapear el `dbsync_error` de `execute()` de modo que solo los errores de esquema
  recreen la base. Hoy cualquier fallo se convierte en `STEP_ERROR_UPDATE_STMT`, y con
  la política upstream eso borraría la base ante un `SQLITE_BUSY`;
- registrar `recreateReason()` también en FIM, que upstream no lo hace;
- verificar que la recreación de FIM vacíe `container_context`, la caché de contexto
  y los presupuestos (#10 y #11).

Los paquetes de 4.x se ocupan solos: los instaladores deb, rpm, macOS, `wazuh.sh` y
MSI borran `fim.db` y `local.db` al subir de 4.x a 5.x. Una base de 4.14 (`user_version` 1
con otro esquema) no llega a la migración por la vía soportada. Si llegara, la
política upstream la recrearía.

### 4. Colisión y pérdida de identidad en la migración

**Reproducido con los scripts reales.**
La [migración FIM](../src/syscheckd/src/db/src/fimDB.hpp#L144) y la de
[dbsync_osinfo](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L662)
copian `SELECT '', ...` sin preservar un `container_id` ya existente.

El historial anterior a `deb575ea3b` ya tenía PK compuesta y construía DBSync sin vector
de upgrades: esas bases de desarrollo quedaban estampadas como versión 1. Pero el
esquema publicado sin contenedores, documentado y cubierto por las
[pruebas de upgrade FIM](../src/syscheckd/src/db/tests/db/ComponentTest/upgradeInterface/fim_db_upgrade_test.cpp#L24),
no tiene esa columna. En ese esquema, asignar `''` es correcto.

Reproducción SQLite en memoria: crear el esquema con PK compuesta, insertar los casos
indicados y ejecutar el script literal v2→v3 dentro de una transacción:

| Entrada | FIM y dbsync_osinfo |
| --- | --- |
| Solo fila host | Migra correctamente |
| Host y contenedor con la misma clave natural | `UNIQUE constraint failed`; rollback; versión permanece en 2 |
| Solo fila de contenedor | Migra sin error, **pero la convierte en fila host** |

Método, que importa para reproducirlo: el motor ejecuta cada paso con `sqlite3_exec`
dentro de una transacción, es decir **aborta en el primer error**. Reproducirlo con el
CLI `sqlite3` sin `-bail` da un resultado distinto y peor: el script sigue tras el INSERT
fallido, ejecuta `DROP TABLE file_entry_upgrade_v3_old`, confirma y deja `file_entry`
**vacía** en versión 3. Eso es un artefacto del CLI, no el comportamiento del agente, y no
debe citarse como pérdida total de datos.

La última variante amplía el comentario: no basta con evitar la colisión; hay que
preservar la identidad. En una actualización desde v1, el paso v1→v2 ya confirmado
puede permanecer aplicado aunque el siguiente se revierta.

**Corrección:** elegir y documentar si se soportan bases intermedias de desarrollo.
Si se soportan, reconocer el esquema real antes de seleccionar la copia: conservar
`container_id` cuando exista y asignar `''` solo al esquema legado sin contenedores.
Cubrir las 13 tablas de Syscollector, no únicamente osinfo. Si no se soportan,
recreación explícita de firmas de desarrollo reconocidas, sin transformar silenciosamente
sus filas en host. No usar `INSERT OR IGNORE/REPLACE`, que oculta pérdida de datos.
Un paso nuevo al final del vector no rescata una base que falla en un paso anterior.

**Actualización (reanálisis de integración, 2026-10-23) — colisión de numeración
con 5.0.0, bloqueante:** `70666bdb5b` agregó a Syscollector
`UPGRADE_SQL_STATEMENTS = { "ALTER TABLE dbsync_osinfo RENAME COLUMN os_distribution_release TO os_display_version;" }`.
Un agente 5.0.0 GA deja `local.db` en `user_version` 2, ya renombrado. Esta rama usa ese
mismo índice 0 para crear `container_context`. Con un `local.db` de 5.0.0:

- el motor ve la versión 2, **salta** el paso que crea `container_context` y ejecuta la
  reconstrucción de osinfo;
- esa reconstrucción copia `os_distribution_release`, que ya no existe (`no such column`);
- con el motor de esta rama, Syscollector queda deshabilitado en cada inicio; con el de
  upstream, la base se recrea siempre, aunque la causa sea un bug de numeración.

Las versiones de upstream ya son inmutables (v1 = esquema 5.0 inicial, v2 = rename), así
que el vector integrado debe ser:

| Paso | Contenido |
| --- | --- |
| v1→v2 (índice 0) | `RENAME COLUMN` de upstream, **idéntico** al publicado |
| v2→v3 | `container_context` |
| v3→v4 | reconstrucción de `dbsync_osinfo` con `os_display_version` |
| v4→v5 … v15→v16 | las otras 12 tablas, desplazadas en uno |

Resultado: Syscollector pasa a `user_version` **16**, `CURRENT_SCHEMA_VERSION` = 16, y los
nombres `*_upgrade_vN_old` se renumeran. Un `local.db` de 5.0.0-rc1 o anterior queda en
v1 con `os_distribution_release` y recorre la cadena completa. Hay que actualizar también
la DDL de `OS_SQL_STATEMENT` de la rama a `os_display_version`.

FIM no tiene pasos de upgrade upstream: sigue en v1 en 5.0.0, 5.0.1 y `main`. Su DDL no
cambió desde el merge-base, salvo el encabezado. La numeración v1→v2→v3 de FIM sigue
siendo válida y no hace falta renumerar.

Esto solo corrige la numeración. La colisión de PK sobre bases de desarrollo con
`container_id` estampadas como v1 sigue abierta como antes. Con la política upstream ya
no deshabilita el módulo: la base se recrea y se hace un full sync. Eso es aceptable si
se decide no soportar esas bases, pero el caso "solo fila de contenedor → fila host"
no falla y sigue convirtiendo filas en silencio. Si no se soportan esas bases, cada paso
de reconstrucción debería abortar (y así forzar la recreación) cuando la tabla vieja
ya tiene `container_id`. Por ejemplo, una sentencia que falle si
`pragma_table_info('<tabla>_upgrade_vN_old')` contiene `container_id`.

### 5. Prune después de fallar la lectura de IDs

**Confirmado.** [sweepStale](../src/syscheckd/src/ebpf/src/container_baseline_fim.cpp#L595)
continúa hacia `fim_db_prune_container_contexts` si falla la consulta de IDs.
Los contextos borrados no están demostrados huérfanos: pueden seguir teniendo filas
que debían emitir DELETE con ese contexto.

**Corrección:** ante lectura fallida o resultado inválido, no autorizar el prune
destructivo. Si se quiere recuperar huérfanos independientemente, comprobar ausencia
real de filas con una consulta fiable. Hacer visible el error y reintentar en una pasada
posterior. Resolverlo junto con #6: una lectura exitosa tampoco demuestra un sweep exitoso.

### 6. Sweep fallido libera contexto y presupuesto

**Confirmado.** [ScopedContainerTxn::finish](../src/syscheckd/src/ebpf/src/container_baseline_fim.cpp#L324)
no devuelve el resultado; el error se registra a debug.
[SweepOneContainer](../src/syscheckd/src/ebpf/src/container_baseline_fim.cpp#L398)
libera presupuesto y elimina contexto incluso si no hubo transacción válida o falló
la detección de borrados. El callback `DB_ERROR` tampoco propaga un fallo al propietario.

**Corrección:** devolver un resultado explícito y acumular errores de callbacks.
Solo terminar la limpieza cuando se confirme el borrado. Ante fallo parcial, conservar
el contexto, no resetear arbitrariamente el presupuesto y reconciliarlo con las filas
que realmente sobreviven. Propagar también errores de cierre y borrado de contexto.
El prune global no debe volver a borrar los contextos retenidos por un sweep fallido.
No prometer atomicidad de alertas ya emitidas si DBSync no la garantiza.

### 7. Lifecycle ignorado con el intervalo por defecto

**Ya corregido y probado.** La rama de
[syncLoop con intervalo cero](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L3689)
consume `m_containerScanRequested` y ejecuta solo el pase de contenedor si todavía
no venció el deadline absoluto del host. Una notificación lifecycle no convierte
el scan horario en un scan adelantado ni reinicia su intervalo.
El test
[`aLifecycleNotificationIsHonouredOnTheDefaultCoupledCadence`](../src/wazuh_modules/syscollector/tests/sysCollectorImp/syscollectorImp_test.cpp#L820)
comprueba el modo por defecto con intervalo host de 100 s y `scan_on_start` desactivado.
También se actualizó el comentario de
[container_sweep_schedule.hpp](../src/syscheckd/src/ebpf/include/container_sweep_schedule.hpp#L15),
que describía el comportamiento anterior.

### 8. Contrato de snapshot para metadatos

**Decisión de producto acordada (2026-10-26): el contexto representa el último
conocido al emitir el documento.** La frescura se evalúa en el momento de emisión;
no se promete que todos los documentos indexados reflejen siempre los metadatos
actuales del contenedor.
[ecsData](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L1442)
adjunta el contexto disponible al emitir. Guardar un contexto nuevo no emite inventario y el
[delta de Syscollector](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L3015)
ignora cambios exclusivamente de metadatos. Por tanto, un cambio de etiquetas,
annotations u owner no reescribe por sí solo los documentos ya indexados.
[FIM](../src/syscheckd/src/db/src/db.cpp#L864) también persiste el contexto sin
generar por ello una modificación de archivo.

La [justificación de normalización](24-container-context-measured.md) quiere evitar
precisamente una tormenta de MODIFIED por editar una etiqueta. Por tanto, no restaurar
el blob en cada fila ni incorporar metadatos al checksum del archivo/inventario.
Un scan que encuentre datos iguales no garantiza reemitirlos, y eso es compatible con
el contrato acordado. Cuando un documento se emita por su flujo normal, debe adjuntar
el último contexto que esté disponible entonces; no se añade una vía de reemisión solo
para converger documentos anteriores.

**Criterio:** comprobar que una emisión posterior a la persistencia de contexto nuevo
incluye ese contexto, y que cambiar solo metadatos no reescribe documentos previos ni
genera alertas stateless FIM de modificación de archivo. No requiere convergencia
retroactiva ni una latencia máxima de actualización del inventario indexado.
Reutilizar resincronización existente solo después de comprobar que reenvía documentos
sin cambio de contenido y que el receptor acepta sus versiones.

### 9. Sweep repetitivo con contenedores detenidos

**Corregido.** El fallback sin deltas ahora compara el conjunto de IDs de contenedor
publicados con el conjunto visto en la lista anterior, en vez de comparar su tamaño
con `containerCount()`, que solo cuenta mappings positivos de cgroup. Los contenedores
detenidos o sin cgroup ya no sostienen una desigualdad permanente. El test
`DetectsAnIdentityReplacementWithTheSameCardinality` cubre una sustitución con igual
cardinalidad; el intervalo resolver estable ya no solicita nuevos sweeps.

### 10. Memoización de Syscollector sobrevive a la DB

**Confirmado para reemplazo/reinicialización en el mismo proceso.**
[storeContainerContext](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L2681)
retorna éxito si encuentra el mismo string en memoria.
[releaseResources](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L1308),
[deleteDatabaseUnlocked](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L4789)
y [init](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L1013) no limpian
ese mapa ni el memo de lectura. Un reinicio de proceso sí los descarta.
`closeAndDeleteDatabase()` cierra y borra; no recrea por sí mismo. El fallo aparece al
asociar después el singleton con una base nueva conservando esa memoización.

**Corrección:** invalidación única de cachés vinculada al ciclo de vida de la base,
bajo el mutex correspondiente y con los usuarios quiescentes. Limpiar mapa de strings,
último ID y último bloque al sustituir/cerrar la base; revisar el resto del estado
derivado del contenedor en esos mismos caminos. Probar el mismo ID y string en dos
bases distintas dentro del mismo proceso.

### 11. Persistencia FIM no ejecutada se cachea como éxito

**Confirmado el contrato incorrecto; efecto posterior condicionado.**
[FIMDB::updateItem](../src/syscheckd/src/db/src/fimDB.cpp#L41) no hace nada si está
deteniéndose o no tiene handler y no devuelve estado.
[fim_db_set_container_context](../src/syscheckd/src/db/src/db.cpp#L864)
interpreta ausencia de excepción como éxito y publica en caché.

Eso demuestra un falso positivo de persistencia. No demuestra por sí solo que luego
se guarden filas: las escrituras de filas también atraviesan guards del mismo handler.
El escenario debe probarse con interleavings de cierre/reinit; no asumir que el daemon
continúa escribiendo normalmente después del stop.

**Corrección:** informar explícitamente «ejecutado/falló/no disponible», mediante un
contrato comprobable o una operación específica de contexto. Cachear solo tras
persistencia confirmada y dentro de la misma vida de DB. Revisar callers directamente
afectados, evitando cambiar sin necesidad la semántica de todos los wrappers.

### 12. Fuga de msg

**Confirmado en el código previo al rebase; ya corregido.** Al resolver el
conflicto entre `0658229ec9` (la fila llega como `cJSON*` y pasa a ser propiedad
de la función) y la versión de nfr3 (devuelve la decisión de `sync`),
[fim_persist_baseline_row](../src/syscheckd/src/ebpf/src/container_baseline_fim_bridge.c#L785)
quedó liberando `msg` también cuando falta `validate_and_persist`. Ahora todas
las salidas liberan `msg`, y el camino de rechazo ya no vuelve a parsear el texto
original: `sync` y `container_id` se capturan antes de normalizar.

**Prueba añadida:** `AnUnregisteredHostStillReleasesTheRow` pasa una fila poseída
con el callback ausente y espera `-1`; puede ejecutarse bajo ASan/LSan o Valgrind
para detectar fugas o doble liberación.

### 13. Altas desencadenan sweep global

**Confirmado con matiz de frecuencia.**
[refreshContainerList](../src/syscheckd/src/ebpf/src/container_event_drain.cpp#L579)
eleva una solicitud si el lote contiene alguna alta. No necesariamente hay un sweep
por cada alta: varias solicitudes/eventos pueden coalescerse.
La siembra inicial también solicita uno; puede repetirse trabajo que ya hizo el baseline.
El costo existe porque el consumidor vuelve a listar y consulta IDs de la tabla grande.
No se midió aquí cuánto bloquea con 300.000 filas.

**Corrección:** separar refresco de admisión y barrido destructivo. En altas, actualizar
la admisión autoritativa antes del walk y reservar el sweep para bajas justificadas y
reconciliación periódica segura. No admitir indiscriminadamente todo ID nuevo: respetar
el cap y su indicador de admisión. Usar `container_context` como fuente de candidatos
solo si se demuestra que no puede haber filas sin contexto; #5/#6/#10/#11 impiden
asumir hoy ese invariante.

**Implementado:** al recibir una alta delta, el drain usa el veredicto `synced` del
registro para actualizar solo esa entrada de admisión antes de entregar el evento al
router y su walk. No solicita `requestSweep()` por la alta, evitando así el
`SELECT DISTINCT` sobre `file_entry` y la reconciliación global de admisión. La
actualización incremental no consulta filas y conserva el indicador de cap de
container_instances; la reconciliación periódica y las listas completas siguen
disponibles para recuperar estado y procesar removals.

**Regresión:** `IncrementalAdmissionUpdateDoesNotQueryAllFileRows` verifica que la
actualización por ID cambia la admisión sin invocar las consultas globales de IDs FIM.

### 14. Reescritura de contexto FIM sin cambios

**Corregido.** `fim_db_set_container_context` compara el string completo con el último
que persistió correctamente. `updateItemIfNeeded` comprueba que FIMDB siga disponible
y omite `syncRow` si el contexto no cambió, conservando el contrato de #11; los setters
se serializan para que dos cambios concurrentes no dejen una memo desfasada respecto
de la base. La comparación queda invalidada por los mismos
caminos de borrado, prune, teardown y recreación que limpian la caché de bloques.
Una prueba de FIMDB verifica que `syncRow` no se invoca para una fila marcada
sin cambios; la prueba de baseline verifica que el contexto sigue siendo legible
entre reconciliaciones y que un cambio de metadatos actualiza el bloque almacenado.

### 15. DDL histórico mutable

**Riesgo prevenido.** El primer elemento de
[fimDbUpgradeStatements](../src/syscheckd/src/db/src/fimDB.hpp#L144) y
[getUpgradeStatements](../src/wazuh_modules/syscollector/src/syscollectorImp.cpp#L662)
usa ahora el SQL literal v1→v2, independiente de las constantes de creación.
`fim_db_upgrade_test` pasa y la compilación de agente con `TEST=yes` incluye
Syscollector. Añadir una prueba que fije el SQL histórico evitará que una edición
futura vuelva a mezclarlos.

## 3. Plan de ejecución por entregas

### Entrega A — Memoria y resultados fiables

**Comentarios:** #1, #11, la prueba de #12 y la invalidación de #10.

1. Corregir ownership del miss FIM (el cleanup del bridge ya quedó corregido en el rebase).
2. Hacer observable si se ejecutó la escritura de contexto.
3. Atar cachés a la vida de la DB; impedir publicaciones tardías tras cierre/reinit.
4. Revisar el cierre del consumidor frente al teardown sin introducir un join
   indefinido ni trabajo no seguro dentro de un signal handler.

**Salida:** ninguna lectura usa memoria transferida sin protección; un setter no
reporta éxito por una operación omitida; una nueva DB no hereda memoización antigua.

**Estado: hecho** (`a3996546e8`, `eda799ee07`; prueba de #12 en `28ef3342c6`).
`fill()` duplica bajo el lock y solo cachea si ningún escritor corrió desde la lectura
(contador de generación). `updateItem`/`removeItem` devuelven si se ejecutaron y el
setter devuelve `FIMDB_ERR` sin cachear. Syscollector olvida la memo en `init`,
`releaseResources` y `deleteDatabase`. Pruebas: carrera de lectura en frío contra
`clear`/`set` (limpia bajo Valgrind), setter tras teardown, contexto reescrito tras
recrear la DB y host sin registrar sin fugas (Valgrind). El punto 4 (cierre del
consumidor frente al teardown) queda cubierto por la copia bajo lock; no se tocó el join.

### Entrega B — Borrado conservador y contabilidad

**Comentarios:** #5, #6. Requiere los contratos de resultado de A donde se compartan.

1. Propagar inicio, delete detection, callbacks y cierre hasta el llamador del sweep.
2. Mantener contextos y presupuesto de contenedores cuyo borrado no se confirmó.
3. No ejecutar prune ciego tras una consulta o sweep fallido.
4. Registrar errores operativos con nivel visible y reintentar sin contarlos como éxito.

**Salida:** las filas supervivientes conservan contexto; el presupuesto no se pone a
cero por un fallo; los DELETE legítimos siguen enriquecidos.

**Estado: hecho** (`28ef3342c6`). Si falla la lectura de IDs no hay sweep ni prune.
`SweepOneContainer` decide por las filas que quedan
(`fim_db_count_container_rows == 0`), no por el resultado de la transacción: un
`deleted_rows` fallido igualmente cierra la transacción y `close()` borra las filas
(caso 6 de `fim_container_txn_test`). Los contenedores no barridos se suman al
conjunto vivo del prune. Pruebas en `container_reporting_test`: IDs ilegibles y
fallo al iniciar la transacción, ambos con reintento exitoso.

### Entrega C — Autoridad del inventario y lifecycle

**Comentarios:** #2 y #7; implementación independiente de A/B salvo integración final.

1. Definir y propagar completitud de snapshot/epoch desde container_instances hasta
   las APIs compartidas del baseline y los dos consumidores.
2. Separar IDs existentes de cgroups resueltos y admisión.
3. Bloquear inferencia de bajas durante descubrimiento incompleto, no toda la detección.
4. Habilitar solicitudes lifecycle con intervalo cero sin alterar el deadline del host.
5. Actualizar documentación del protocolo, configuración y comentarios del scheduler.

**Salida:** reiniciar modulesd no borra contenedores vivos; el modo por defecto atiende
notificaciones y el scan periódico sigue existiendo aunque haya churn continuo.

**Estado: hecho** (`2e8ff0ab6e`). #7 ya estaba implementado en ambos modos de cadencia.
#2 se resolvió así:

- `MetadataStore` expone `snapshot_complete` y `known_container_ids` en la respuesta de
  lista;
- los clientes tratan como incompleta cualquier respuesta ambigua;
- FIM y Syscollector no barren ni podan con snapshots incompletos;
- un resync incompleto no avanza el cursor.

Pendiente: prueba de integración en VM reiniciando modulesd.

### Entrega D — Compatibilidad y recuperación

**Comentarios:** #3, #4, #15.

Decisiones previas, que este plan no da por aprobadas:

- Soporte de rollback y qué bases concretas pueden reconstruirse.
- Compatibilidad de bases intermedias, nunca publicadas, y necesidad de preservar filas.
- Estrategia de respaldo, DataClean/full sync y recuperación si falla la reconstrucción.

**Estado parcial:** #15 ya está congelado en SQL literal en ambos vectores de upgrade.

**Integración con 5.0.x (requisito previo de esta entrega):** traer `origin/main` o
`5.0.0` a la base de la rama. Después:

1. adoptar el `initialize` upstream (recrear en versión mayor o upgrade fallido) y
   retirar `DB_VERSION_AHEAD_OF_SCHEMA`; mantener `execute()` y clasificar los errores
   transitorios; log de `recreateReason()` en FIM;
2. Syscollector: anteponer el `RENAME COLUMN` publicado como v1→v2, desplazar los pasos
   de contenedor (v16) y pasar la DDL de osinfo a `os_display_version`;
3. guard de #4 (**decidido**): abortar la reconstrucción si la tabla vieja ya tiene
   `container_id`, para que la base se recree en vez de convertirse en silencio;
4. matriz de pruebas:
   - FIM v1 de 5.0 → v3;
   - Syscollector v1 (5.0.0-rc1) → v16;
   - Syscollector v2 (5.0.0 GA) → v16;
   - versión mayor → recreación con `recreateReason`;
   - fallo transitorio → sin borrado.

Esfuerzo estimado: 1,5–2,5 días-persona, casi todo en resolver conflictos y en la matriz.

**Decisión:** esperar a que `37532-nfr3-container-limits` incorpore `main`, y luego
rebasear esta rama y aplicar los puntos 1–4 sin cherry-picks parciales.

Implementar la política elegida y una matriz
de esquemas reales. No modificar migraciones publicadas como si nadie las hubiera corrido,
ni agregar un paso final esperando que repare fallos anteriores. Al ser trabajo aún no
publicado según la documentación de la rama, aclarar esa frontera antes de fijar versiones.

**Salida:** upgrade soportado y rollback acordado no dejan módulos inactivos ni convierten
filas de contenedores en host. Errores fuera de la política se rechazan explícitamente.

### Entrega E — Costo de reconciliación

**Comentarios:** #9, #13, #14.

Dependencias reales:

- #14 necesita el contrato de persistencia e invalidación de A.
- #9/#13 deben usar las semánticas de existencia/admisión definidas en C.
- Sustituir candidatos por `container_context` requiere demostrar primero los invariantes
  de A/B; no es un cambio necesario para eliminar sweeps por altas.

Separar tareas pequeñas del pase global, comparar conjuntos equivalentes y coalescer
solicitudes. Instrumentar conteos de consultas, escrituras y tiempo del consumidor
antes/después; no aceptar solo una mejora teórica.

**Estado: hecho** (`a5c796dddb`, `2e8ff0ab6e`).

- #9 compara conjuntos de identidad.
- #14 omite contextos idénticos.
- #13: un alta por delta ya no pide sweep; solo actualiza la admisión de ese contenedor
  con `fim_container_update_admitted`.

Pendiente: benchmark con unas 300k filas.

**Salida:** un contenedor detenido estable no genera sweeps por comparación errónea;
una alta no exige `SELECT DISTINCT file_entry`; N contextos idénticos no repiten N
syncRow/parseos.

### Entrega F — Contrato de metadatos

**Comentario:** #8.

**Decisión acordada:** snapshot del último contexto conocido al emitir. No implementar
refresco retroactivo de documentos ni cambios en el protocolo de sincronización para
forzar convergencia tras una actualización de metadatos.

**Salida:** contrato documentado y probado en el punto de emisión; ninguna corrección
genera falsas modificaciones de archivos ni tormentas de inventario por cada edición
de etiqueta.

## 4. Pruebas de aceptación

Extender las suites existentes de
[DBSync](../src/shared_modules/dbsync/tests/interface/dbsync_test.cpp),
[upgrade FIM](../src/syscheckd/src/db/tests/db/ComponentTest/upgradeInterface/fim_db_upgrade_test.cpp),
[Syscollector](../src/wazuh_modules/syscollector/tests/sysCollectorImp/syscollectorImp_test.cpp),
[eBPF user-space](../src/syscheckd/src/ebpf/tests/unit/),
[metadata store](../src/wazuh_modules/container_instances/ci_impl/tests/container_admission_store_test.cpp)
y [baseline](../src/wazuh_modules/container_baseline/container_baseline_impl/tests/container_baseline_scanner_test.cpp).
Agregar harnesses focalizados donde el bridge/drain no estén cubiertos; los tests de
helpers no sustituyen la verificación del cableado real.

| Casos | Prueba y resultado requerido |
| --- | --- |
| #1 | Forzar interleaving de miss con replace/erase/clear; ASan sin UAF, copia devuelta válida. Complementar con TSan para sincronización; no depender solo de estrés probabilístico |
| #10/#11/#14 | Setter sin handler y con stop: error explícito, sin caché exitosa. Fallo SQL: sin memo de éxito. Cerrar/recrear/reinit con mismo ID/string: contexto presente en la nueva DB. N repeticiones tras una escritura confirmada: cero syncRow/parseos adicionales |
| #12 | Callback nulo y callback válido: cero fugas/doble free con ASan/LSan o Valgrind |
| #5/#6 | Inyectar fallo en SELECT IDs, inicio de transacción, deleted_rows, callback y cierre: contextos de filas supervivientes conservados y presupuesto coherente. Reintento exitoso: DELETE enriquecidos y cleanup final |
| #2 | DB presembrada y modulesd reiniciado con running sin inode, fuente aún enumerando y lista vacía temporal: cero DELETE por esa ausencia; al completar snapshot no hay reseed por pérdida artificial. Contenedor realmente eliminado sí desaparece |
| #2 | Repetir para FIM y Syscollector, conexión caída, stopped, exceso de cap y resync por journal truncado; no confundir no resuelto/no admitido con eliminado |
| #7 | Intervalo contenedor 0, host 3600 s, scan_on_start yes/no: una notificación se atiende sin esperar el host. Inyección con reloj controlado: churn no desplaza el deadline host; pausa/stop no giran en busy loop |
| #3 | Versión futura en bases reconstruibles: recuperación según política, módulos activos y reconciliación manager. Consumidor sin política: rechazo. Backup/recreación fallidos: error visible, sin éxito aparente |
| #4/#15 | Esquema publicado v1 sin container_id; desarrollo v1/v2 con host+contenedor compartiendo clave y contenedor sin host; versiones parciales. Preservar IDs, checksums, versiones, sync, índices y filas, o ejecutar la recreación explícitamente acordada. Upgrade fallido conserva datos y versión del paso anterior |
| #9/#13 | Fallback sin deltas con contenedor detenido y lista estable durante N polls: cero sweeps adicionales por falso cambio. Alta: admisión correcta antes del walk, sin SELECT DISTINCT global. Sustitución con igual cardinalidad: no perder reconciliación legítima |
| #13 | Fixture representativa de 300.000 filas: contar sweeps y consultas globales y medir p50/p95 de espera del consumidor antes/después; sin pérdida de eventos. Fijar presupuesto de latencia con el baseline medido, no inventarlo |
| #8 | Persistir un cambio solo de label/annotation/owner: no reescribir documentos ya indexados ni generar alertas stateless FIM. Una emisión normal posterior debe incluir el último contexto persistido disponible; no se exige convergencia retroactiva |

Para integración con eventos reales y carga del proveedor eBPF, usar la VM de pruebas
con cgroup v2 y Docker/Kubernetes. En la implementación, ejecutar primero suites
focalizadas y luego compilación release e integración; no tomar este análisis como
certificación de build o runtime.

## 5. Orden y presupuesto global

1. A y B primero: eliminan fallos de memoria y pérdida de contexto ante errores.
2. C a continuación; las decisiones de D y F pueden resolverse mientras tanto.
3. D antes de declarar upgrade/rollback soportados; #15 puede entrar con la primera tanda.
4. E después de los invariantes que necesita; no optimizar sobre una lista destructiva
   que aún no sea autoritativa.
5. F según contrato acordado, sin bloquear arreglos independientes.

Presupuesto orientativo agrupado:

| Bloque | Días-persona |
| --- | --- |
| A: memoria, persistencia e invalidación | 2–3 |
| B: sweep y prune seguros | 1–2 |
| C: autoridad y scheduler | 4–6 |
| D: recuperación y migraciones | 2–5 |
| E: eficiencia | 2–4 |
| Integración cruzada y regresiones | 2–3 |
| **Base sin propagación nueva de metadatos** | **13–23** |
| F: refresh retroactivo de metadatos | No requerido por el contrato acordado |

No es un compromiso de calendario: la parte alta corresponde a preservar esquemas
intermedios, coordinar recuperación con el manager y cubrir reinicios/fallos parciales.
Si se elige documentar rollback no soportado, baja el trabajo de implementación de #3,
pero no debe presentarse como rollback corregido.

## 6. Criterio de cierre

- Ningún borrado por ausencia procede de un snapshot sin autoridad.
- Ningún contexto se retira mientras sobrevivan filas que lo necesitan.
- Ningún presupuesto se libera por un borrado no confirmado.
- Cachés describen solo la DB vigente y escrituras realmente ejecutadas.
- Identidad host/contenedor se conserva en los upgrades soportados.
- Lifecycle funciona con configuración por defecto sin alterar la cadencia host.
- Las optimizaciones se verifican mediante conteos de trabajo y medidas.
- El contexto emitido corresponde al último valor conocido disponible en ese momento; no se exige convergencia retroactiva de documentos indexados.
- El agente compila y las pruebas focalizadas e integradas correspondientes pasan.
