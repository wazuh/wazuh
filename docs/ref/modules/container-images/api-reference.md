# API Reference

The Container Images module provides an internal C and C++ interface for interaction between `wazuh-modulesd` and the `libcontainer_images.so` shared library.

> **Note:** This is not a user-facing API. This development stage exposes lifecycle and logging functions only. Persistence is internal to the shared library; event and synchronization APIs are not available yet.

---

## Internal APIs

### Core Module Functions

#### `wm_container_images_main()`

Main entry point for the Container Images module thread.

```c
#ifdef WIN32
static DWORD WINAPI wm_container_images_main(void *arg);
#else
static void* wm_container_images_main(wm_container_images_t *data);
#endif
```

**Description:**

Loads the Container Images shared library, resolves the required exported symbols, sets the logging callback, initializes the C++ implementation, and starts the scan loop.

---

#### `wm_container_images_stop()`

Stops the Container Images module.

```c
static void wm_container_images_stop(wm_container_images_t *data);
```

**Description:**

Forwards the stop request to the shared library when the library has already been loaded.

---

## Container Images C/C++ Library Interface

#### `container_images_set_log_function()`

Sets the logging callback used by the C++ library.

```c
EXPORTED void container_images_set_log_function(log_callback_t callback);
```

**Callback Signature:**

```c
typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));
```

**Description:**

The callback is configured before initialization. The library uses it to send log messages back to the C glue layer with the fixed tag `container_images`.

---

#### `container_images_init()`

Initializes the C++ implementation with the parsed module configuration.

```c
EXPORTED void container_images_init(const unsigned int interval,
                                    const bool scanOnStart,
                                    const bool enabled,
                                    const char** referenceTypes,
                                    const char** referenceValues,
                                    const unsigned int referencesCount);
```

**Parameters:**

- `interval`: Seconds between scans.
- `scanOnStart`: Run a scan immediately after startup.
- `enabled`: Enable or disable the module.
- `referenceTypes`: Array of configured reference entry types: `ref`, `archive` or `local`.
- `referenceValues`: Array of configured reference values, parallel to `referenceTypes`.
- `referencesCount`: Number of entries in both arrays.

---

#### `container_images_start()`

Starts the scan loop.

```c
EXPORTED void container_images_start();
```

**Description:**

Runs the module until `container_images_stop()` is called. This function blocks while the module is active.

---

#### `container_images_stop()`

Signals the scan loop to stop.

```c
EXPORTED void container_images_stop();
```

**Description:**

Wakes the interval wait and allows `container_images_start()` to return.

---

#### `container_images_release_resources()`

Releases the C++ implementation instance.

```c
EXPORTED void container_images_release_resources();
```

**Description:**

Called by the C glue layer after `container_images_start()` returns.

---

## C++ Implementation Classes

### `ContainerImages` Class

The `ContainerImages` singleton bridges the C ABI to the C++ implementation.

| Method | Description |
|--------|-------------|
| `setLogFunction()` | Stores the logging callback in `LoggingHelper`. |
| `init()` | Creates the `ContainerImagesImpl` instance from `ContainerImagesConfig`. |
| `start()` | Calls the implementation `run()` method. |
| `stop()` | Calls the implementation `stop()` method. |
| `releaseResources()` | Resets the implementation instance. |

### `ContainerImagesImpl` Class

The `ContainerImagesImpl` class owns the scan loop and reader creation.

| Method | Description |
|--------|-------------|
| `run()` | Runs scan on start, then waits for the configured interval between scans. |
| `stop()` | Stops the loop and wakes the condition variable. |
| `scanOnce()` | Creates readers, discovers image references and their packages, stores them, and logs the scan result. |
| `makeReader()` | Creates the reader for a configured reference, or reports the reference type as unimplemented. |

### `IImageReader` Interface

`IImageReader` is the internal extension point for source-specific discovery.

```cpp
class IImageReader
{
    public:
        virtual ~IImageReader() = default;
        virtual std::vector<ImageReferenceRecord> discover() = 0;
        virtual std::string sourceType() const = 0;
};
```

The current implementation provides `ArchiveImageReader`, which reads saved image archives and OCI image layout directories.

### `IByteStream` Interface

`IByteStream` is the sequential byte source every layer is read through, so a layer can come from a file, from a member of an archive, or later from a remote blob without changing the reader.

```cpp
class IByteStream
{
    public:
        virtual ~IByteStream() = default;
        virtual std::size_t read(char* buffer, std::size_t size) = 0;
};
```

Implementations: `FileByteStream`, `MemoryByteStream`, `BoundedByteStream` and `GzipByteStream`.

### `IPackageDbParser` Interface

`IPackageDbParser` is the extension point for package database formats. A new format is added by implementing it and registering the paths it owns in `knownPackageDatabases()`.

```cpp
class IPackageDbParser
{
    public:
        virtual ~IPackageDbParser() = default;
        virtual std::vector<ImagePackageRecord> parse(const std::string& content, const std::string& dbPath) const = 0;
        virtual std::string format() const = 0;
};
```

The current implementations are `DpkgParser` and `ApkParser`.
