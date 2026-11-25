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

#### `container_images_set_engine_options()`

Sets the container engine options. Called before `container_images_init()`, and only needed when a `<local>` reference is configured.

```c
EXPORTED void container_images_set_engine_options(const char* dockerSocket);
```

**Parameters:**

- `dockerSocket`: Unix socket of the Docker engine that `<local>docker` reads from. The configuration parser takes it from the engine block of the same `<container_security>`. NULL or empty when no Docker engine is configured, in which case a `<local>docker` reference builds no reader.

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
| `makeReader()` | Creates the reader for a configured reference, or reports why it cannot (an unsupported engine name, a missing Docker socket, a platform without engines). |

### `IImageReader` Interface

`IImageReader` is the internal extension point for source-specific discovery.

```cpp
class IImageReader
{
    public:
        virtual ~IImageReader() = default;
        virtual ImageReadResult discover() = 0;
        virtual std::string sourceType() const = 0;
};
```

### `IEngineImageSource` Interface

`IEngineImageSource` is what `EngineImageReader` needs of a container engine. `DockerImageSource` implements it over the Docker Engine API on a Unix socket; tests use a fake.

```cpp
class IEngineImageSource
{
    public:
        virtual ~IEngineImageSource() = default;
        virtual bool listImages(std::vector<EngineImage>& images, std::string& error) = 0;
        virtual std::unique_ptr<IBlobStream> exportImage(const std::string& id,
                                                         std::uint64_t maxBytes,
                                                         std::string& error) = 0;
};
```

`EngineImage` holds `id`, `repoTags` and `repoDigests` as the engine lists them. `exportImage()` returns the saved image archive (`docker save`) as a stream; a transfer that fails after it started is reported by the stream's `failed()`.

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

### `PackageDb::read`

The package database parser is shared with container runtime security and lives in `src/data_provider/src/packages/packageDbParser.hpp`. It works on bytes and in-image paths, never on the host filesystem.

```cpp
namespace PackageDb
{
    using Files = std::map<std::string, std::string>; // in-image path (no leading slash) to content

    bool isDatabasePath(const std::string& path);      // a file the parser reads, so a caller keeps its content
    Result read(const Files& files);                   // packages, and one report per database found
}
```

`Result::databases` says, for each database, how many packages it gave, whether it was skipped because another location of the same format was read, and why it could not be read. A new format is added there, not in the module.
