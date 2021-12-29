#ifndef __CATALOG_H__
#define __CATALOG_H__

#include <string>
#include <vector>
#include <memory>

#include "storageDriver/StorageDriverInterface.hpp"
#include "storageDriver/disk/diskStorage.hpp"

class Catalog {

    private:
        std::unique_ptr<StorageDriverInterface> storageDriver;

    public:
        /**
         * @brief Create the catalog manager from the given driver to connect.
         * @param storageDriver The storage driver to connect to. The driver is destroyed when the catalog is freed.
         */
        Catalog(std::unique_ptr<StorageDriverInterface> storageDriver) {
            this->storageDriver = std::move(storageDriver);
        }

        /**
         * @brief Dump pending changes and freed driver storage.
         */
        ~Catalog() {
            storageDriver.reset();
        }

        /**
         * @brief Get the decoder for the given decoder name.
         * @param decoderName The name of the decoder.
         * @return The decoder.
         */
        rapidjson::Document getDecoder(std::string_view decoderName);

        /**
         * @brief Get the Decoder list
         * @return std::vector<std::string_view> the list of decoders.
         */
        std::vector<std::string_view> getDecoderList();
};
#endif // __CATALOG_H__
